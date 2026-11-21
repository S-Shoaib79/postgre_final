/*-------------------------------------------------------------------------
 *
 * discreet_metadata.c
 *	  Discreet metadata service: asset records for columns marked for
 *	  encryption in their comment.
 *
 * A column is marked with its comment (pg_description):
 *
 *	COMMENT ON COLUMN employee.salary IS 'encrypt=yes; desc=Employee salary';
 *
 * encrypt takes yes/no (or true/false, on/off, 1/0); desc is optional and,
 * when present, must come last (it runs to the end of the comment).
 *
 * CREATE TABLE (DefineRelation) and COMMENT ON (CommentObject) remember the
 * table.  When the transaction commits, the service reads the comment of
 * every column of those tables and writes one asset record per column with
 * encrypt=yes to metadata.json in the data directory:
 *
 *	[
 *	  {"assetName": "AST-5-16385-3", "assetDescription": "Employee salary",
 *	   "columnId": 3, "tableId": 16385, "databaseId": 5, "columnName": ...}
 *	]
 *
 * (each record is on one line in the file).  A table's old records are
 * replaced, so a later COMMENT updates them; records of other tables and
 * databases are kept.  DROP TABLE (heap_drop_with_catalog) remembers the
 * table too: it no longer exists at commit, so its records are removed.  Writing at commit means a rolled-back CREATE TABLE
 * writes nothing, and a table created and commented in one transaction is
 * written once.
 *
 * src/backend/commands/discreet_metadata.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include <ctype.h>

#include "access/transam.h"
#include "access/xact.h"
#include "catalog/pg_class.h"
#include "commands/comment.h"
#include "commands/dbcommands.h"
#include "commands/discreet_metadata.h"
#include "common/string.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "storage/fd.h"
#include "storage/lock.h"
#include "utils/builtins.h"
#include "utils/json.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"

/* In the data directory, the backend's working directory */
#define DISCREET_METADATA_FILE		"metadata.json"
#define DISCREET_METADATA_TMPFILE	"metadata.json.tmp"

/* Tables created or commented on in the current transaction */
static List *pending_relids = NIL;
static bool callback_registered = false;

static void _PGS_Discreet_Metadata_XactCallback(XactEvent event, void *arg);

/*
 * Remember a table created or commented on; its records are written at
 * commit.  Catalog tables and other relation kinds are filtered there.
 */
void
_PGS_Discreet_Metadata_Track(Oid relid)
{
	MemoryContext oldcxt;

	if (!OidIsValid(relid) || relid < FirstNormalObjectId)
		return;

	if (!callback_registered)
	{
		RegisterXactCallback(_PGS_Discreet_Metadata_XactCallback, NULL);
		callback_registered = true;
	}

	oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	pending_relids = list_append_unique_oid(pending_relids, relid);
	MemoryContextSwitchTo(oldcxt);
}

/* Strip leading and trailing white space in place */
static char *
_PGS_Discreet_Metadata_Trim(char *s)
{
	char	   *end;

	while (isspace((unsigned char) *s))
		s++;
	end = s + strlen(s);
	while (end > s && isspace((unsigned char) end[-1]))
		end--;
	*end = '\0';
	return s;
}

/*
 * Read a column comment "encrypt=yes; desc=<text>".  Keys are
 * case-insensitive; desc (or description) is optional and runs to the end of
 * the comment.  Returns true when encryption is allowed, with *desc set to
 * the description or NULL.
 */
static bool
_PGS_Discreet_Metadata_ParseComment(const char *comment, char **desc)
{
	char	   *p = pstrdup(comment);
	bool		encrypt = false;

	*desc = NULL;
	while (p != NULL)
	{
		char	   *next = strchr(p, ';');
		char	   *eq;
		char	   *key;

		if (next != NULL)
			*next++ = '\0';

		eq = strchr(p, '=');
		if (eq != NULL)
		{
			*eq = '\0';
			key = _PGS_Discreet_Metadata_Trim(p);

			if (pg_strcasecmp(key, "desc") == 0 ||
				pg_strcasecmp(key, "description") == 0)
			{
				char	   *val;

				/* The description is the rest of the comment, ';' included */
				if (next != NULL)
					next[-1] = ';';
				val = _PGS_Discreet_Metadata_Trim(eq + 1);
				if (*val != '\0')
					*desc = pstrdup(val);
				break;
			}

			if (pg_strcasecmp(key, "encrypt") == 0)
			{
				bool		val;

				if (parse_bool(_PGS_Discreet_Metadata_Trim(eq + 1), &val))
					encrypt = val;
			}
		}
		p = next;
	}

	return encrypt;
}

/*
 * Unique asset name of a column: AST-<databaseId>-<tableId>-<columnId>.
 * The three ids together are unique in the cluster.
 */
static char *
_PGS_Discreet_Metadata_AssetName(Oid dbid, Oid relid, AttrNumber attnum)
{
	return psprintf("AST-%u-%u-%d", dbid, relid, attnum);
}

/* Append the asset records (JSON, one line each) of one table to *records */
static void
_PGS_Discreet_Metadata_CollectTable(Oid relid, List **records)
{
	char		relkind = get_rel_relkind(relid);
	Relation	rel;
	TupleDesc	tupdesc;
	char	   *dbname;
	char	   *tablename;

	/* Dropped (DROP TABLE): no records, so Write() only removes the old ones */
	if (relkind == '\0')
	{
		elog(LOG, "[DISCREET_METADATA] table %u of database %u dropped: its records are removed",
			 relid, MyDatabaseId);
		return;
	}

	/* Not a table (view, sequence, ...) */
	if (relkind != RELKIND_RELATION && relkind != RELKIND_PARTITIONED_TABLE)
		return;

	rel = RelationIdGetRelation(relid);
	if (!RelationIsValid(rel))
		return;

	tupdesc = RelationGetDescr(rel);
	dbname = get_database_name(MyDatabaseId);
	tablename = psprintf("%s.%s",
						 get_namespace_name(RelationGetNamespace(rel)),
						 RelationGetRelationName(rel));

	for (int i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);
		char	   *comment;
		char	   *desc;
		char	   *asset;
		StringInfoData buf;

		if (att->attisdropped)
			continue;

		comment = GetComment(relid, RelationRelationId, att->attnum);
		if (comment == NULL || !_PGS_Discreet_Metadata_ParseComment(comment, &desc))
			continue;

		/* No desc in the comment: identify the column by name */
		if (desc == NULL)
			desc = psprintf("%s.%s", tablename, NameStr(att->attname));

		asset = _PGS_Discreet_Metadata_AssetName(MyDatabaseId, relid, att->attnum);

		/* tableId and databaseId stay together: the file is filtered on them */
		initStringInfo(&buf);
		appendStringInfoString(&buf, "{\"assetName\": ");
		escape_json(&buf, asset);
		appendStringInfoString(&buf, ", \"assetDescription\": ");
		escape_json(&buf, desc);
		appendStringInfo(&buf, ", \"columnId\": %d, \"tableId\": %u, \"databaseId\": %u",
						 att->attnum, relid, MyDatabaseId);
		appendStringInfoString(&buf, ", \"columnName\": ");
		escape_json(&buf, NameStr(att->attname));
		appendStringInfoString(&buf, ", \"tableName\": ");
		escape_json(&buf, tablename);
		appendStringInfoString(&buf, ", \"databaseName\": ");
		escape_json(&buf, dbname ? dbname : "");
		appendStringInfoChar(&buf, '}');

		*records = lappend(*records, buf.data);

		elog(LOG, "[DISCREET_METADATA] asset %s | %s.%s (column %d, table %u, database %u) | %s",
			 asset, tablename, NameStr(att->attname), att->attnum, relid,
			 MyDatabaseId, desc);
	}

	RelationClose(rel);
}

/*
 * Rewrite metadata.json: keep the records of tables not touched in this
 * transaction, replace the records of the touched ones.
 */
static void
_PGS_Discreet_Metadata_Write(void)
{
	List	   *records = NIL;
	List	   *kept = NIL;
	List	   *keys = NIL;
	LOCKTAG		tag;
	FILE	   *fp;
	StringInfoData out;
	ListCell   *lc;
	bool		first = true;
	int			nkept;
	int			nremoved = 0;

	foreach(lc, pending_relids)
	{
		Oid			relid = lfirst_oid(lc);

		keys = lappend(keys, psprintf("\"tableId\": %u, \"databaseId\": %u,",
									  relid, MyDatabaseId));
		_PGS_Discreet_Metadata_CollectTable(relid, &records);
	}

	/*
	 * One writer at a time, across all databases (database field 0): an
	 * advisory lock held until this transaction ends.
	 */
	SET_LOCKTAG_ADVISORY(tag, InvalidOid, 0x44495343, 0x4D455441, 2);
	(void) LockAcquire(&tag, ExclusiveLock, false, false);

	/* Records are one per line, between "[" and "]" */
	fp = AllocateFile(DISCREET_METADATA_FILE, "r");
	if (fp != NULL)
	{
		StringInfoData line;

		initStringInfo(&line);
		while (pg_get_line_buf(fp, &line))
		{
			char	   *rec = _PGS_Discreet_Metadata_Trim(line.data);
			size_t		len = strlen(rec);
			bool		replaced = false;
			ListCell   *lk;

			if (rec[0] != '{')
				continue;
			if (rec[len - 1] == ',')
				rec[len - 1] = '\0';

			foreach(lk, keys)
			{
				if (strstr(rec, (char *) lfirst(lk)) != NULL)
				{
					replaced = true;
					break;
				}
			}
			if (replaced)
				nremoved++;
			else
				kept = lappend(kept, pstrdup(rec));
		}
		FreeFile(fp);
	}
	else if (errno != ENOENT)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("[DISCREET_METADATA] could not read \"%s\": %m",
						DISCREET_METADATA_FILE)));
		return;
	}

	/* Counted before list_concat() appends the new records to kept */
	nkept = list_length(kept);

	initStringInfo(&out);
	appendStringInfoString(&out, "[\n");
	foreach(lc, list_concat(kept, records))
	{
		appendStringInfo(&out, "%s  %s", first ? "" : ",\n", (char *) lfirst(lc));
		first = false;
	}
	appendStringInfoString(&out, first ? "]\n" : "\n]\n");

	/* Write a temporary file and rename it, so readers never see half a file */
	fp = AllocateFile(DISCREET_METADATA_TMPFILE, PG_BINARY_W);
	if (fp == NULL ||
		fwrite(out.data, 1, out.len, fp) != (size_t) out.len)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("[DISCREET_METADATA] could not write \"%s\": %m",
						DISCREET_METADATA_TMPFILE)));
		if (fp != NULL)
			FreeFile(fp);
		return;
	}
	if (FreeFile(fp) != 0)
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("[DISCREET_METADATA] could not close \"%s\": %m",
						DISCREET_METADATA_TMPFILE)));
		return;
	}
	if (durable_rename(DISCREET_METADATA_TMPFILE, DISCREET_METADATA_FILE, WARNING) != 0)
		return;

	elog(LOG, "[DISCREET_METADATA] wrote %s | %d record(s) for %d table(s) of database %u, %d old record(s) removed, %d other record(s) kept",
		 DISCREET_METADATA_FILE, list_length(records), list_length(pending_relids),
		 MyDatabaseId, nremoved, nkept);
}

/* Write at commit; forget the tables when the transaction ends */
static void
_PGS_Discreet_Metadata_XactCallback(XactEvent event, void *arg)
{
	switch (event)
	{
		case XACT_EVENT_PRE_COMMIT:
			if (pending_relids != NIL)
				_PGS_Discreet_Metadata_Write();
			break;
		case XACT_EVENT_COMMIT:
		case XACT_EVENT_ABORT:
		case XACT_EVENT_PREPARE:
		case XACT_EVENT_PARALLEL_COMMIT:
		case XACT_EVENT_PARALLEL_ABORT:
			/* The list itself goes with TopTransactionContext */
			pending_relids = NIL;
			break;
		default:
			break;
	}
}
