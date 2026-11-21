/*-------------------------------------------------------------------------
 *
 * discreet_hooks.c
 *	  Discreet R1/W1 executor instrumentation hooks.
 *
 * Everything the executor calls for the Discreet test suite (TC-01..TC-12):
 *
 *	_PGS_LogExecutorTableInfo / _PGS_Discreet_LogExecutorRun
 *		the logger hook (standard_ExecutorRun, ExecInsert/Update/Delete)
 *	_PGS_Discreet_R1_Intercept
 *		R1, called from ExecutePlan() for each result row before delivery
 *	_PGS_Discreet_W1_Insert / _PGS_Discreet_W1_Update / _PGS_Discreet_W1_Delete
 *		W1, called from nodeModifyTable.c before each row is written
 *
 * Kept out of execMain.c and nodeModifyTable.c so those files carry only the
 * hook calls.  Synthetic test data only: these log column values.
 *
 * src/backend/executor/discreet_hooks.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "access/tableam.h"
#include "access/transam.h"
#include "catalog/pg_class.h"
#include "catalog/pg_type.h"
#include "common/int.h"
#include "executor/discreet_hooks.h"
#include "catalog/namespace.h"
#include "executor/executor.h"
#include "executor/spi.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "nodes/makefuncs.h"
#include "nodes/nodeFuncs.h"
#include "nodes/plannodes.h"
#include "optimizer/optimizer.h"
#include "parser/parsetree.h"
#include "utils/array.h"
#include "utils/builtins.h"
#include "utils/datum.h"
#include "utils/guc.h"
#include "utils/guc_tables.h"
#include "utils/lsyscache.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"


/* ----------------------------------------------------------------
 *		Logger hook and R1 (read side)
 * ----------------------------------------------------------------
 */

/*
 * Custom hook function to log table ID, PID, and thread ID
 */
void
_PGS_LogExecutorTableInfo(const char *action, Oid table_oid, const char *relname)
{
#ifdef WIN32
	unsigned long threadId = (unsigned long) GetCurrentThreadId();
#else
	unsigned long threadId = (unsigned long) MyProcPid;
#endif

	if (relname != NULL && OidIsValid(table_oid))
	{
		elog(LOG, "[CUSTOM_HOOK] Action: %s | Table: %s (OID: %u) | PID: %d | Thread ID: %lu",
			 action, relname, (unsigned int) table_oid, (int) MyProcPid, threadId);
	}
	else if (OidIsValid(table_oid))
	{
		elog(LOG, "[CUSTOM_HOOK] Action: %s | Table OID: %u | PID: %d | Thread ID: %lu",
			 action, (unsigned int) table_oid, (int) MyProcPid, threadId);
	}
	else
	{
		elog(LOG, "[CUSTOM_HOOK] Action: %s | Table: (Virtual/None) | PID: %d | Thread ID: %lu",
			 action, (int) MyProcPid, threadId);
	}
}

/*
 * Logger hook for ExecutorRun: one line per table the plan uses, or one
 * "(Virtual/None)" line when it uses none.
 */
void
_PGS_Discreet_LogExecutorRun(QueryDesc *queryDesc)
{
	if (queryDesc->plannedstmt != NULL && queryDesc->plannedstmt->relationOids != NIL)
	{
		ListCell   *lc;

		foreach(lc, queryDesc->plannedstmt->relationOids)
		{
			Oid			relOid = lfirst_oid(lc);
			char	   *rname = get_rel_name(relOid);

			_PGS_LogExecutorTableInfo("ExecutorRun", relOid, rname);
		}
	}
	else
	{
		_PGS_LogExecutorTableInfo("ExecutorRun", InvalidOid, NULL);
	}
}

/*
 * DISCREET R1 helpers.
 *
 * The test suite (TC-01..TC-12) needs more than the final values: which scan
 * produced them (TC-01..04), which base table and column each output column
 * came from (TC-09 JOIN, TC-10 expressions), and whether the application
 * identity came from a trusted place (TC-12).
 */

/* Human-readable name of a scan node, or NULL for non-scan nodes. */
static const char *
_PGS_Discreet_ScanName(Plan *plan)
{
	switch (nodeTag(plan))
	{
		case T_SeqScan:
			return "Seq Scan";
		case T_IndexScan:
			return "Index Scan";
		case T_IndexOnlyScan:
			return "Index Only Scan";
		case T_BitmapHeapScan:
			return "Bitmap Heap Scan";
		case T_TidScan:
			return "Tid Scan";
		case T_TidRangeScan:
			return "Tid Range Scan";
		case T_SampleScan:
			return "Sample Scan";
		case T_FunctionScan:
			return "Function Scan";
		case T_ValuesScan:
			return "Values Scan";
		case T_SubqueryScan:
			return "Subquery Scan";
		case T_CteScan:
			return "CTE Scan";
		default:
			return NULL;
	}
}

/* Walk the plan tree and list every scan with the relation it reads. */
static void
_PGS_Discreet_CollectScans(Plan *plan, List *rtable, StringInfo out)
{
	const char *scan;

	if (plan == NULL)
		return;

	scan = _PGS_Discreet_ScanName(plan);
	if (scan != NULL)
	{
		Index		scanrelid = ((Scan *) plan)->scanrelid;
		const char *relname = NULL;

		if (scanrelid > 0 && scanrelid <= list_length(rtable))
		{
			RangeTblEntry *rte = rt_fetch(scanrelid, rtable);

			if (rte->rtekind == RTE_RELATION)
				relname = get_rel_name(rte->relid);
		}
		if (out->len > 0)
			appendStringInfoString(out, ", ");
		appendStringInfo(out, "%s on %s", scan, relname ? relname : "(non-relation)");
	}

	_PGS_Discreet_CollectScans(plan->lefttree, rtable, out);
	_PGS_Discreet_CollectScans(plan->righttree, rtable, out);

	/* Append / MergeAppend children (partitions, UNION ALL) */
	if (IsA(plan, Append))
	{
		ListCell   *lc;

		foreach(lc, ((Append *) plan)->appendplans)
			_PGS_Discreet_CollectScans((Plan *) lfirst(lc), rtable, out);
	}
	else if (IsA(plan, MergeAppend))
	{
		ListCell   *lc;

		foreach(lc, ((MergeAppend *) plan)->mergeplans)
			_PGS_Discreet_CollectScans((Plan *) lfirst(lc), rtable, out);
	}
}

/* "employee.salary attnum 4" for a range-table index and column number. */
static void
_PGS_Discreet_AppendColumnRef(StringInfo out, List *rtable, Index rtindex, AttrNumber attno)
{
	if (rtindex > 0 && rtindex <= list_length(rtable))
	{
		RangeTblEntry *rte = rt_fetch(rtindex, rtable);

		if (rte->rtekind == RTE_RELATION && attno > 0)
		{
			char	   *relname = get_rel_name(rte->relid);
			char	   *attname = get_attname(rte->relid, attno, true);

			appendStringInfo(out, "%s.%s attnum %d",
							 relname ? relname : "?", attname ? attname : "?", (int) attno);
			return;
		}
	}
	appendStringInfoString(out, "(not a base column)");
}

/*
 * Where output column `resno` came from.
 *
 * A plain column carries its base table and column on the target entry
 * (resorigtbl/resorigcol, the same thing the client RowDescription reports).
 * For a computed column, the base columns it reads are found through the
 * syntactic Var referents (varnosyn/varattnosyn), which keep pointing at the
 * range table even after joins renumber Vars to OUTER/INNER.
 */
static void
_PGS_Discreet_AppendSource(StringInfo out, PlannedStmt *stmt, AttrNumber resno)
{
	ListCell   *lc;
	TargetEntry *tle = NULL;

	if (stmt == NULL || stmt->planTree == NULL)
		return;

	foreach(lc, stmt->planTree->targetlist)
	{
		TargetEntry *candidate = (TargetEntry *) lfirst(lc);

		if (candidate->resno == resno)
		{
			tle = candidate;
			break;
		}
	}
	if (tle == NULL)
		return;

	if (OidIsValid(tle->resorigtbl) && tle->resorigcol > 0)
	{
		char	   *relname = get_rel_name(tle->resorigtbl);
		char	   *attname = get_attname(tle->resorigtbl, tle->resorigcol, true);

		appendStringInfo(out, " source: %s.%s attnum %d",
						 relname ? relname : "?", attname ? attname : "?",
						 (int) tle->resorigcol);
	}
	else
	{
		List	   *vars = pull_var_clause((Node *) tle->expr,
										   PVC_RECURSE_AGGREGATES |
										   PVC_RECURSE_WINDOWFUNCS |
										   PVC_RECURSE_PLACEHOLDERS);
		ListCell   *vc;
		bool		first = true;

		appendStringInfoString(out, " source: computed");
		foreach(vc, vars)
		{
			Var		   *var = (Var *) lfirst(vc);

			appendStringInfoString(out, first ? " from " : ", ");
			_PGS_Discreet_AppendColumnRef(out, stmt->rtable, var->varnosyn, var->varattnosyn);
			first = false;
		}
		list_free(vars);
	}
}

/*
 * The application identity is only trusted when an administrator set it:
 * ALTER ROLE / ALTER DATABASE ... SET discreet.app_user, or postgresql.conf.
 * A SET in the session, or startup options the client sends (PGOPTIONS), are
 * client-asserted and never validated (TC-12: "never a client-asserted
 * value").
 */
static bool
_PGS_Discreet_IdentityTrusted(const char *name)
{
	struct config_generic *record = find_option(name, false, true, DEBUG5);

	if (record == NULL)
		return false;
	switch (record->source)
	{
		case PGC_S_FILE:
		case PGC_S_DATABASE:
		case PGC_S_USER:
		case PGC_S_DATABASE_USER:
			return true;
		default:
			return false;
	}
}

/*
 * DISCREET R1: Intercept result tuples in ExecutePlan right before sendTuples
 */
void
_PGS_Discreet_R1_Intercept(QueryDesc *queryDesc, TupleTableSlot *slot, uint64 row_num)
{
	TupleDesc	tupdesc = slot->tts_tupleDescriptor;
	PlannedStmt *stmt = queryDesc != NULL ? queryDesc->plannedstmt : NULL;
	StringInfoData buf;
	StringInfoData tables_buf;
	int			i;
	const char *app_user;
	const char *tenant;
	const char *req_id;

	initStringInfo(&buf);
	initStringInfo(&tables_buf);

	/* Determine target relation(s) from query plan if available */
	if (stmt != NULL && stmt->relationOids != NIL)
	{
		ListCell   *lc;
		bool		first = true;

		foreach(lc, stmt->relationOids)
		{
			Oid			relOid = lfirst_oid(lc);
			char	   *rname = get_rel_name(relOid);

			if (!first)
				appendStringInfoString(&tables_buf, ", ");
			appendStringInfo(&tables_buf, "%s (OID: %u)", rname ? rname : "unknown", (unsigned int) relOid);
			first = false;
		}
	}
	else
	{
		appendStringInfoString(&tables_buf, "(Virtual/Expression)");
	}

	/* Once per query: the scan path that produced the rows (TC-01..TC-04) */
	if (row_num == 1 && stmt != NULL && stmt->planTree != NULL)
	{
		StringInfoData scans;

		initStringInfo(&scans);
		_PGS_Discreet_CollectScans(stmt->planTree, stmt->rtable, &scans);
		elog(LOG, "[DISCREET_R1] PLAN | Table: %s | Scans: %s",
			 tables_buf.data, scans.len > 0 ? scans.data : "(none)");
		pfree(scans.data);
	}

	slot_getallattrs(slot);

	appendStringInfo(&buf, "[DISCREET_R1] READ row %llu | Table: %s",
					 (unsigned long long) row_num, tables_buf.data);

	for (i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
		bool		isnull = slot->tts_isnull[i];

		if (isnull)
		{
			appendStringInfo(&buf, " | attnum %d (%s): NULL isnull: true",
							 i + 1, NameStr(attr->attname));
		}
		else
		{
			Oid			typoutput;
			bool		typisvarlena;
			char	   *val_str;

			getTypeOutputInfo(attr->atttypid, &typoutput, &typisvarlena);
			val_str = OidOutputFunctionCall(typoutput, slot->tts_values[i]);
			appendStringInfo(&buf, " | attnum %d (%s): %s isnull: false",
							 i + 1, NameStr(attr->attname), val_str ? val_str : "");
		}
		/* Base table and column behind this output column (TC-09, TC-10) */
		_PGS_Discreet_AppendSource(&buf, stmt, (AttrNumber) (i + 1));
	}

	/* Application identity (TC-12) */
	app_user = GetConfigOption("discreet.app_user", true, false);
	if (app_user != NULL && app_user[0] != '\0')
	{
		tenant = GetConfigOption("discreet.tenant", true, false);
		req_id = GetConfigOption("discreet.request_id", true, false);
		appendStringInfo(&buf, " | app_user: %s | tenant: %s | request_id: %s | validated: %s",
						 app_user, tenant ? tenant : "none", req_id ? req_id : "none",
						 _PGS_Discreet_IdentityTrusted("discreet.app_user") ? "true" : "false (client-asserted)");
	}

	elog(LOG, "%s", buf.data);

	pfree(buf.data);
	pfree(tables_buf.data);
}


/* ----------------------------------------------------------------
 *		W1 (write side)
 * ----------------------------------------------------------------
 */

/*
 * DISCREET W1: Inspect row before persistent INSERT
 *
 * stage "entry": the row as ExecInsert receives it.
 * stage "final": the row about to be stored, after BEFORE ROW triggers,
 * generated columns and constraint checks (TC-05: final row timing).
 */
void
_PGS_Discreet_W1_Insert(Relation rel, TupleTableSlot *slot, const char *stage)
{
	TupleDesc tupdesc = slot->tts_tupleDescriptor;
	StringInfoData buf;
	int i;

	initStringInfo(&buf);
	slot_getallattrs(slot);

	appendStringInfo(&buf, "[DISCREET_W1] INSERT (%s) | Table: %s (OID: %u)",
					 stage,
					 RelationGetRelationName(rel),
					 (unsigned int) RelationGetRelid(rel));

	for (i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
		bool isnull = slot->tts_isnull[i];

		if (isnull)
		{
			appendStringInfo(&buf, " | %d (%s): NULL", i + 1, NameStr(attr->attname));
		}
		else
		{
			Oid typoutput;
			bool typisvarlena;
			char *val_str;

			getTypeOutputInfo(attr->atttypid, &typoutput, &typisvarlena);
			val_str = OidOutputFunctionCall(typoutput, slot->tts_values[i]);
			appendStringInfo(&buf, " | %d (%s): %s", i + 1, NameStr(attr->attname), val_str ? val_str : "");
		}
	}

	elog(LOG, "%s", buf.data);
	pfree(buf.data);
}

/*
 * DISCREET W1: Inspect old and new values before persistent UPDATE
 */
void
_PGS_Discreet_W1_Update(Relation rel, TupleTableSlot *slot, ItemPointer tupleid)
{
	TupleDesc tupdesc = slot->tts_tupleDescriptor;
	TupleTableSlot *oldSlot = NULL;
	StringInfoData buf;
	int i;

	initStringInfo(&buf);
	slot_getallattrs(slot);

	appendStringInfo(&buf, "[DISCREET_W1] UPDATE | Table: %s (OID: %u)",
					 RelationGetRelationName(rel),
					 (unsigned int) RelationGetRelid(rel));

	/* Fetch old row image if possible to compare old and new values */
	if (tupleid && ItemPointerIsValid(tupleid))
	{
		oldSlot = table_slot_create(rel, NULL);
		if (!table_tuple_fetch_row_version(rel, tupleid, SnapshotAny, oldSlot))
		{
			ExecDropSingleTupleTableSlot(oldSlot);
			oldSlot = NULL;
		}
		else
		{
			slot_getallattrs(oldSlot);
		}
	}

	for (i = 0; i < tupdesc->natts; i++)
	{
		Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
		char *new_val = "NULL";
		char *old_val = "NULL";
		bool new_null = slot->tts_isnull[i];
		bool old_null = (oldSlot != NULL) ? oldSlot->tts_isnull[i] : true;
		Oid typoutput;
		bool typisvarlena;

		getTypeOutputInfo(attr->atttypid, &typoutput, &typisvarlena);

		if (!new_null)
			new_val = OidOutputFunctionCall(typoutput, slot->tts_values[i]);

		if (oldSlot && !old_null)
			old_val = OidOutputFunctionCall(typoutput, oldSlot->tts_values[i]);

		/* Report changed column(s) */
		if (new_null != old_null || (new_val && old_val && strcmp(new_val, old_val) != 0))
		{
			appendStringInfo(&buf, " | attnum: %d (%s) old_value: %s new_value: %s",
							 i + 1, NameStr(attr->attname), old_val, new_val);
		}
	}

	if (oldSlot)
		ExecDropSingleTupleTableSlot(oldSlot);

	elog(LOG, "%s", buf.data);
	pfree(buf.data);
}

/*
 * DISCREET W1: Inspect row before persistent DELETE
 */
void
_PGS_Discreet_W1_Delete(Relation rel, ItemPointer tupleid)
{
	StringInfoData buf;
	TupleTableSlot *oldSlot = NULL;
	initStringInfo(&buf);

	appendStringInfo(&buf, "[DISCREET_W1] DELETE | Table: %s (OID: %u)",
					 RelationGetRelationName(rel),
					 (unsigned int) RelationGetRelid(rel));

	if (tupleid && ItemPointerIsValid(tupleid))
	{
		oldSlot = table_slot_create(rel, NULL);
		if (table_tuple_fetch_row_version(rel, tupleid, SnapshotAny, oldSlot))
		{
			TupleDesc tupdesc = oldSlot->tts_tupleDescriptor;
			int i;
			slot_getallattrs(oldSlot);

			for (i = 0; i < tupdesc->natts; i++)
			{
				Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
				if (!oldSlot->tts_isnull[i])
				{
					Oid typoutput;
					bool typisvarlena;
					char *val_str;

					getTypeOutputInfo(attr->atttypid, &typoutput, &typisvarlena);
					val_str = OidOutputFunctionCall(typoutput, oldSlot->tts_values[i]);
					appendStringInfo(&buf, " | %s: %s", NameStr(attr->attname), val_str ? val_str : "");
				}
				else
				{
					appendStringInfo(&buf, " | %s: NULL", NameStr(attr->attname));
				}
			}
		}
		ExecDropSingleTupleTableSlot(oldSlot);
	}

	appendStringInfoString(&buf, " | No new row image");

	elog(LOG, "%s", buf.data);
	pfree(buf.data);
}


/* ----------------------------------------------------------------
 *		Integer shift: +10 on write (W1), -10 on read (R1)
 *
 * Integer columns (int2, int4, int8) of user tables are stored 10 higher
 * than the client wrote them, so the table and every hook log line after
 * the shift hold the shifted value, and SELECT gives the client back the
 * original value.  Columns named "id", and foreign keys to them, are not
 * shifted (_PGS_Discreet_IsIdColumn).  SET discreet.shift_integers = off
 * disables it.
 * ----------------------------------------------------------------
 */

#define DISCREET_SHIFT 10

/* On unless discreet.shift_integers is set to a false value */
static bool
_PGS_Discreet_ShiftEnabled(void)
{
	const char *val = GetConfigOption("discreet.shift_integers", true, false);
	bool		enabled;

	if (val == NULL || val[0] == '\0' || !parse_bool(val, &enabled))
		return true;
	return enabled;
}

/* Only user tables are shifted: never system catalogs, TOAST or foreign tables. */
static bool
_PGS_Discreet_IsShiftedRel(Oid relid)
{
	char		relkind;

	if (relid < FirstNormalObjectId)
		return false;
	relkind = get_rel_relkind(relid);
	return relkind == RELKIND_RELATION || relkind == RELKIND_PARTITIONED_TABLE;
}

/*
 * Columns the shift leaves alone: a column named "id", and a foreign key
 * column that references one (so the foreign key still matches the stored
 * id).  Write, read and the planner rewrite all use this test.
 */
static bool
_PGS_Discreet_IsIdColumn(Oid relid, AttrNumber attnum)
{
	char	   *attname = get_attname(relid, attnum, true);
	Relation	rel;
	ListCell   *lc;
	bool		result = false;

	if (attname == NULL)
		return false;
	if (pg_strcasecmp(attname, "id") == 0)
		return true;

	rel = RelationIdGetRelation(relid);
	if (!RelationIsValid(rel))
		return false;
	foreach(lc, RelationGetFKeyList(rel))
	{
		ForeignKeyCacheInfo *fk = lfirst_node(ForeignKeyCacheInfo, lc);

		for (int i = 0; i < fk->nkeys && !result; i++)
		{
			if (fk->conkey[i] == attnum)
			{
				char	   *refname = get_attname(fk->confrelid, fk->confkey[i], true);

				result = refname != NULL && pg_strcasecmp(refname, "id") == 0;
			}
		}
		if (result)
			break;
	}
	RelationClose(rel);
	return result;
}

/*
 * Does this output column come straight from a stored integer column?  R1
 * subtracts 10 from exactly these, and the planner rewrite leaves exactly
 * these for R1, so both must use this test.
 */
static bool
_PGS_Discreet_OriginIsShifted(TargetEntry *tle, Oid typid)
{
	return OidIsValid(tle->resorigtbl) && tle->resorigcol > 0 &&
		_PGS_Discreet_IsShiftedRel(tle->resorigtbl) &&
		get_atttype(tle->resorigtbl, tle->resorigcol) == typid &&
		!_PGS_Discreet_IsIdColumn(tle->resorigtbl, tle->resorigcol);
}

/* value + delta for int2/int4/int8: 1 done, 0 not an integer type, -1 out of range */
static int
_PGS_Discreet_ShiftDatum(Oid typid, Datum value, int delta, Datum *result)
{
	switch (typid)
	{
		case INT2OID:
			{
				int16		r;

				if (pg_add_s16_overflow(DatumGetInt16(value), (int16) delta, &r))
					return -1;
				*result = Int16GetDatum(r);
				return 1;
			}
		case INT4OID:
			{
				int32		r;

				if (pg_add_s32_overflow(DatumGetInt32(value), (int32) delta, &r))
					return -1;
				*result = Int32GetDatum(r);
				return 1;
			}
		case INT8OID:
			{
				int64		r;

				if (pg_add_s64_overflow(DatumGetInt64(value), (int64) delta, &r))
					return -1;
				*result = Int64GetDatum(r);
				return 1;
			}
		default:
			return 0;
	}
}

static char *
_PGS_Discreet_ValueText(Oid typid, Datum value)
{
	Oid			typoutput;
	bool		typisvarlena;

	getTypeOutputInfo(typid, &typoutput, &typisvarlena);
	return OidOutputFunctionCall(typoutput, value);
}

/*
 * Add DISCREET_SHIFT to the integer columns of a row about to be written:
 * every column, or (all_cols false) only the attnums in cols, offset by
 * FirstLowInvalidHeapAttributeNumber as ExecGetUpdatedCols() returns them.
 */
static void
_PGS_Discreet_ShiftWrite(EState *estate, Relation rel, TupleTableSlot *slot,
					Bitmapset *cols, bool all_cols, const char *action)
{
	TupleDesc	tupdesc = slot->tts_tupleDescriptor;
	int			natts = tupdesc->natts;
	MemoryContext oldcxt;
	Datum	   *values;
	bool	   *nulls;
	StringInfoData buf;
	int			nshifted = 0;
	int			i;

	/* SQL inside the server (PL functions, triggers, FK checks) writes as is */
	if (!_PGS_Discreet_ShiftEnabled() || _PGS_SPI_is_connected() ||
		!_PGS_Discreet_IsShiftedRel(RelationGetRelid(rel)))
		return;

	oldcxt = MemoryContextSwitchTo(GetPerTupleMemoryContext(estate));

	slot_getallattrs(slot);
	values = palloc_array(Datum, natts);
	nulls = palloc_array(bool, natts);
	memcpy(nulls, slot->tts_isnull, sizeof(*nulls) * natts);

	initStringInfo(&buf);
	appendStringInfo(&buf, "[DISCREET_SHIFT] %s +%d | Table: %s (OID: %u)",
					 action, DISCREET_SHIFT,
					 RelationGetRelationName(rel),
					 (unsigned int) RelationGetRelid(rel));

	for (i = 0; i < natts; i++)
	{
		Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
		CompactAttribute *cattr = TupleDescCompactAttr(tupdesc, i);

		values[i] = slot->tts_values[i];
		if (nulls[i])
			continue;

		if (!attr->attisdropped &&
			(all_cols ||
			 bms_is_member(i + 1 - FirstLowInvalidHeapAttributeNumber, cols)) &&
			!_PGS_Discreet_IsIdColumn(RelationGetRelid(rel), (AttrNumber) (i + 1)))
		{
			Datum		stored;
			int			res = _PGS_Discreet_ShiftDatum(attr->atttypid, values[i],
												  DISCREET_SHIFT, &stored);

			if (res < 0)
				ereport(ERROR,
						(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
						 errmsg("value %s in column \"%s\" is out of range after adding %d",
								_PGS_Discreet_ValueText(attr->atttypid, values[i]),
								NameStr(attr->attname), DISCREET_SHIFT)));
			if (res > 0)
			{
				appendStringInfo(&buf, " | %d (%s): %s -> stored %s",
								 i + 1, NameStr(attr->attname),
								 _PGS_Discreet_ValueText(attr->atttypid, values[i]),
								 _PGS_Discreet_ValueText(attr->atttypid, stored));
				values[i] = stored;
				nshifted++;
				continue;
			}
		}

		/* The slot is cleared below, so keep our own copy of the value */
		values[i] = datumCopy(values[i], cattr->attbyval, cattr->attlen);
	}

	if (nshifted > 0)
	{
		ExecClearTuple(slot);
		memcpy(slot->tts_values, values, sizeof(*values) * natts);
		memcpy(slot->tts_isnull, nulls, sizeof(*nulls) * natts);
		ExecStoreVirtualTuple(slot);
		ExecMaterializeSlot(slot);

		elog(LOG, "%s", buf.data);
	}

	MemoryContextSwitchTo(oldcxt);
}

/*
 * DISCREET W1: shift the row ExecInsert is about to store.
 *
 * An UPDATE (or MERGE ... UPDATE) that moves a row to another partition also
 * inserts it there; its other columns are already stored shifted, so only
 * the columns the UPDATE sets are shifted.
 */
void
_PGS_Discreet_W1_ShiftInsert(ModifyTableState *mtstate, ResultRelInfo *resultRelInfo,
						TupleTableSlot *slot)
{
	EState	   *estate = mtstate->ps.state;
	Relation	rel = resultRelInfo->ri_RelationDesc;
	bool		row_move;

	row_move = mtstate->operation == CMD_UPDATE ||
		(mtstate->operation == CMD_MERGE &&
		 mtstate->mt_merge_action != NULL &&
		 mtstate->mt_merge_action->mas_action->commandType == CMD_UPDATE);

	if (row_move)
		_PGS_Discreet_ShiftWrite(estate, rel, slot,
							ExecGetUpdatedCols(resultRelInfo, estate), false,
							"UPDATE (row moved)");
	else
		_PGS_Discreet_ShiftWrite(estate, rel, slot, NULL, true, "INSERT");
}

/*
 * DISCREET W1: shift the columns an UPDATE sets, just before the new row
 * version is written.  The other columns come from the stored row and are
 * already shifted.
 */
void
_PGS_Discreet_W1_ShiftUpdate(ResultRelInfo *resultRelInfo, EState *estate,
						TupleTableSlot *slot)
{
	_PGS_Discreet_ShiftWrite(estate, resultRelInfo->ri_RelationDesc, slot,
						ExecGetUpdatedCols(resultRelInfo, estate), false,
						"UPDATE");
}

/*
 * DISCREET R1: give the client the original value back.  Called after
 * _PGS_Discreet_R1_Intercept, so the READ log line shows the stored (+10) value.
 *
 * Only output columns that are a plain integer column of a user table are
 * changed here.  Computed values (expressions, aggregates) already work on
 * the original values: the planner rewrite below (_PGS_Discreet_PlannerRewrite)
 * subtracts 10 from the column before using it.  Rows that stay inside the
 * server (SPI: PL/pgSQL, triggers, foreign key checks) keep the stored values.
 */
void
_PGS_Discreet_R1_Unshift(QueryDesc *queryDesc, TupleTableSlot *slot, uint64 row_num)
{
	PlannedStmt *stmt = queryDesc != NULL ? queryDesc->plannedstmt : NULL;
	TupleDesc	tupdesc = slot->tts_tupleDescriptor;
	int			natts = tupdesc->natts;
	MemoryContext oldcxt;
	Datum	   *values;
	StringInfoData buf;
	int			nshifted = 0;
	ListCell   *lc;
	int			i;

	if (stmt == NULL || stmt->planTree == NULL || queryDesc->dest == NULL ||
		queryDesc->estate == NULL || !_PGS_Discreet_ShiftEnabled() || _PGS_SPI_is_connected())
		return;

	/*
	 * Rows leaving the query: to the client directly, through COPY TO, a
	 * holdable cursor or a portal's store (tuplestore), or as the result of
	 * an SQL function.
	 */
	switch (queryDesc->dest->mydest)
	{
		case DestRemote:
		case DestRemoteExecute:
		case DestRemoteSimple:
		case DestCopyOut:
		case DestTuplestore:
		case DestSQLFunction:
			break;
		default:
			return;
	}

	oldcxt = MemoryContextSwitchTo(GetPerTupleMemoryContext(queryDesc->estate));

	slot_getallattrs(slot);
	values = palloc_array(Datum, natts);
	memcpy(values, slot->tts_values, sizeof(*values) * natts);
	initStringInfo(&buf);

	foreach(lc, stmt->planTree->targetlist)
	{
		TargetEntry *tle = (TargetEntry *) lfirst(lc);
		Form_pg_attribute attr;
		Datum		original;

		i = tle->resno - 1;
		if (tle->resjunk || i < 0 || i >= natts || slot->tts_isnull[i])
			continue;
		attr = TupleDescAttr(tupdesc, i);
		if (!_PGS_Discreet_OriginIsShifted(tle, attr->atttypid))
			continue;

		/* Not an integer, or a value too low to have been shifted: leave it */
		if (_PGS_Discreet_ShiftDatum(attr->atttypid, values[i],
								-DISCREET_SHIFT, &original) <= 0)
			continue;

		appendStringInfo(&buf, " | attnum %d (%s): stored %s -> returned %s",
						 i + 1, NameStr(attr->attname),
						 _PGS_Discreet_ValueText(attr->atttypid, values[i]),
						 _PGS_Discreet_ValueText(attr->atttypid, original));
		values[i] = original;
		nshifted++;
	}

	if (nshifted > 0)
	{
		bool	   *nulls = palloc_array(bool, natts);

		/*
		 * Store the row as a new virtual tuple: some receivers (tuplestore)
		 * read the slot's physical tuple rather than tts_values.  Copy the
		 * other values first, since clearing the slot may release them.
		 */
		memcpy(nulls, slot->tts_isnull, sizeof(*nulls) * natts);
		for (i = 0; i < natts; i++)
		{
			CompactAttribute *cattr = TupleDescCompactAttr(tupdesc, i);

			if (!nulls[i] && !cattr->attbyval)
				values[i] = datumCopy(values[i], cattr->attbyval, cattr->attlen);
		}
		ExecClearTuple(slot);
		memcpy(slot->tts_values, values, sizeof(*values) * natts);
		memcpy(slot->tts_isnull, nulls, sizeof(*nulls) * natts);
		ExecStoreVirtualTuple(slot);
		ExecMaterializeSlot(slot);

		elog(LOG, "[DISCREET_SHIFT] READ -%d row %llu%s",
			 DISCREET_SHIFT, (unsigned long long) row_num, buf.data);
	}

	MemoryContextSwitchTo(oldcxt);
}


/* ----------------------------------------------------------------
 *		Integer shift in the planner: queries use the original values
 *
 * The table holds every integer column +10, so a client's
 * "WHERE id = 1" has to look for the stored 11, and "salary * 12",
 * "sum(salary)" or "SET qty = qty + 1" have to start from the stored value
 * minus 10.  _PGS_Discreet_PlannerRewrite() rewrites each query the client sends,
 * before it is planned:
 *
 *	- a comparison between a stored column and a value moves the shift to the
 *	  value, so indexes still work:  id = 1  ->  id = 11,
 *	  id IN (1, 2)  ->  id IN (11, 12),  id > $1  ->  id > $1 + 10;
 *	- a comparison between two stored columns is left alone (both shifted);
 *	- anywhere else a stored column is used it becomes (column - 10):
 *	  salary * 12  ->  (salary - 10) * 12,  sum(salary) -> sum(salary - 10);
 *	- INSERT ... SELECT, UPDATE SET, ON CONFLICT SET, MERGE and RETURNING use
 *	  the original values too (W1 adds the 10 back when the row is written);
 *	- a bare column in the SELECT list is left alone: R1 (_PGS_Discreet_R1_Unshift)
 *	  subtracts the 10 as the row leaves, after the R1 log line has shown the
 *	  stored value.
 *
 * SQL run inside the server (SPI: PL functions, triggers, foreign key checks
 * and cascades) is not rewritten: it works on the stored values, so a
 * foreign key compares stored with stored.
 * ----------------------------------------------------------------
 */

typedef struct DiscreetShiftContext
{
	List	   *levels;			/* Query at varlevelsup 0, 1, 2, ... */
	Query	   *sublink;		/* subselect the PARAM_SUBLINK Params refer to */
} DiscreetShiftContext;

static void _PGS_Discreet_RewriteQuery(Query *query, List *outer, bool top, bool setop_leaf);
static Node *_PGS_Discreet_UnshiftMutator(Node *node, DiscreetShiftContext *ctx);
static bool _PGS_Discreet_IsShiftedLeaf(Node *node, List *levels, Query *sublink);

static bool
_PGS_Discreet_IsShiftType(Oid typid)
{
	return typid == INT2OID || typid == INT4OID || typid == INT8OID;
}

/* expr + delta (or - for a negative delta), in expr's own integer type */
static Node *
_PGS_Discreet_MakeShift(Node *expr, int delta)
{
	Oid			typid = exprType(expr);
	int16		typlen;
	bool		typbyval;
	Datum		amount;
	Oid			opno;
	Expr	   *op;

	switch (typid)
	{
		case INT2OID:
			amount = Int16GetDatum((int16) abs(delta));
			break;
		case INT4OID:
			amount = Int32GetDatum(abs(delta));
			break;
		default:
			amount = Int64GetDatum((int64) abs(delta));
			break;
	}
	get_typlenbyval(typid, &typlen, &typbyval);
	opno = OpernameGetOprid(list_make2(makeString("pg_catalog"),
									   makeString(delta < 0 ? "-" : "+")),
							typid, typid);
	if (!OidIsValid(opno))
		elog(ERROR, "integer operator for type %u not found", typid);

	op = make_opclause(opno, typid, false, (Expr *) expr,
					   (Expr *) makeConst(typid, -1, InvalidOid, typlen,
										  amount, false, typbyval),
					   InvalidOid, InvalidOid);
	set_opfuncid((OpExpr *) op);
	return (Node *) op;
}

/* A value the client wrote, as stored (+10); NULL when that is not possible */
static Node *
_PGS_Discreet_ToStored(Node *expr)
{
	if (IsA(expr, Const))
	{
		Const	   *c = (Const *) expr;
		Datum		stored;

		/* NULL, or too large to shift: the caller falls back */
		if (c->constisnull ||
			_PGS_Discreet_ShiftDatum(c->consttype, c->constvalue,
								DISCREET_SHIFT, &stored) <= 0)
			return NULL;
		c = copyObject(c);
		c->constvalue = stored;
		return (Node *) c;
	}
	if (!_PGS_Discreet_IsShiftType(exprType(expr)))
		return NULL;
	return _PGS_Discreet_MakeShift(expr, DISCREET_SHIFT);
}

/* A constant integer array with every element +10; NULL when not possible */
static Node *
_PGS_Discreet_ArrayToStored(Node *expr, Oid elemtype)
{
	Const	   *c;
	ArrayType  *arr;
	Datum	   *elems;
	bool	   *nulls;
	int			nelems;
	int16		typlen;
	bool		typbyval;
	char		typalign;
	int			i;

	if (!IsA(expr, Const) || ((Const *) expr)->constisnull)
		return NULL;
	c = (Const *) expr;
	arr = DatumGetArrayTypeP(c->constvalue);
	if (ARR_NDIM(arr) != 1)
		return NULL;

	get_typlenbyvalalign(elemtype, &typlen, &typbyval, &typalign);
	deconstruct_array(arr, elemtype, typlen, typbyval, typalign,
					  &elems, &nulls, &nelems);
	for (i = 0; i < nelems; i++)
	{
		if (nulls[i] ||
			_PGS_Discreet_ShiftDatum(elemtype, elems[i], DISCREET_SHIFT, &elems[i]) <= 0)
			return NULL;
	}

	c = copyObject(c);
	c->constvalue = PointerGetDatum(construct_array(elems, nelems, elemtype,
													typlen, typbyval, typalign));
	return (Node *) c;
}

/* =, <>, <, >, <= or >= between two built-in integer types */
static bool
_PGS_Discreet_IsIntComparison(Oid opno, Oid ltype, Oid rtype)
{
	char	   *name;

	if (opno >= FirstNormalObjectId ||
		!_PGS_Discreet_IsShiftType(ltype) || !_PGS_Discreet_IsShiftType(rtype))
		return false;
	name = get_opname(opno);
	return name != NULL &&
		(strcmp(name, "=") == 0 || strcmp(name, "<>") == 0 ||
		 strcmp(name, "<") == 0 || strcmp(name, ">") == 0 ||
		 strcmp(name, "<=") == 0 || strcmp(name, ">=") == 0);
}

/*
 * Is output column resno of this query a stored (shifted) value?  The
 * leaves of UNION/INTERSECT/EXCEPT and RETURNING lists are rewritten to the
 * original values, so those never are.
 */
static bool
_PGS_Discreet_IsShiftedOutput(Query *query, AttrNumber resno, List *outer)
{
	TargetEntry *tle;

	if (query == NULL || query->commandType != CMD_SELECT ||
		query->setOperations != NULL)
		return false;
	tle = get_tle_by_resno(query->targetList, resno);
	if (tle == NULL || tle->resjunk)
		return false;
	return _PGS_Discreet_IsShiftedLeaf((Node *) tle->expr, lcons(query, list_copy(outer)), NULL);
}

/*
 * Is this node, as it is, a stored (shifted) integer value?  That is a
 * column of a user table, or something that passes one through unchanged:
 * a subquery, view, CTE, join or GROUP BY column, or a scalar subquery,
 * whose value is such a column.
 */
static bool
_PGS_Discreet_IsShiftedLeaf(Node *node, List *levels, Query *sublink)
{
	if (node == NULL)
		return false;

	if (IsA(node, Var))
	{
		Var		   *var = (Var *) node;
		Query	   *query;
		RangeTblEntry *rte;

		if (var->varattno <= 0 || !_PGS_Discreet_IsShiftType(var->vartype) ||
			var->varlevelsup >= list_length(levels))
			return false;
		levels = list_copy_tail(levels, var->varlevelsup);
		query = (Query *) linitial(levels);
		if (var->varno < 1 || var->varno > list_length(query->rtable))
			return false;
		rte = rt_fetch(var->varno, query->rtable);

		switch (rte->rtekind)
		{
			case RTE_RELATION:
				return _PGS_Discreet_IsShiftedRel(rte->relid) &&
					get_atttype(rte->relid, var->varattno) == var->vartype &&
					!_PGS_Discreet_IsIdColumn(rte->relid, var->varattno);

			case RTE_SUBQUERY:
				return _PGS_Discreet_IsShiftedOutput(rte->subquery, var->varattno, levels);

			case RTE_JOIN:
				{
					Node	   *alias;

					if (var->varattno > list_length(rte->joinaliasvars))
						return false;
					alias = (Node *) list_nth(rte->joinaliasvars, var->varattno - 1);

					/* FULL JOIN USING: COALESCE of the two sides */
					if (alias != NULL && IsA(alias, CoalesceExpr))
					{
						ListCell   *lc;

						foreach(lc, ((CoalesceExpr *) alias)->args)
						{
							if (!_PGS_Discreet_IsShiftedLeaf((Node *) lfirst(lc), levels, NULL))
								return false;
						}
						return true;
					}
					return _PGS_Discreet_IsShiftedLeaf(alias, levels, NULL);
				}

			case RTE_CTE:
				{
					List	   *ctelevels;
					ListCell   *lc;

					if (rte->ctelevelsup >= list_length(levels))
						return false;
					ctelevels = list_copy_tail(levels, rte->ctelevelsup);
					foreach(lc, ((Query *) linitial(ctelevels))->cteList)
					{
						CommonTableExpr *cte = (CommonTableExpr *) lfirst(lc);

						if (strcmp(cte->ctename, rte->ctename) != 0)
							continue;
						if (cte->cterecursive || !IsA(cte->ctequery, Query))
							return false;
						return _PGS_Discreet_IsShiftedOutput((Query *) cte->ctequery,
														var->varattno, ctelevels);
					}
					return false;
				}

			case RTE_GROUP:
				if (var->varattno > list_length(rte->groupexprs))
					return false;
				return _PGS_Discreet_IsShiftedLeaf((Node *) list_nth(rte->groupexprs,
																var->varattno - 1),
											  levels, NULL);

			default:
				return false;
		}
	}

	/* "x IN (SELECT col ...)": the Param stands for the subselect's column */
	if (IsA(node, Param))
	{
		Param	   *param = (Param *) node;

		if (sublink == NULL || param->paramkind != PARAM_SUBLINK)
			return false;
		return _PGS_Discreet_IsShiftedOutput(sublink, param->paramid, levels);
	}

	/* A scalar subquery "(SELECT col ...)" */
	if (IsA(node, SubLink))
	{
		SubLink    *sl = (SubLink *) node;

		if (sl->subLinkType != EXPR_SUBLINK || !IsA(sl->subselect, Query))
			return false;
		return _PGS_Discreet_IsShiftedOutput((Query *) sl->subselect, 1, levels);
	}

	return false;
}

/* A copy of a SubLink with its subquery and test expression rewritten */
static Node *
_PGS_Discreet_RewriteSubLink(SubLink *sl, DiscreetShiftContext *ctx)
{
	SubLink    *newsl = copyObject(sl);
	DiscreetShiftContext subctx;

	_PGS_Discreet_RewriteQuery((Query *) newsl->subselect, ctx->levels, false, false);

	subctx.levels = ctx->levels;
	subctx.sublink = (Query *) newsl->subselect;
	newsl->testexpr = _PGS_Discreet_UnshiftMutator(newsl->testexpr, &subctx);
	return (Node *) newsl;
}

/* A stored leaf, kept stored (only a scalar subquery needs rewriting inside) */
static Node *
_PGS_Discreet_KeepStored(Node *leaf, DiscreetShiftContext *ctx)
{
	if (IsA(leaf, SubLink))
		return _PGS_Discreet_RewriteSubLink((SubLink *) leaf, ctx);
	return (Node *) copyObject(leaf);
}

/*
 * Rewrite an expression so it computes on original values (see the section
 * comment).  Returns a new tree.
 */
static Node *
_PGS_Discreet_UnshiftMutator(Node *node, DiscreetShiftContext *ctx)
{
	if (node == NULL)
		return NULL;

	/* GROUPING() arguments must stay identical to the GROUP BY expressions */
	if (IsA(node, GroupingFunc))
		return (Node *) copyObject(node);

	if (_PGS_Discreet_IsShiftedLeaf(node, ctx->levels, ctx->sublink))
		return _PGS_Discreet_MakeShift(_PGS_Discreet_KeepStored(node, ctx), -DISCREET_SHIFT);

	if (IsA(node, SubLink))
		return _PGS_Discreet_RewriteSubLink((SubLink *) node, ctx);

	if (IsA(node, OpExpr))
	{
		OpExpr	   *op = (OpExpr *) node;

		if (list_length(op->args) == 2 &&
			_PGS_Discreet_IsIntComparison(op->opno,
									 exprType(linitial(op->args)),
									 exprType(lsecond(op->args))))
		{
			Node	   *l = (Node *) linitial(op->args);
			Node	   *r = (Node *) lsecond(op->args);
			bool		lstored = _PGS_Discreet_IsShiftedLeaf(l, ctx->levels, ctx->sublink);
			bool		rstored = _PGS_Discreet_IsShiftedLeaf(r, ctx->levels, ctx->sublink);
			OpExpr	   *newop;

			/* stored column vs stored column: both +10, compare as they are */
			if (lstored && rstored)
			{
				newop = makeNode(OpExpr);
				memcpy(newop, op, sizeof(OpExpr));
				newop->args = list_make2(_PGS_Discreet_KeepStored(l, ctx),
										 _PGS_Discreet_KeepStored(r, ctx));
				return (Node *) newop;
			}

			/* stored column vs a value: compare with the value + 10 */
			if (lstored != rstored)
			{
				Node	   *value = _PGS_Discreet_UnshiftMutator(lstored ? r : l, ctx);
				Node	   *stored = _PGS_Discreet_ToStored(value);

				if (stored != NULL)
				{
					Node	   *column = _PGS_Discreet_KeepStored(lstored ? l : r, ctx);

					newop = makeNode(OpExpr);
					memcpy(newop, op, sizeof(OpExpr));
					newop->args = lstored ? list_make2(column, stored)
						: list_make2(stored, column);
					return (Node *) newop;
				}
				/* else fall through: (column - 10) compared with the value */
			}
		}
	}

	/* col IN (1, 2, 3), col = ANY ($1): shift the list, not the column */
	if (IsA(node, ScalarArrayOpExpr))
	{
		ScalarArrayOpExpr *saop = (ScalarArrayOpExpr *) node;

		if (list_length(saop->args) == 2)
		{
			Node	   *scalar = (Node *) linitial(saop->args);
			Node	   *array = (Node *) lsecond(saop->args);
			Oid			elemtype = get_element_type(exprType(array));

			if (_PGS_Discreet_IsIntComparison(saop->opno, exprType(scalar), elemtype) &&
				_PGS_Discreet_IsShiftedLeaf(scalar, ctx->levels, ctx->sublink))
			{
				Node	   *values = _PGS_Discreet_UnshiftMutator(array, ctx);
				Node	   *stored = NULL;

				if (IsA(values, Const))
					stored = _PGS_Discreet_ArrayToStored(values, elemtype);
				else if (IsA(values, ArrayExpr))
				{
					ArrayExpr  *arr = (ArrayExpr *) copyObject(values);
					ListCell   *lc;

					stored = (Node *) arr;
					foreach(lc, arr->elements)
					{
						Node	   *elem = _PGS_Discreet_ToStored((Node *) lfirst(lc));

						if (elem == NULL)
						{
							stored = NULL;
							break;
						}
						lfirst(lc) = elem;
					}
				}

				if (stored != NULL)
				{
					ScalarArrayOpExpr *newsaop = makeNode(ScalarArrayOpExpr);

					memcpy(newsaop, saop, sizeof(ScalarArrayOpExpr));
					newsaop->args = list_make2(_PGS_Discreet_KeepStored(scalar, ctx), stored);
					return (Node *) newsaop;
				}
			}
		}
	}

	return expression_tree_mutator(node, _PGS_Discreet_UnshiftMutator, ctx);
}

/*
 * SELECT list: a bare stored column stays stored.  At the top level R1
 * subtracts the 10 as the row leaves (it finds the column through
 * resorigtbl), and in a subquery the outer query sees it as stored.
 * Everything else computes on original values.
 */
static void
_PGS_Discreet_RewriteSelectList(List *tlist, DiscreetShiftContext *ctx, bool top)
{
	ListCell   *lc;

	foreach(lc, tlist)
	{
		TargetEntry *tle = (TargetEntry *) lfirst(lc);
		Node	   *expr = (Node *) tle->expr;
		bool		keep = false;

		/* at the top, only what R1 will find (a view column is not) */
		if (_PGS_Discreet_IsShiftedLeaf(expr, ctx->levels, NULL))
			keep = top ? (IsA(expr, Var) &&
						  _PGS_Discreet_OriginIsShifted(tle, exprType(expr))) : true;

		tle->expr = (Expr *) (keep ? _PGS_Discreet_KeepStored(expr, ctx)
							  : _PGS_Discreet_UnshiftMutator(expr, ctx));
	}
}

/*
 * Values being written or returned (INSERT, UPDATE SET, MERGE, ON CONFLICT
 * SET, RETURNING, UNION leaves): all original values.
 */
static void
_PGS_Discreet_RewriteValueList(List *tlist, DiscreetShiftContext *ctx, bool clear_origin)
{
	ListCell   *lc;

	foreach(lc, tlist)
	{
		TargetEntry *tle = (TargetEntry *) lfirst(lc);

		tle->expr = (Expr *) _PGS_Discreet_UnshiftMutator((Node *) tle->expr, ctx);
		if (clear_origin)
		{
			/* already original: R1 must not subtract again */
			tle->resorigtbl = InvalidOid;
			tle->resorigcol = 0;
		}
	}
}

static void
_PGS_Discreet_RewriteQuery(Query *query, List *outer, bool top, bool setop_leaf)
{
	DiscreetShiftContext ctx;
	ListCell   *lc;

	if (query == NULL || query->commandType == CMD_UTILITY)
		return;

	/* lcons() can change the list it is given, and outer belongs to the caller */
	ctx.levels = lcons(query, list_copy(outer));
	ctx.sublink = NULL;

	foreach(lc, query->cteList)
	{
		CommonTableExpr *cte = (CommonTableExpr *) lfirst(lc);

		if (IsA(cte->ctequery, Query))
			_PGS_Discreet_RewriteQuery((Query *) cte->ctequery, ctx.levels, false, false);
	}

	/* Subqueries first, so the outer query sees which of their columns are stored */
	foreach(lc, query->rtable)
	{
		RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);

		switch (rte->rtekind)
		{
			case RTE_SUBQUERY:
				_PGS_Discreet_RewriteQuery(rte->subquery, ctx.levels, false,
									  query->setOperations != NULL);
				break;
			case RTE_FUNCTION:
				{
					ListCell   *fl;

					foreach(fl, rte->functions)
					{
						RangeTblFunction *rtfunc = (RangeTblFunction *) lfirst(fl);

						rtfunc->funcexpr = _PGS_Discreet_UnshiftMutator(rtfunc->funcexpr, &ctx);
					}
				}
				break;
			case RTE_VALUES:
				rte->values_lists = (List *)
					_PGS_Discreet_UnshiftMutator((Node *) rte->values_lists, &ctx);
				break;
			case RTE_GROUP:
				{
					ListCell   *gl;

					/* GROUP BY col stays stored; GROUP BY expressions compute */
					foreach(gl, rte->groupexprs)
					{
						Node	   *expr = (Node *) lfirst(gl);

						if (_PGS_Discreet_IsShiftedLeaf(expr, ctx.levels, NULL))
							lfirst(gl) = _PGS_Discreet_KeepStored(expr, &ctx);
						else
							lfirst(gl) = _PGS_Discreet_UnshiftMutator(expr, &ctx);
					}
				}
				break;
			default:
				break;
		}

		/* Row-level security policies (USING) filter like WHERE */
		if (rte->securityQuals != NIL)
			rte->securityQuals = (List *)
				_PGS_Discreet_UnshiftMutator((Node *) rte->securityQuals, &ctx);
	}

	/* WHERE, JOIN ... ON and HAVING */
	query->jointree = (FromExpr *)
		_PGS_Discreet_UnshiftMutator((Node *) query->jointree, &ctx);
	query->havingQual = _PGS_Discreet_UnshiftMutator(query->havingQual, &ctx);

	switch (query->commandType)
	{
		case CMD_SELECT:
			if (setop_leaf)
				_PGS_Discreet_RewriteValueList(query->targetList, &ctx, false);
			else if (query->setOperations == NULL)
				_PGS_Discreet_RewriteSelectList(query->targetList, &ctx, top);
			break;
		case CMD_INSERT:
		case CMD_UPDATE:
			_PGS_Discreet_RewriteValueList(query->targetList, &ctx, false);
			break;
		default:
			break;
	}

	if (query->commandType == CMD_MERGE)
	{
		foreach(lc, query->mergeActionList)
		{
			MergeAction *action = (MergeAction *) lfirst(lc);

			action->qual = _PGS_Discreet_UnshiftMutator(action->qual, &ctx);
			_PGS_Discreet_RewriteValueList(action->targetList, &ctx, false);
		}
		query->mergeJoinCondition =
			_PGS_Discreet_UnshiftMutator(query->mergeJoinCondition, &ctx);
	}

	if (query->onConflict != NULL)
	{
		_PGS_Discreet_RewriteValueList(query->onConflict->onConflictSet, &ctx, false);
		query->onConflict->onConflictWhere =
			_PGS_Discreet_UnshiftMutator(query->onConflict->onConflictWhere, &ctx);
	}

	_PGS_Discreet_RewriteValueList(query->returningList, &ctx, true);
}

/*
 * Called from planner() for every query before it is planned: rewrite the
 * client's queries to use the original values.
 */
void
_PGS_Discreet_PlannerRewrite(Query *parse)
{
	if (!_PGS_Discreet_ShiftEnabled() || _PGS_SPI_is_connected())
		return;
	_PGS_Discreet_RewriteQuery(parse, NIL, true, false);
}
