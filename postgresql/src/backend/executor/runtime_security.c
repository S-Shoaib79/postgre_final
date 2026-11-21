/*
 * NOT BUILT (kept for reference): this code now lives in execMain.c
 * (statement end, SPI, login / logout, transaction callbacks, sending)
 * and nodeModifyTable.c (_PGS_RuntimeSecurity_CaptureRow).  The file is no
 * longer in src/backend/executor/meson.build.
 */
/*-------------------------------------------------------------------------
 *
 * runtime_security.c
 *	  Runtime security check: executor hooks on the tenant, user and
 *	  role-asset tables ("Schema for Runtime Security Check").
 *
 * The tables are made by role_asset_schema.sql.  The hooks find them by
 * table name, in whatever schema the statement wrote to:
 *
 *	INSERT INTO tenant          the tenant is sent to AM
 *	INSERT INTO tenant_user     the user is sent to AM (username, role)
 *	UPDATE tenant_user SET status = 1   login: user_asset_map gets a row per
 *	                            asset of the user's role (a copy of
 *	                            role_asset_map), and asset_key is set to the
 *	                            value AM returns for each asset
 *	UPDATE tenant_user SET status = 0   logout: the user's asset keys are
 *	                            removed
 *	INSERT/UPDATE/DELETE on app_role, app_asset or role_asset_map
 *	                            (the one-time role_asset_data.sql) the
 *	                            role-asset matrix is sent to AM
 *
 * ExecModifyTable() calls _PGS_RuntimeSecurity_CaptureRow() for each row, which
 * only remembers the row's id.  standard_ExecutorFinish() calls
 * _PGS_RuntimeSecurity_StatementEnd(), which reads the rows back with SPI, does
 * the login/logout work and builds the JSON for AM.  Login asks AM for the
 * values at once, as they are stored in the same transaction.  The tenant,
 * user and matrix are sent when the transaction commits, so a rolled-back
 * INSERT sends nothing.  The HTTP calls are in am_client.cpp.
 *
 * src/backend/executor/runtime_security.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "access/xact.h"
#include "catalog/pg_type.h"
#include "executor/am_client.h"
#include "executor/executor.h"
#include "executor/runtime_security.h"
#include "executor/spi.h"
#include "miscadmin.h"
#include "parser/parse_relation.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"

/*
 * asset_key in user_asset_map: a 32-byte key, base64 (44 characters: 43
 * and one '='). AM values of any other size are not stored.
 */
#define RSC_KEY_BYTES 32
#define RSC_KEY_PATTERN "^[A-Za-z0-9+/]{43}=$"

typedef enum RscEventKind
{
	RSC_TENANT_CREATED,
	RSC_USER_CREATED,
	RSC_USER_STATUS,
	RSC_MATRIX_CHANGED,
} RscEventKind;

/* A row caught in ExecModifyTable, handled at the end of its statement */
typedef struct RscEvent
{
	RscEventKind kind;
	EState	   *estate;			/* statement that wrote the row */
	int			nestlevel;		/* (sub)transaction that wrote it */
	char	   *schema;			/* schema of the table written */
	int64		id;				/* tenant_id or user_id */
} RscEvent;

/* A call to AM, made when the transaction commits */
typedef struct RscSend
{
	int			nestlevel;
	const char *endpoint;		/* "tenants", "users" or "roles" */
	int64		tenant_id;		/* picks the API key; 0 = default key */
	char	   *body;
} RscSend;

/* Both lists live in TopTransactionContext */
static List *pending_events = NIL;
static List *pending_sends = NIL;
static bool callbacks_registered = false;
static bool rsc_busy = false;	/* running our own SPI queries */

static void _PGS_rsc_xact_callback(XactEvent event, void *arg);
static void _PGS_rsc_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
								 SubTransactionId parentSubid, void *arg);

static bool
_PGS_rsc_is_matrix_table(const char *relname)
{
	return strcmp(relname, "role_asset_map") == 0 ||
		strcmp(relname, "app_role") == 0 ||
		strcmp(relname, "app_asset") == 0;
}

/* The bigint id column of a captured row, or false if it has none */
static bool
_PGS_rsc_row_id(Relation rel, TupleTableSlot *slot, const char *column, int64 *id)
{
	AttrNumber	attnum = attnameAttNum(rel, column, false);
	Datum		value;
	bool		isnull;

	if (attnum <= 0 || slot == NULL || TupIsNull(slot))
		return false;
	value = slot_getattr(slot, attnum, &isnull);
	if (isnull)
		return false;

	switch (TupleDescAttr(RelationGetDescr(rel), attnum - 1)->atttypid)
	{
		case INT8OID:
			*id = DatumGetInt64(value);
			return true;
		case INT4OID:
			*id = DatumGetInt32(value);
			return true;
		default:
			return false;
	}
}

/*
 * Called by ExecModifyTable() for each row it inserts, updates or deletes
 * (slot is the new row; NULL for DELETE and MERGE).  Remembers the rows of
 * the runtime security tables; everything else returns at once.
 */
void
_PGS_RuntimeSecurity_CaptureRow(ModifyTableState *mtstate,
						   ResultRelInfo *resultRelInfo,
						   CmdType operation,
						   TupleTableSlot *slot)
{
	Relation	rel = resultRelInfo->ri_RelationDesc;
	EState	   *estate = mtstate->ps.state;
	const char *relname = RelationGetRelationName(rel);
	RscEventKind kind;
	int64		id = 0;
	MemoryContext oldcxt;
	RscEvent   *ev;

	if (rsc_busy || !IsNormalProcessingMode())
		return;

	if (_PGS_rsc_is_matrix_table(relname))
	{
		ListCell   *lc;

		/* One matrix event per statement is enough */
		foreach(lc, pending_events)
		{
			RscEvent   *e = (RscEvent *) lfirst(lc);

			if (e->kind == RSC_MATRIX_CHANGED && e->estate == estate)
				return;
		}
		kind = RSC_MATRIX_CHANGED;
	}
	else if (strcmp(relname, "tenant") == 0 && operation == CMD_INSERT)
	{
		if (!_PGS_rsc_row_id(rel, slot, "tenant_id", &id))
			return;
		kind = RSC_TENANT_CREATED;
	}
	else if (strcmp(relname, "tenant_user") == 0 && operation == CMD_INSERT)
	{
		if (!_PGS_rsc_row_id(rel, slot, "user_id", &id))
			return;
		kind = RSC_USER_CREATED;
	}
	else if (strcmp(relname, "tenant_user") == 0 && operation == CMD_UPDATE)
	{
		AttrNumber	status = attnameAttNum(rel, "status", false);

		/* Only an UPDATE that sets the status is a login or logout */
		if (status <= 0 ||
			!bms_is_member(status - FirstLowInvalidHeapAttributeNumber,
						   ExecGetUpdatedCols(resultRelInfo, estate)))
			return;
		if (!_PGS_rsc_row_id(rel, slot, "user_id", &id))
			return;
		kind = RSC_USER_STATUS;
	}
	else
		return;

	if (!callbacks_registered)
	{
		RegisterXactCallback(_PGS_rsc_xact_callback, NULL);
		RegisterSubXactCallback(_PGS_rsc_subxact_callback, NULL);
		callbacks_registered = true;
	}

	oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	ev = palloc(sizeof(RscEvent));
	ev->kind = kind;
	ev->estate = estate;
	ev->nestlevel = GetCurrentTransactionNestLevel();
	ev->schema = get_namespace_name(RelationGetNamespace(rel));
	ev->id = id;
	pending_events = lappend(pending_events, ev);
	MemoryContextSwitchTo(oldcxt);
}

/* ---------------------------------------------------------------- SPI */

/* Run a query with $1 = id (bigint) and, if given, $2 = arg (text) */
static uint64
_PGS_rsc_exec(const char *sql, int64 id, const char *arg)
{
	Oid			types[2] = {INT8OID, TEXTOID};
	Datum		values[2];
	int			ret;

	values[0] = Int64GetDatum(id);
	if (arg != NULL)
		values[1] = CStringGetTextDatum(arg);

	ret = SPI_execute_with_args(sql, arg != NULL ? 2 : 1, types, values,
								NULL, false, 0);
	if (ret < 0)
		elog(ERROR, "runtime security: query failed (%s): %s",
			 SPI_result_code_string(ret), sql);
	return SPI_processed;
}

/* Column col (1-based) of the first result row, NULL if it is null */
static char *
_PGS_rsc_value(int col)
{
	return SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, col);
}

/* Queue a call to AM for commit */
static void
_PGS_rsc_queue_send(const char *endpoint, int64 tenant_id, const char *body)
{
	MemoryContext oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	RscSend    *s;

	/* The matrix is sent whole, so only its latest version is kept */
	if (strcmp(endpoint, "roles") == 0)
	{
		List	   *keep = NIL;
		ListCell   *lc;

		foreach(lc, pending_sends)
		{
			RscSend    *old = (RscSend *) lfirst(lc);

			if (strcmp(old->endpoint, "roles") != 0)
				keep = lappend(keep, old);
		}
		pending_sends = keep;
	}

	s = palloc(sizeof(RscSend));
	s->nestlevel = GetCurrentTransactionNestLevel();
	s->endpoint = endpoint;
	s->tenant_id = tenant_id;
	s->body = pstrdup(body);
	pending_sends = lappend(pending_sends, s);
	MemoryContextSwitchTo(oldcxt);
}

/* ------------------------------------------------------- login / logout */

/*
 * Login (status 1): copy the user's role assets from role_asset_map into
 * user_asset_map and store the value AM returns for each as asset_key.
 */
static void
_PGS_rsc_login(const char *q, int64 user_id, int64 tenant_id, const char *username)
{
	char	   *response = NULL;
	char		errbuf[256];
	int			status;
	uint64		n;

	/* Assets the role no longer grants */
	_PGS_rsc_exec(psprintf("DELETE FROM %s.user_asset_map k "
					  "WHERE k.user_id = $1 AND NOT EXISTS ("
					  " SELECT 1 FROM %s.role_asset_map m"
					  " JOIN %s.tenant_user u ON u.role_id = m.app_role_id"
					  " WHERE u.user_id = $1 AND m.app_asset_id = k.asset_id)",
					  q, q, q), user_id, NULL);
	/* A row per asset of the role */
	_PGS_rsc_exec(psprintf("INSERT INTO %s.user_asset_map (asset_id, user_id) "
					  "SELECT m.app_asset_id, u.user_id FROM %s.role_asset_map m"
					  " JOIN %s.tenant_user u ON u.role_id = m.app_role_id"
					  " WHERE u.user_id = $1 "
					  "ON CONFLICT (user_id, asset_id) DO NOTHING",
					  q, q, q), user_id, NULL);
	/* No key from an earlier session survives */
	_PGS_rsc_exec(psprintf("UPDATE %s.user_asset_map SET asset_key = NULL "
					  "WHERE user_id = $1 AND asset_key IS NOT NULL", q),
			 user_id, NULL);

	status = _PGS_AmClient_Call("user_assets", username, tenant_id, NULL,
						   &response, errbuf, sizeof(errbuf));
	if (status == 0)
	{
		ereport(LOG,
				(errmsg("runtime security: login of user %lld: AM is not configured (am_client.conf), no asset keys stored",
						(long long) user_id)));
		_PGS_AmClient_Free(response);
		return;
	}
	if (status != 200 || response == NULL)
	{
		ereport(WARNING,
				(errmsg("runtime security: login of user %lld: could not get the asset values from AM",
						(long long) user_id),
				 status < 0 ? errdetail("%s", errbuf) :
				 errdetail("AM answered HTTP %d.", status)));
		_PGS_AmClient_Free(response);
		return;
	}

	/* PostgreSQL parses AM's JSON: data.assets[] {name, value} */
	_PGS_rsc_exec("SELECT 1 WHERE pg_input_is_valid($2, 'jsonb')", user_id, response);
	if (SPI_processed == 0)
	{
		ereport(WARNING,
				(errmsg("runtime security: login of user %lld: AM's answer is not valid JSON",
						(long long) user_id)));
		_PGS_AmClient_Free(response);
		return;
	}
	n = _PGS_rsc_exec(psprintf("UPDATE %s.user_asset_map k SET asset_key = a.value "
						  "FROM jsonb_to_recordset("
						  " CASE WHEN jsonb_typeof($2::jsonb #> '{data,assets}') = 'array'"
						  " THEN $2::jsonb #> '{data,assets}' ELSE '[]' END)"
						  " AS a(name text, value text), %s.app_asset s "
						  "WHERE k.user_id = $1 AND s.app_asset_name = a.name"
						  " AND k.asset_id = s.app_asset_id"
						  " AND a.value ~ '" RSC_KEY_PATTERN "'",
						  q, q), user_id, response);
	_PGS_AmClient_Free(response);

	ereport(LOG,
			(errmsg("runtime security: login of user %lld: %llu asset keys stored",
					(long long) user_id, (unsigned long long) n)));
}

/* Logout (status 0): remove the user's asset keys */
static void
_PGS_rsc_logout(const char *q, int64 user_id)
{
	uint64		n;

	n = _PGS_rsc_exec(psprintf("UPDATE %s.user_asset_map SET asset_key = NULL "
						  "WHERE user_id = $1 AND asset_key IS NOT NULL", q),
				 user_id, NULL);
	ereport(LOG,
			(errmsg("runtime security: logout of user %lld: %llu asset keys removed",
					(long long) user_id, (unsigned long long) n)));
}

/* --------------------------------------------------------------- events */

static void
_PGS_rsc_tenant_created(const char *q, int64 tenant_id)
{
	if (_PGS_rsc_exec(psprintf("SELECT json_build_object("
						  "'tenantId', tenant_id, 'name', tenant_name)::text "
						  "FROM %s.tenant WHERE tenant_id = $1", q),
				 tenant_id, NULL) == 0)
		return;					/* not inserted after all (ON CONFLICT) */
	_PGS_rsc_queue_send("tenants", tenant_id, _PGS_rsc_value(1));
}

static void
_PGS_rsc_user_created(const char *q, int64 user_id)
{
	int64		tenant_id;

	if (_PGS_rsc_exec(psprintf("SELECT json_build_object("
						  "'username', u.user_name, 'role', r.app_role_name,"
						  " 'displayName', u.user_name)::text, u.tenant_id, u.status "
						  "FROM %s.tenant_user u"
						  " LEFT JOIN %s.app_role r ON r.app_role_id = u.role_id "
						  "WHERE u.user_id = $1", q, q),
				 user_id, NULL) == 0)
		return;
	tenant_id = pg_strtoint64(_PGS_rsc_value(2));
	_PGS_rsc_queue_send("users", tenant_id, _PGS_rsc_value(1));

	/*
	 * AM only knows the user after commit, so a user created already active
	 * gets the map rows now and the keys at the next login.
	 */
	if (strcmp(_PGS_rsc_value(3), "1") == 0)
	{
		_PGS_rsc_exec(psprintf("INSERT INTO %s.user_asset_map (asset_id, user_id) "
						  "SELECT m.app_asset_id, u.user_id FROM %s.role_asset_map m"
						  " JOIN %s.tenant_user u ON u.role_id = m.app_role_id"
						  " WHERE u.user_id = $1 "
						  "ON CONFLICT (user_id, asset_id) DO NOTHING",
						  q, q, q), user_id, NULL);
		ereport(NOTICE,
				(errmsg("runtime security: user %lld was created with status 1; asset keys are stored at the next login",
						(long long) user_id)));
	}
}

static void
_PGS_rsc_user_status(const char *q, int64 user_id)
{
	char	   *status;
	char	   *username;
	int64		tenant_id;

	if (_PGS_rsc_exec(psprintf("SELECT status, tenant_id, user_name "
						  "FROM %s.tenant_user WHERE user_id = $1", q),
				 user_id, NULL) == 0)
		return;
	status = _PGS_rsc_value(1);
	tenant_id = pg_strtoint64(_PGS_rsc_value(2));
	username = _PGS_rsc_value(3);

	if (strcmp(status, "1") == 0)
		_PGS_rsc_login(q, user_id, tenant_id, username);
	else
		_PGS_rsc_logout(q, user_id);
}

/*
 * The role-asset matrix in the shape of AM's role list (GET /api/v1/roles),
 * with each asset's permissions as 1/0.
 */
static void
_PGS_rsc_matrix_changed(const char *q)
{
	_PGS_rsc_exec(psprintf("SELECT json_build_object('roles', coalesce(json_agg("
					  " json_build_object("
					  "  'name', r.app_role_name, 'description', NULL,"
					  "  'assets', coalesce((SELECT json_agg(a.app_asset_name ORDER BY a.app_asset_id)"
					  "    FROM %s.role_asset_map m JOIN %s.app_asset a ON a.app_asset_id = m.app_asset_id"
					  "    WHERE m.app_role_id = r.app_role_id), '[]'),"
					  "  'permissions', coalesce((SELECT json_agg(json_build_object("
					  "     'asset', a.app_asset_name, 'tableName', a.table_name,"
					  "     'canCreate', m.can_create::int, 'canRead', m.can_read::int,"
					  "     'canUpdate', m.can_update::int, 'canDelete', m.can_delete::int,"
					  "     'canBeOwner', m.can_be_owner::int) ORDER BY a.app_asset_id)"
					  "    FROM %s.role_asset_map m JOIN %s.app_asset a ON a.app_asset_id = m.app_asset_id"
					  "    WHERE m.app_role_id = r.app_role_id), '[]'))"
					  " ORDER BY r.app_role_id), '[]'))::text "
					  "FROM %s.app_role r",
					  q, q, q, q, q), 0, NULL);
	_PGS_rsc_queue_send("roles", 0, _PGS_rsc_value(1));
}

static void
_PGS_rsc_process(List *events)
{
	ListCell   *lc;

	rsc_busy = true;
	PG_TRY();
	{
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "runtime security: SPI_connect failed");

		foreach(lc, events)
		{
			RscEvent   *ev = (RscEvent *) lfirst(lc);
			const char *q = quote_identifier(ev->schema);

			switch (ev->kind)
			{
				case RSC_TENANT_CREATED:
					_PGS_rsc_tenant_created(q, ev->id);
					break;
				case RSC_USER_CREATED:
					_PGS_rsc_user_created(q, ev->id);
					break;
				case RSC_USER_STATUS:
					_PGS_rsc_user_status(q, ev->id);
					break;
				case RSC_MATRIX_CHANGED:
					_PGS_rsc_matrix_changed(q);
					break;
			}
		}

		SPI_finish();
	}
	PG_FINALLY();
	{
		rsc_busy = false;
	}
	PG_END_TRY();
}

/*
 * Called by standard_ExecutorFinish(): handle the rows this statement
 * caught.
 */
void
_PGS_RuntimeSecurity_StatementEnd(EState *estate)
{
	List	   *mine = NIL;
	List	   *rest = NIL;
	ListCell   *lc;
	MemoryContext oldcxt;

	if (pending_events == NIL || rsc_busy)
		return;

	oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	foreach(lc, pending_events)
	{
		RscEvent   *ev = (RscEvent *) lfirst(lc);

		if (ev->estate == estate)
			mine = lappend(mine, ev);
		else
			rest = lappend(rest, ev);
	}
	MemoryContextSwitchTo(oldcxt);

	if (mine == NIL)
		return;
	pending_events = rest;
	_PGS_rsc_process(mine);
}

/* ------------------------------------------------------------- commit */

static void
_PGS_rsc_send_all(void)
{
	ListCell   *lc;

	foreach(lc, pending_sends)
	{
		RscSend    *s = (RscSend *) lfirst(lc);
		char	   *response = NULL;
		char		errbuf[256];
		int			status;

		status = _PGS_AmClient_Call(s->endpoint, NULL, s->tenant_id, s->body,
							   &response, errbuf, sizeof(errbuf));
		if (status == 0)
			ereport(LOG,
					(errmsg("runtime security: AM is not configured (am_client.conf); %s payload written to am_outbox.jsonl",
							s->endpoint)));
		else if (status < 0)
			ereport(WARNING,
					(errmsg("runtime security: could not send %s to AM: %s",
							s->endpoint, errbuf)));
		else if (status >= 200 && status < 300)
			ereport(LOG,
					(errmsg("runtime security: sent %s to AM (HTTP %d)",
							s->endpoint, status)));
		else
			ereport(WARNING,
					(errmsg("runtime security: AM refused %s (HTTP %d): %.300s",
							s->endpoint, status, response ? response : "")));
		_PGS_AmClient_Free(response);
	}
}

static void
_PGS_rsc_xact_callback(XactEvent event, void *arg)
{
	switch (event)
	{
		case XACT_EVENT_PRE_COMMIT:
			/* Rows whose statement did not reach ExecutorFinish */
			if (pending_events != NIL)
			{
				List	   *events = pending_events;

				pending_events = NIL;
				_PGS_rsc_process(events);
			}
			break;
		case XACT_EVENT_COMMIT:
			_PGS_rsc_send_all();
			pending_events = NIL;
			pending_sends = NIL;
			break;
		case XACT_EVENT_PREPARE:
			if (pending_sends != NIL)
				ereport(WARNING,
						(errmsg("runtime security: nothing is sent to AM for a prepared transaction")));
			pending_events = NIL;
			pending_sends = NIL;
			break;
		case XACT_EVENT_ABORT:
		case XACT_EVENT_PARALLEL_ABORT:
			pending_events = NIL;
			pending_sends = NIL;
			rsc_busy = false;
			break;
		default:
			break;
	}
}

/*
 * A rolled-back savepoint forgets what it caught; a released one hands it
 * to its parent.
 */
static void
_PGS_rsc_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
					 SubTransactionId parentSubid, void *arg)
{
	int			level = GetCurrentTransactionNestLevel();
	List	   *events = NIL;
	List	   *sends = NIL;
	ListCell   *lc;
	MemoryContext oldcxt;

	if (event != SUBXACT_EVENT_ABORT_SUB && event != SUBXACT_EVENT_COMMIT_SUB)
		return;

	oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	foreach(lc, pending_events)
	{
		RscEvent   *ev = (RscEvent *) lfirst(lc);

		if (ev->nestlevel < level)
			events = lappend(events, ev);
		else if (event == SUBXACT_EVENT_COMMIT_SUB)
		{
			ev->nestlevel = level - 1;
			events = lappend(events, ev);
		}
	}
	foreach(lc, pending_sends)
	{
		RscSend    *s = (RscSend *) lfirst(lc);

		if (s->nestlevel < level)
			sends = lappend(sends, s);
		else if (event == SUBXACT_EVENT_COMMIT_SUB)
		{
			s->nestlevel = level - 1;
			sends = lappend(sends, s);
		}
	}
	MemoryContextSwitchTo(oldcxt);

	pending_events = events;
	pending_sends = sends;
	if (event == SUBXACT_EVENT_ABORT_SUB)
		rsc_busy = false;
}
