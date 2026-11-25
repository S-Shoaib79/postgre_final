/*-------------------------------------------------------------------------
 *
 * am_keys_worker.c
 *	  The endpoint the Asset Access Service (AM) sends a signed-in user's
 *	  asset keys to; PostgreSQL part.  A background worker listens on
 *	  127.0.0.1:<keys_port> and writes each pushed key into
 *	  user_asset_map.asset_key.  The HTTP and settings work is in
 *	  am_keys.cpp (see am_keys.h).
 *
 * The user must be signed in (user_accounts.login_status = 1; the login hook
 * has then made the user_asset_map rows), and the push's loginId must be the
 * token_id of a live OAuth session of that user (oauth_tokens, see
 * merged/05_oauth.sql): keys for a revoked or expired session, or for another
 * user's session, are refused.  The AM sends the keys right after
 * it answered the login OK, so a push for a user who is not signed in yet is
 * retried for up to keys_wait_seconds.  Types the user's role does not have
 * are ignored.  Sign-out (login_status = 0) removes the keys, as before.
 *
 * Loaded at server start:  shared_preload_libraries = 'am_keys'
 * No PostgreSQL source file is changed.  Neither the secret nor a key is ever
 * written to the log.
 *
 * postgresql-changes/contrib/am_keys/am_keys_worker.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/xact.h"
#include "executor/spi.h"
#include "fmgr.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "postmaster/bgworker.h"
#include "postmaster/interrupt.h"
#include "storage/latch.h"
#include "tcop/tcopprot.h"
#include "utils/builtins.h"
#include "utils/memutils.h"
#include "utils/snapmgr.h"

#include "am_keys.h"

PG_MODULE_MAGIC;

PGDLLEXPORT void _PG_init(void);
PGDLLEXPORT void AmKeysListenerMain(Datum main_arg);

#define AMK_READ_TIMEOUT_MS	5000
#define AMK_BODY_MAX		4096

/* What one push did */
typedef struct AmkResult
{
	int			status;
	int			users;			/* signed-in users matching the push */
	char		body[AMK_BODY_MAX];
} AmkResult;

static void
amk_reply(AmkResult *r, int status, const char *code, const char *message)
{
	r->status = status;
	_PGS_AmKeys_ErrorBody(code, message, r->body, sizeof(r->body));
}

/*
 * Checks the JSON, then writes the keys.  PostgreSQL parses the JSON.  Whether
 * it is JSON at all is a query of its own: the planner folds $1::jsonb in the
 * other queries, which would fail before any CASE.
 */
static const char *const amk_valid_sql = "SELECT pg_input_is_valid($1, 'jsonb')";

/*
 * The jar (asset-access-service.jar) delivers {"tenant": <slug>, "username",
 * "role", "requestId", "assets"}: requestId is our loginId, and the slug is
 * lower(tenants.org_code).  Both are mapped to the fields used below.  An
 * unknown slug gives tenantId '' and so matches no user (NOT_SIGNED_IN).
 */
static const char *const amk_normalize_sql =
"SELECT CASE WHEN jsonb_typeof($1::jsonb) <> 'object' THEN $1 ELSE ($1::jsonb"
" || jsonb_strip_nulls(jsonb_build_object("
"   'loginId', coalesce(nullif($1::jsonb ->> 'loginId', ''), $1::jsonb ->> 'requestId'),"
"   'tenantId', coalesce($1::jsonb ->> 'tenantId',"
"     CASE WHEN $1::jsonb ? 'tenant' THEN coalesce((SELECT t.tenant_id::text FROM public.tenants t"
"       WHERE lower(t.org_code) = lower($1::jsonb ->> 'tenant')), '') END))))::text END";

static const char *const amk_check_sql =
"SELECT CASE"
" WHEN jsonb_typeof($1::jsonb) <> 'object' THEN 'INVALID_JSON'"
" WHEN coalesce($1::jsonb ->> 'username', '') = '' THEN 'MISSING_USERNAME'"
" WHEN coalesce($1::jsonb ->> 'loginId', '') = '' THEN 'MISSING_LOGIN_ID'"
" WHEN jsonb_typeof($1::jsonb -> 'assets') IS DISTINCT FROM 'array'"
"   OR jsonb_array_length($1::jsonb -> 'assets') = 0 THEN 'MISSING_ASSETS'"
" WHEN EXISTS (SELECT 1 FROM jsonb_array_elements($1::jsonb -> 'assets') e"
"   WHERE jsonb_typeof(e) <> 'object' OR coalesce(e ->> 'name', '') = ''"
"   OR coalesce(e ->> 'value', '') !~ '^[A-Za-z0-9+/]{43}=$') THEN 'INVALID_VALUE'"
" ELSE '' END";

static const char *const amk_store_sql =
"WITH req AS (SELECT $1::jsonb AS j),"
" u AS (SELECT ua.user_id FROM public.user_accounts ua, req"
"   WHERE ua.username = req.j ->> 'username' AND ua.login_status = 1"
"   AND (req.j ->> 'tenantId' IS NULL OR ua.tenant_id::text = req.j ->> 'tenantId')"
"   AND EXISTS (SELECT 1 FROM public.oauth_tokens t"                //pp validating login id against a live session
"     WHERE t.token_id = req.j ->> 'loginId' AND t.user_id = ua.user_id"
"     AND t.revoked_at IS NULL AND t.session_expires_at > now())),"
" s AS (UPDATE public.user_asset_map k SET asset_key = a.value"      //pp Writes keys into user_asset_map
"   FROM u, req, jsonb_to_recordset(req.j -> 'assets') AS a(name text, value text)"
"   WHERE (SELECT count(*) FROM u) = 1 AND k.user_id = u.user_id AND k.type_id = a.name"
"   RETURNING k.type_id)"
" SELECT (SELECT count(*) FROM u)::int,"
"  json_build_object("
"   'message', format('Stored %s key(s) for ''%s''.', (SELECT count(*) FROM s), req.j ->> 'username'),"
"   'data', json_build_object("
"     'username', req.j ->> 'username', 'loginId', req.j ->> 'loginId',"
"     'stored', (SELECT coalesce(json_agg(type_id ORDER BY type_id), '[]') FROM s),"
"     'not_stored', (SELECT coalesce(json_agg(e ->> 'name' ORDER BY e ->> 'name'), '[]')"
"        FROM jsonb_array_elements(req.j -> 'assets') e"
"        WHERE e ->> 'name' NOT IN (SELECT type_id FROM s))))::text,"
"  (SELECT coalesce(string_agg(type_id, ',' ORDER BY type_id), '') FROM s),"
"  req.j ->> 'username', coalesce(req.j ->> 'loginId', ''),"
"  (SELECT min(user_id) FROM u)::text"
" FROM req";

/*
 * After the keys are stored: the table and column of each stored type
 * (protected_type_catalog), the user's tenant and the key.
 */
static const char *const amk_targets_sql =
"SELECT c.table_name, c.column_name, k.tenant_id::text, k.asset_key"
" FROM public.user_asset_map k"
" JOIN public.protected_type_catalog c ON c.type_id = k.type_id"
" WHERE k.user_id = $1::bigint AND k.asset_key IS NOT NULL"
"   AND k.type_id = ANY (string_to_array($2, ','))"
" ORDER BY k.type_id";

/*
 * Encrypts every plaintext value of the column for the tenant with the key:
 * AES-256-CBC (pgcrypto), a random 16-byte IV per value, stored as
 * base64(IV || ciphertext) -- 44 characters for up to 15 bytes, 64 for up to
 * 31, so it fits VARCHAR(64).  A value already in that form is ciphertext
 * and is left alone; a longer value would not fit and is left alone too.
 * %1$s = table, %2$s = column (both quoted).
 */
static const char *const amk_encrypt_sql =
"UPDATE public.%1$s t SET %2$s = ("
"   SELECT encode(r.iv || public.encrypt_iv(convert_to(t.%2$s::text, 'UTF8'),"
"     decode($1, 'base64'), r.iv, 'aes-cbc/pad:pkcs'), 'base64')"
"   FROM (SELECT public.gen_random_bytes(16) AS iv) r)"
" WHERE t.tenant_id = $2::bigint AND t.%2$s IS NOT NULL"
"   AND octet_length(t.%2$s::text) <= 31"
"   AND t.%2$s::text !~ '^[A-Za-z0-9+/]{43}=$'"
"   AND t.%2$s::text !~ '^[A-Za-z0-9+/]{64}$'";

/* Encrypts the tenant's data of each type just stored for the user. */
static void
amk_encrypt_data(const char *user_id, const char *stored)
{
	Oid			argtypes[2] = {TEXTOID, TEXTOID};
	Datum		values[2];
	SPITupleTable *targets;
	uint64		ntargets;

	if (stored[0] == '\0')
		return;
	values[0] = CStringGetTextDatum(user_id);
	values[1] = CStringGetTextDatum(stored);
	/* not read-only: it must see the keys amk_store_sql has just written */
	SPI_execute_with_args(amk_targets_sql, 2, argtypes, values, NULL, false, 0);
	targets = SPI_tuptable;
	ntargets = SPI_processed;

	for (uint64 i = 0; i < ntargets; i++)
	{
		char	   *table = SPI_getvalue(targets->vals[i], targets->tupdesc, 1);
		char	   *column = SPI_getvalue(targets->vals[i], targets->tupdesc, 2);
		char	   *tenant = SPI_getvalue(targets->vals[i], targets->tupdesc, 3);
		char	   *key = SPI_getvalue(targets->vals[i], targets->tupdesc, 4);
		char	   *sql = psprintf(amk_encrypt_sql, quote_identifier(table), quote_identifier(column));

		values[0] = CStringGetTextDatum(key);
		values[1] = CStringGetTextDatum(tenant);
		SPI_execute_with_args(sql, 2, argtypes, values, NULL, false, 0);
		ereport(LOG,
				(errmsg("am_keys: encrypted %llu value(s) of %s.%s for tenant %s",
						(unsigned long long) SPI_processed, table, column, tenant)));
	}
}

/* One attempt, in its own transaction; any error is rolled back (500). */
static void
amk_store_once(const char *json, AmkResult *r)
{
	MemoryContext caller = CurrentMemoryContext;
	Oid			argtypes[1] = {TEXTOID};
	Datum		values[1];

	r->status = 0;
	r->users = 0;
	SetCurrentStatementStartTimestamp();
	StartTransactionCommand();
	PG_TRY();
	{
		bool		isnull;
		char	   *problem;

		SPI_connect();
		PushActiveSnapshot(GetTransactionSnapshot());
		pgstat_report_activity(STATE_RUNNING, "am_keys: storing pushed asset keys");
		values[0] = CStringGetTextDatum(json);

		SPI_execute_with_args(amk_valid_sql, 1, argtypes, values, NULL, true, 1);
		if (DatumGetBool(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull)))
		{
			SPI_execute_with_args(amk_normalize_sql, 1, argtypes, values, NULL, true, 1);
			values[0] = CStringGetTextDatum(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1));
			SPI_execute_with_args(amk_check_sql, 1, argtypes, values, NULL, true, 1);
			problem = SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1);
		}
		else
			problem = "INVALID_JSON";
		if (strcmp(problem, "INVALID_JSON") == 0)
			amk_reply(r, 400, problem, "The body is not a JSON object.");
		else if (strcmp(problem, "MISSING_USERNAME") == 0)
			amk_reply(r, 400, problem, "username is required.");
		else if (strcmp(problem, "MISSING_LOGIN_ID") == 0)
			amk_reply(r, 400, problem, "loginId is required: the id the login server sent with the login.");
		else if (strcmp(problem, "MISSING_ASSETS") == 0)
			amk_reply(r, 400, problem, "assets must be a non-empty list.");
		else if (strcmp(problem, "INVALID_VALUE") == 0)
			amk_reply(r, 400, problem,
					  "Each asset needs a name (type id, e.g. A01) and a value: a 32-byte key in base64 (44 characters ending in '=').");
		else
		{
			SPI_execute_with_args(amk_store_sql, 1, argtypes, values, NULL, false, 1);
			r->users = DatumGetInt32(SPI_getbinval(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 1, &isnull));
			if (r->users == 1)
			{
				r->status = 200;
				strlcpy(r->body, SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 2),
						sizeof(r->body));
				ereport(LOG,
						(errmsg("am_keys: keys for user \"%s\" (loginId %.6s...): stored [%s]",
								SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 4),
								SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 5),
								SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3))));
				amk_encrypt_data(SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 6),
								 SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, 3));
			}
			else if (r->users > 1)
				amk_reply(r, 409, "AMBIGUOUS_USER",
						  "More than one tenant has this username signed in: send tenantId too.");
			else
				amk_reply(r, 409, "NOT_SIGNED_IN",
						  "The user is not signed in with this loginId (no live OAuth session).");
		}

		SPI_finish();
		PopActiveSnapshot();
		CommitTransactionCommand();
	}
	PG_CATCH();
	{
		ErrorData  *edata;

		MemoryContextSwitchTo(caller);
		edata = CopyErrorData();
		FlushErrorState();
		AbortCurrentTransaction();
		ereport(LOG, (errmsg("am_keys: could not store the pushed keys: %s", edata->message)));
		FreeErrorData(edata);
		amk_reply(r, 500, "DB_ERROR", "Database error; see the PostgreSQL log.");
	}
	PG_END_TRY();
	MemoryContextSwitchTo(caller);
	pgstat_report_activity(STATE_IDLE, NULL);
}

/* amk_store_once, retried while the user's login is not committed yet. */
static void
amk_store(const char *json, AmkResult *r)
{
	int			wait_ms = _PGS_AmKeys_IntSetting(DataDir, "keys_wait_seconds", 10, 0, 300) * 1000;

	for (;;)
	{
		amk_store_once(json, r);
		if (!(r->status == 409 && r->users == 0) || wait_ms <= 0)
			return;
		(void) WaitLatch(MyLatch, WL_LATCH_SET | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH, 500, PG_WAIT_EXTENSION);
		ResetLatch(MyLatch);
		CHECK_FOR_INTERRUPTS();
		wait_ms -= 500;
	}
}

/* ---------------------------------------------------------------- HTTP */

static void
amk_send(pgsocket sock, int status, const char *body)
{
	char		out[AMK_BODY_MAX + 512];
	int			len = _PGS_AmKeys_Response(status, body, out, sizeof(out));
	int			done = 0;

	while (len > 0 && done < len)
	{
		int			n = send(sock, out + done, len - done, 0);

		if (n <= 0)
			break;
		done += n;
	}
}

static void
amk_error(pgsocket sock, int status, const char *code, const char *message)
{
	AmkResult	r;

	amk_reply(&r, status, code, message);
	amk_send(sock, status, r.body);
}

/* Reads one request into buf; 1 = complete, 0 = nothing / gave up, -1 = too large or not HTTP. */
static int
amk_read(pgsocket sock, char *buf, int *len, AmkRequest *req)
{
	*len = 0;
	for (;;)
	{
		int			ev,
					n,
					parsed;

		ev = WaitLatchOrSocket(NULL, WL_SOCKET_READABLE | WL_TIMEOUT | WL_EXIT_ON_PM_DEATH,
							   sock, AMK_READ_TIMEOUT_MS, PG_WAIT_EXTENSION);
		if (ev & WL_TIMEOUT)
			return 0;
#ifdef WIN32
		pgwin32_noblock = 1;
#endif
		n = recv(sock, buf + *len, AMK_MAX_REQUEST + 1 - *len, 0);
#ifdef WIN32
		pgwin32_noblock = 0;
#endif
		if (n < 0 && (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR))
			continue;
		if (n <= 0)
			return 0;
		*len += n;
		parsed = _PGS_AmKeys_ParseRequest(buf, *len, req);
		if (parsed != 0)
			return parsed;
		if (*len > AMK_MAX_REQUEST)
			return -1;
	}
}

static void
amk_handle(pgsocket sock, char *buf)
{
	AmkRequest	req;
	AmkResult	r;
	char		secret[512];
	int			len;
	int			got = amk_read(sock, buf, &len, &req);

	if (got < 0)
		{
		amk_error(sock, 413, "TOO_LARGE", "The request is too large or not HTTP.");
		return;
	}
	if (got == 0)
	{
		if (len > 0)
			amk_error(sock, 400, "BAD_REQUEST", "Incomplete HTTP request.");
		return;
	}
	if (strcmp(req.path, AMK_PATH) != 0)
		{
		amk_error(sock, 404, "NO_SUCH_ENDPOINT", "No such endpoint.");
		return;
	}
	if (strcmp(req.method, "POST") != 0)
		{
		amk_error(sock, 405, "METHOD_NOT_ALLOWED", "Use POST.");
		return;
	}

	_PGS_AmKeys_Setting(DataDir, "push_secret", secret, sizeof(secret));
	if (secret[0] == '\0')
		{
		amk_error(sock, 503, "PUSH_DISABLED", "Set push_secret in am_client.conf.");
		return;
	}
	if (req.secret[0] == '\0')
		{
		amk_error(sock, 401, "SECRET_REQUIRED", "Send the shared secret in X-AM-Secret.");
		return;
	}
	if (!_PGS_AmKeys_SecretOk(req.secret, secret))
	{
		ereport(LOG, (errmsg("am_keys: push refused: wrong X-AM-Secret")));
		{
		amk_error(sock, 401, "INVALID_SECRET", "X-AM-Secret is wrong.");
		return;
	}
	}
	if (strncmp(req.content_type, "application/json", 16) != 0)
		{
		amk_error(sock, 415, "UNSUPPORTED_MEDIA_TYPE", "Send Content-Type: application/json.");
		return;
	}

	buf[req.body_offset + req.body_len] = '\0';
	if ((int) strlen(buf + req.body_offset) != req.body_len)
		{
		amk_error(sock, 400, "INVALID_JSON", "The body is not a JSON object.");
		return;
	}
	amk_store(buf + req.body_offset, &r);
	amk_send(sock, r.status, r.body);
}

/* -------------------------------------------------------------- worker */

void
AmKeysListenerMain(Datum main_arg)
{
	int			port = _PGS_AmKeys_IntSetting(DataDir, "keys_port", 7001, 1, 65535);
	char		db[NAMEDATALEN];
	char	   *buf;
	pgsocket	listener;
	struct sockaddr_in addr;

	_PGS_AmKeys_Setting(DataDir, "keys_database", db, sizeof(db));
	if (db[0] == '\0')
		strlcpy(db, "erms", sizeof(db));

	pqsignal(SIGHUP, SignalHandlerForConfigReload);
	pqsignal(SIGTERM, die);
	BackgroundWorkerUnblockSignals();
	BackgroundWorkerInitializeConnection(db, NULL, 0);

	listener = socket(AF_INET, SOCK_STREAM, 0);
	if (listener == PGINVALID_SOCKET)
		ereport(FATAL, (errmsg("am_keys: could not create a socket: %m")));
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons((unsigned short) port);
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);	/* 127.0.0.1 only */
	if (bind(listener, (struct sockaddr *) &addr, sizeof(addr)) < 0 || listen(listener, 16) < 0)
		ereport(FATAL,
				(errmsg("am_keys: could not listen on 127.0.0.1:%d: %m", port),
				 errhint("Another program may be using the port; set keys_port in am_client.conf.")));

	buf = MemoryContextAlloc(TopMemoryContext, AMK_MAX_REQUEST + 2);
	ereport(LOG, (errmsg("am_keys: listening on http://127.0.0.1:%d%s (database \"%s\")",
						 port, AMK_PATH, db)));

	for (;;)
	{
		int			ev;
		pgsocket	conn;

		ev = WaitLatchOrSocket(MyLatch, WL_LATCH_SET | WL_SOCKET_ACCEPT | WL_EXIT_ON_PM_DEATH,  /* socket pp */
							   listener, -1, PG_WAIT_EXTENSION);
		if (ev & WL_LATCH_SET)
			ResetLatch(MyLatch);
		CHECK_FOR_INTERRUPTS();
		if (ConfigReloadPending)
			ConfigReloadPending = false;	/* settings are read per request */
		if (!(ev & WL_SOCKET_ACCEPT))
			continue;

		conn = accept(listener, NULL, NULL);
		if (conn == PGINVALID_SOCKET)
			continue;
		amk_handle(conn, buf);
		closesocket(conn);
	}
}

void
_PG_init(void)
{
	BackgroundWorker worker;

	if (!process_shared_preload_libraries_in_progress)
		ereport(ERROR,
				(errmsg("am_keys must be loaded at server start"),
				 errhint("Add am_keys to shared_preload_libraries in postgresql.conf and restart.")));

	memset(&worker, 0, sizeof(worker));
	worker.bgw_flags = BGWORKER_SHMEM_ACCESS | BGWORKER_BACKEND_DATABASE_CONNECTION;
	worker.bgw_start_time = BgWorkerStart_RecoveryFinished;
	worker.bgw_restart_time = 10;
	strlcpy(worker.bgw_name, "am_keys listener", BGW_MAXLEN);
	strlcpy(worker.bgw_type, "am_keys listener", BGW_MAXLEN);
	strlcpy(worker.bgw_library_name, "am_keys", MAXPGPATH);
	strlcpy(worker.bgw_function_name, "AmKeysListenerMain", BGW_MAXLEN);
	RegisterBackgroundWorker(&worker);
}
