# ERMS Login, OAuth 2.0 and Asset Keys — Architecture and Code Map

As of 2026-11-20. Every code point is `file:line` in `D:\postgres-dev`. Line numbers are for the files as they are on disk today.

## 1. Status

- **Done and applied:** `oauth_tokens` table and session functions (`merged\05_oauth.sql`) are in the `erms` database.
- **Done:** `login-server\login_server.py` is an OAuth 2.0 server (token, refresh, introspect, revoke, userinfo, metadata). Tested on a spare port: 20 of 22 checks pass.
- **Built, not yet loaded:** the new `am_keys.dll` (refuses keys without a live session) is in `build\am_keys\`. PostgreSQL still runs the old one from `install\lib\`, so the 2 `am_keys` checks fail until PostgreSQL is restarted with it.
- **Right now:** PostgreSQL and its keys endpoint (port 7001) are running; the login app (7000) and AM stub (8097) are stopped.

To finish (PowerShell):

```
powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\stop.ps1 -StopPostgres
D:\postgres-dev\postgresql-changes\contrib\am_keys\build_am_keys.bat
powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\start.ps1
python D:\postgres-dev\login-server\test_oauth.py          (expect 22/22)
```

## 2. Components

| Component | Runs as | Address | Code |
|---|---|---|---|
| Login app + OAuth 2.0 server | Python (stdlib only) | 127.0.0.1:7000 | `login-server\login_server.py` |
| AM (Asset Access Service) | Java service; `am_stub.py` stands in for its login | 127.0.0.1:8097 (stub) | `login-server\am_stub.py` |
| Keys endpoint | Background worker inside PostgreSQL (`am_keys.dll`) | 127.0.0.1:7001/api/am/keys | `postgresql-changes\contrib\am_keys\` |
| Login/logout hook | Patched PostgreSQL executor | inside every backend | `postgresql-changes\src\backend\executor\nodeModifyTable.c`, `execMain.c` |
| AM client (old pull path) | C++ in the PostgreSQL server | calls `url` in `am_client.conf` | `postgresql-changes\src\backend\executor\am_client.cpp` |
| Database | PostgreSQL 20devel, database `erms` | localhost:5432 | `merged\01_schema.sql`, `merged\05_oauth.sql` |

Settings: `login-server\config.json` (login app; not in git) and `data\am_client.conf` (PostgreSQL: AM url, tenant API keys, `push_secret`, `keys_port`, `keys_database`, `keys_wait_seconds`).

## 3. The picture

```
 Browser / API client
   |  1. POST /login (form)  or  POST /oauth/token grant_type=password  (tenant, username, password)
   v
 +---------------------------------------------------------------+
 | login_server.py  :7000                                        |
 |  - finds the user (user_accounts + tenants)                   |
 |  - makes token_id  = the loginId (public session id)          |
 |  - 2. asks the AM: POST /api/v1/auth/login  (X-Api-Key)  ------+-----> AM / am_stub.py :8097
 |       <- 200 {"result":"OK"}  or  401 FAILURE (never keys)    |              |
 |  - 3. one transaction in PostgreSQL:                          |              |
 |       INSERT oauth_tokens (hashes only)                       |              |
 |       UPDATE user_accounts SET login_status = 1  ----+        |              |
 |  - returns access_token / refresh_token / cookie     |        |              |
 +------------------------------------------------------|--------+              |
                                                        v                       |
 +------------------------------------------------------------------------+     |
 | PostgreSQL  (database erms)                                            |     |
 |  hook (nodeModifyTable.c -> execMain.c):                               |     |
 |    login_status 1 -> user_asset_map rows for the role, keys cleared    |     |
 |    login_status 0 -> keys removed                                      |     |
 |                                                                        |     |
 |  am_keys background worker  :7001  <-----------------------------------+-----+
 |    4. POST /api/am/keys  X-AM-Secret, {loginId, username, assets[]}    |
 |       checks: secret, JSON, loginId = live oauth_tokens session of the |
 |       user, then UPDATE user_asset_map SET asset_key = ...             |
 |                                                                        |
 |  oauth_end_sessions() / oauth_sweep():                                 |
 |    last live session ends -> login_status = 0 -> hook removes keys     |
 +------------------------------------------------------------------------+
   5. revoke / sign-out / expiry (sweeper every 30 s)  -> oauth_end_sessions
```

The login app never sees a key. The AM never gives keys to the login app. PostgreSQL only accepts keys for a session it can see in `oauth_tokens`.

## 4. Sign-in, step by step

| # | What happens | Where |
|---|---|---|
| 1 | Request arrives: browser form `POST /login`, or `POST /oauth/token` | routing `login_server.py:449-457` (route table `:450`); form handler `browser_login` `:569`; token endpoint `token` `:463` |
| 2 | Body read (form or JSON) | `Handler.params` `login_server.py:391` |
| 3 | Client checked: `client_id` from Basic auth or body, must be in `clients` | `Handler.client_id` `login_server.py:402` |
| 4 | Scope checked (subset of `read write`) | `check_scope` `login_server.py:349` |
| 5 | User and tenant looked up; both must be `ACTIVE` | `sign_in` `login_server.py:315`; query `db_find_user` `:133`; refusals `:326`, `:329` |
| 6 | Session id made: `token_id` (24 random bytes, URL-safe). It is the `loginId` | `login_server.py:331` |
| 7 | AM asked to check the password, with the tenant's API key from `am_client.conf` | `call_am_login` `login_server.py:273`; API key `api_key_for` `:264`; AM url `am_url` `:269`; settings file `am_settings` `:249` |
| 8 | AM stub: checks the password, answers OK/FAILURE, then pushes keys in a thread | `am_stub.py:62` (`do_POST`), password check `:78-82`, push thread `:89`, answer `:90` |
| 9 | Tokens made: access (always), refresh (API clients only) | `login_server.py:337-338` |
| 10 | One transaction: session row (SHA-256 of the tokens) + `login_status = 1` | `db_create_session` `login_server.py:155`; INSERT `:160`; UPDATE `:166`; hash `token_hash` `:101` |
| 11 | PostgreSQL hook runs on that UPDATE (section 6): rows for the role, old keys cleared | `nodeModifyTable.c:5089` -> `execMain.c:479` -> `execMain.c:3943` -> `_PGS_rsc_login` `execMain.c:3758` |
| 12 | Answer: browser gets cookie `sid` (HttpOnly, SameSite=Lax); API gets the token JSON | cookie `login_server.py:578`; JSON `:493-497` |

Errors on this path (`OAuthError` `login_server.py:309`): `invalid_request` (missing fields), `invalid_client` (401), `invalid_scope`, `invalid_grant` (wrong password, unknown user, not ACTIVE), `server_error` 503 (AM or database unreachable).

## 5. Key push: AM to PostgreSQL

| # | What happens | Where |
|---|---|---|
| 1 | AM (stub) builds the keys: one 32-byte key per type A01-A04, base64 | `am_stub.py:33` (`send_keys`), `:35` |
| 2 | `POST http://127.0.0.1:7001/api/am/keys` with `X-AM-Secret` and the same `loginId` | `am_stub.py:37-39` |
| 3 | Worker accepts the connection (loopback only) | listener `AmKeysListenerMain` `am_keys_worker.c:346`; 127.0.0.1 `:369`; bind `:370`; accept `:394`; handle `:397` |
| 4 | HTTP read and parsed (C++) | `amk_read` `am_keys_worker.c:244`; `_PGS_AmKeys_ParseRequest` `am_keys.cpp:85` (secret header `:114`) |
| 5 | Path `/api/am/keys`, method POST | `am_keys_worker.c:297`, `:302`; `AMK_PATH` `am_keys.h:22` |
| 6 | Secret compared in constant time against `push_secret` | `am_keys_worker.c:308-325`; `_PGS_AmKeys_Setting` `am_keys.cpp:122`; `_PGS_AmKeys_SecretOk` `am_keys.cpp:163` |
| 7 | Content type must be JSON | `am_keys_worker.c:327` |
| 8 | Body validated: JSON object, username, **loginId**, assets with 44-char base64 keys | `amk_valid_sql` `am_keys_worker.c:72`; `amk_check_sql` `:74` (loginId `:78`); error mapping `:138-151` |
| 9 | User found: username signed in (`login_status = 1`), optional tenantId, **and a live `oauth_tokens` session with `token_id = loginId` for that user** | `amk_store_sql` `am_keys_worker.c:86`; user CTE `:88`; session check `:91-93` |
| 10 | Keys written into `user_asset_map` (only types the role has) | `am_keys_worker.c:94-97` |
| 11 | No match yet (login not committed): retried every 0.5 s for up to `keys_wait_seconds` (10) | `amk_store` `am_keys_worker.c:198`; setting `:200`; retry `:205-207` |
| 12 | Answer: 200 with stored/not stored, or `NOT_SIGNED_IN` / `AMBIGUOUS_USER` (409) | `am_keys_worker.c:154-172`; body `_PGS_AmKeys_Response` `am_keys.cpp:176` |
| 13 | Worker registered at server start (`shared_preload_libraries = 'am_keys'`) | `_PG_init` `am_keys_worker.c:403`; register `:420` |

Each attempt runs in its own transaction; a database error is rolled back and answered 500 `DB_ERROR` (`amk_store_once` `am_keys_worker.c:113`). Neither the secret nor a key is logged.

## 6. The PostgreSQL login/logout hook

Any `UPDATE user_accounts SET login_status = ...` (from the login app, `oauth_end_sessions`, or by hand) goes through the patched executor:

| # | What happens | Where |
|---|---|---|
| 1 | Each row of the UPDATE is looked at before it is applied | `ExecModifyTable` `nodeModifyTable.c:4692`; call `:5089` |
| 2 | Is it `user_accounts` setting `login_status` or `status`, in a schema with `user_asset_map`? If so, keep the user id | `_PGS_RuntimeSecurity_CaptureRow` `nodeModifyTable.c:4630`; check `:4667-4671`; event `:4681` -> `_PGS_RuntimeSecurity_AddEvent` `execMain.c:3635` |
| 3 | At the end of the statement the events are handled | `standard_ExecutorFinish` `execMain.c:441` -> `:479` -> `_PGS_RuntimeSecurity_StatementEnd` `execMain.c:4025` -> `_PGS_rsc_process` `execMain.c:3976` |
| 4 | Signed in and ACTIVE -> login; else -> logout | `_PGS_rsc_user_status` `execMain.c:3923`; login `:3943`; logout `:3950` |
| 5 | Login: drop rows of types the role lost, add a row per type of the role, clear every key | `_PGS_rsc_login` `execMain.c:3758`; `:3766-3778`; type list `RSC_USER_TYPES` `:3743` |
| 6 | Login, old pull path: also GETs the assets from the AM (`path.user_assets`). Not used by the push flow; logs a warning when the AM url is not reachable | `execMain.c:3780`; `_PGS_AmClient_Call` `am_client.cpp:432` (`:465`, `:481`) |
| 7 | Logout: every key of the user set to NULL | `_PGS_rsc_logout` `execMain.c:3840` |
| 8 | Rows from statements that did not reach ExecutorFinish are handled at commit | `_PGS_rsc_xact_callback` `execMain.c:4090` |

Because every `login_status = 1` clears the keys, a second sign-in of the same user gets fresh keys from the AM for the new loginId.

## 7. Token lifecycle

| Event | What happens | Where |
|---|---|---|
| Request with a token | Bearer header or `sid` cookie -> SHA-256 -> live session lookup (not revoked, not expired, user and tenant ACTIVE, `login_status = 1`) | `Handler.session` `login_server.py:416`; `db_session_by_access` `:172`; conditions `LIVE` `:151` |
| Refresh | `grant_type=refresh_token`: same client only; scope may only narrow; both tokens replaced in one UPDATE; a used refresh token stops working (row lock stops two parallel uses) | `login_server.py:472-486`; `db_session_by_refresh` `:182`; `db_rotate` `:192` (`WITH upd` `:196`) |
| Introspect | `{active: true, username, sub, tenant_id, scope, exp, ...}` or `{active: false}`; `token_type_hint` picks the order | `introspect` `login_server.py:499` |
| Userinfo | Who the token belongs to and which keys are set (never the keys) | `userinfo` `login_server.py:537`; `db_keys` `:224` |
| Revoke | Access or refresh token -> whole session ended; always 200 (RFC 7009) | `revoke` `login_server.py:524`; `db_end_by_token` `:210` |
| Sign-out | Browser `POST /logout` or API `POST /api/logout`: session ended, cookie cleared | `logout` `login_server.py:582` |
| Expiry | Every `sweep_seconds` (30): sessions past `session_expires_at` ended | thread start `login_server.py:660`; `sweeper` `:236`; `db_sweep` `:220`; `oauth_sweep` `05_oauth.sql:64` |
| Session end (all of the above) | Session marked revoked; if the user has no other live session: `login_status = 0` -> hook removes the keys (section 6) | `oauth_end_sessions` `05_oauth.sql:43`; revoke `:48`; sign-out `:52-58` |

Lifetimes: access token `token_lifetime_seconds` (3600); refresh token and API session `refresh_token_lifetime_seconds` (28800); a browser session has no refresh token and lasts as long as its access token.

## 8. Data model

`oauth_tokens` (`merged\05_oauth.sql:18-36`), one row per session:

| Column | Meaning |
|---|---|
| `token_id` | Primary key; public; the `loginId` sent to the AM and checked by `am_keys` |
| `access_hash`, `refresh_hash` | SHA-256 (hex) of the tokens; the tokens themselves are never stored |
| `tenant_id`, `user_id` | The user; foreign key to `user_accounts (tenant_id, user_id)`, ON DELETE CASCADE |
| `client_id`, `scope` | The OAuth client and scope |
| `access_expires_at` | Access token expiry |
| `session_expires_at` | Refresh token expiry (= access expiry when there is no refresh token) |
| `created_at`, `refreshed_at` | Issue and last refresh time |
| `revoked_at`, `revoke_reason` | When and why it ended: `revoked`, `signed_out`, `expired` |

Index on live sessions per user: `ix_oauth_tokens_live_user` (`05_oauth.sql:37`).

Existing tables used (`merged\01_schema.sql`):

- `user_accounts.login_status` 0/1 (`01_schema.sql:35-37`): 1 = signed in; drives the hook.
- `user_asset_map` (`01_schema.sql:47-57`): one row per protected type of the user's role; `asset_key` is the 32-byte key (base64, 44 characters) while signed in, NULL otherwise.
- `tenants`, `user_accounts`, roles and permissions come from the client's schema (`secure_erms\pack\baseline_schema.sql`, included at `01_schema.sql:26`).

A fresh database gets `05_oauth.sql` from `merged\setup_merged.bat:15`.

## 9. Endpoints

Login app (`login_server.py`, 127.0.0.1:7000):

| Method and path | Standard | Body / header | Answer |
|---|---|---|---|
| `POST /oauth/token` | RFC 6749 | `grant_type=password`, `tenant`, `username`, `password` [, `client_id`, `scope`] | `access_token`, `refresh_token`, `token_type`, `expires_in`, `refresh_expires_in`, `scope`, `login_id` |
| `POST /oauth/token` | RFC 6749 | `grant_type=refresh_token`, `refresh_token` [, `client_id`, `scope`] | new pair, same `login_id` |
| `POST /oauth/introspect` | RFC 7662 | `token` [, `token_type_hint`] | `active` + details |
| `POST /oauth/revoke` | RFC 7009 | `token` [, `token_type_hint`] | `200 {}` |
| `GET /oauth/userinfo` | | `Authorization: Bearer` | `sub`, `preferred_username`, `tenant_id`, `org_code`, `scope`, `login_status`, `keys[]` |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | | endpoint list (same at `/.well-known/openid-configuration`) |
| `GET /`, `POST /login`, `POST /logout` | | browser form, cookie `sid` | page `home` `:596` |
| `GET /api/me`, `POST /api/logout` | | Bearer or cookie | the user's key rows (fingerprints only) `api_me` `:631` |

Bodies: form-encoded or JSON. A missing `grant_type` is treated as `password` (older callers).

AM (implemented by the Java AM; `am_stub.py` until then):

- `POST {AM}/api/v1/auth/login`, header `X-Api-Key`, body `{tenantId, username, password, loginId}` -> `200 {"result":"OK"}` or `401 {"result":"FAILURE"}`. No keys.

Keys endpoint (`am_keys`, 127.0.0.1:7001):

- `POST /api/am/keys`, headers `X-AM-Secret`, `Content-Type: application/json`, body `{loginId, username, [tenantId], assets: [{name, value}]}`.
- Error codes: `SECRET_REQUIRED`, `INVALID_SECRET`, `PUSH_DISABLED`, `UNSUPPORTED_MEDIA_TYPE`, `INVALID_JSON`, `MISSING_USERNAME`, `MISSING_LOGIN_ID` (new), `MISSING_ASSETS`, `INVALID_VALUE`, `NOT_SIGNED_IN` (now also: loginId is not a live session of the user), `AMBIGUOUS_USER`, `DB_ERROR`.

## 10. Security properties

- **Keys never pass through the login app or the browser.** The AM pushes them straight into PostgreSQL; the page shows only a SHA-256 fingerprint (`db_keys` `login_server.py:224`).
- **Keys are bound to a session.** `am_keys` stores keys only for the `loginId` of a live session of that same user (`am_keys_worker.c:91-93`). Keys for a revoked or expired session, another user's session or a made-up id are refused.
- **Tokens are stored hashed.** A copy of `oauth_tokens` cannot be used to sign in (`token_hash` `login_server.py:101`).
- **Refresh tokens rotate.** A used refresh token is dead; parallel reuse is stopped by the row lock in `db_rotate` (`login_server.py:192`).
- **Sign-out removes keys.** The last session ending sets `login_status = 0`, and the hook nulls every key (`05_oauth.sql:52`, `execMain.c:3840`).
- **Everything listens on 127.0.0.1 only** (`login_server.py:662`, `am_keys_worker.c:369`).
- **Passwords are never logged or stored by the login app**; the AM checks them.
- **No SQL injection through input:** user input reaches SQL only as psql variables (`:'name'`), numbers through `int()` (`psql` `login_server.py:110`).
- **Known limits:** clients are public (no client secret; `client_id` is only matched against the `clients` list); introspection needs no client auth (fine on 127.0.0.1, add auth before exposing it); no `client_credentials` grant (it has no user, so no keys to bind).

## 11. Configuration

`login-server\config.json` (template `config.example.json`), read in `load_config` `login_server.py:72` (defaults `:52`):

| Key | Default | Meaning |
|---|---|---|
| `port` | 7000 | Login app port (env `ERMS_LOGIN_PORT` overrides, used for tests) |
| `am_url`, `am_login_path` | from `am_client.conf`, `/api/v1/auth/login` | Where the AM login is |
| `am_timeout_seconds` | 5 | AM call timeout |
| `token_lifetime_seconds` | 3600 | Access token |
| `refresh_token_lifetime_seconds` | 28800 | Refresh token / API session |
| `clients` | `["erms_web"]` | Allowed client ids |
| `scopes` | `["read", "write"]` | Allowed scopes |
| `sweep_seconds` | 30 | How often expired sessions are ended |
| `push_secret` | | Given to the stub by `start.ps1`; must equal `push_secret` in `am_client.conf` |
| `psql`, `db_*` | local `erms` as postgres | Database access |

`data\am_client.conf` (read by PostgreSQL on every request): `url`, `api_key.<tenant_id>`, `push_secret`, `keys_port` (7001), `keys_database` (erms), `keys_wait_seconds` (10).

## 12. Files

| File | Role |
|---|---|
| `login-server\login_server.py` | Login page + OAuth 2.0 server |
| `login-server\am_stub.py` | Stand-in for the AM login and key push |
| `login-server\test_oauth.py` | End-to-end test (22 checks) |
| `login-server\start.ps1`, `stop.ps1` | Start/stop PostgreSQL, stub, login app |
| `login-server\show_tables.sql` | Shows `user_accounts` and `user_asset_map` |
| `login-server\README.md` | How to run; contract for the AM developer |
| `merged\05_oauth.sql` | `oauth_tokens`, `oauth_end_sessions`, `oauth_sweep` (safe to re-run) |
| `merged\01_schema.sql` | `login_status`, `user_asset_map` |
| `merged\setup_merged.bat` | Rebuilds `erms` (now includes `05_oauth.sql`) |
| `postgresql-changes\contrib\am_keys\am_keys_worker.c` | Keys endpoint, PostgreSQL side (C) |
| `postgresql-changes\contrib\am_keys\am_keys.cpp`, `am_keys.h` | HTTP parsing, settings, secret check (C++) |
| `postgresql-changes\contrib\am_keys\build_am_keys.bat` | Builds and installs `am_keys.dll` (now fails loudly if the DLL is in use) |
| `postgresql-changes\src\backend\executor\nodeModifyTable.c` | Captures `login_status` updates |
| `postgresql-changes\src\backend\executor\execMain.c` | Login/logout handling of `user_asset_map` |
| `postgresql-changes\src\backend\executor\am_client.cpp` | Old pull path to the AM |

## 13. Tests

`python login-server\test_oauth.py [--server URL] [--tenant ACME] [--username alice.sharma] [--password Alice-pass-1]`

| Section | Checks |
|---|---|
| 1 Metadata | discovery document |
| 2 Password grant | tokens issued; stored as hashes; wrong password 400; unknown client 401; unsupported grant 400 |
| 3 Keys | `login_status = 1` and every `user_asset_map` row has a key |
| 4 Introspect / userinfo | access and refresh active; unknown inactive; userinfo 200; bad token 401 |
| 5 Refresh | new pair, same login_id; old refresh refused; old access inactive; new access works |
| 6 am_keys | unknown loginId 409 `NOT_SIGNED_IN`; no loginId 400 `MISSING_LOGIN_ID` (needs the new DLL) |
| 7 Revoke | 200; access inactive; `login_status = 0` and keys removed; unknown token still 200 |

Last run (2026-11-20, server on port 7010, old DLL loaded): 20/22 passed; the 2 failures are section 6, as expected before the restart. The expiry sweep was tested separately in SQL (rolled back): an expired session was ended with reason `expired` and the user signed out.

Note: `hana.kim` still has `login_status = 1` from before this change, with no session. Once the new DLL is loaded, keys for her are refused until she signs in again.
