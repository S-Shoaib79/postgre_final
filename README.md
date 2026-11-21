# PostgreSQL runtime security: AM keys + OAuth 2.0 token flow

A modified PostgreSQL that runs Secure-ERMS's security by itself. Plain SQL on the tables is
enough, with no application code:

- it tells the access manager (AM, `asset-access-service.jar`) about tenants and users as they
  are inserted,
- an OAuth 2.0 login server (`login-server/`) signs users in through the AM, and the AM sends the
  user's keys **straight to PostgreSQL** (the `am_keys` background worker), so the login app never
  sees a key,
- PostgreSQL stores one 32-byte key per protected type in `user_asset_map`, only for a live OAuth
  session of that user, and removes them on logout, revoke or expiry, or when the user or tenant
  is disabled.

Built on upstream PostgreSQL commit `9e7d152488f197e96f171f0714459c227c3f7693` (master).
Windows only (MSVC + Ninja, WinHTTP).

> **Paths:** the scripts use `D:\postgres-dev` as the root. Clone this repo to
> `D:\postgres-dev`, or change the paths in the `*.bat` files, `login-server\config.json` and
> `merged\*.bat`.

---

## The flow

```
 Setup (setup_merged_jar.ps1, plain SQL; PostgreSQL's hooks call the AM):
 1. Metadata loaded once        roles + protected types + permission matrix ──► AM
 2. INSERT INTO tenants         ──► AM creates the tenant (and its key values)
 3. INSERT INTO user_accounts   ──► AM creates the user

 Login (browser form or POST /oauth/token):
 4. client ──► login app (7000)         tenant, username, password
 5. login app ──► PostgreSQL            session saved in oauth_tokens (pending: no token handed out),
                                        login_status = 1; the hook creates the empty user_asset_map rows
 6. login app ──► AM (8080)             POST /api/v1/auth/login  X-Api-Key: <tenant key>
                                        {username, password, requestId = loginId}
 7. AM ──► PostgreSQL am_keys (7001)    POST /api/am/keys  X-Asset-Delivery-Secret: <push_secret>
                                        {tenant, username, role, requestId, assets: [{name, value}]}
    am_keys checks: secret; requestId = a live session of this user; 32-byte keys
    ──► keys written to user_asset_map, 200 to the AM
 8. AM ──► login app                    200 OK (no keys)
 9. login app ──► client                access token, refresh token, loginId
    Any failure in 6-8 (wrong password, blocked, keys refused): the session is ended at once,
    login_status = 0, no tokens.

 After login:
10. userinfo / introspect / refresh     looked up in oauth_tokens (token hashes only)
11. revoke / sign-out / expiry of the last session  ──► login_status = 0, keys removed
12. user or tenant DISABLED             ──► keys removed at once
```

Test users, with password `<First name>-pass-1` set by the setup (e.g. `hana.kim` /
`Hana-pass-1`):
- Tenant `ACME` (1001): `hana.kim`, `alice.sharma`, ... `bob.lee` is `PENDING_FIRST_LOGIN`, so
  his login is refused.
- Tenant `GLOBEX` (1002): `greg.walsh`, ...

Permission matrix (which key types each role gets):

| Type | HR_ADMIN | HR_MANAGER | DEPT_MANAGER | PAYROLL_OFFICER | EMPLOYEE | TENANT_ADMIN |
|---|---|---|---|---|---|---|
| A01 Date of birth | S I U | S | S | | S | |
| A02 SSN | S I U | S | | S | | |
| A03 Salary | | S | | S I U | S | |
| A04 Account number | | | | S I U | S I U | |

## Repository layout

| Path | What |
|---|---|
| `postgresql/` | The full PostgreSQL source tree (commit above) with our changes already applied |
| `patches/runtime-security.patch` | The same core changes, as one patch against the upstream commit |
| `postgresql-changes/` | Only the changed or added source files, at their place in the tree |
| `postgresql-changes/contrib/am_keys/` | The keys endpoint inside PostgreSQL (background worker + HTTP), built separately |
| `merged/` | The `erms` database: schema, metadata, tenant data, OAuth tables, setup scripts |
| `secure_erms/pack/baseline_schema.sql` | The client's Secure-ERMS schema (loaded by `merged/01_schema.sql`) |
| `login-server/` | OAuth 2.0 login server, end-to-end token test, start/stop scripts, AM stub (optional) |
| `asset-access-handoff/` | The AM: config, SQL and scripts (put `asset-access-service.jar` here; it is not in git) |
| `new/am_client.conf.example` | Template for `data\am_client.conf` |
| `*.bat` | Build, start, stop, status, psql helpers |

Not in git: `build\`, `install\`, `data\` (the cluster, with `am_client.conf`),
`login-server\config.json`, the jar.

---

## 1. Prerequisites

- Windows 10/11, Visual Studio Build Tools (C++), Meson + Ninja, Git
- Strawberry Perl and win_flex_bison (paths are set in `build.bat`; adjust them there)
- Python 3.10+ (the login server and the test use only the standard library)
- Java 21 (the AM jar)

## 2. Build PostgreSQL and am_keys

From an **x64 Native Tools Command Prompt for VS**:

```bat
cd /d D:\postgres-dev
meson setup build postgresql --prefix=D:/postgres-dev/install --buildtype=debugoptimized
build.bat
D:\postgres-dev\postgresql-changes\contrib\am_keys\build_am_keys.bat
```

- Run `meson setup` once only. After that, `build.bat` rebuilds and installs into `install\`.
- `build_am_keys.bat` builds `am_keys.dll` into `install\lib`.
- Run them again after a source change, then restart PostgreSQL.

## 3. One-time configuration

### 3a. The PostgreSQL cluster

```bat
D:\postgres-dev\install\bin\initdb.exe -D D:\postgres-dev\data -U postgres -A trust
copy D:\postgres-dev\new\am_client.conf.example D:\postgres-dev\data\am_client.conf
```

- In `data\postgresql.conf`, set `shared_preload_libraries = 'am_keys'`.
- In `data\am_client.conf`, set:

  | Setting | Value |
  |---|---|
  | `url` | `http://127.0.0.1:8080` (the jar) |
  | `admin_user` / `admin_password` | the jar's platform admin (same as in `application.yml`) |
  | `tenant_admin_user` / `tenant_admin_password` | the first admin PostgreSQL creates in each new tenant |
  | `push_secret` | a long random value. **The same value** goes in `application.yml` (`asset-delivery.secret`) and `login-server\config.json`. |
  | `keys_port`, `keys_database`, `keys_wait_seconds` | leave at `7001`, `erms`, `10` |

  The `api_key.<tenant_id>` lines are added by the setup in section 4.

### 3b. The AM (jar)

Copy `asset-access-service.jar` into `D:\postgres-dev\asset-access-handoff\`. Start
PostgreSQL, then create the jar's database:

```bat
D:\postgres-dev\start.bat
D:\postgres-dev\install\bin\psql.exe -U postgres -v app_password=YOUR-PASSWORD -f D:\postgres-dev\asset-access-handoff\sql\create_database.sql
```

In `asset-access-handoff\config\application.yml`:

| Setting | Value |
|---|---|
| `spring.datasource.password` | the `YOUR-PASSWORD` above |
| `app.bootstrap.admin-password` | the platform admin password (= `admin_password` in `am_client.conf`) |
| `app.asset-delivery.url` | `http://127.0.0.1:7001/api/am/keys` (already set: PostgreSQL's `am_keys`) |
| `app.asset-delivery.secret` | = `push_secret` in `am_client.conf` |

### 3c. The login app

```powershell
cd D:\postgres-dev\login-server
copy config.example.json config.json
```

In `config.json`, keep `"am_url": ""`, so the AM is the jar at the `url` in
`am_client.conf`. Set `"push_secret"` to the same value as in `am_client.conf`.

## 4. Set up `erms` with the jar

| Step | Command | Expect |
|---|---|---|
| 1 | `D:\postgres-dev\start.bat` | `PostgreSQL started successfully` |
| 2 | own window: `cd /d D:\postgres-dev\asset-access-handoff` then `java -jar asset-access-service.jar` | `Started AssetAccessApplication`; console at http://localhost:8080/login |
| 3 | `powershell -ExecutionPolicy Bypass -File D:\postgres-dev\merged\setup_merged_jar.ps1` | steps 1-5, then `Done.` |

Step 3 drops and rebuilds `erms`, then:
- sends the matrix, the tenants and the users to the jar,
- creates each tenant's API key in the jar and adds it to `am_client.conf` as `api_key.<tenant_id>`,
- in its step 5, sets every test user's password in the jar to `<First name>-pass-1`.

On a re-run, 409 warnings (`MAP_ALREADY_LOADED`, `TENANT_EXISTS`, `USER_EXISTS`) are expected:
the jar keeps what it has.

## 5. Test the login flow (browser)

1. Start everything. This starts PostgreSQL if needed, the jar if it is not running, and the
   login app, each in its own window:
   ```powershell
   powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\start.ps1
   ```
   Expect `keys endpoint (am_keys) listening on http://127.0.0.1:7001/api/am/keys`, then
   `jar running on port 8080` (or `already running`), then `Ready.`
2. In the browser that opens (http://127.0.0.1:7000), sign in with tenant `ACME`, user
   `hana.kim` and password `Hana-pass-1`.
3. Look at the tables:
   ```powershell
   & 'D:\postgres-dev\install\bin\psql.exe' -U postgres -d erms -f 'D:\postgres-dev\login-server\show_tables.sql'
   ```
   - `hana.kim` has `login_status = 1`.
   - `user_asset_map` has her role's types (A01, A02, A03), each with a 44-character
     `asset_key` delivered by the jar.
   - `data\server.log` has `am_keys: keys for user "hana.kim" (loginId ...): stored [A01,A02,A03]`.
4. Press **Sign out** and run step 3 again: `login_status = 0` and the keys are gone.
5. Sign in with a wrong password. The page says `Wrong tenant, username or password.`,
   `login_status` stays 0 and no keys are stored.

## 6. Test the token system (OAuth 2.0)

The login server is an OAuth 2.0 authorization server. Sessions live in PostgreSQL
(`oauth_tokens`, created by `merged\05_oauth.sql`), so they survive a restart of the login app.
Only SHA-256 hashes of the tokens are stored. The session id (`loginId`) is the `requestId` the
jar sends back with the keys. `am_keys` stores keys only for that live session.

| Endpoint | Standard | What |
|---|---|---|
| `POST /oauth/token` | RFC 6749 | `grant_type=password` (`tenant`, `username`, `password`) or `grant_type=refresh_token`. Each refresh replaces **both** tokens. |
| `POST /oauth/introspect` | RFC 7662 | `token` → `{active: true, username, tenant_id, scope, exp, ...}` or `{active: false}` |
| `POST /oauth/revoke` | RFC 7009 | ends the whole session (access or refresh token). Always `200`. |
| `GET /oauth/userinfo` | | `Authorization: Bearer <token>` → user, tenant, which keys are set (never the keys) |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 | endpoint list |

Access tokens last 1 hour (`token_lifetime_seconds`) and refresh tokens 8 hours
(`refresh_token_lifetime_seconds`). Expired sessions are swept every `sweep_seconds`. A user
stays logged in while **any** of their sessions is live.

### 6a. Automated end-to-end test

With the servers from section 5 running:

```powershell
python D:\postgres-dev\login-server\test_oauth.py
```

It signs in `alice.sharma` / `Alice-pass-1` (tenant ACME) and checks:
- a wrong password is refused,
- getting a token, then userinfo and introspect,
- the keys arrive in `user_asset_map`,
- refresh: the old tokens must stop working,
- am_keys refuses a key push with a wrong `loginId`,
- revoke, and the keys are removed.

Expect every line to be `[PASS]`. Options: `--tenant`, `--username`, `--password`, `--server`.
Note: the jar blocks a user for 15 minutes after 5 failed logins (`429`).

### 6b. By hand (PowerShell)

```powershell
$S = 'http://127.0.0.1:7000'

# 1. get a token pair (the jar has just delivered the keys to PostgreSQL)
$t = Invoke-RestMethod -Method Post "$S/oauth/token" -Body @{grant_type='password'; tenant='ACME'; username='hana.kim'; password='Hana-pass-1'}
$t   # access_token, refresh_token, expires_in, scope, login_id

# 2. who is it, and which keys are set
Invoke-RestMethod "$S/oauth/userinfo" -Headers @{Authorization = "Bearer $($t.access_token)"}

# 3. introspect: active = true
Invoke-RestMethod -Method Post "$S/oauth/introspect" -Body @{token=$t.access_token}

# 4. refresh: new pair; the old access token is now inactive
$t2 = Invoke-RestMethod -Method Post "$S/oauth/token" -Body @{grant_type='refresh_token'; refresh_token=$t.refresh_token}
Invoke-RestMethod -Method Post "$S/oauth/introspect" -Body @{token=$t.access_token}    # active = false

# 5. revoke: session ends, login_status = 0, keys removed
Invoke-RestMethod -Method Post "$S/oauth/revoke" -Body @{token=$t2.refresh_token}
Invoke-RestMethod -Method Post "$S/oauth/introspect" -Body @{token=$t2.access_token}   # active = false
```

After steps 1 and 5, run `show_tables.sql` (section 5, step 3) to see the keys appear and
disappear.

Negative checks:

| Try | Expect |
|---|---|
| Wrong password | `/oauth/token` gives `400 invalid_grant`; no session, no keys |
| `bob.lee` (`PENDING_FIRST_LOGIN`) | refused before the AM is called |
| A key push with a wrong `loginId`, or one for a session that has ended | am_keys answers `409 NOT_SIGNED_IN` (the automated test checks this) |
| A key push with a wrong secret | am_keys answers `401 INVALID_SECRET` |
| Stop PostgreSQL's am_keys (or set a wrong `asset-delivery.secret`), then sign in | the jar answers `502 ASSET_DELIVERY_FAILED`, the login app gives `503 server_error`, and the session is ended |

### 6c. Stop

```powershell
powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\stop.ps1 -StopPostgres
```

Stop the jar with Ctrl+C in its window.

## 7. Login without the login app (PostgreSQL only)

```sql
-- psql -U postgres -d erms
UPDATE user_accounts SET login_status = 1 WHERE username = 'alice.sharma';
SELECT type_id, asset_key FROM user_asset_map WHERE user_id = 4106;   -- rows A01, A03, A04
UPDATE user_accounts SET login_status = 0 WHERE username = 'alice.sharma';
SELECT type_id, asset_key FROM user_asset_map WHERE user_id = 4106;   -- keys gone
```

The keys themselves only arrive through a login with the jar (section 5), because the jar sends
values only with a login delivery.

## 8. Without the jar: the AM stub (optional)

`login-server\am_stub.py` stands in for the jar, for development without Java. In
`login-server\config.json`, set `"am_url": "http://127.0.0.1:8097"`, and in
`data\am_client.conf` set `url =` (empty). Then run `setup_merged.bat` instead of
`setup_merged_jar.ps1`, and `start.ps1` starts the stub instead of the jar. The stub keeps the
first password it sees for each user.

## Troubleshooting

| Problem | Fix |
|---|---|
| `am_keys is not listening on port 7001` | `shared_preload_libraries = 'am_keys'` is missing in `data\postgresql.conf`, or `am_keys.dll` was not built. Restart PostgreSQL after the change. |
| Sign-in says `Sign-in is unavailable: the AM could not deliver the keys` | The jar got `502 ASSET_DELIVERY_FAILED`. Check that `asset-delivery.url` is `http://127.0.0.1:7001/api/am/keys` and `asset-delivery.secret` = `push_secret`, then look for `am_keys` lines in `data\server.log`. |
| `Wrong tenant, username or password.` with the right password | The setup's step 5 did not set the passwords. Re-run `setup_merged_jar.ps1`, or set one with `PUT /api/v1/users/{username}/password`. |
| `Too many failed sign-ins` | The jar blocks a user for 15 minutes after 5 failures. Wait, or try another user. |
| `No API key for tenant ...` | `api_key.<tenant_id>` is missing in `am_client.conf`. Re-run `setup_merged_jar.ps1`. |
| The jar stops with `Could not get Connection` | PostgreSQL is not running: run `start.bat` first, then the jar. |
| `push_secret is empty in config.json` | Set it, with the same value as in `data\am_client.conf`. |
| `Database erms is not reachable` | Run `merged\setup_merged_jar.ps1`. |
| `oauth_tokens is missing` | `psql -U postgres -d erms -f D:\postgres-dev\merged\05_oauth.sql` |
| WARNING `could not get the asset values from AM` at login | Harmless with the jar: PostgreSQL's login hook asks `GET /api/v1/users/{u}/assets`, and the jar sends values only with the login delivery. |
| WARNING `AM refused ... (HTTP 401)` | Wrong `admin_password` or `api_key.<tenant_id>` in `am_client.conf`. |
| You need to change the matrix in the jar | Stop the jar, run `psql -U postgres -f D:\postgres-dev\asset-access-handoff\sql\reset_database.sql`, start the jar, remove the `api_key.*` lines from `am_client.conf`, and run `setup_merged_jar.ps1`. |
| `psql` is not recognized | Use `D:\postgres-dev\install\bin\psql.exe`, or run `env.bat` first. |

More detail: `login-server\OAUTH_ARCHITECTURE.md`.
