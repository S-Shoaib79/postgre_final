# Testing the whole flow: jar (AM) + PostgreSQL am_keys + OAuth login app

Step-by-step commands with the result to expect at each step. Run everything in **PowerShell**,
one block at a time, in order. The flow itself is described in `README.md`.

| Service | Address | What it does |
|---|---|---|
| PostgreSQL (`erms`) | `localhost:5432` | Tables, login hook, OAuth sessions (`oauth_tokens`) |
| am_keys (inside PostgreSQL) | `http://127.0.0.1:7001/api/am/keys` | Receives the keys from the jar and stores them only for a live session |
| AM (`asset-access-service.jar`) | `http://127.0.0.1:8080` | Checks the password, then delivers the keys to am_keys |
| Login app (`login_server.py`) | `http://127.0.0.1:7000` | Login page + OAuth 2.0 (token, refresh, introspect, revoke) |

Test users: password `<First name>-pass-1`, for example `hana.kim` / `Hana-pass-1` (tenant
`ACME`), `alice.sharma` / `Alice-pass-1` (ACME), `greg.walsh` / `Greg-pass-1` (`GLOBEX`).

---

## 0. One-time settings

The same shared secret goes in three places:
- `push_secret` in `data\am_client.conf`,
- `asset-delivery.secret` in `asset-access-handoff\config\application.yml`,
- `push_secret` in `login-server\config.json`.

This block takes the secret already in `config.json` (or creates one if it is empty) and writes
it to all three:

```powershell
$j = 'D:\postgres-dev\login-server\config.json'
if (-not (Test-Path $j)) { Copy-Item 'D:\postgres-dev\login-server\config.example.json' $j }
$cfg = Get-Content -Raw $j | ConvertFrom-Json
if (-not $cfg.push_secret -or $cfg.push_secret -like 'change-*') { $cfg.push_secret = 'erms-' + [guid]::NewGuid().ToString('N') }
$cfg.am_url = ''                                  # empty = the jar, at the url in am_client.conf
$cfg | ConvertTo-Json -Depth 5 | Set-Content -Encoding ASCII $j
$secret = $cfg.push_secret

$c = 'D:\postgres-dev\data\am_client.conf'
(Get-Content $c) -replace '^\s*url\s*=.*', 'url = http://127.0.0.1:8080' `
                 -replace '^\s*push_secret\s*=.*', "push_secret = $secret" | Set-Content -Encoding ASCII $c
if (-not (Select-String $c -Pattern '^\s*push_secret' -Quiet)) { Add-Content -Encoding ASCII $c "push_secret = $secret" }

$y = 'D:\postgres-dev\asset-access-handoff\config\application.yml'
(Get-Content $y) -replace '^(\s*secret:\s*).*', "`${1}$secret" | Set-Content -Encoding ASCII $y

Select-String $c -Pattern '^\s*(url|push_secret|keys_)'
Select-String $y -Pattern 'url:|secret:|password:'
```

**Expect:**
- `am_client.conf` shows `url = http://127.0.0.1:8080`, `push_secret = erms-...`,
  `keys_port = 7001`, `keys_database = erms` and `keys_wait_seconds = 10`.
- `application.yml` shows `url: http://127.0.0.1:7001/api/am/keys` and `secret:` with the same
  `erms-...` value.

Also check by hand:
- In `application.yml`, the database `password:` and `admin-password:` are no longer
  `CHANGE-...`. Copy them from `asset-access-handoff-n\config\application.yml` if you set them
  there before.
- `admin_password` in `am_client.conf` equals `admin-password` in `application.yml`.
- `data\postgresql.conf` has `shared_preload_libraries = 'am_keys'`.

## 1. Rebuild am_keys and restart PostgreSQL

```powershell
D:\postgres-dev\stop.bat
cmd /c D:\postgres-dev\postgresql-changes\contrib\am_keys\build_am_keys.bat
D:\postgres-dev\start.bat
```

**Expect:**
- The build ends without `[ERROR]`, and `am_keys.dll` is copied into `install\lib`.
- `PostgreSQL started successfully`.
- Port 7001 is listening (am_keys). This should print `True`:
  ```powershell
  [bool](Get-NetTCPConnection -State Listen -LocalPort 7001 -ErrorAction SilentlyContinue)
  ```

## 2. Start the jar (own window)

```powershell
Start-Process powershell -WorkingDirectory D:\postgres-dev\asset-access-handoff -ArgumentList '-NoExit','-Command','java -jar asset-access-service.jar'
```

**Expect:**
- The new window ends with `Started AssetAccessApplication`.
- http://localhost:8080/login opens the jar's console.

If the jar was already running and you changed `application.yml` in step 0, stop it with Ctrl+C
and start it again: it reads the secret only at start-up.

## 3. Build `erms` and register everything in the jar

```powershell
powershell -ExecutionPolicy Bypass -File D:\postgres-dev\merged\setup_merged_jar.ps1
```

**Expect, in order:**

| Line | Meaning |
|---|---|
| `1. Fresh database erms, 01_schema.sql, 02_metadata.sql (matrix -> jar)` | `erms` rebuilt, matrix sent |
| `2. 03_tenant_data.sql, tenants` | ACME and GLOBEX sent to the jar |
| `3. API keys for the tenants` | `key created ...` or `key already in am_client.conf` for 1001 and 1002 |
| `4. 03_tenant_data.sql, the rest` | users sent to the jar |
| `4b. 05_oauth.sql` | OAuth tables created |
| `5. Test passwords in the jar` | one line per user, e.g. `hana.kim (tenant 1001): Hana-pass-1` |
| `Done.` | |

On a re-run, WARNINGs with `409` (`MAP_ALREADY_LOADED`, `TENANT_EXISTS`, `USER_EXISTS`) are
normal: the jar keeps what it already has.

**Check:**
```powershell
& 'D:\postgres-dev\install\bin\psql.exe' -U postgres -d erms -c "SELECT count(*) FROM oauth_tokens"
```
**Expect:** `0`, not `relation "oauth_tokens" does not exist`.

## 4. Start the login app

```powershell
powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\start.ps1
```

**Expect:**
```
1. PostgreSQL
   already running
   database erms: 10 users
   keys endpoint (am_keys) listening on http://127.0.0.1:7001/api/am/keys
2. AM
   jar already running on port 8080
3. Login app
   login app running on port 7000 (own window)
Ready. Sign in at http://127.0.0.1:7000 ...
```

The login app's window shows `AM: http://127.0.0.1:8080/api/v1/auth/login`. It must **not**
show `8097` (the stub) or `oauth_tokens is missing`.

## 5. Browser login

1. On http://127.0.0.1:7000, sign in with tenant `ACME`, user `hana.kim` and password
   `Hana-pass-1`.
2. Check the tables and the log:
   ```powershell
   & 'D:\postgres-dev\install\bin\psql.exe' -U postgres -d erms -f 'D:\postgres-dev\login-server\show_tables.sql'
   Select-String D:\postgres-dev\data\server.log -Pattern 'am_keys' | Select-Object -Last 3
   ```

**Expect:**
- The page shows hana.kim signed in, with her session id (loginId).
- `user_accounts`: `hana.kim` has `login_status = 1`.
- `user_asset_map`: rows A01, A02 and A03 for her, each `asset_key` 44 characters ending in `=`.
- `server.log`: `am_keys: keys for user "hana.kim" (loginId ...): stored [A01,A02,A03]`.
- The jar's window shows the login, and the login app's window shows
  `AM POST /api/v1/auth/login for 'hana.kim' ... -> 200 OK`.

3. Press **Sign out** and run step 2's commands again.

**Expect:** `login_status = 0`, and her `asset_key` values are empty.

4. Sign in again with password `wrong-pass-1`.

**Expect:**
- The page says `Wrong tenant, username or password.`
- `login_status` stays 0, and no keys are stored.

## 6. Automated token test

```powershell
python D:\postgres-dev\login-server\test_oauth.py
```

**Expect:** every line is `[PASS]`, and nothing is `[FAIL]`. It checks, for `alice.sharma`:
- a wrong password is refused (`400 invalid_grant`),
- a token pair, then userinfo and introspect (`active: true`),
- her keys arrive in `user_asset_map`,
- refresh: the new pair works and the old tokens are refused,
- am_keys refuses a key push with a wrong loginId (`NOT_SIGNED_IN`),
- revoke: the session ends, `login_status = 0`, the keys are removed.

## 7. Token system by hand

```powershell
$S = 'http://127.0.0.1:7000'
$t = Invoke-RestMethod -Method Post "$S/oauth/token" -Body @{grant_type='password'; tenant='ACME'; username='hana.kim'; password='Hana-pass-1'}; $t
```
**Expect:** `access_token`, `refresh_token`, `token_type = Bearer`, `expires_in = 3600`,
`scope` and `login_id`.

```powershell
Invoke-RestMethod "$S/oauth/userinfo" -Headers @{Authorization = "Bearer $($t.access_token)"}
```
**Expect:** `hana.kim`, tenant 1001 (ACME), and keys A01, A02 and A03 shown as set. The key
values are never shown.

```powershell
Invoke-RestMethod -Method Post "$S/oauth/introspect" -Body @{token=$t.access_token}
```
**Expect:** `active = True`, `username = hana.kim`, `tenant_id = 1001`, and `exp`.

```powershell
$t2 = Invoke-RestMethod -Method Post "$S/oauth/token" -Body @{grant_type='refresh_token'; refresh_token=$t.refresh_token}
Invoke-RestMethod -Method Post "$S/oauth/introspect" -Body @{token=$t.access_token}
Invoke-RestMethod -Method Post "$S/oauth/introspect" -Body @{token=$t2.access_token}
```
**Expect:**
- The refresh gives a new token pair.
- The old access token: `active = False`.
- The new one: `active = True`.

```powershell
Invoke-RestMethod -Method Post "$S/oauth/revoke" -Body @{token=$t2.refresh_token}
Invoke-RestMethod -Method Post "$S/oauth/introspect" -Body @{token=$t2.access_token}
& 'D:\postgres-dev\install\bin\psql.exe' -U postgres -d erms -f 'D:\postgres-dev\login-server\show_tables.sql'
```
**Expect:**
- The revoke answers `200`.
- introspect: `active = False`.
- `hana.kim` has `login_status = 0`, and her keys are empty.

## 8. Failure checks

```powershell
# wrong password
try { Invoke-RestMethod -Method Post "$S/oauth/token" -Body @{grant_type='password'; tenant='ACME'; username='hana.kim'; password='wrong-pass-1'} } catch { $_.ErrorDetails.Message }
```
**Expect:** `{"error": "invalid_grant", "error_description": "Wrong tenant, username or password."}`

```powershell
# user still PENDING_FIRST_LOGIN
try { Invoke-RestMethod -Method Post "$S/oauth/token" -Body @{grant_type='password'; tenant='ACME'; username='bob.lee'; password='Bob-pass-1'} } catch { $_.ErrorDetails.Message }
```
**Expect:** `invalid_grant`, `This account or its tenant is not active.` The jar is not called.

```powershell
# a key push for a session that does not exist
$secret = (Get-Content -Raw D:\postgres-dev\login-server\config.json | ConvertFrom-Json).push_secret
$body = '{"tenant":"acme","username":"hana.kim","requestId":"not-a-session","assets":[{"name":"A01","value":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]}'
try { Invoke-RestMethod -Method Post http://127.0.0.1:7001/api/am/keys -Headers @{'X-Asset-Delivery-Secret'=$secret} -ContentType 'application/json' -Body $body } catch { $_.ErrorDetails.Message }
```
**Expect:**
- After a wait of up to 10 seconds (`keys_wait_seconds`), am_keys answers `NOT_SIGNED_IN`.
- No keys are stored.

```powershell
# a key push with a wrong secret
try { Invoke-RestMethod -Method Post http://127.0.0.1:7001/api/am/keys -Headers @{'X-Asset-Delivery-Secret'='wrong'} -ContentType 'application/json' -Body $body } catch { $_.ErrorDetails.Message }
```
**Expect:** `INVALID_SECRET`.

Note: the jar blocks a user for 15 minutes after 5 failed logins (`Too many failed sign-ins`).
Don't run the wrong-password check more than 4 times in a row for the same user.

## 9. Stop

```powershell
powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\stop.ps1 -StopPostgres
```
Then press Ctrl+C in the jar's window.

**Expect:** `port 7000: stopped (python, PID ...)`, then `Done.`, and PostgreSQL stopped.

