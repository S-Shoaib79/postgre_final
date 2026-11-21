<#
.SYNOPSIS
  setup_merged.bat, but with the real AM (asset-access-service.jar) instead of
  the mock: recreates "erms" and loads 01, 02 and 03 the same way, so the
  hooks send the matrix, the tenants and the users to the jar.

.DESCRIPTION
  The jar hands out a tenant's API key only in its console, and PostgreSQL
  needs that key (api_key.<tenant_id> in am_client.conf) before it can send
  the tenant's users. So 03_tenant_data.sql is loaded in two parts, unchanged:

    1. 01_schema.sql, 02_metadata.sql    -> matrix sent to the jar (admin API)
    2. 03's first transaction (tenants)  -> each tenant created in the jar
    3. for each tenant without a key: sign in to the jar's console as the
       tenant's first admin, create an API key, add it to am_client.conf
    4. the rest of 03                     -> users sent with their tenant's key

  Safe to re-run: the jar keeps its map, tenants and users (it answers
  MAP_ALREADY_LOADED, TENANT_EXISTS, USER_EXISTS, logged as WARNINGs), and
  keys already in am_client.conf are kept.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File D:\postgres-dev\merged\setup_merged_jar.ps1

.NOTES
  PostgreSQL (the rebuilt one) and the jar must be running, and am_client.conf
  must point at the jar with admin_user / tenant_admin_user set.
  WARNING: drops and recreates the database "erms" (only that database).
#>
$ErrorActionPreference = 'Stop'
$PgBin = 'D:\postgres-dev\install\bin'
$Conf = 'D:\postgres-dev\data\am_client.conf'
$Here = $PSScriptRoot

function Read-Conf {
    $cfg = @{}
    foreach ($line in Get-Content $Conf) {
        $line = ($line -split '#', 2)[0]
        if ($line -match '^\s*([^=]+?)\s*=\s*(.*?)\s*$') { $cfg[$Matches[1]] = $Matches[2] }
    }
    return $cfg
}

function Invoke-Psql([string[]] $Arguments, [string] $InputText = $null) {
    # psql prints PostgreSQL's WARNINGs on stderr; Windows PowerShell would
    # turn each one into a terminating error under 'Stop'.
    $ErrorActionPreference = 'Continue'
    $all = @('-X', '-q', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres') + $Arguments
    if ($null -ne $InputText) { $out = $InputText | & "$PgBin\psql.exe" @all 2>&1 }
    else { $out = & "$PgBin\psql.exe" @all 2>&1 }
    $out | ForEach-Object { "   $_" } | Write-Host
    if ($LASTEXITCODE -ne 0) { throw "psql failed: $Arguments" }
}

# Signs in to the jar's console as the tenant admin and creates an API key.
# The console is a web form (CSRF token + session cookie); the jar has no
# API for keys, by design: a key is shown once, to a person.
function New-TenantApiKey([string] $BaseUrl, [string] $Slug, [string] $User, [string] $Password, [string] $Label) {
    $csrf = { param($html) if ($html -match 'name="_csrf" value="([^"]+)"') { $Matches[1] } else { throw 'no CSRF token on the page' } }
    $page = Invoke-WebRequest -UseBasicParsing "$BaseUrl/login" -SessionVariable web
    $null = Invoke-WebRequest -UseBasicParsing "$BaseUrl/login" -WebSession $web -Method Post -Body @{
        _csrf = (& $csrf $page.Content); tenant = $Slug; username = $User; password = $Password }
    $page = Invoke-WebRequest -UseBasicParsing "$BaseUrl/manage/api-keys" -WebSession $web
    if ($page.Content -notmatch 'action="/manage/api-keys"') { throw "could not sign in to the console as $User@$Slug" }
    $page = Invoke-WebRequest -UseBasicParsing "$BaseUrl/manage/api-keys" -WebSession $web -Method Post -Body @{
        _csrf = (& $csrf $page.Content); label = $Label }
    if ($page.Content -notmatch '(ak_[0-9a-f]{16}\.[A-Za-z0-9_-]+)') { throw "the console did not show a new key for $Slug" }
    return $Matches[1]
}

$cfg = Read-Conf
foreach ($k in 'url', 'admin_user', 'tenant_admin_user', 'tenant_admin_password') {
    if (-not $cfg[$k]) { throw "$Conf has no '$k'. See the comments in am_client.cpp." }
}
$Url = $cfg['url'].TrimEnd('/')
try { $null = Invoke-WebRequest -UseBasicParsing "$Url/login" -TimeoutSec 5 }
catch { throw "The jar does not answer at $Url. Start it first (java -jar asset-access-service.jar)." }

Write-Host "1. Fresh database erms, 01_schema.sql, 02_metadata.sql (matrix -> jar)"
Invoke-Psql @('-d', 'postgres', '-c', 'DROP DATABASE IF EXISTS erms WITH (FORCE)', '-c', 'CREATE DATABASE erms')
Invoke-Psql @('-d', 'erms', '-f', "$Here\01_schema.sql")
Invoke-Psql @('-d', 'erms', '-f', "$Here\02_metadata.sql")

# 03_tenant_data.sql, split after its first transaction (the tenants)
$lines = Get-Content -Encoding UTF8 "$Here\03_tenant_data.sql"
$end = [Array]::IndexOf($lines, 'COMMIT;')
$tenantsPart = ($lines[0..$end] -join "`n")
if ($end -lt 0 -or $tenantsPart -notmatch 'INSERT INTO tenants' -or $tenantsPart -match 'user_accounts') {
    throw '03_tenant_data.sql no longer starts with a tenants-only transaction; update this script.'
}

Write-Host "2. 03_tenant_data.sql, tenants (-> jar, each with its first admin)"
Invoke-Psql @('-d', 'erms') $tenantsPart

Write-Host "3. API keys for the tenants"
$tenants = & "$PgBin\psql.exe" -X -At -U postgres -d erms -c "SELECT tenant_id || '|' || lower(org_code) FROM tenants ORDER BY tenant_id"
foreach ($row in $tenants) {
    $id, $slug = $row -split '\|'
    if ($cfg["api_key.$id"]) { Write-Host "   tenant $id ($slug): key already in am_client.conf"; continue }
    $key = New-TenantApiKey $Url $slug $cfg['tenant_admin_user'] $cfg['tenant_admin_password'] "PostgreSQL erms, tenant $id"
    Add-Content -Path $Conf -Value "api_key.$id = $key" -Encoding ASCII
    Write-Host "   tenant $id ($slug): key created in the jar's console and added to am_client.conf"
}

Write-Host "4. 03_tenant_data.sql, the rest (users -> jar with their tenant's key)"
Invoke-Psql @('-d', 'erms') (($lines[($end + 1)..($lines.Count - 1)]) -join "`n")

Write-Host "4b. 05_oauth.sql (oauth_tokens and the session functions for the login app)"
Invoke-Psql @('-d', 'erms', '-f', "$Here_oauth.sql")

# PostgreSQL registers each user in the jar with a random password nobody knows
# (user_password = random). For the login flow, give every test user a known one:
# <First name>-pass-1, e.g. hana.kim -> Hana-pass-1 (PUT /api/v1/users/{u}/password).
Write-Host "5. Test passwords in the jar (<First name>-pass-1, e.g. hana.kim -> Hana-pass-1)"
$cfg = Read-Conf
$users = & "$PgBin\psql.exe" -X -At -U postgres -d erms -c "SELECT tenant_id || '|' || username FROM user_accounts ORDER BY tenant_id, username"
foreach ($row in $users) {
    $id, $name = $row -split '\|'
    $key = $cfg["api_key.$id"]
    if (-not $key) { Write-Host "   $name (tenant $id): no api_key.$id in am_client.conf, skipped" -ForegroundColor Yellow; continue }
    $first = ($name -split '\.')[0]
    $password = $first.Substring(0, 1).ToUpper() + $first.Substring(1) + '-pass-1'
    try {
        $null = Invoke-RestMethod -Method Put -Uri "$Url/api/v1/users/$name/password" -Headers @{ 'X-Api-Key' = $key } `
            -ContentType 'application/json; charset=utf-8' -Body (@{ password = $password } | ConvertTo-Json)
        Write-Host "   $name (tenant $id): $password"
    } catch {
        Write-Host "   $name (tenant $id): could not set the password ($($_.Exception.Message))" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Done. PostgreSQL's warnings about AM, if any, are in D:\postgres-dev\data\server.log."
Write-Host "Sign in through the login app: powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\start.ps1"
Write-Host "Try a login by hand:  $PgBin\psql.exe -U postgres -d erms"
Write-Host "  UPDATE user_accounts SET login_status = 1 WHERE username = 'alice.sharma';"
Write-Host "  SELECT type_id, asset_key FROM user_asset_map WHERE user_id = 4106;"
