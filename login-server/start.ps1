<#
  Starts the whole ERMS login flow, each server in its own window:
    1. PostgreSQL (only if it is not running yet)
       (with am_keys loaded, PostgreSQL itself listens on 127.0.0.1:7001/api/am/keys for the AM's keys)
    2. the AM: asset-access-service.jar when config.json's am_url is empty (started if needed),
       or the AM stub (am_stub.py) when am_url points at this machine
    3. the login app (login_server.py): sends the login to the AM, gets OK or FAILURE back
  and then opens the login page in the browser.

  Run:  powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\start.ps1
#>
$here   = $PSScriptRoot
$root   = Split-Path $here -Parent
$pgBin  = Join-Path $root 'install\bin'
$pgData = Join-Path $root 'data'

function Test-Port([int] $p) {
    [bool] (Get-NetTCPConnection -State Listen -LocalPort $p -ErrorAction SilentlyContinue)
}
function Wait-Port([int] $p, [int] $seconds = 15) {
    for ($i = 0; $i -lt $seconds * 2; $i++) {
        if (Test-Port $p) { return $true }
        Start-Sleep -Milliseconds 500
    }
    return $false
}

# ---- settings
$cfgPath = Join-Path $here 'config.json'
if (-not (Test-Path $cfgPath)) {
    Copy-Item (Join-Path $here 'config.example.json') $cfgPath
    Write-Host "Created config.json from config.example.json"
}
$cfg  = Get-Content -Raw $cfgPath | ConvertFrom-Json
$port = 7000
if ($cfg.port) { $port = [int] $cfg.port }
# PostgreSQL's keys endpoint (am_keys background worker): keys_port in data\am_client.conf
$keysPort = 7001
$kp = Select-String -Path (Join-Path $pgData 'am_client.conf') -Pattern '^\s*keys_port\s*=\s*(\d+)' -ErrorAction SilentlyContinue
if ($kp) { $keysPort = [int] $kp.Matches[0].Groups[1].Value }
if (-not $cfg.push_secret) {
    Write-Host "push_secret is empty in config.json: set it first." -ForegroundColor Red
    exit 1
}

# ---- 1. PostgreSQL
Write-Host "1. PostgreSQL"
$null = & "$pgBin\pg_ctl.exe" -D $pgData status
if ($LASTEXITCODE -eq 0) {
    Write-Host "   already running"
} else {
    # Started with -PassThru + WaitForExit so the script does not wait on the server itself.
    $p = Start-Process -FilePath "$pgBin\pg_ctl.exe" -NoNewWindow -PassThru `
        -ArgumentList @('-D', $pgData, '-l', (Join-Path $pgData 'server.log'), 'start', '-w')
    $p.WaitForExit()
    $null = & "$pgBin\pg_ctl.exe" -D $pgData status
    if ($LASTEXITCODE -ne 0) {
        Write-Host "   FAILED to start. See $pgData\server.log" -ForegroundColor Red
        exit 1
    }
    Write-Host "   started"
}
$count = & "$pgBin\psql.exe" -X -q -At -U postgres -d erms -c "SELECT count(*) FROM user_accounts"
if ($LASTEXITCODE -ne 0) {
    Write-Host "   Database erms is not reachable. Set it up with $root\merged\setup_merged.bat" -ForegroundColor Red
    exit 1
}
Write-Host "   database erms: $count users"
if (Wait-Port $keysPort 10) {
    Write-Host "   keys endpoint (am_keys) listening on http://127.0.0.1:$keysPort/api/am/keys"
} else {
    Write-Host "   am_keys is not listening on port ${keysPort}: check shared_preload_libraries = 'am_keys' in postgresql.conf and $pgData\server.log" -ForegroundColor Red
    exit 1
}

# ---- 2. AM
Write-Host "2. AM"
$amUrl = [string] $cfg.am_url
if (-not $amUrl) {
    # The real AM: asset-access-service.jar, at the url in data\am_client.conf
    $jarDir = Join-Path $root 'asset-access-handoff'
    $jarPort = 8080
    $u = Select-String -Path (Join-Path $pgData 'am_client.conf') -Pattern '^\s*url\s*=\s*https?://[^:/]+:(\d+)' -ErrorAction SilentlyContinue
    if ($u) { $jarPort = [int] $u.Matches[0].Groups[1].Value }
    if (Test-Port $jarPort) {
        Write-Host "   jar already running on port $jarPort"
    } elseif (-not (Test-Path (Join-Path $jarDir 'asset-access-service.jar'))) {
        Write-Host "   asset-access-service.jar is not in $jarDir" -ForegroundColor Red; exit 1
    } else {
        $cmd = "`$host.UI.RawUI.WindowTitle = 'AM jar :$jarPort'; java -jar asset-access-service.jar"
        Start-Process powershell -WorkingDirectory $jarDir -ArgumentList @('-NoExit', '-Command', $cmd)
        if (Wait-Port $jarPort 90) { Write-Host "   jar running on port $jarPort (own window)" }
        else { Write-Host "   the jar did not start: look at its window" -ForegroundColor Red; exit 1 }
    }
} elseif ($amUrl -match '^http://(127\.0\.0\.1|localhost):(\d+)/?$') {
    $amPort = [int] $Matches[2]
    if (Test-Port $amPort) {
        Write-Host "   port $amPort is already in use (stub already running?): leaving it"
    } else {
        $cmd = "`$host.UI.RawUI.WindowTitle = 'AM stub :$amPort'; " +
               "python am_stub.py --port $amPort --secret '$($cfg.push_secret)' --keys-endpoint 'http://127.0.0.1:$keysPort/api/am/keys'"
        Start-Process powershell -WorkingDirectory $here -ArgumentList @('-NoExit', '-Command', $cmd)
        if (Wait-Port $amPort) { Write-Host "   AM stub running on port $amPort (own window)" }
        else { Write-Host "   AM stub did not start: look at its window" -ForegroundColor Red; exit 1 }
    }
} else {
    Write-Host "   using the AM at $amUrl"
}

# ---- 3. login app
Write-Host "3. Login app"
if (Test-Port $port) {
    Write-Host "   port $port is already in use (login app already running?): leaving it"
} else {
    $cmd = "`$host.UI.RawUI.WindowTitle = 'ERMS login :$port'; python login_server.py"
    Start-Process powershell -WorkingDirectory $here -ArgumentList @('-NoExit', '-Command', $cmd)
    if (Wait-Port $port) { Write-Host "   login app running on port $port (own window)" }
    else { Write-Host "   login app did not start: look at its window" -ForegroundColor Red; exit 1 }
}

Start-Process "http://127.0.0.1:$port"
Write-Host ""
Write-Host "Ready. Sign in at http://127.0.0.1:$port  (tenant ACME, user hana.kim, password Hana-pass-1)" -ForegroundColor Green
Write-Host "See the tables:  & '$root\install\bin\psql.exe' -U postgres -d erms -f '$here\show_tables.sql'"
Write-Host "Stop:            powershell -ExecutionPolicy Bypass -File $here\stop.ps1"
