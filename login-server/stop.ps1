<#
  Stops the login app and the AM stub (the Python processes on their ports).
  Add -StopPostgres to stop PostgreSQL too.

  Run:  powershell -ExecutionPolicy Bypass -File D:\postgres-dev\login-server\stop.ps1 [-StopPostgres]
#>
param([switch] $StopPostgres)

$here = $PSScriptRoot
$root = Split-Path $here -Parent
$cfg  = Get-Content -Raw (Join-Path $here 'config.json') | ConvertFrom-Json
$ports = @(7000)
if ($cfg.port) { $ports = @([int] $cfg.port) }
if ([string] $cfg.am_url -match '^http://(127\.0\.0\.1|localhost):(\d+)/?$') { $ports += [int] $Matches[2] }

foreach ($port in $ports) {
    $conn = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $conn) { Write-Host "port ${port}: nothing running"; continue }
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -like 'python*') {
        Stop-Process -Id $proc.Id -Force
        Write-Host "port ${port}: stopped (python, PID $($proc.Id))"
    } else {
        Write-Host "port ${port}: used by '$($proc.ProcessName)', not ours: left running" -ForegroundColor Yellow
    }
}

if ($StopPostgres) {
    & (Join-Path $root 'install\bin\pg_ctl.exe') -D (Join-Path $root 'data') stop -m fast
}
Write-Host "Done. (The server windows stay open at a prompt; close them.)"
