<#
.SYNOPSIS
  A stand-in for the receiving app, for testing logins on a development machine.

.DESCRIPTION
  Listens on http://localhost:9090/assets, checks the X-Asset-Delivery-Secret header,
  prints each delivery and answers 204 (or 401 if the secret is wrong). Stop with Ctrl+C.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\test-receiver.ps1 -Secret 'CHANGE-to-a-long-random-shared-secret'
#>
param(
    [Parameter(Mandatory = $true)] [string] $Secret,
    [int] $Port = 9090
)

$ErrorActionPreference = 'Stop'

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$Port/")
try {
    $listener.Start()
} catch {
    Write-Host "Cannot listen on port ${Port}: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Another program (often an earlier test receiver that is still running) holds this port."
    Write-Host "Find it with:  netsh http show servicestate view=requestq   (look for :$Port and its process id)"
    Write-Host "Or use another port: -Port 9091, and set app.asset-delivery.url to http://localhost:9091/assets."
    exit 1
}
Write-Host "Test receiver listening on http://localhost:$Port/assets (Ctrl+C to stop)"
try {
    while ($listener.IsListening) {
        # Wait in short steps so that Ctrl+C can stop the script between them.
        $pending = $listener.GetContextAsync()
        while (-not $pending.AsyncWaitHandle.WaitOne(500)) { }
        $context = $pending.GetAwaiter().GetResult()
        $request = $context.Request
        $reader = New-Object System.IO.StreamReader($request.InputStream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd()
        if ($request.Url.AbsolutePath.TrimEnd('/') -ne '/assets') {
            $context.Response.StatusCode = 404
        } elseif ($request.HttpMethod -ne 'POST') {
            $context.Response.StatusCode = 405
        } elseif ($request.Headers['X-Asset-Delivery-Secret'] -ne $Secret) {
            Write-Host 'Refused a delivery: wrong or missing secret'
            $context.Response.StatusCode = 401
        } else {
            $delivery = $body | ConvertFrom-Json
            Write-Host "Delivery for $($delivery.tenant)/$($delivery.username) (role $($delivery.role), request $($delivery.requestId)):"
            if (@($delivery.assets).Count -eq 0) { Write-Host '    (no assets)' }
            foreach ($asset in $delivery.assets) {
                Write-Host ("    {0,-24} {1}" -f $asset.name, $asset.value)
            }
            $context.Response.StatusCode = 204
        }
        $context.Response.Close()
    }
} finally {
    if ($listener.IsListening) { $listener.Stop() }
    $listener.Close()
}
