<#
.SYNOPSIS
  Checks that an API key works end to end: lists the roles, registers a test user with the
  first role, logs the user in (which delivers the user's assets to the receiver), then
  disables the test user. Needs a receiver at app.asset-delivery.url: for a test, run
  scripts\test-receiver.ps1 in another window first.

.EXAMPLE
  .\scripts\smoke-test.ps1 -ApiKey 'ak_0123456789abcdef.xxxxxxxx'

.NOTES
  Users cannot be deleted, so each run leaves one disabled user named smoke-<random>.
#>
param(
    [Parameter(Mandatory = $true)] [string] $ApiKey,
    [string] $BaseUrl = 'http://localhost:8080'
)

$ErrorActionPreference = 'Stop'

# Turns a failed web request into the service's problem document (message, code, httpStatus).
# Returns $null only when no HTTP answer came back at all (service down, wrong URL).
# Windows PowerShell 5.1 does not always fill ErrorDetails, so the body is also read from
# the response stream.
function Get-Problem($err) {
    $response = $err.Exception.Response
    if ($null -eq $response) { return $null }
    $status = [int]$response.StatusCode
    $text = $err.ErrorDetails.Message
    if (-not $text) {
        try {
            $stream = $response.GetResponseStream()
            if ($stream.CanSeek) { $stream.Position = 0 }
            $text = (New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)).ReadToEnd()
        } catch { }
    }
    $problem = $null
    if ($text) { try { $problem = $text | ConvertFrom-Json } catch { } }
    if ($null -eq $problem -or -not $problem.message) {
        $problem = [pscustomobject]@{ message = "The service answered HTTP $status."; code = '' }
    }
    $problem | Add-Member -NotePropertyName httpStatus -NotePropertyValue $status -Force
    return $problem
}

function Invoke-Api([string] $Method, [string] $Path, $Body = $null) {
    $request = @{ Method = $Method; Uri = "$BaseUrl$Path"; Headers = @{ 'X-Api-Key' = $ApiKey } }
    if ($null -ne $Body) {
        $request.Body = [System.Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Depth 10))
        $request.ContentType = 'application/json; charset=utf-8'
    }
    try {
        return Invoke-RestMethod @request
    } catch {
        $problem = Get-Problem $_
        if ($null -eq $problem) { throw "Cannot reach $BaseUrl ($($_.Exception.Message)). Is the service running?" }
        throw "$Method $Path failed (HTTP $($problem.httpStatus)): $($problem.message) $($problem.code)"
    }
}

$username = 'smoke-' + [guid]::NewGuid().ToString('N').Substring(0, 8)

Write-Host "1. GET /api/v1/roles"
$roles = Invoke-Api GET '/api/v1/roles'
Write-Host "   $($roles.message)"
$role = @($roles.data)[0].name

Write-Host "2. POST /api/v1/users  ($username, role '$role')"
$created = Invoke-Api POST '/api/v1/users' @{ username = $username; password = 'smoke-test-password'; role = $role }
Write-Host "   $($created.message)"

Write-Host "3. POST /api/v1/auth/login  ($username)"
try {
    $login = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/v1/auth/login" -Headers @{ 'X-Api-Key' = $ApiKey } `
        -ContentType 'application/json; charset=utf-8' `
        -Body ([System.Text.Encoding]::UTF8.GetBytes((@{ username = $username; password = 'smoke-test-password'; requestId = 'smoke-test' } | ConvertTo-Json)))
    Write-Host "   $($login.message) The receiver has the user's assets."
} catch {
    $problem = Get-Problem $_
    if ($null -eq $problem) { throw "Cannot reach $BaseUrl ($($_.Exception.Message)). Is the service running?" }
    if ($problem.code -eq 'ASSET_DELIVERY_FAILED' -or $problem.httpStatus -eq 502) {
        throw ("The password was accepted, but the assets could not be delivered: $($problem.message) " +
               "Check app.asset-delivery.url and .secret in config\application.yml, and that the receiver " +
               "is running (scripts\test-receiver.ps1 for a test).")
    }
    throw "POST /api/v1/auth/login failed (HTTP $($problem.httpStatus)): $($problem.message) $($problem.code)"
}

Write-Host "4. PUT /api/v1/users/$username/enabled  (false)"
$disabled = Invoke-Api PUT "/api/v1/users/$username/enabled" @{ enabled = $false }
Write-Host "   $($disabled.message)"

Write-Host ""
Write-Host "Smoke test passed: the API key, user registration, login and asset delivery all work."
