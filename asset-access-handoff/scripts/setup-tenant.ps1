<#
.SYNOPSIS
  One-time setup of a local Asset Access Service: loads the role/asset map (if not loaded yet)
  and creates a tenant with its first admin.

.EXAMPLE
  .\scripts\setup-tenant.ps1 -AdminPassword 'the-platform-admin-password' -TenantAdminPassword 'manager-password-123'

.NOTES
  Works in Windows PowerShell 5.1 and PowerShell 7. The service must be running.
  The map can be loaded only once per database. To start again, see sql/reset_database.sql.
#>
param(
    [string] $BaseUrl = 'http://localhost:8080',
    [string] $AdminUser = 'admin',
    [Parameter(Mandatory = $true)] [string] $AdminPassword,
    [string] $MapFile = '',
    [string] $TenantSlug = 'acme',
    [string] $TenantName = 'Acme Corp',
    [string] $TenantAdmin = 'manager',
    [Parameter(Mandatory = $true)] [string] $TenantAdminPassword
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

# Default map file: samples\role-asset-map.json next to this scripts folder. Worked out here,
# not in param(), because Windows PowerShell 5.1 can leave $PSScriptRoot empty there.
if (-not $MapFile) {
    $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $MapFile = Join-Path $scriptDir '..\samples\role-asset-map.json'
}
if (-not (Test-Path -LiteralPath $MapFile)) {
    throw "Map file not found: $MapFile. Pass the path with -MapFile."
}
$MapFile = (Resolve-Path -LiteralPath $MapFile).Path

# Calls the service and returns the parsed JSON body. On an error status, prints the service's
# message and code, and returns the parsed problem document with an extra 'failed' property.
function Invoke-Api([string] $Method, [string] $Path, $Body = $null, [string] $Token = $null) {
    $request = @{ Method = $Method; Uri = "$BaseUrl$Path"; Headers = @{} }
    if ($Token) { $request.Headers['Authorization'] = "Bearer $Token" }
    if ($null -ne $Body) {
        $json = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 10 }
        $request.Body = [System.Text.Encoding]::UTF8.GetBytes($json)
        $request.ContentType = 'application/json; charset=utf-8'
    }
    try {
        return Invoke-RestMethod @request
    } catch {
        $problem = Get-Problem $_
        if ($null -eq $problem) { throw "Cannot reach $BaseUrl ($($_.Exception.Message)). Is the service running?" }
        $problem | Add-Member -NotePropertyName failed -NotePropertyValue $true -Force
        return $problem
    }
}

Write-Host "1. Logging in as platform admin '$AdminUser'..."
$login = Invoke-Api POST '/api/admin/auth/token' @{ username = $AdminUser; password = $AdminPassword }
if ($login.failed) { throw "Login failed: $($login.message) ($($login.code))" }
$token = $login.data.accessToken
Write-Host "   $($login.message)"

try {
    Write-Host "2. Checking the role/asset map..."
    $map = Invoke-Api GET '/api/admin/role-asset-map' -Token $token
    if ($map.failed) { throw "$($map.message) ($($map.code))" }
    if (@($map.data.PSObject.Properties).Count -gt 0) {
        Write-Host "   Already loaded: $($map.message) Skipping."
    } else {
        Write-Host "   Not loaded yet. Loading $MapFile ..."
        $mapJson = Get-Content -Raw -Encoding UTF8 $MapFile
        $loaded = Invoke-Api POST '/api/admin/role-asset-map' $mapJson -Token $token
        if ($loaded.failed) { throw "Loading the map failed: $($loaded.message) ($($loaded.code))" }
        Write-Host "   $($loaded.message)"
    }

    Write-Host "3. Creating tenant '$TenantSlug' with admin '$TenantAdmin'..."
    $tenant = Invoke-Api POST '/api/admin/tenants' @{
        slug = $TenantSlug; name = $TenantName
        admin = @{ username = $TenantAdmin; password = $TenantAdminPassword }
    } -Token $token
    if ($tenant.failed -and $tenant.code -eq 'TENANT_EXISTS') {
        Write-Host "   $($tenant.message) Keeping the existing tenant."
    } elseif ($tenant.failed) {
        throw "Creating the tenant failed: $($tenant.message) ($($tenant.code))"
    } else {
        Write-Host "   $($tenant.message)"
    }
} finally {
    $null = Invoke-Api POST '/api/admin/auth/logout' -Token $token
}

Write-Host ""
Write-Host "Done. Next, create an API key for the client app:"
Write-Host "  1. Open $BaseUrl/login"
Write-Host "  2. Tenant: $TenantSlug   Username: $TenantAdmin   Password: (the tenant admin password)"
Write-Host "  3. Open 'API keys', create a key, and copy it (it is shown only once)."
Write-Host "  4. Test it:  .\scripts\smoke-test.ps1 -ApiKey 'ak_...'"
