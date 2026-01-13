#Requires -Version 5.1
<#
.SYNOPSIS
    SCM Authentication Helper Script for Strata Cloud Manager API

.DESCRIPTION
    Retrieves and caches OAuth2 access tokens for Strata Cloud Manager API.

.PARAMETER Command
    The command to execute: token, refresh, test, or clear

.PARAMETER ClientId
    Client ID (or set SCM_CLIENT_ID environment variable)

.PARAMETER ClientSecret
    Client Secret (or set SCM_CLIENT_SECRET environment variable)

.PARAMETER TsgId
    TSG ID (or set SCM_TSG_ID environment variable)

.EXAMPLE
    # Using environment variables
    $env:SCM_CLIENT_ID = "your-client-id"
    $env:SCM_CLIENT_SECRET = "your-client-secret"
    $env:SCM_TSG_ID = "1234567890"
    .\scm-auth.ps1 token

.EXAMPLE
    # Using parameters
    .\scm-auth.ps1 -Command token -ClientId "id" -ClientSecret "secret" -TsgId "123"

.EXAMPLE
    # Use token in API call
    $token = .\scm-auth.ps1 token
    Invoke-RestMethod -Uri "https://api.strata.paloaltonetworks.com/config/v1/..." -Headers @{Authorization="Bearer $token"}

.NOTES
    Tokens are cached in $env:USERPROFILE\.scm_token_cache
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet("token", "refresh", "test", "clear", "")]
    [string]$Command = "",

    [Alias("c")]
    [string]$ClientId,

    [Alias("s")]
    [string]$ClientSecret,

    [Alias("t")]
    [string]$TsgId
)

$ErrorActionPreference = "Stop"

# Configuration
$AuthUrl = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
# Use USERPROFILE on Windows, HOME on Unix
$HomeDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { $env:HOME }
$TokenCache = Join-Path $HomeDir ".scm_token_cache"

# Use parameters or environment variables
if (-not $ClientId) { $ClientId = $env:SCM_CLIENT_ID }
if (-not $ClientSecret) { $ClientSecret = $env:SCM_CLIENT_SECRET }
if (-not $TsgId) { $TsgId = $env:SCM_TSG_ID }

# Output functions
function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Green -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $Message -ForegroundColor White
}

function Show-Usage {
    Write-Host @"
Usage: .\scm-auth.ps1 [OPTIONS] COMMAND

Strata Cloud Manager Authentication Helper

Commands:
    token       Get an access token (cached if valid)
    refresh     Force token refresh
    test        Test authentication and print token info
    clear       Clear cached token

Options:
    -ClientId, -c      Client ID (or set SCM_CLIENT_ID env var)
    -ClientSecret, -s  Client Secret (or set SCM_CLIENT_SECRET env var)
    -TsgId, -t         TSG ID (or set SCM_TSG_ID env var)

Environment Variables:
    SCM_CLIENT_ID             Service account client ID
    SCM_CLIENT_SECRET         Service account client secret
    SCM_TSG_ID                Tenant Service Group ID

Examples:
    # Using environment variables
    `$env:SCM_CLIENT_ID = "your-client-id"
    `$env:SCM_CLIENT_SECRET = "your-client-secret"
    `$env:SCM_TSG_ID = "1234567890"
    .\scm-auth.ps1 token

    # Using command line options
    .\scm-auth.ps1 -ClientId "client-id" -ClientSecret "secret" -TsgId "tsg-id" token

    # Use token in API call
    `$token = .\scm-auth.ps1 token
    Invoke-RestMethod -Uri "https://api.strata.paloaltonetworks.com/config/v1/..." -Headers @{Authorization="Bearer `$token"}
"@
}

function Test-Credentials {
    if (-not $ClientId) {
        Write-Error "Client ID not set. Use -ClientId or set SCM_CLIENT_ID"
        exit 1
    }
    if (-not $ClientSecret) {
        Write-Error "Client Secret not set. Use -ClientSecret or set SCM_CLIENT_SECRET"
        exit 1
    }
    if (-not $TsgId) {
        Write-Error "TSG ID not set. Use -TsgId or set SCM_TSG_ID"
        exit 1
    }
}

function Get-CachedToken {
    if (Test-Path $TokenCache) {
        $cached = Get-Content $TokenCache -Raw
        $parts = $cached -split "\|"
        if ($parts.Count -ge 2) {
            $token = $parts[0]
            $expiry = [long]$parts[1]
            $now = [DateTimeOffset]::Now.ToUnixTimeSeconds()

            # Return cached token if still valid (with 60s buffer)
            if ($expiry -gt ($now + 60)) {
                return $token
            }
        }
    }
    return $null
}

function Request-NewToken {
    Test-Credentials

    Write-Info "Requesting new access token..." | Out-Host

    $body = "grant_type=client_credentials&scope=tsg_id:$TsgId"
    $authBytes = [System.Text.Encoding]::UTF8.GetBytes("${ClientId}:${ClientSecret}")
    $authBase64 = [Convert]::ToBase64String($authBytes)

    try {
        $response = Invoke-RestMethod -Uri $AuthUrl -Method Post `
            -Headers @{
            "Content-Type"  = "application/x-www-form-urlencoded"
            "Authorization" = "Basic $authBase64"
        } `
            -Body $body
    }
    catch {
        $errorResponse = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
        if ($errorResponse.error_description) {
            Write-Error "Authentication failed: $($errorResponse.error_description)"
        }
        else {
            Write-Error "Authentication failed: $_"
        }
        exit 1
    }

    $token = $response.access_token
    $expiresIn = $response.expires_in

    if (-not $token) {
        Write-Error "Failed to extract access token from response"
        exit 1
    }

    # Calculate expiry timestamp
    $expiry = [DateTimeOffset]::Now.ToUnixTimeSeconds() + $expiresIn

    # Cache the token
    "${token}|${expiry}" | Set-Content $TokenCache -Force
    # Set restrictive permissions (Windows equivalent)
    $acl = Get-Acl $TokenCache
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        $env:USERNAME, "FullControl", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl $TokenCache $acl

    Write-Info "Token obtained, expires in ${expiresIn}s" | Out-Host
    return $token
}

function Get-Token {
    $cachedToken = Get-CachedToken
    if ($cachedToken) {
        Write-Info "Using cached token" | Out-Host
        return $cachedToken
    }
    else {
        return Request-NewToken
    }
}

function Test-Token {
    Test-Credentials

    $token = Get-Token

    Write-Host "Token Preview: $($token.Substring(0, [Math]::Min(50, $token.Length)))..."
    Write-Host ""

    Write-Info "Testing API access..."

    try {
        $response = Invoke-RestMethod `
            -Uri "https://api.strata.paloaltonetworks.com/config/v1/jobs?limit=1" `
            -Headers @{
            "Authorization" = "Bearer $token"
            "Content-Type"  = "application/json"
        }

        Write-Info "Authentication successful!"
        Write-Host "API Response: $($response | ConvertTo-Json -Compress)"
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            401 { Write-Error "Authentication failed - token invalid or expired" }
            403 { Write-Error "Authorization failed - insufficient permissions" }
            default { Write-Error "Unexpected response: HTTP $statusCode" }
        }
    }
}

function Clear-TokenCache {
    if (Test-Path $TokenCache) {
        Remove-Item $TokenCache -Force
        Write-Info "Token cache cleared"
    }
    else {
        Write-Info "No cached token found"
    }
}

# Main execution
switch ($Command) {
    "token" {
        # Output only the token (no info messages to stdout)
        $token = Get-Token
        Write-Output $token
    }
    "refresh" {
        Remove-Item $TokenCache -Force -ErrorAction SilentlyContinue
        $token = Request-NewToken
        Write-Output $token
    }
    "test" {
        Test-Token
    }
    "clear" {
        Clear-TokenCache
    }
    "" {
        Write-Error "No command specified"
        Show-Usage
        exit 1
    }
    default {
        Write-Error "Unknown command: $Command"
        Show-Usage
        exit 1
    }
}
