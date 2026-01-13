#Requires -Version 5.1
<#
.SYNOPSIS
    Deploy FIPS 140-3 Compliant Profiles to Strata Cloud Manager

.DESCRIPTION
    Creates FIPS 140-3 compliant crypto profiles in SCM:
    - IKE Crypto Profiles (max, recommended, compat)
    - IPSec Crypto Profiles (max, recommended, compat, gp)
    - TLS Service Profiles (requires certificate)
    - Interface Management Profiles

.PARAMETER Certificate
    Certificate name for TLS profiles (required for TLS profile creation)

.PARAMETER Folder
    SCM folder to deploy profiles to (default: Shared)

.EXAMPLE
    # Set environment variables first
    $env:SCM_CLIENT_ID = "your-client-id"
    $env:SCM_CLIENT_SECRET = "your-client-secret"
    $env:SCM_TSG_ID = "1234567890"

    # Deploy without TLS profiles
    .\deploy-fips-profiles.ps1

    # Deploy with TLS profiles
    .\deploy-fips-profiles.ps1 -Certificate "Forward-Trust-CA"

.NOTES
    Requires SCM credentials set via environment variables:
    - SCM_CLIENT_ID
    - SCM_CLIENT_SECRET
    - SCM_TSG_ID
#>

param(
    [string]$Certificate = "",
    [string]$Folder = "Shared"
)

$ErrorActionPreference = "Stop"

# Configuration
$ClientId = $env:SCM_CLIENT_ID
$ClientSecret = $env:SCM_CLIENT_SECRET
$TsgId = $env:SCM_TSG_ID

$AuthUrl = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
$ApiUrl = "https://api.strata.paloaltonetworks.com"

# Output functions
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Write-Status {
    param(
        [string]$Status,
        [string]$Message
    )
    switch ($Status) {
        "CREATED" { Write-Host "  [CREATED] " -ForegroundColor Green -NoNewline; Write-Host $Message }
        "EXISTS" { Write-Host "  [EXISTS] " -ForegroundColor Yellow -NoNewline; Write-Host $Message }
        "ERROR" { Write-Host "  [ERROR] " -ForegroundColor Red -NoNewline; Write-Host $Message }
        "INFO" { Write-Host "  [INFO] " -ForegroundColor Cyan -NoNewline; Write-Host $Message }
    }
}

# Validate credentials
if (-not $ClientId -or -not $ClientSecret -or -not $TsgId) {
    Write-Host "ERROR: Missing credentials" -ForegroundColor Red
    Write-Host "Set SCM_CLIENT_ID, SCM_CLIENT_SECRET, and SCM_TSG_ID environment variables"
    exit 1
}

Write-Header "FIPS 140-3 PROFILE DEPLOYMENT"
Write-Host "Folder: $Folder"
Write-Host "Certificate: $(if ($Certificate) { $Certificate } else { 'Not specified' })"

# Get access token
Write-Host ""
Write-Host "[AUTHENTICATION]" -ForegroundColor Cyan

$body = "grant_type=client_credentials&scope=tsg_id:$TsgId"
$authBytes = [System.Text.Encoding]::UTF8.GetBytes("${ClientId}:${ClientSecret}")
$authBase64 = [Convert]::ToBase64String($authBytes)

try {
    $tokenResponse = Invoke-RestMethod -Uri $AuthUrl -Method Post `
        -Headers @{
        "Content-Type"  = "application/x-www-form-urlencoded"
        "Authorization" = "Basic $authBase64"
    } `
        -Body $body

    $AccessToken = $tokenResponse.access_token
}
catch {
    Write-Host "ERROR: Failed to get access token" -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

if (-not $AccessToken) {
    Write-Host "ERROR: Failed to get access token" -ForegroundColor Red
    exit 1
}

Write-Status "INFO" "Authentication successful"

# Helper function to create profile
function New-Profile {
    param(
        [string]$Endpoint,
        [hashtable]$Data,
        [string]$Name
    )

    $uri = "${ApiUrl}${Endpoint}?folder=${Folder}"
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    $jsonBody = $Data | ConvertTo-Json -Depth 10

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $headers -Body $jsonBody
        Write-Status "CREATED" $Name
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        switch ($statusCode) {
            409 { Write-Status "EXISTS" $Name }
            default {
                $errorBody = $_.ErrorDetails.Message
                Write-Status "ERROR" "$Name (HTTP $statusCode): $errorBody"
            }
        }
    }
}

# ==================== IKE Crypto Profiles ====================
Write-Host ""
Write-Host "[IKE CRYPTO PROFILES]" -ForegroundColor Cyan

# Maximum Security
New-Profile -Endpoint "/sse/config/v1/ike-crypto-profiles" -Name "fips-ike-crypto-max" -Data @{
    name       = "fips-ike-crypto-max"
    encryption = @("aes-256-gcm")
    hash       = @("sha512")
    dh_group   = @("group20")
    lifetime   = @{ hours = 8 }
}

# Recommended
New-Profile -Endpoint "/sse/config/v1/ike-crypto-profiles" -Name "fips-ike-crypto-recommended" -Data @{
    name       = "fips-ike-crypto-recommended"
    encryption = @("aes-256-cbc", "aes-128-gcm")
    hash       = @("sha384", "sha256")
    dh_group   = @("group20", "group19")
    lifetime   = @{ hours = 8 }
}

# Compatible
New-Profile -Endpoint "/sse/config/v1/ike-crypto-profiles" -Name "fips-ike-crypto-compat" -Data @{
    name       = "fips-ike-crypto-compat"
    encryption = @("aes-256-cbc", "aes-256-gcm", "aes-128-cbc", "aes-128-gcm")
    hash       = @("sha512", "sha384", "sha256")
    dh_group   = @("group20", "group19", "group16", "group14")
    lifetime   = @{ hours = 8 }
}

# ==================== IPSec Crypto Profiles ====================
Write-Host ""
Write-Host "[IPSEC CRYPTO PROFILES]" -ForegroundColor Cyan

# Maximum Security
New-Profile -Endpoint "/sse/config/v1/ipsec-crypto-profiles" -Name "fips-ipsec-crypto-max" -Data @{
    name     = "fips-ipsec-crypto-max"
    esp      = @{
        encryption     = @("aes-256-gcm")
        authentication = @("sha512")
    }
    dh_group = "group20"
    lifetime = @{ hours = 1 }
    lifesize = @{ gb = 100 }
}

# Recommended
New-Profile -Endpoint "/sse/config/v1/ipsec-crypto-profiles" -Name "fips-ipsec-crypto-recommended" -Data @{
    name     = "fips-ipsec-crypto-recommended"
    esp      = @{
        encryption     = @("aes-256-gcm", "aes-128-gcm")
        authentication = @("sha384", "sha256")
    }
    dh_group = "group20"
    lifetime = @{ hours = 1 }
}

# Compatible
New-Profile -Endpoint "/sse/config/v1/ipsec-crypto-profiles" -Name "fips-ipsec-crypto-compat" -Data @{
    name     = "fips-ipsec-crypto-compat"
    esp      = @{
        encryption     = @("aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc")
        authentication = @("sha512", "sha384", "sha256")
    }
    dh_group = "group14"
    lifetime = @{ hours = 1 }
}

# GlobalProtect
New-Profile -Endpoint "/sse/config/v1/ipsec-crypto-profiles" -Name "fips-ipsec-crypto-gp" -Data @{
    name     = "fips-ipsec-crypto-gp"
    esp      = @{
        encryption     = @("aes-256-gcm", "aes-128-gcm")
        authentication = @("sha256")
    }
    dh_group = "group19"
    lifetime = @{ hours = 1 }
}

# ==================== TLS Service Profiles ====================
Write-Host ""
Write-Host "[TLS SERVICE PROFILES]" -ForegroundColor Cyan

if ($Certificate) {
    # Maximum Security
    New-Profile -Endpoint "/sse/config/v1/tls-service-profiles" -Name "fips-ssl-tls-max" -Data @{
        name              = "fips-ssl-tls-max"
        protocol_settings = @{
            min_version = "tls1-2"
            max_version = "tls1-3"
        }
        certificate       = $Certificate
    }

    # Recommended
    New-Profile -Endpoint "/sse/config/v1/tls-service-profiles" -Name "fips-ssl-tls-recommended" -Data @{
        name              = "fips-ssl-tls-recommended"
        protocol_settings = @{
            min_version = "tls1-2"
            max_version = "tls1-3"
        }
        certificate       = $Certificate
    }

    # TLS 1.3 Only
    New-Profile -Endpoint "/sse/config/v1/tls-service-profiles" -Name "fips-ssl-tls-1-3-only" -Data @{
        name              = "fips-ssl-tls-1-3-only"
        protocol_settings = @{
            min_version = "tls1-3"
            max_version = "tls1-3"
        }
        certificate       = $Certificate
    }
}
else {
    Write-Status "INFO" "Skipped - no certificate specified (use -Certificate)"
}

# ==================== Interface Management Profiles ====================
Write-Host ""
Write-Host "[INTERFACE MANAGEMENT PROFILES]" -ForegroundColor Cyan

# Full Management
New-Profile -Endpoint "/sse/config/v1/interface-management-profiles" -Name "fips-mgmt-profile" -Data @{
    name   = "fips-mgmt-profile"
    https  = $true
    ssh    = $true
    http   = $false
    telnet = $false
    ping   = $true
}

# HTTPS Only
New-Profile -Endpoint "/sse/config/v1/interface-management-profiles" -Name "fips-https-only" -Data @{
    name   = "fips-https-only"
    https  = $true
    ssh    = $false
    http   = $false
    telnet = $false
    ping   = $true
}

# ==================== Push Configuration ====================
Write-Host ""
Write-Host "[PUSHING CONFIGURATION]" -ForegroundColor Cyan

$pushUri = "${ApiUrl}/sse/config/v1/config-versions/candidate:push"
$pushHeaders = @{
    "Authorization" = "Bearer $AccessToken"
    "Content-Type"  = "application/json"
}
$pushBody = @{
    folders     = @($Folder)
    description = "FIPS 140-3 compliant profiles deployment"
} | ConvertTo-Json

try {
    $pushResponse = Invoke-RestMethod -Uri $pushUri -Method Post -Headers $pushHeaders -Body $pushBody

    if ($pushResponse.job_id) {
        Write-Status "INFO" "Configuration push initiated (Job ID: $($pushResponse.job_id))"
    }
    else {
        Write-Status "INFO" "Configuration push initiated"
    }
}
catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    $errorBody = $_.ErrorDetails.Message
    Write-Status "ERROR" "Push failed (HTTP $statusCode): $errorBody"
}

Write-Header "DEPLOYMENT COMPLETE"
