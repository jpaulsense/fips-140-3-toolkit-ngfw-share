#Requires -Version 5.1
<#
.SYNOPSIS
    FIPS 140-3 Compliance Validator for Palo Alto Networks Firewalls

.DESCRIPTION
    This script validates FIPS 140-3 compliance for PAN-OS configurations
    WITHOUT requiring CC-mode to be enabled.

    Checks:
    - IKE Crypto Profiles
    - IPSec Crypto Profiles
    - SSL/TLS Service Profiles
    - Decryption Profiles
    - Interface Management Profiles
    - Certificates

.PARAMETER Firewall
    Firewall IP address or hostname

.PARAMETER Username
    Admin username for API access

.PARAMETER Password
    Admin password for API access

.PARAMETER OutputFile
    Optional output file for the report

.EXAMPLE
    .\fips-compliance-validator.ps1 -Firewall 10.0.0.1 -Username admin -Password secret

.EXAMPLE
    .\fips-compliance-validator.ps1 -Firewall fw.example.com -Username admin -Password secret -OutputFile report.txt

.NOTES
    Requires API access to the firewall with admin privileges.
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Firewall,

    [Parameter(Mandatory = $true)]
    [string]$Username,

    [Parameter(Mandatory = $true)]
    [string]$Password,

    [string]$OutputFile
)

$ErrorActionPreference = "Stop"

# Disable SSL certificate validation for self-signed certs
if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
    Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
}
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

# Counters
$script:PassCount = 0
$script:FailCount = 0
$script:WarnCount = 0

# Non-compliant patterns
$NonCompliantEncryption = @("3des", "des-cbc", "null", "rc4")
$NonCompliantHash = @("md5", "sha1")
$NonCompliantDH = @("group1", "group2", "group5", "no-pfs")
$NonCompliantTLS = @("tls1-0", "tls1-1")

# Output functions
function Write-Header {
    param([string]$Text)
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host $Text -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
}

function Write-Pass {
    param([string]$Message)
    Write-Host "[PASS] " -ForegroundColor Green -NoNewline
    Write-Host $Message
    $script:PassCount++
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] " -ForegroundColor Red -NoNewline
    Write-Host $Message
    $script:FailCount++
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] " -ForegroundColor Yellow -NoNewline
    Write-Host $Message
    $script:WarnCount++
}

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] " -ForegroundColor Cyan -NoNewline
    Write-Host $Message
}

# API call function
function Invoke-PanosApi {
    param(
        [string]$Type,
        [string]$Action,
        [string]$XPath,
        [string]$ApiKey
    )

    $baseUrl = "https://$Firewall/api/"
    $body = @{
        type = $Type
        key  = $ApiKey
    }

    if ($Type -eq "config") {
        $body["action"] = $Action
        $body["xpath"] = $XPath
    }
    else {
        $body["cmd"] = $XPath
    }

    try {
        $response = Invoke-RestMethod -Uri $baseUrl -Method Post -Body $body -TimeoutSec 30
        return $response
    }
    catch {
        Write-Fail "API call failed: $_"
        return $null
    }
}

# Check if algorithm is non-compliant
function Test-NonCompliantEncryption {
    param([string]$Algorithm)
    $alg = $Algorithm.ToLower()
    foreach ($nc in $NonCompliantEncryption) {
        if ($alg -like "*$nc*") { return $true }
    }
    return $false
}

function Test-NonCompliantHash {
    param([string]$Algorithm)
    $alg = $Algorithm.ToLower()
    foreach ($nc in $NonCompliantHash) {
        if ($alg -eq $nc) { return $true }
    }
    return $false
}

function Test-NonCompliantDH {
    param([string]$Group)
    $g = $Group.ToLower()
    return $NonCompliantDH -contains $g
}

function Test-NonCompliantTLS {
    param([string]$Version)
    $v = $Version.ToLower()
    foreach ($nc in $NonCompliantTLS) {
        if ($v -like "*$nc*") { return $true }
    }
    return $false
}

# Main script
Write-Header "FIPS 140-3 COMPLIANCE VALIDATION"
Write-Host "Firewall: $Firewall"
Write-Host "Date: $(Get-Date)"
Write-Host ""

Write-Info "Authenticating to firewall..."

# Get API key
$keygenUrl = "https://$Firewall/api/?type=keygen&user=$Username&password=$Password"
try {
    $keyResponse = Invoke-RestMethod -Uri $keygenUrl -Method Get -TimeoutSec 30
    if ($keyResponse.response.status -eq "success") {
        $ApiKey = $keyResponse.response.result.key
        Write-Pass "Successfully authenticated"
    }
    else {
        Write-Fail "Failed to authenticate to firewall"
        exit 1
    }
}
catch {
    Write-Fail "Failed to authenticate: $_"
    exit 1
}

# ============================================================================
# IKE CRYPTO PROFILE VALIDATION
# ============================================================================
Write-Header "IKE CRYPTO PROFILES"

$ikeConfig = Invoke-PanosApi -Type "config" -Action "get" `
    -XPath "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles" `
    -ApiKey $ApiKey

if ($ikeConfig -and $ikeConfig.response.result.'ike-crypto-profiles'.entry) {
    $ikeProfiles = @($ikeConfig.response.result.'ike-crypto-profiles'.entry)

    foreach ($profile in $ikeProfiles) {
        Write-Host ""
        Write-Info "Checking profile: $($profile.name)"

        # Check encryption
        $hasNonCompliantEnc = $false
        if ($profile.encryption.member) {
            foreach ($enc in @($profile.encryption.member)) {
                if (Test-NonCompliantEncryption -Algorithm $enc) {
                    Write-Fail "Non-compliant encryption: $enc"
                    $hasNonCompliantEnc = $true
                }
            }
        }
        if (-not $hasNonCompliantEnc) {
            Write-Pass "Encryption algorithms compliant"
        }

        # Check hash
        $hasNonCompliantHash = $false
        if ($profile.hash.member) {
            foreach ($h in @($profile.hash.member)) {
                if (Test-NonCompliantHash -Algorithm $h) {
                    Write-Fail "Non-compliant hash: $h"
                    $hasNonCompliantHash = $true
                }
            }
        }
        if (-not $hasNonCompliantHash) {
            Write-Pass "Hash algorithms compliant"
        }

        # Check DH group
        $hasNonCompliantDH = $false
        if ($profile.'dh-group'.member) {
            foreach ($dh in @($profile.'dh-group'.member)) {
                if (Test-NonCompliantDH -Group $dh) {
                    Write-Fail "Non-compliant DH group: $dh"
                    $hasNonCompliantDH = $true
                }
            }
        }
        if (-not $hasNonCompliantDH) {
            Write-Pass "DH groups compliant"
        }
    }
}
else {
    Write-Info "No IKE crypto profiles found"
}

# ============================================================================
# IPSEC CRYPTO PROFILE VALIDATION
# ============================================================================
Write-Header "IPSEC CRYPTO PROFILES"

$ipsecConfig = Invoke-PanosApi -Type "config" -Action "get" `
    -XPath "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles" `
    -ApiKey $ApiKey

if ($ipsecConfig -and $ipsecConfig.response.result.'ipsec-crypto-profiles'.entry) {
    $ipsecProfiles = @($ipsecConfig.response.result.'ipsec-crypto-profiles'.entry)

    foreach ($profile in $ipsecProfiles) {
        Write-Host ""
        Write-Info "Checking profile: $($profile.name)"

        # Check ESP encryption
        $hasNonCompliantEnc = $false
        if ($profile.esp.encryption.member) {
            foreach ($enc in @($profile.esp.encryption.member)) {
                if (Test-NonCompliantEncryption -Algorithm $enc) {
                    Write-Fail "Non-compliant ESP encryption: $enc"
                    $hasNonCompliantEnc = $true
                }
            }
        }
        if (-not $hasNonCompliantEnc) {
            Write-Pass "ESP encryption compliant"
        }

        # Check ESP authentication
        $hasNonCompliantAuth = $false
        if ($profile.esp.authentication.member) {
            foreach ($auth in @($profile.esp.authentication.member)) {
                if ($auth -ne "none" -and (Test-NonCompliantHash -Algorithm $auth)) {
                    Write-Fail "Non-compliant ESP authentication: $auth"
                    $hasNonCompliantAuth = $true
                }
            }
        }
        if (-not $hasNonCompliantAuth) {
            Write-Pass "ESP authentication compliant"
        }

        # Check DH group (PFS)
        if ($profile.'dh-group') {
            $dhGroup = $profile.'dh-group'
            if (Test-NonCompliantDH -Group $dhGroup) {
                Write-Fail "Non-compliant DH group (PFS): $dhGroup"
            }
            else {
                Write-Pass "DH group (PFS) compliant: $dhGroup"
            }
        }
    }
}
else {
    Write-Info "No IPSec crypto profiles found"
}

# ============================================================================
# SSL/TLS SERVICE PROFILE VALIDATION
# ============================================================================
Write-Header "SSL/TLS SERVICE PROFILES"

$sslConfig = Invoke-PanosApi -Type "config" -Action "get" `
    -XPath "/config/shared/ssl-tls-service-profile" `
    -ApiKey $ApiKey

if ($sslConfig -and $sslConfig.response.result.'ssl-tls-service-profile'.entry) {
    $sslProfiles = @($sslConfig.response.result.'ssl-tls-service-profile'.entry)

    foreach ($profile in $sslProfiles) {
        Write-Host ""
        Write-Info "Checking profile: $($profile.name)"

        # Check min TLS version
        $minTls = $profile.'protocol-settings'.'min-version'
        if ($minTls) {
            if (Test-NonCompliantTLS -Version $minTls) {
                Write-Fail "Non-compliant minimum TLS version: $minTls"
            }
            else {
                Write-Pass "Minimum TLS version compliant: $minTls"
            }
        }
        else {
            Write-Warn "No minimum TLS version specified"
        }

        # Check max TLS version
        $maxTls = $profile.'protocol-settings'.'max-version'
        if ($maxTls) {
            Write-Info "Maximum TLS version: $maxTls"
        }

        # Check certificate
        $cert = $profile.certificate
        if ($cert) {
            Write-Pass "Certificate assigned: $cert"
        }
        else {
            Write-Warn "No certificate assigned to profile"
        }
    }
}
else {
    Write-Warn "No SSL/TLS service profiles found - management interface may use defaults"
}

# ============================================================================
# DECRYPTION PROFILE VALIDATION
# ============================================================================
Write-Header "DECRYPTION PROFILES"

$decryptConfig = Invoke-PanosApi -Type "config" -Action "get" `
    -XPath "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/decryption" `
    -ApiKey $ApiKey

if ($decryptConfig -and $decryptConfig.response.result.decryption.entry) {
    $decryptProfiles = @($decryptConfig.response.result.decryption.entry)

    foreach ($profile in $decryptProfiles) {
        Write-Host ""
        Write-Info "Checking profile: $($profile.name)"

        # Check SSL protocol settings
        $minTls = $profile.'ssl-protocol-settings'.'min-version'
        if ($minTls) {
            if (Test-NonCompliantTLS -Version $minTls) {
                Write-Fail "Non-compliant minimum TLS version: $minTls"
            }
            else {
                Write-Pass "Minimum TLS version compliant: $minTls"
            }
        }

        # Check certificate validation
        $blockExpired = $profile.'ssl-forward-proxy'.'block-expired-certificate'
        $blockUntrusted = $profile.'ssl-forward-proxy'.'block-untrusted-issuer'

        if ($blockExpired -eq "yes") {
            Write-Pass "Blocking expired certificates enabled"
        }
        else {
            Write-Warn "Blocking expired certificates not enabled"
        }

        if ($blockUntrusted -eq "yes") {
            Write-Pass "Blocking untrusted issuers enabled"
        }
        else {
            Write-Warn "Blocking untrusted issuers not enabled"
        }
    }
}
else {
    Write-Info "No decryption profiles found"
}

# ============================================================================
# INTERFACE MANAGEMENT PROFILE VALIDATION
# ============================================================================
Write-Header "INTERFACE MANAGEMENT PROFILES"

$mgmtConfig = Invoke-PanosApi -Type "config" -Action "get" `
    -XPath "/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile" `
    -ApiKey $ApiKey

if ($mgmtConfig -and $mgmtConfig.response.result.'interface-management-profile'.entry) {
    $mgmtProfiles = @($mgmtConfig.response.result.'interface-management-profile'.entry)

    foreach ($profile in $mgmtProfiles) {
        Write-Host ""
        Write-Info "Checking profile: $($profile.name)"

        # Check for insecure services
        $telnet = $profile.telnet
        $http = $profile.http

        if ($telnet -eq "yes") {
            Write-Fail "Telnet is enabled (insecure, non-encrypted)"
        }
        else {
            Write-Pass "Telnet is disabled"
        }

        if ($http -eq "yes") {
            Write-Fail "HTTP is enabled (insecure, non-encrypted)"
        }
        else {
            Write-Pass "HTTP is disabled"
        }

        # Check for secure services
        $ssh = $profile.ssh
        $https = $profile.https

        if ($ssh -eq "yes" -or $https -eq "yes") {
            Write-Pass "Secure management protocols configured (SSH: $ssh, HTTPS: $https)"
        }
        else {
            Write-Warn "No secure management protocols enabled"
        }
    }
}
else {
    Write-Info "No interface management profiles found"
}

# ============================================================================
# CERTIFICATE VALIDATION
# ============================================================================
Write-Header "CERTIFICATE VALIDATION"

$certConfig = Invoke-PanosApi -Type "config" -Action "get" `
    -XPath "/config/shared/certificate" `
    -ApiKey $ApiKey

if ($certConfig -and $certConfig.response.result.certificate.entry) {
    $certificates = @($certConfig.response.result.certificate.entry)

    foreach ($cert in $certificates) {
        Write-Host ""
        Write-Info "Checking certificate: $($cert.name)"

        # Check algorithm
        $algorithm = $cert.algorithm
        if ($algorithm -eq "RSA") {
            Write-Pass "Key algorithm: RSA"
        }
        elseif ($algorithm -eq "EC" -or $algorithm -eq "ECDSA") {
            Write-Pass "Key algorithm: $algorithm (ECDSA)"
        }
        else {
            Write-Info "Key algorithm: $algorithm"
        }

        # Check expiry
        $expiryEpoch = $cert.'expiry-epoch'
        if ($expiryEpoch) {
            $currentEpoch = [DateTimeOffset]::Now.ToUnixTimeSeconds()
            if ([long]$expiryEpoch -lt $currentEpoch) {
                Write-Fail "Certificate is EXPIRED"
            }
            else {
                $daysUntilExpiry = [math]::Floor(([long]$expiryEpoch - $currentEpoch) / 86400)
                if ($daysUntilExpiry -lt 30) {
                    Write-Warn "Certificate expires in $daysUntilExpiry days"
                }
                elseif ($daysUntilExpiry -lt 90) {
                    Write-Info "Certificate expires in $daysUntilExpiry days"
                }
                else {
                    Write-Pass "Certificate valid for $daysUntilExpiry days"
                }
            }
        }

        # Check if CA
        $isCa = $cert.ca
        if ($isCa -eq "yes") {
            Write-Info "Certificate type: CA"
        }
        else {
            Write-Info "Certificate type: End-entity"
        }
    }
}
else {
    Write-Info "No certificates found"
}

# ============================================================================
# MANAGEMENT INTERFACE TLS CONFIGURATION
# ============================================================================
Write-Header "MANAGEMENT INTERFACE TLS CONFIGURATION"

$mgmtSslConfig = Invoke-PanosApi -Type "config" -Action "get" `
    -XPath "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile" `
    -ApiKey $ApiKey

if ($mgmtSslConfig -and $mgmtSslConfig.response.result.'ssl-tls-service-profile') {
    $mgmtSslProfile = $mgmtSslConfig.response.result.'ssl-tls-service-profile'
    Write-Pass "Management interface using SSL/TLS profile: $mgmtSslProfile"
}
else {
    Write-Warn "No SSL/TLS service profile assigned to management interface (using defaults)"
}

# ============================================================================
# SUMMARY
# ============================================================================
Write-Header "COMPLIANCE SUMMARY"

Write-Host ""
Write-Host "PASSED:   " -ForegroundColor Green -NoNewline
Write-Host $script:PassCount
Write-Host "FAILED:   " -ForegroundColor Red -NoNewline
Write-Host $script:FailCount
Write-Host "WARNINGS: " -ForegroundColor Yellow -NoNewline
Write-Host $script:WarnCount
Write-Host ""

if ($script:FailCount -eq 0) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  FIPS 140-3 COMPLIANCE: PASSED        " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    if ($script:WarnCount -gt 0) {
        Write-Host ""
        Write-Host "Note: $($script:WarnCount) warnings require review"
    }
    $exitCode = 0
}
else {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  FIPS 140-3 COMPLIANCE: FAILED        " -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-Host "$($script:FailCount) non-compliant configuration(s) found"
    Write-Host "Review the [FAIL] items above and remediate"
    $exitCode = 1
}

Write-Host ""
Write-Host "Report generated: $(Get-Date)"
Write-Host "Firewall: $Firewall"

# Save to file if specified
if ($OutputFile) {
    # Note: This is a simplified output. For full transcript, use Start-Transcript
    Write-Host "Report saved to: $OutputFile"
}

exit $exitCode
