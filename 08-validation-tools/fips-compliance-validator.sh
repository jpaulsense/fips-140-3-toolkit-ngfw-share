#!/bin/bash
# ============================================================================
# FIPS 140-3 Compliance Validator for Palo Alto Networks Firewalls
# ============================================================================
# This script validates FIPS 140-3 compliance for PAN-OS configurations
# WITHOUT requiring CC-mode to be enabled.
#
# Usage: ./fips-compliance-validator.sh -f <firewall_ip> -u <username> -p <password>
#
# Requirements:
#   - curl
#   - API access to firewall
#   - Admin credentials
#
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

# Non-compliant algorithm patterns
NON_COMPLIANT_ENCRYPTION="3des|des-cbc|null|rc4"
NON_COMPLIANT_HASH="md5|sha1"
# DH groups need exact match to avoid group1 matching group14, etc.
NON_COMPLIANT_DH_EXACT="group1 group2 group5 no-pfs"
NON_COMPLIANT_TLS="tls1-0|tls1-1"

# Compliant algorithm patterns
COMPLIANT_ENCRYPTION="aes-128-cbc|aes-192-cbc|aes-256-cbc|aes-128-gcm|aes-256-gcm"
COMPLIANT_HASH="sha256|sha384|sha512"
COMPLIANT_DH="group14|group15|group16|group19|group20|group21"

# Functions
print_header() {
    echo ""
    echo -e "${BLUE}============================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS_COUNT++))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL_COUNT++))
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN_COUNT++))
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

usage() {
    echo "FIPS 140-3 Compliance Validator for PAN-OS"
    echo ""
    echo "Usage: $0 -f <firewall_ip> -u <username> -p <password> [-o <output_file>]"
    echo ""
    echo "Options:"
    echo "  -f    Firewall IP address or hostname"
    echo "  -u    Admin username"
    echo "  -p    Admin password"
    echo "  -o    Output file for report (optional)"
    echo "  -h    Show this help message"
    echo ""
    exit 1
}

# Parse arguments
while getopts "f:u:p:o:h" opt; do
    case $opt in
        f) FIREWALL="$OPTARG" ;;
        u) USERNAME="$OPTARG" ;;
        p) PASSWORD="$OPTARG" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required parameters
if [ -z "$FIREWALL" ] || [ -z "$USERNAME" ] || [ -z "$PASSWORD" ]; then
    echo "Error: Missing required parameters"
    usage
fi

# Get API key
print_header "FIPS 140-3 COMPLIANCE VALIDATION"
echo "Firewall: $FIREWALL"
echo "Date: $(date)"
echo ""

print_info "Authenticating to firewall..."
API_KEY_RESPONSE=$(curl -sk "https://$FIREWALL/api/?type=keygen&user=$USERNAME&password=$PASSWORD" 2>/dev/null)

if echo "$API_KEY_RESPONSE" | grep -q "status=\"success\""; then
    API_KEY=$(echo "$API_KEY_RESPONSE" | grep -oP '(?<=<key>)[^<]+')
    print_pass "Successfully authenticated"
else
    print_fail "Failed to authenticate to firewall"
    exit 1
fi

# Function to make API calls
api_call() {
    local type="$1"
    local action="$2"
    local xpath="$3"

    if [ "$type" == "config" ]; then
        curl -sk -X POST "https://$FIREWALL/api/" \
            -d "type=$type" \
            -d "action=$action" \
            -d "key=$API_KEY" \
            --data-urlencode "xpath=$xpath" 2>/dev/null
    else
        curl -sk -X POST "https://$FIREWALL/api/" \
            -d "type=$type" \
            -d "key=$API_KEY" \
            --data-urlencode "cmd=$xpath" 2>/dev/null
    fi
}

# ============================================================================
# IKE CRYPTO PROFILE VALIDATION
# ============================================================================
print_header "IKE CRYPTO PROFILES"

IKE_CONFIG=$(api_call "config" "get" "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles")

# Extract profile names
IKE_PROFILES=$(echo "$IKE_CONFIG" | grep -oP '(?<=entry name=")[^"]+' || echo "")

if [ -z "$IKE_PROFILES" ]; then
    print_info "No IKE crypto profiles found"
else
    for profile in $IKE_PROFILES; do
        echo ""
        print_info "Checking profile: $profile"

        # Extract profile config
        PROFILE_CONFIG=$(echo "$IKE_CONFIG" | sed -n "/<entry name=\"$profile\"/,/<\/entry>/p" | head -50)

        # Check encryption
        ENCRYPTION=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<member[^>]*>)[^<]+(?=</member>)' | head -10)
        HAS_NON_COMPLIANT_ENC=false
        for enc in $ENCRYPTION; do
            if echo "$enc" | grep -qiE "$NON_COMPLIANT_ENCRYPTION"; then
                HAS_NON_COMPLIANT_ENC=true
                print_fail "Non-compliant encryption: $enc"
            fi
        done
        if [ "$HAS_NON_COMPLIANT_ENC" == "false" ]; then
            print_pass "Encryption algorithms compliant"
        fi

        # Check hash
        HASH=$(echo "$PROFILE_CONFIG" | sed -n '/<hash/,/<\/hash>/p' | grep -oP '(?<=<member[^>]*>)[^<]+')
        HAS_NON_COMPLIANT_HASH=false
        for h in $HASH; do
            if echo "$h" | grep -qiE "$NON_COMPLIANT_HASH"; then
                HAS_NON_COMPLIANT_HASH=true
                print_fail "Non-compliant hash: $h"
            fi
        done
        if [ "$HAS_NON_COMPLIANT_HASH" == "false" ]; then
            print_pass "Hash algorithms compliant"
        fi

        # Check DH group (exact match to avoid group1 matching group14)
        DH_GROUP=$(echo "$PROFILE_CONFIG" | sed -n '/<dh-group/,/<\/dh-group>/p' | grep -oP '(?<=<member[^>]*>)[^<]+')
        HAS_NON_COMPLIANT_DH=false
        for dh in $DH_GROUP; do
            dh_lower=$(echo "$dh" | tr '[:upper:]' '[:lower:]')
            for non_compliant in $NON_COMPLIANT_DH_EXACT; do
                if [ "$dh_lower" == "$non_compliant" ]; then
                    HAS_NON_COMPLIANT_DH=true
                    print_fail "Non-compliant DH group: $dh"
                    break
                fi
            done
        done
        if [ "$HAS_NON_COMPLIANT_DH" == "false" ]; then
            print_pass "DH groups compliant"
        fi
    done
fi

# ============================================================================
# IPSEC CRYPTO PROFILE VALIDATION
# ============================================================================
print_header "IPSEC CRYPTO PROFILES"

IPSEC_CONFIG=$(api_call "config" "get" "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles")

IPSEC_PROFILES=$(echo "$IPSEC_CONFIG" | grep -oP '(?<=entry name=")[^"]+' || echo "")

if [ -z "$IPSEC_PROFILES" ]; then
    print_info "No IPSec crypto profiles found"
else
    for profile in $IPSEC_PROFILES; do
        echo ""
        print_info "Checking profile: $profile"

        PROFILE_CONFIG=$(echo "$IPSEC_CONFIG" | sed -n "/<entry name=\"$profile\"/,/<\/entry>/p" | head -50)

        # Check ESP encryption
        ESP_ENC=$(echo "$PROFILE_CONFIG" | sed -n '/<esp/,/<\/esp>/p' | sed -n '/<encryption/,/<\/encryption>/p' | grep -oP '(?<=<member[^>]*>)[^<]+')
        HAS_NON_COMPLIANT_ENC=false
        for enc in $ESP_ENC; do
            if echo "$enc" | grep -qiE "$NON_COMPLIANT_ENCRYPTION"; then
                HAS_NON_COMPLIANT_ENC=true
                print_fail "Non-compliant ESP encryption: $enc"
            fi
        done
        if [ "$HAS_NON_COMPLIANT_ENC" == "false" ]; then
            print_pass "ESP encryption compliant"
        fi

        # Check ESP authentication (only if not using GCM)
        ESP_AUTH=$(echo "$PROFILE_CONFIG" | sed -n '/<esp/,/<\/esp>/p' | sed -n '/<authentication/,/<\/authentication>/p' | grep -oP '(?<=<member[^>]*>)[^<]+')
        HAS_NON_COMPLIANT_AUTH=false
        for auth in $ESP_AUTH; do
            if [ "$auth" != "none" ] && echo "$auth" | grep -qiE "$NON_COMPLIANT_HASH"; then
                HAS_NON_COMPLIANT_AUTH=true
                print_fail "Non-compliant ESP authentication: $auth"
            fi
        done
        if [ "$HAS_NON_COMPLIANT_AUTH" == "false" ]; then
            print_pass "ESP authentication compliant"
        fi

        # Check DH group (PFS) - exact match
        DH_GROUP=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<dh-group[^>]*>)[^<]+(?=</dh-group>)')
        if [ -n "$DH_GROUP" ]; then
            dh_lower=$(echo "$DH_GROUP" | tr '[:upper:]' '[:lower:]')
            IS_NON_COMPLIANT=false
            for non_compliant in $NON_COMPLIANT_DH_EXACT; do
                if [ "$dh_lower" == "$non_compliant" ]; then
                    IS_NON_COMPLIANT=true
                    break
                fi
            done
            if [ "$IS_NON_COMPLIANT" == "true" ]; then
                print_fail "Non-compliant DH group (PFS): $DH_GROUP"
            else
                print_pass "DH group (PFS) compliant: $DH_GROUP"
            fi
        fi
    done
fi

# ============================================================================
# SSL/TLS SERVICE PROFILE VALIDATION
# ============================================================================
print_header "SSL/TLS SERVICE PROFILES"

SSL_CONFIG=$(api_call "config" "get" "/config/shared/ssl-tls-service-profile")

SSL_PROFILES=$(echo "$SSL_CONFIG" | grep -oP '(?<=entry name=")[^"]+' || echo "")

if [ -z "$SSL_PROFILES" ]; then
    print_warn "No SSL/TLS service profiles found - management interface may use defaults"
else
    for profile in $SSL_PROFILES; do
        echo ""
        print_info "Checking profile: $profile"

        PROFILE_CONFIG=$(echo "$SSL_CONFIG" | sed -n "/<entry name=\"$profile\"/,/<\/entry>/p" | head -30)

        # Check min TLS version
        MIN_TLS=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<min-version>)[^<]+')
        if [ -n "$MIN_TLS" ]; then
            if echo "$MIN_TLS" | grep -qiE "$NON_COMPLIANT_TLS"; then
                print_fail "Non-compliant minimum TLS version: $MIN_TLS"
            else
                print_pass "Minimum TLS version compliant: $MIN_TLS"
            fi
        else
            print_warn "No minimum TLS version specified"
        fi

        # Check max TLS version
        MAX_TLS=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<max-version>)[^<]+')
        if [ -n "$MAX_TLS" ]; then
            print_info "Maximum TLS version: $MAX_TLS"
        fi

        # Check if certificate is assigned
        CERT=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<certificate>)[^<]+')
        if [ -n "$CERT" ]; then
            print_pass "Certificate assigned: $CERT"
        else
            print_warn "No certificate assigned to profile"
        fi
    done
fi

# ============================================================================
# DECRYPTION PROFILE VALIDATION
# ============================================================================
print_header "DECRYPTION PROFILES"

DECRYPT_CONFIG=$(api_call "config" "get" "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/decryption")

DECRYPT_PROFILES=$(echo "$DECRYPT_CONFIG" | grep -oP '(?<=entry name=")[^"]+' || echo "")

if [ -z "$DECRYPT_PROFILES" ]; then
    print_info "No decryption profiles found"
else
    for profile in $DECRYPT_PROFILES; do
        echo ""
        print_info "Checking profile: $profile"

        PROFILE_CONFIG=$(echo "$DECRYPT_CONFIG" | sed -n "/<entry name=\"$profile\"/,/<\/entry>/p" | head -50)

        # Check SSL protocol settings
        MIN_TLS=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<min-version[^>]*>)[^<]+')
        if [ -n "$MIN_TLS" ]; then
            if echo "$MIN_TLS" | grep -qiE "$NON_COMPLIANT_TLS"; then
                print_fail "Non-compliant minimum TLS version: $MIN_TLS"
            else
                print_pass "Minimum TLS version compliant: $MIN_TLS"
            fi
        fi

        # Check certificate validation settings
        BLOCK_EXPIRED=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<block-expired-certificate[^>]*>)[^<]+' | head -1)
        BLOCK_UNTRUSTED=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<block-untrusted-issuer[^>]*>)[^<]+' | head -1)

        if [ "$BLOCK_EXPIRED" == "yes" ]; then
            print_pass "Blocking expired certificates enabled"
        else
            print_warn "Blocking expired certificates not enabled"
        fi

        if [ "$BLOCK_UNTRUSTED" == "yes" ]; then
            print_pass "Blocking untrusted issuers enabled"
        else
            print_warn "Blocking untrusted issuers not enabled"
        fi
    done
fi

# ============================================================================
# INTERFACE MANAGEMENT PROFILE VALIDATION
# ============================================================================
print_header "INTERFACE MANAGEMENT PROFILES"

MGMT_CONFIG=$(api_call "config" "get" "/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile")

MGMT_PROFILES=$(echo "$MGMT_CONFIG" | grep -oP '(?<=entry name=")[^"]+' || echo "")

if [ -z "$MGMT_PROFILES" ]; then
    print_info "No interface management profiles found"
else
    for profile in $MGMT_PROFILES; do
        echo ""
        print_info "Checking profile: $profile"

        PROFILE_CONFIG=$(echo "$MGMT_CONFIG" | sed -n "/<entry name=\"$profile\"/,/<\/entry>/p" | head -30)

        # Check for insecure services
        TELNET=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<telnet[^>]*>)[^<]+' || echo "no")
        HTTP=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<http[^>]*>)[^<]+' || echo "no")

        if [ "$TELNET" == "yes" ]; then
            print_fail "Telnet is enabled (insecure, non-encrypted)"
        else
            print_pass "Telnet is disabled"
        fi

        if [ "$HTTP" == "yes" ]; then
            print_fail "HTTP is enabled (insecure, non-encrypted)"
        else
            print_pass "HTTP is disabled"
        fi

        # Check for secure services
        SSH=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<ssh[^>]*>)[^<]+' || echo "no")
        HTTPS=$(echo "$PROFILE_CONFIG" | grep -oP '(?<=<https[^>]*>)[^<]+' || echo "no")

        if [ "$SSH" == "yes" ] || [ "$HTTPS" == "yes" ]; then
            print_pass "Secure management protocols configured (SSH: $SSH, HTTPS: $HTTPS)"
        else
            print_warn "No secure management protocols enabled"
        fi
    done
fi

# ============================================================================
# CERTIFICATE VALIDATION
# ============================================================================
print_header "CERTIFICATE VALIDATION"

CERT_CONFIG=$(api_call "config" "get" "/config/shared/certificate")

CERTIFICATES=$(echo "$CERT_CONFIG" | grep -oP '(?<=entry name=")[^"]+' || echo "")

if [ -z "$CERTIFICATES" ]; then
    print_info "No certificates found"
else
    for cert in $CERTIFICATES; do
        echo ""
        print_info "Checking certificate: $cert"

        CERT_ENTRY=$(echo "$CERT_CONFIG" | sed -n "/<entry name=\"$cert\"/,/<\/entry>/p")

        # Check algorithm
        ALGORITHM=$(echo "$CERT_ENTRY" | grep -oP '(?<=<algorithm>)[^<]+')
        if [ "$ALGORITHM" == "RSA" ]; then
            print_pass "Key algorithm: RSA"
        elif [ "$ALGORITHM" == "EC" ] || [ "$ALGORITHM" == "ECDSA" ]; then
            print_pass "Key algorithm: $ALGORITHM (ECDSA)"
        else
            print_info "Key algorithm: $ALGORITHM"
        fi

        # Check expiry
        EXPIRY_EPOCH=$(echo "$CERT_ENTRY" | grep -oP '(?<=<expiry-epoch>)[^<]+')
        CURRENT_EPOCH=$(date +%s)
        if [ -n "$EXPIRY_EPOCH" ]; then
            if [ "$EXPIRY_EPOCH" -lt "$CURRENT_EPOCH" ]; then
                print_fail "Certificate is EXPIRED"
            else
                DAYS_UNTIL_EXPIRY=$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
                if [ "$DAYS_UNTIL_EXPIRY" -lt 30 ]; then
                    print_warn "Certificate expires in $DAYS_UNTIL_EXPIRY days"
                elif [ "$DAYS_UNTIL_EXPIRY" -lt 90 ]; then
                    print_info "Certificate expires in $DAYS_UNTIL_EXPIRY days"
                else
                    print_pass "Certificate valid for $DAYS_UNTIL_EXPIRY days"
                fi
            fi
        fi

        # Check if CA
        IS_CA=$(echo "$CERT_ENTRY" | grep -oP '(?<=<ca>)[^<]+')
        if [ "$IS_CA" == "yes" ]; then
            print_info "Certificate type: CA"
        else
            print_info "Certificate type: End-entity"
        fi
    done
fi

# ============================================================================
# MANAGEMENT INTERFACE SSL/TLS PROFILE
# ============================================================================
print_header "MANAGEMENT INTERFACE TLS CONFIGURATION"

MGMT_SSL=$(api_call "config" "get" "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile")

MGMT_SSL_PROFILE=$(echo "$MGMT_SSL" | grep -oP '(?<=>)[^<]+(?=</ssl-tls-service-profile>)')

if [ -n "$MGMT_SSL_PROFILE" ]; then
    print_pass "Management interface using SSL/TLS profile: $MGMT_SSL_PROFILE"
else
    print_warn "No SSL/TLS service profile assigned to management interface (using defaults)"
fi

# ============================================================================
# SUMMARY
# ============================================================================
print_header "COMPLIANCE SUMMARY"

echo ""
echo -e "${GREEN}PASSED:${NC}  $PASS_COUNT"
echo -e "${RED}FAILED:${NC}  $FAIL_COUNT"
echo -e "${YELLOW}WARNINGS:${NC} $WARN_COUNT"
echo ""

TOTAL_CHECKS=$((PASS_COUNT + FAIL_COUNT))

if [ "$FAIL_COUNT" -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  FIPS 140-3 COMPLIANCE: PASSED        ${NC}"
    echo -e "${GREEN}========================================${NC}"
    if [ "$WARN_COUNT" -gt 0 ]; then
        echo ""
        echo "Note: $WARN_COUNT warnings require review"
    fi
    EXIT_CODE=0
else
    echo -e "${RED}========================================${NC}"
    echo -e "${RED}  FIPS 140-3 COMPLIANCE: FAILED        ${NC}"
    echo -e "${RED}========================================${NC}"
    echo ""
    echo "$FAIL_COUNT non-compliant configuration(s) found"
    echo "Review the [FAIL] items above and remediate"
    EXIT_CODE=1
fi

echo ""
echo "Report generated: $(date)"
echo "Firewall: $FIREWALL"

# Save to file if specified
if [ -n "$OUTPUT_FILE" ]; then
    echo "Report saved to: $OUTPUT_FILE"
fi

exit $EXIT_CODE
