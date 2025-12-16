# FIPS 140-3 Compliance Check - API Methods

## Overview

This document provides API-based methods for verifying FIPS 140-3 compliance on Palo Alto Networks firewalls. These methods can be integrated into automation pipelines and compliance monitoring systems.

---

## Prerequisites

### Generate API Key

```bash
# Get API key via API
curl -k -X GET "https://<firewall>/api/?type=keygen&user=<username>&password=<password>"

# Response contains API key
# <response status="success"><result><key>LUFRPT...</key></result></response>
```

### Set Environment Variables

```bash
export FIREWALL_IP="192.168.1.1"
export API_KEY="your-api-key"
```

---

## Individual Component API Checks

### Get IKE Crypto Profiles

```bash
curl -k -X GET "https://$FIREWALL_IP/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=$API_KEY" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
```

### Get IPSec Crypto Profiles

```bash
curl -k -X GET "https://$FIREWALL_IP/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=$API_KEY" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
```

### Get SSL/TLS Service Profiles

```bash
curl -k -X GET "https://$FIREWALL_IP/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=$API_KEY" \
    -d "xpath=/config/shared/ssl-tls-service-profile"
```

### Get Certificate Information

```bash
# Get certificate summary
curl -k -X POST "https://$FIREWALL_IP/api/" \
    -d "type=op" \
    -d "key=$API_KEY" \
    -d "cmd=<show><certificate><summary></summary></certificate></show>"

# Get specific certificate details
curl -k -X POST "https://$FIREWALL_IP/api/" \
    -d "type=op" \
    -d "key=$API_KEY" \
    -d "cmd=<show><certificate><name>cert-name</name></certificate></show>"
```

### Get SSH Host Key Information

```bash
curl -k -X POST "https://$FIREWALL_IP/api/" \
    -d "type=op" \
    -d "key=$API_KEY" \
    -d "cmd=<show><ssh><system><host-key><fingerprint></fingerprint></host-key></system></ssh></show>"
```

### Get Active VPN Tunnels

```bash
# Get IKE SA
curl -k -X POST "https://$FIREWALL_IP/api/" \
    -d "type=op" \
    -d "key=$API_KEY" \
    -d "cmd=<show><vpn><ike-sa></ike-sa></vpn></show>"

# Get IPSec SA
curl -k -X POST "https://$FIREWALL_IP/api/" \
    -d "type=op" \
    -d "key=$API_KEY" \
    -d "cmd=<show><vpn><ipsec-sa></ipsec-sa></vpn></show>"
```

---

## Comprehensive API Audit Script

### Python Compliance Checker

```python
#!/usr/bin/env python3
"""
FIPS 140-3 Compliance Checker for Palo Alto Networks Firewalls
Uses API to retrieve and analyze configuration
"""

import requests
import xml.etree.ElementTree as ET
import json
import sys
from datetime import datetime

# Disable SSL warnings for self-signed certs
requests.packages.urllib3.disable_warnings()

# Configuration
FIREWALL_IP = "192.168.1.1"
API_KEY = "your-api-key"

# Non-compliant algorithm patterns
NON_COMPLIANT = {
    'encryption': ['3des', 'des', 'null', 'rc4'],
    'hash': ['md5', 'sha1'],
    'dh_group': ['group1', 'group2', 'group5', 'no-pfs'],
    'tls_version': ['tls1-0', 'tls1-1']
}

def api_request(params):
    """Make API request to firewall"""
    base_url = f"https://{FIREWALL_IP}/api/"
    params['key'] = API_KEY
    response = requests.get(base_url, params=params, verify=False)
    return ET.fromstring(response.content)

def api_op_request(cmd):
    """Make operational API request"""
    params = {
        'type': 'op',
        'cmd': cmd
    }
    return api_request(params)

def api_config_request(xpath):
    """Make configuration API request"""
    params = {
        'type': 'config',
        'action': 'get',
        'xpath': xpath
    }
    return api_request(params)

def check_ike_crypto_profiles():
    """Check IKE crypto profiles for compliance"""
    print("\n=== IKE Crypto Profiles ===")
    issues = []

    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
    result = api_config_request(xpath)

    for profile in result.findall('.//entry'):
        profile_name = profile.get('name')
        print(f"\nProfile: {profile_name}")

        # Check encryption
        for enc in profile.findall('.//encryption/member'):
            if any(nc in enc.text.lower() for nc in NON_COMPLIANT['encryption']):
                issues.append(f"IKE {profile_name}: Non-compliant encryption '{enc.text}'")
                print(f"  [FAIL] Encryption: {enc.text}")
            else:
                print(f"  [PASS] Encryption: {enc.text}")

        # Check hash
        for hash_alg in profile.findall('.//hash/member'):
            if any(nc in hash_alg.text.lower() for nc in NON_COMPLIANT['hash']):
                issues.append(f"IKE {profile_name}: Non-compliant hash '{hash_alg.text}'")
                print(f"  [FAIL] Hash: {hash_alg.text}")
            else:
                print(f"  [PASS] Hash: {hash_alg.text}")

        # Check DH group
        for dh in profile.findall('.//dh-group/member'):
            if any(nc in dh.text.lower() for nc in NON_COMPLIANT['dh_group']):
                issues.append(f"IKE {profile_name}: Non-compliant DH group '{dh.text}'")
                print(f"  [FAIL] DH Group: {dh.text}")
            else:
                print(f"  [PASS] DH Group: {dh.text}")

    return issues

def check_ipsec_crypto_profiles():
    """Check IPSec crypto profiles for compliance"""
    print("\n=== IPSec Crypto Profiles ===")
    issues = []

    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
    result = api_config_request(xpath)

    for profile in result.findall('.//entry'):
        profile_name = profile.get('name')
        print(f"\nProfile: {profile_name}")

        # Check ESP encryption
        for enc in profile.findall('.//esp/encryption/member'):
            if any(nc in enc.text.lower() for nc in NON_COMPLIANT['encryption']):
                issues.append(f"IPSec {profile_name}: Non-compliant encryption '{enc.text}'")
                print(f"  [FAIL] Encryption: {enc.text}")
            else:
                print(f"  [PASS] Encryption: {enc.text}")

        # Check ESP authentication
        for auth in profile.findall('.//esp/authentication/member'):
            if any(nc in auth.text.lower() for nc in NON_COMPLIANT['hash']):
                issues.append(f"IPSec {profile_name}: Non-compliant authentication '{auth.text}'")
                print(f"  [FAIL] Authentication: {auth.text}")
            else:
                print(f"  [PASS] Authentication: {auth.text}")

        # Check DH group (PFS)
        dh = profile.find('.//dh-group')
        if dh is not None:
            if any(nc in dh.text.lower() for nc in NON_COMPLIANT['dh_group']):
                issues.append(f"IPSec {profile_name}: Non-compliant DH group '{dh.text}'")
                print(f"  [FAIL] PFS Group: {dh.text}")
            else:
                print(f"  [PASS] PFS Group: {dh.text}")

    return issues

def check_ssl_tls_profiles():
    """Check SSL/TLS service profiles for compliance"""
    print("\n=== SSL/TLS Service Profiles ===")
    issues = []

    xpath = "/config/shared/ssl-tls-service-profile"
    result = api_config_request(xpath)

    for profile in result.findall('.//entry'):
        profile_name = profile.get('name')
        print(f"\nProfile: {profile_name}")

        # Check min TLS version
        min_ver = profile.find('.//protocol-settings/min-version')
        if min_ver is not None:
            if any(nc in min_ver.text.lower() for nc in NON_COMPLIANT['tls_version']):
                issues.append(f"SSL/TLS {profile_name}: Non-compliant min version '{min_ver.text}'")
                print(f"  [FAIL] Min TLS Version: {min_ver.text}")
            else:
                print(f"  [PASS] Min TLS Version: {min_ver.text}")

        # Check for disabled weak algorithms
        enc_3des = profile.find('.//protocol-settings/enc-algo-3des')
        if enc_3des is not None and enc_3des.text.lower() == 'yes':
            issues.append(f"SSL/TLS {profile_name}: 3DES enabled")
            print(f"  [FAIL] 3DES: Enabled")
        else:
            print(f"  [PASS] 3DES: Disabled")

        enc_rc4 = profile.find('.//protocol-settings/enc-algo-rc4')
        if enc_rc4 is not None and enc_rc4.text.lower() == 'yes':
            issues.append(f"SSL/TLS {profile_name}: RC4 enabled")
            print(f"  [FAIL] RC4: Enabled")
        else:
            print(f"  [PASS] RC4: Disabled")

        auth_sha1 = profile.find('.//protocol-settings/auth-algo-sha1')
        if auth_sha1 is not None and auth_sha1.text.lower() == 'yes':
            issues.append(f"SSL/TLS {profile_name}: SHA-1 enabled")
            print(f"  [WARN] SHA-1: Enabled")

    return issues

def check_certificates():
    """Check certificates for compliance"""
    print("\n=== Certificates ===")
    issues = []

    result = api_op_request("<show><certificate><summary></summary></certificate></show>")

    for cert in result.findall('.//entry'):
        cert_name = cert.find('cert-name')
        if cert_name is None:
            continue

        cert_name = cert_name.text
        print(f"\nCertificate: {cert_name}")

        # Check key size
        key_size = cert.find('public-key-length')
        if key_size is not None:
            size = int(key_size.text)
            if size < 2048:
                issues.append(f"Certificate {cert_name}: Key size {size} < 2048 bits")
                print(f"  [FAIL] Key Size: {size} bits")
            else:
                print(f"  [PASS] Key Size: {size} bits")

        # Check expiration
        not_after = cert.find('not-valid-after')
        if not_after is not None:
            print(f"  [INFO] Expires: {not_after.text}")

    return issues

def generate_report(all_issues):
    """Generate compliance report"""
    print("\n" + "="*60)
    print("FIPS 140-3 COMPLIANCE REPORT")
    print("="*60)
    print(f"Firewall: {FIREWALL_IP}")
    print(f"Date: {datetime.now().isoformat()}")
    print(f"Total Issues Found: {len(all_issues)}")
    print("="*60)

    if all_issues:
        print("\nNON-COMPLIANT ITEMS:")
        for i, issue in enumerate(all_issues, 1):
            print(f"  {i}. {issue}")
        print("\nSTATUS: NON-COMPLIANT")
    else:
        print("\nNo compliance issues found.")
        print("\nSTATUS: COMPLIANT")

    return len(all_issues) == 0

def main():
    print("Starting FIPS 140-3 Compliance Check...")
    print(f"Target: {FIREWALL_IP}")

    all_issues = []

    try:
        all_issues.extend(check_ike_crypto_profiles())
        all_issues.extend(check_ipsec_crypto_profiles())
        all_issues.extend(check_ssl_tls_profiles())
        all_issues.extend(check_certificates())

        compliant = generate_report(all_issues)

        # Exit with appropriate code
        sys.exit(0 if compliant else 1)

    except Exception as e:
        print(f"\nError during compliance check: {e}")
        sys.exit(2)

if __name__ == "__main__":
    main()
```

---

## Bash API Audit Script

### Comprehensive Bash Script

```bash
#!/bin/bash
#
# FIPS 140-3 Compliance Checker for Palo Alto Networks Firewalls
# Bash/cURL implementation
#

# Configuration
FIREWALL_IP="${1:-192.168.1.1}"
API_KEY="${2:-your-api-key}"
REPORT_FILE="fips_compliance_report_$(date +%Y%m%d_%H%M%S).txt"

# Non-compliant patterns (regex)
NON_COMPLIANT_ENC="3des|des|null|rc4"
NON_COMPLIANT_HASH="md5|sha1"
NON_COMPLIANT_DH="group1|group2|group5|no-pfs"
NON_COMPLIANT_TLS="tls1-0|tls1-1"

# Initialize issue counter
ISSUES=0

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

log() {
    echo -e "$1" | tee -a "$REPORT_FILE"
}

check_pattern() {
    local text="$1"
    local pattern="$2"
    local item="$3"

    if echo "$text" | grep -iE "$pattern" > /dev/null; then
        log "${RED}[FAIL]${NC} $item contains non-compliant settings"
        ((ISSUES++))
        return 1
    else
        log "${GREEN}[PASS]${NC} $item is compliant"
        return 0
    fi
}

api_config() {
    local xpath="$1"
    curl -sk "https://$FIREWALL_IP/api/?type=config&action=get&key=$API_KEY&xpath=$xpath"
}

api_op() {
    local cmd="$1"
    curl -sk "https://$FIREWALL_IP/api/?type=op&key=$API_KEY&cmd=$cmd"
}

# Start report
log "=========================================="
log "FIPS 140-3 COMPLIANCE AUDIT REPORT"
log "=========================================="
log "Firewall: $FIREWALL_IP"
log "Date: $(date)"
log "=========================================="

# Get system info
log "\n=== SYSTEM INFORMATION ==="
SYSINFO=$(api_op "<show><system><info></info></system></show>")
HOSTNAME=$(echo "$SYSINFO" | grep -oP '(?<=<hostname>)[^<]+')
VERSION=$(echo "$SYSINFO" | grep -oP '(?<=<sw-version>)[^<]+')
log "Hostname: $HOSTNAME"
log "PAN-OS Version: $VERSION"

# Check IKE Crypto Profiles
log "\n=== IKE CRYPTO PROFILES ==="
IKE_CONFIG=$(api_config "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles")

check_pattern "$IKE_CONFIG" "$NON_COMPLIANT_ENC" "IKE Encryption"
check_pattern "$IKE_CONFIG" "$NON_COMPLIANT_HASH" "IKE Hash"
check_pattern "$IKE_CONFIG" "$NON_COMPLIANT_DH" "IKE DH Groups"

# Check IPSec Crypto Profiles
log "\n=== IPSEC CRYPTO PROFILES ==="
IPSEC_CONFIG=$(api_config "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles")

check_pattern "$IPSEC_CONFIG" "$NON_COMPLIANT_ENC" "IPSec Encryption"
check_pattern "$IPSEC_CONFIG" "$NON_COMPLIANT_HASH" "IPSec Authentication"
check_pattern "$IPSEC_CONFIG" "$NON_COMPLIANT_DH" "IPSec PFS Groups"

# Check SSL/TLS Profiles
log "\n=== SSL/TLS SERVICE PROFILES ==="
TLS_CONFIG=$(api_config "/config/shared/ssl-tls-service-profile")

check_pattern "$TLS_CONFIG" "$NON_COMPLIANT_TLS" "TLS Min Version"
check_pattern "$TLS_CONFIG" "$NON_COMPLIANT_ENC" "TLS Encryption"
check_pattern "$TLS_CONFIG" "auth-algo-sha1.*yes" "TLS SHA-1 Auth"

# Check Certificates
log "\n=== CERTIFICATES ==="
CERTS=$(api_op "<show><certificate><summary></summary></certificate></show>")

# Check for weak key sizes (< 2048 bits)
WEAK_KEYS=$(echo "$CERTS" | grep -oP '(?<=<public-key-length>)\d+(?=</public-key-length>)' | while read size; do
    if [ "$size" -lt 2048 ]; then
        echo "$size"
    fi
done)

if [ -n "$WEAK_KEYS" ]; then
    log "${RED}[FAIL]${NC} Certificates with keys < 2048 bits found"
    ((ISSUES++))
else
    log "${GREEN}[PASS]${NC} All certificates have adequate key sizes"
fi

# Check SSH Host Keys
log "\n=== SSH HOST KEYS ==="
SSH_KEYS=$(api_op "<show><ssh><system><host-key><fingerprint></fingerprint></host-key></system></ssh></show>")
log "SSH Host Key Fingerprints retrieved"
log "${GREEN}[INFO]${NC} Manual verification required for key sizes"

# Check Active VPN Tunnels
log "\n=== ACTIVE VPN TUNNELS ==="
IKE_SA=$(api_op "<show><vpn><ike-sa></ike-sa></vpn></show>")
IPSEC_SA=$(api_op "<show><vpn><ipsec-sa></ipsec-sa></vpn></show>")

check_pattern "$IKE_SA" "$NON_COMPLIANT_ENC" "Active IKE SA Encryption"
check_pattern "$IKE_SA" "$NON_COMPLIANT_HASH" "Active IKE SA Hash"
check_pattern "$IPSEC_SA" "$NON_COMPLIANT_ENC" "Active IPSec SA Encryption"

# Summary
log "\n=========================================="
log "COMPLIANCE SUMMARY"
log "=========================================="
log "Total Issues Found: $ISSUES"

if [ $ISSUES -eq 0 ]; then
    log "\n${GREEN}STATUS: COMPLIANT${NC}"
    log "No FIPS 140-3 compliance issues detected."
    EXIT_CODE=0
else
    log "\n${RED}STATUS: NON-COMPLIANT${NC}"
    log "$ISSUES compliance issues require attention."
    EXIT_CODE=1
fi

log "\nReport saved to: $REPORT_FILE"
log "=========================================="

exit $EXIT_CODE
```

### Usage

```bash
# Make script executable
chmod +x fips_compliance_check.sh

# Run with default settings
./fips_compliance_check.sh

# Run with specific firewall and API key
./fips_compliance_check.sh 192.168.1.1 LUFRPT...

# Run and capture output
./fips_compliance_check.sh 192.168.1.1 LUFRPT... 2>&1 | tee audit.log
```

---

## Integration with CI/CD

### GitHub Actions Workflow

```yaml
name: FIPS Compliance Check

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight
  workflow_dispatch:

jobs:
  compliance-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: pip install requests

      - name: Run Compliance Check
        env:
          FIREWALL_IP: ${{ secrets.FIREWALL_IP }}
          API_KEY: ${{ secrets.FIREWALL_API_KEY }}
        run: |
          python fips_compliance_checker.py

      - name: Upload Report
        uses: actions/upload-artifact@v3
        with:
          name: compliance-report
          path: fips_compliance_report_*.txt
```

---

## Strata Cloud Manager API Compliance Check

### SCM Compliance Script

```bash
#!/bin/bash
#
# FIPS 140-3 Compliance Checker for Strata Cloud Manager
#

SCM_API_URL="https://api.sase.paloaltonetworks.com/sse/config/v1"
ACCESS_TOKEN="${1:-your-token}"

# Function to check profiles
check_profiles() {
    local endpoint="$1"
    local name="$2"

    echo "Checking $name..."

    response=$(curl -s -X GET "$SCM_API_URL/$endpoint" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json")

    # Check for non-compliant settings
    if echo "$response" | grep -iE "3des|des|md5|sha1|group1|group2|group5" > /dev/null; then
        echo "[FAIL] Non-compliant settings found in $name"
        return 1
    else
        echo "[PASS] $name configuration is compliant"
        return 0
    fi
}

echo "=== SCM FIPS 140-3 Compliance Check ==="

check_profiles "ike-crypto-profiles" "IKE Crypto Profiles"
check_profiles "ipsec-crypto-profiles" "IPSec Crypto Profiles"
check_profiles "ssl-tls-service-profiles" "SSL/TLS Service Profiles"
check_profiles "decryption-profiles" "Decryption Profiles"

echo "=== Compliance Check Complete ==="
```
