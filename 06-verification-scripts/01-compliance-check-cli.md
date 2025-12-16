# FIPS 140-3 Compliance Check - CLI Commands

## Overview

This document provides CLI commands for verifying FIPS 140-3 compliance on Palo Alto Networks firewalls. Use these commands to audit configurations and identify non-compliant settings.

---

## Quick Compliance Check Commands

### IKE Crypto Profile Verification

```bash
# List all IKE crypto profiles
show running config network ike crypto-profiles ike-crypto-profiles

# Check for non-compliant algorithms
show running config network ike crypto-profiles ike-crypto-profiles | match -i "3des\|des\|md5\|sha1\|group1\|group2\|group5"

# If matches found, the profile contains non-compliant settings
```

### IPSec Crypto Profile Verification

```bash
# List all IPSec crypto profiles
show running config network ike crypto-profiles ipsec-crypto-profiles

# Check for non-compliant algorithms
show running config network ike crypto-profiles ipsec-crypto-profiles | match -i "3des\|des\|md5\|sha1\|null\|no-pfs\|group1\|group2\|group5"
```

### SSL/TLS Service Profile Verification

```bash
# List all SSL/TLS service profiles
show running config ssl-tls-service-profile

# Check for non-compliant settings
show running config ssl-tls-service-profile | match -i "tls1-0\|tls1-1\|3des\|rc4\|sha1"

# Verify minimum TLS version
show running config ssl-tls-service-profile | match -i "min-version"
```

### SSH Configuration Verification

```bash
# Show SSH host key information
show ssh system host-key fingerprint

# Verify SSH configuration
show running config deviceconfig system ssh

# Check SSH algorithms in use (during active session)
debug system ssh show-algorithms
```

### Certificate Verification

```bash
# List all certificates with key info
show certificate summary

# Check specific certificate details
show certificate name <cert-name>

# Verify certificate key size (look for RSA 2048+ or ECDSA P-256+)
show certificate name <cert-name> | match -i "key\|algorithm\|signature"
```

---

## Comprehensive Compliance Audit Script

### Firewall-Side Audit (Run on CLI)

```bash
#!/bin/bash
# FIPS 140-3 Compliance Audit Script
# Run each section on the firewall CLI

echo "=========================================="
echo "FIPS 140-3 COMPLIANCE AUDIT REPORT"
echo "Date: $(date)"
echo "=========================================="

echo ""
echo "=== SYSTEM INFORMATION ==="
show system info | match -i "hostname\|ip-address\|sw-version"

echo ""
echo "=== IKE CRYPTO PROFILES ==="
echo "Checking for non-compliant IKE algorithms..."
show running config network ike crypto-profiles ike-crypto-profiles

echo ""
echo "Non-compliant algorithms found (if any):"
show running config network ike crypto-profiles ike-crypto-profiles | match -i "3des\|des\|md5\|sha1\|group1\|group2\|group5"

echo ""
echo "=== IPSEC CRYPTO PROFILES ==="
echo "Checking for non-compliant IPSec algorithms..."
show running config network ike crypto-profiles ipsec-crypto-profiles

echo ""
echo "Non-compliant algorithms found (if any):"
show running config network ike crypto-profiles ipsec-crypto-profiles | match -i "3des\|des\|md5\|sha1\|null\|no-pfs\|group1\|group2\|group5"

echo ""
echo "=== SSL/TLS SERVICE PROFILES ==="
echo "Checking TLS configuration..."
show running config ssl-tls-service-profile

echo ""
echo "Non-compliant settings found (if any):"
show running config ssl-tls-service-profile | match -i "tls1-0\|tls1-1\|3des\|rc4\|sha1"

echo ""
echo "=== CERTIFICATES ==="
echo "Certificate Summary:"
show certificate summary

echo ""
echo "=== SSH CONFIGURATION ==="
show ssh system host-key fingerprint
show running config deviceconfig system ssh

echo ""
echo "=== ACTIVE VPN TUNNELS ==="
echo "IKE Security Associations:"
show vpn ike-sa

echo ""
echo "IPSec Security Associations:"
show vpn ipsec-sa

echo ""
echo "=== MANAGEMENT INTERFACE ==="
show running config deviceconfig system ssl-tls-service-profile
show running config deviceconfig system service

echo ""
echo "=========================================="
echo "END OF COMPLIANCE AUDIT REPORT"
echo "=========================================="
```

---

## Individual Component Checks

### Check Active IKE SA Algorithms

```bash
# Show active IKE Security Associations with algorithm details
show vpn ike-sa detail

# Sample output interpretation:
# - Look for: AES-256-GCM, AES-256-CBC, AES-128-GCM (COMPLIANT)
# - Flag: 3DES, DES (NON-COMPLIANT)
# - Look for: SHA-256, SHA-384, SHA-512 (COMPLIANT)
# - Flag: SHA-1, MD5 (NON-COMPLIANT)
# - Look for: Group 14, 15, 16, 19, 20, 21 (COMPLIANT)
# - Flag: Group 1, 2, 5 (NON-COMPLIANT)
```

### Check Active IPSec SA Algorithms

```bash
# Show active IPSec Security Associations with algorithm details
show vpn ipsec-sa detail

# Sample output interpretation:
# - Look for: ESP_AES-256-GCM, ESP_AES-256-CBC (COMPLIANT)
# - Flag: ESP_3DES, ESP_DES, ESP_NULL (NON-COMPLIANT)
# - Look for: HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 (COMPLIANT)
# - Flag: HMAC-SHA-1, HMAC-MD5 (NON-COMPLIANT)
```

### Check GlobalProtect TLS Configuration

```bash
# Show GlobalProtect portal configuration
show running config network global-protect global-protect-portal | match -i ssl-tls

# Show GlobalProtect gateway configuration
show running config network global-protect global-protect-gateway | match -i ssl-tls

# Show GlobalProtect IPSec crypto profile
show running config network global-protect global-protect-gateway | match -i ipsec-crypto
```

### Check Decryption Profile Settings

```bash
# Show decryption profiles
show running config profiles decryption

# Check for TLS version settings
show running config profiles decryption | match -i "min-version\|max-version"

# Check for algorithm settings
show running config profiles decryption | match -i "3des\|rc4\|sha1\|rsa"
```

---

## Certificate Compliance Checks

### Verify All Certificate Key Sizes

```bash
# Script to check all certificates for compliance
# Run each certificate check individually

# Get list of certificates
show certificate summary

# For each certificate, verify compliance
# Certificate should show:
# - RSA: 2048 bits or greater
# - ECDSA: P-256, P-384, or P-521
# - Signature: SHA-256, SHA-384, or SHA-512

# Example check for specific certificate
show certificate name <certificate-name> | match -i "public key\|signature algorithm\|not before\|not after"
```

### Check Certificate Expiration

```bash
# Show all certificates with expiration dates
show certificate summary

# Filter for certificates expiring within 30 days
# (Requires manual review of dates)

# Validate certificate chain
request certificate validate certificate-name <cert-name>
```

---

## SSH Compliance Verification

### Verify SSH Host Key Compliance

```bash
# Show SSH host key details
show ssh system host-key

# Get fingerprints for documentation
show ssh system host-key fingerprint

# Expected compliance:
# - RSA: 2048 bits or greater
# - ECDSA: P-256, P-384, or P-521
```

### External SSH Algorithm Test

Run from an external system:

```bash
# Test SSH connection and show negotiated algorithms
ssh -v admin@<firewall-ip> 2>&1 | grep -i "kex\|cipher\|mac"

# Enumerate supported algorithms
nmap --script ssh2-enum-algos -p 22 <firewall-ip>

# Expected compliant algorithms:
# KEX: ecdh-sha2-nistp256, ecdh-sha2-nistp384, diffie-hellman-group14-sha256, diffie-hellman-group16-sha512
# Cipher: aes256-gcm@openssh.com, aes128-gcm@openssh.com, aes256-ctr, aes128-ctr
# MAC: hmac-sha2-512, hmac-sha2-256
```

---

## Management Interface TLS Verification

### Check Applied TLS Profile

```bash
# Show SSL/TLS profile applied to management
show running config deviceconfig system ssl-tls-service-profile

# Show profile details
show running config ssl-tls-service-profile <profile-name>
```

### External TLS Test

Run from an external system:

```bash
# Test TLS connection
openssl s_client -connect <firewall-ip>:443 2>/dev/null | \
    grep -i "protocol\|cipher"

# Verify TLS 1.0 is disabled (should fail)
openssl s_client -connect <firewall-ip>:443 -tls1 2>&1 | grep -i "handshake\|error"

# Verify TLS 1.1 is disabled (should fail)
openssl s_client -connect <firewall-ip>:443 -tls1_1 2>&1 | grep -i "handshake\|error"

# Verify TLS 1.2 works (should succeed)
openssl s_client -connect <firewall-ip>:443 -tls1_2 2>/dev/null | grep -i "cipher"

# Verify TLS 1.3 works (should succeed)
openssl s_client -connect <firewall-ip>:443 -tls1_3 2>/dev/null | grep -i "cipher"

# Enumerate all supported ciphers
nmap --script ssl-enum-ciphers -p 443 <firewall-ip>
```

---

## Compliance Summary Commands

### Generate Compliance Summary

```bash
# System info
echo "=== SYSTEM ===" && show system info | match -i "hostname\|sw-version"

# Non-compliant IKE check
echo "=== IKE NON-COMPLIANT ===" && \
show running config network ike crypto-profiles | match -i "3des\|des\|md5\|sha1\|group1\|group2\|group5"

# Non-compliant SSL/TLS check
echo "=== SSL/TLS NON-COMPLIANT ===" && \
show running config ssl-tls-service-profile | match -i "tls1-0\|tls1-1\|3des\|rc4"

# Certificate summary
echo "=== CERTIFICATES ===" && show certificate summary

# Active tunnels
echo "=== ACTIVE TUNNELS ===" && show vpn ike-sa | match -i "gateway"
```

---

## Non-Compliant Algorithm Reference

### Algorithms to Flag as Non-Compliant

| Category | Non-Compliant Values | Replace With |
|----------|---------------------|--------------|
| Encryption | 3des, des, null, rc4 | aes-128-*, aes-256-* |
| Hash | md5, sha1 | sha256, sha384, sha512 |
| DH Groups | group1, group2, group5, no-pfs | group14, group15, group16, group19, group20 |
| TLS Version | tls1-0, tls1-1 | tls1-2, tls1-3 |
| Key Exchange | RSA (for TLS) | ECDHE, DHE |

### Compliant Algorithm Quick Reference

| Category | Compliant Options |
|----------|-------------------|
| Encryption | aes-128-cbc, aes-256-cbc, aes-128-gcm, aes-256-gcm |
| Hash | sha256, sha384, sha512 |
| DH Groups | group14, group15, group16, group19, group20, group21 |
| TLS Version | tls1-2, tls1-3 |
| Key Exchange | ECDHE, DHE |
| RSA Key Size | 2048-bit minimum |
| ECDSA Curves | P-256, P-384, P-521 |
