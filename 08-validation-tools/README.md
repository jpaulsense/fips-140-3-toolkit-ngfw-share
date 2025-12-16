# FIPS 140-3 Compliance Validation Tools

## Overview

This directory contains validation scripts for verifying FIPS 140-3 compliance on Palo Alto Networks firewalls WITHOUT requiring CC-mode to be enabled.

## Severity Levels

The validator distinguishes between different severity levels:

| Level | Description | Action Required |
|-------|-------------|-----------------|
| **FAIL** | Non-compliant settings that are **actively IN USE** | Immediate remediation required |
| **HIGH RISK** | Non-compliant settings that exist but are **NOT in use** | Cleanup recommended to prevent accidental use |
| **WARN** | Configuration issues that need review | Review and address as needed |
| **PASS** | Compliant settings | No action needed |

### Compliance Outcomes

| Status | Meaning |
|--------|---------|
| **PASSED** | All settings compliant, no issues found |
| **PASSED WITH HIGH RISK** | No active issues, but unused non-compliant profiles exist |
| **FAILED** | Non-compliant settings are actively in use |

## Available Tools

### 1. Bash Script (`fips-compliance-validator.sh`)

A standalone bash script for quick compliance validation.

**Requirements:**
- Bash 4.0+
- curl
- API access to firewall

**Usage:**

```bash
chmod +x fips-compliance-validator.sh
./fips-compliance-validator.sh -f <firewall_ip> -u <username> -p <password>
```

**Options:**
- `-f` - Firewall IP address or hostname
- `-u` - Admin username
- `-p` - Admin password
- `-o` - Output file for report (optional)
- `-h` - Show help

### 2. Python Script (`fips-compliance-validator.py`)

A more comprehensive Python-based validator with detailed output.

**Requirements:**
- Python 3.6+
- requests library

**Installation:**

```bash
pip install requests
```

**Usage:**

```bash
python3 fips-compliance-validator.py -f <firewall_ip> -u <username> -p <password>
```

**Options:**
- `-f, --firewall` - Firewall IP address or hostname
- `-u, --username` - Admin username
- `-p, --password` - Admin password
- `-o, --output` - Output file for report (optional)

## Profile Usage Detection

The validator first gathers information about which profiles are actively in use:

| Profile Type | Usage Checked In |
|--------------|------------------|
| IKE Crypto Profiles | IKE Gateways |
| IPSec Crypto Profiles | IPSec Tunnels, GlobalProtect Gateways |
| SSL/TLS Service Profiles | Management Interface, GlobalProtect Portals/Gateways |
| Decryption Profiles | Decryption Rules |
| Interface Management Profiles | Ethernet, Loopback, Tunnel, VLAN interfaces |

Profiles that are **not referenced anywhere** in the configuration are marked as `[NOT USED]` and non-compliant findings are reported as `[HIGH RISK]` instead of `[FAIL]`.

## What Gets Validated

### IKE Crypto Profiles
- Encryption algorithms (flags: 3DES, DES, RC4)
- Hash algorithms (flags: MD5, SHA-1)
- DH Groups (flags: Group 1, 2, 5)

### IPSec Crypto Profiles
- ESP encryption algorithms
- ESP authentication algorithms
- DH Groups for PFS
- No-PFS configuration

### SSL/TLS Service Profiles
- Minimum TLS version (flags: TLS 1.0, TLS 1.1)
- Maximum TLS version
- Certificate assignment

### Decryption Profiles
- TLS version settings
- Certificate validation settings
- Blocking of expired/untrusted certificates

### Interface Management Profiles
- Insecure protocols (Telnet, HTTP)
- Secure protocols (SSH, HTTPS)

### Certificates
- Key algorithm type
- Expiration status
- Key size (where available)

### Management Interface
- SSL/TLS profile assignment

## Example Output

```
============================================================
FIPS 140-3 COMPLIANCE VALIDATION
============================================================
Firewall: 10.82.84.14
Date: 2024-12-15 14:30:00

[INFO] Authenticating to firewall...
[PASS] Successfully authenticated

============================================================
GATHERING PROFILE USAGE INFORMATION
============================================================
[INFO] Checking IKE gateway configurations...
[INFO]   IKE Gateway 'vpn-gateway-1' uses profile: fips-ike-crypto-max
[INFO] Checking IPSec tunnel configurations...
[INFO]   IPSec Tunnel 'site-to-site-vpn' uses profile: fips-ipsec-crypto-max
[INFO] Checking GlobalProtect gateway configurations...
[INFO] Checking management interface configuration...

[INFO] IKE crypto profiles in use: 1
[INFO] IPSec crypto profiles in use: 1
[INFO] SSL/TLS profiles in use: 0

============================================================
IKE CRYPTO PROFILES
============================================================

[INFO] Checking profile: fips-ike-crypto-max [IN USE]
[PASS] Encryption algorithms compliant
[PASS] Hash algorithms compliant
[PASS] DH groups compliant

[INFO] Checking profile: default [NOT USED]
[HIGH RISK] Non-compliant encryption (not in use): 3des
[HIGH RISK] Non-compliant hash (not in use): sha1
[HIGH RISK] Non-compliant DH group (not in use): group2

...

============================================================
COMPLIANCE SUMMARY
============================================================

PASSED:      61
FAILED:      0   (Non-compliant AND in use)
HIGH RISK:   6   (Non-compliant but NOT in use)
WARNINGS:    2

==================================================
  FIPS 140-3 COMPLIANCE: PASSED WITH HIGH RISK
==================================================

No active non-compliant configurations, but
6 unused non-compliant profile(s) exist.

Recommendation: Remove or update unused non-compliant profiles
to prevent accidental use in future configurations.
```

## Exit Codes

- `0` - All checks passed (FIPS 140-3 compliant)
- `1` - One or more checks failed (non-compliant settings IN USE)
- `2` - Passed with high risk (non-compliant settings exist but NOT in use)

## Non-Compliant Algorithms Reference

| Category | Non-Compliant | Replace With |
|----------|---------------|--------------|
| Encryption | 3DES, DES, NULL, RC4 | AES-128/256-CBC, AES-128/256-GCM |
| Hash | MD5, SHA-1 | SHA-256, SHA-384, SHA-512 |
| DH Groups | Group 1, 2, 5, no-pfs | Group 14, 15, 16, 19, 20, 21 |
| TLS Version | TLS 1.0, TLS 1.1 | TLS 1.2, TLS 1.3 |

## Remediation

If the validation fails, use the FIPS 140-3 compliant profiles from this toolkit:

1. **IKE Crypto Profiles**: See `01-ipsec-ike/01-ike-crypto-profiles.md`
2. **IPSec Crypto Profiles**: See `01-ipsec-ike/02-ipsec-crypto-profiles.md`
3. **SSL/TLS Profiles**: See `02-ssl-tls/01-ssl-tls-service-profiles.md`
4. **Decryption Profiles**: See `02-ssl-tls/02-decryption-profiles.md`
5. **SSH Configuration**: See `03-ssh/01-ssh-service-profile.md`

## Integration with CI/CD

These scripts can be integrated into CI/CD pipelines for automated compliance checking:

```yaml
# Example GitHub Actions workflow
- name: Validate FIPS Compliance
  run: |
    python3 fips-compliance-validator.py \
      -f ${{ secrets.FIREWALL_IP }} \
      -u ${{ secrets.FIREWALL_USER }} \
      -p ${{ secrets.FIREWALL_PASS }}
```

## Limitations

- SSH algorithm validation requires external nmap/ssh testing
- Certificate key size validation requires certificate export
- Some checks depend on PAN-OS version capabilities
- Scripts assume single vsys (vsys1) configuration
