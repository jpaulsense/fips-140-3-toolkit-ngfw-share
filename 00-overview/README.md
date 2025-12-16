# Palo Alto Networks FIPS 140-3 Compliance Toolkit

## Overview

This toolkit provides comprehensive guidance for configuring Palo Alto Networks firewalls to use FIPS 140-3 compliant cryptographic settings **WITHOUT** enabling CC-mode (Common Criteria mode). This approach allows organizations to achieve FIPS-compliant cryptographic configurations while maintaining operational flexibility.

## Important Distinction: FIPS-Compliant Settings vs. FIPS-CC Mode

| Aspect | FIPS-Compliant Settings (This Toolkit) | FIPS-CC Mode |
|--------|----------------------------------------|--------------|
| Approach | Manual configuration of approved algorithms | System-enforced restrictions |
| Flexibility | Selective per-feature compliance | All-or-nothing enforcement |
| Operational Impact | Minimal - choose what to harden | Significant - many features restricted |
| Audit Trail | Requires documentation | Built-in enforcement |
| Rollback | Easy - change individual settings | Requires system reboot |

## FIPS 140-3 Approved Cryptographic Algorithms

### Symmetric Encryption (AES)
- **AES-CBC**: 128, 192, 256-bit keys
- **AES-GCM**: 128, 256-bit keys
- **AES-CTR**: 128, 192, 256-bit keys
- **AES-CCM**: 128-bit keys

### Key Exchange
- **DH Groups**: 14 (2048-bit), 15 (3072-bit), 16 (4096-bit)
- **ECDH**: NIST curves P-256, P-384, P-521

### Hash Functions & HMAC
- SHA-256, SHA-384, SHA-512
- HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512

### Digital Signatures
- **RSA**: 2048-bit keys or greater
- **ECDSA**: NIST curves P-256, P-384, P-521

## Toolkit Structure

```
PAN-FIPS-140-3-Toolkit/
├── 00-overview/
│   └── README.md (this file)
│
├── 01-ipsec-ike/
│   ├── 01-ike-crypto-profiles.md
│   ├── 02-ipsec-crypto-profiles.md
│   ├── 03-certificate-requirements.md
│   └── 04-tunnel-configuration.md
│
├── 02-ssl-tls/
│   ├── 01-ssl-tls-service-profiles.md
│   ├── 02-decryption-profiles.md
│   ├── 03-globalprotect-settings.md
│   └── 04-certificate-profiles.md
│
├── 03-ssh/
│   ├── 01-ssh-service-profile.md
│   ├── 02-ssh-host-keys.md
│   └── 03-ssh-decryption.md
│
├── 04-admin-web-interface/
│   ├── 01-management-interface-tls.md
│   └── 02-certificate-management.md
│
├── 05-strata-cloud-manager/
│   ├── 01-scm-snippets-overview.md
│   ├── 02-ike-crypto-snippet.md
│   ├── 03-ipsec-crypto-snippet.md
│   ├── 04-ssl-tls-snippet.md
│   └── 05-ssh-snippet.md
│
├── 06-verification-scripts/
│   ├── 01-compliance-check-cli.md
│   ├── 02-compliance-check-api.md
│   └── 03-audit-report-generator.md
│
└── 07-api-reference/
    ├── 01-api-overview.md
    ├── 02-ike-crypto-api.md
    ├── 03-ipsec-crypto-api.md
    ├── 04-ssl-tls-api.md
    └── 05-ssh-api.md
```

## Quick Reference: Compliant vs. Non-Compliant Settings

### Algorithms to USE (FIPS 140-3 Compliant)

| Category | Compliant Options |
|----------|-------------------|
| Encryption | AES-128-CBC, AES-192-CBC, AES-256-CBC, AES-128-GCM, AES-256-GCM |
| Key Exchange | DH Group 14, 15, 16; ECDH P-256, P-384, P-521 |
| Hashing | SHA-256, SHA-384, SHA-512 |
| Authentication | HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 |
| RSA Keys | 2048-bit minimum |
| ECDSA Keys | P-256 (256-bit), P-384 (384-bit), P-521 (521-bit) |

### Algorithms to AVOID (Non-Compliant)

| Category | Non-Compliant Options |
|----------|----------------------|
| Encryption | DES, 3DES, RC4, AES-128-CCM-8 |
| Key Exchange | DH Group 1, 2, 5; RSA key exchange |
| Hashing | MD5, SHA-1 |
| Authentication | HMAC-MD5, HMAC-SHA-1 |
| RSA Keys | Less than 2048-bit |
| TLS Versions | TLS 1.0, TLS 1.1 |

## Implementation Priority

1. **Critical (Immediate)**: Administrative access (SSH, Web UI)
2. **High**: VPN tunnels (IPSec/IKE, GlobalProtect)
3. **Medium**: SSL/TLS Decryption profiles
4. **Standard**: Internal service communications

## Version Compatibility

This toolkit is designed for:
- PAN-OS 10.1 and later
- PAN-OS 11.x series
- Strata Cloud Manager (Prisma Access)

## Disclaimer

This toolkit provides guidance for achieving FIPS 140-3 compliant cryptographic configurations. Organizations requiring formal FIPS 140-3 certification should enable FIPS-CC mode and follow Palo Alto Networks' official certification documentation.
