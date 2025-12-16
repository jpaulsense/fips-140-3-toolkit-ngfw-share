# SSL/TLS Service Profile Snippets - FIPS 140-3 Compliance

## Overview

This document provides Strata Cloud Manager snippets for FIPS 140-3 compliant SSL/TLS service profiles. These profiles are used for management interface access, GlobalProtect, and other TLS-secured services.

---

## Snippet: Maximum Security (TLS 1.3 Only)

### JSON Configuration

```json
{
    "name": "fips-ssl-tls-max",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Maximum Security - TLS 1.3 only",
    "protocol_settings": {
        "min_version": "tls1-3",
        "max_version": "tls1-3"
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ssl-tls-service-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-max",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Maximum Security - TLS 1.3 only",
        "protocol_settings": {
            "min_version": "tls1-3",
            "max_version": "tls1-3"
        }
    }'
```

---

## Snippet: Recommended (TLS 1.2-1.3)

### JSON Configuration

```json
{
    "name": "fips-ssl-tls-recommended",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Recommended - TLS 1.2 and 1.3 with FIPS ciphers",
    "protocol_settings": {
        "min_version": "tls1-2",
        "max_version": "tls1-3",
        "keyxchg_algo_rsa": false,
        "keyxchg_algo_dhe": true,
        "keyxchg_algo_ecdhe": true,
        "enc_algo_3des": false,
        "enc_algo_rc4": false,
        "enc_algo_aes_128_cbc": true,
        "enc_algo_aes_256_cbc": true,
        "enc_algo_aes_128_gcm": true,
        "enc_algo_aes_256_gcm": true,
        "auth_algo_sha1": false,
        "auth_algo_sha256": true,
        "auth_algo_sha384": true
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ssl-tls-service-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-recommended",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Recommended - TLS 1.2 and 1.3 with FIPS ciphers",
        "protocol_settings": {
            "min_version": "tls1-2",
            "max_version": "tls1-3",
            "keyxchg_algo_rsa": false,
            "keyxchg_algo_dhe": true,
            "keyxchg_algo_ecdhe": true,
            "enc_algo_3des": false,
            "enc_algo_rc4": false,
            "enc_algo_aes_128_cbc": true,
            "enc_algo_aes_256_cbc": true,
            "enc_algo_aes_128_gcm": true,
            "enc_algo_aes_256_gcm": true,
            "auth_algo_sha1": false,
            "auth_algo_sha256": true,
            "auth_algo_sha384": true
        }
    }'
```

---

## Snippet: GCM Only (Authenticated Encryption)

### JSON Configuration

```json
{
    "name": "fips-ssl-tls-gcm",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 GCM Only - AEAD ciphers preferred",
    "protocol_settings": {
        "min_version": "tls1-2",
        "max_version": "tls1-3",
        "keyxchg_algo_rsa": false,
        "keyxchg_algo_dhe": false,
        "keyxchg_algo_ecdhe": true,
        "enc_algo_3des": false,
        "enc_algo_rc4": false,
        "enc_algo_aes_128_cbc": false,
        "enc_algo_aes_256_cbc": false,
        "enc_algo_aes_128_gcm": true,
        "enc_algo_aes_256_gcm": true,
        "auth_algo_sha1": false,
        "auth_algo_sha256": true,
        "auth_algo_sha384": true
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ssl-tls-service-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-gcm",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 GCM Only - AEAD ciphers preferred",
        "protocol_settings": {
            "min_version": "tls1-2",
            "max_version": "tls1-3",
            "keyxchg_algo_rsa": false,
            "keyxchg_algo_dhe": false,
            "keyxchg_algo_ecdhe": true,
            "enc_algo_3des": false,
            "enc_algo_rc4": false,
            "enc_algo_aes_128_cbc": false,
            "enc_algo_aes_256_cbc": false,
            "enc_algo_aes_128_gcm": true,
            "enc_algo_aes_256_gcm": true,
            "auth_algo_sha1": false,
            "auth_algo_sha256": true,
            "auth_algo_sha384": true
        }
    }'
```

---

## Snippet: GlobalProtect Optimized

### JSON Configuration

```json
{
    "name": "fips-ssl-tls-gp",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 for GlobalProtect - Optimized for client compatibility",
    "protocol_settings": {
        "min_version": "tls1-2",
        "max_version": "tls1-3",
        "keyxchg_algo_rsa": false,
        "keyxchg_algo_dhe": true,
        "keyxchg_algo_ecdhe": true,
        "enc_algo_3des": false,
        "enc_algo_rc4": false,
        "enc_algo_aes_128_cbc": true,
        "enc_algo_aes_256_cbc": true,
        "enc_algo_aes_128_gcm": true,
        "enc_algo_aes_256_gcm": true,
        "auth_algo_sha1": false,
        "auth_algo_sha256": true,
        "auth_algo_sha384": true
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ssl-tls-service-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-gp",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 for GlobalProtect",
        "protocol_settings": {
            "min_version": "tls1-2",
            "max_version": "tls1-3",
            "keyxchg_algo_rsa": false,
            "keyxchg_algo_dhe": true,
            "keyxchg_algo_ecdhe": true,
            "enc_algo_3des": false,
            "enc_algo_rc4": false,
            "enc_algo_aes_128_cbc": true,
            "enc_algo_aes_256_cbc": true,
            "enc_algo_aes_128_gcm": true,
            "enc_algo_aes_256_gcm": true,
            "auth_algo_sha1": false,
            "auth_algo_sha256": true,
            "auth_algo_sha384": true
        }
    }'
```

---

## Decryption Profile Snippet

### JSON Configuration

```json
{
    "name": "fips-decryption-profile",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Decryption Profile",
    "ssl_forward_proxy": {
        "block_expired_certificate": true,
        "block_untrusted_issuer": true,
        "block_unknown_cert": true,
        "strip_alpn": false
    },
    "ssl_protocol_settings": {
        "min_version": "tls1-2",
        "max_version": "tls1-3",
        "keyxchg_algo_rsa": false,
        "keyxchg_algo_dhe": true,
        "keyxchg_algo_ecdhe": true,
        "enc_algo_3des": false,
        "enc_algo_rc4": false,
        "enc_algo_aes_128_cbc": true,
        "enc_algo_aes_256_cbc": true,
        "enc_algo_aes_128_gcm": true,
        "enc_algo_aes_256_gcm": true,
        "auth_algo_sha1": false,
        "auth_algo_sha256": true,
        "auth_algo_sha384": true
    },
    "ssl_no_proxy": {
        "block_expired_certificate": true,
        "block_untrusted_issuer": true
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/decryption-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-decryption-profile",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Decryption Profile",
        "ssl_forward_proxy": {
            "block_expired_certificate": true,
            "block_untrusted_issuer": true,
            "block_unknown_cert": true
        },
        "ssl_protocol_settings": {
            "min_version": "tls1-2",
            "max_version": "tls1-3",
            "keyxchg_algo_rsa": false,
            "enc_algo_3des": false,
            "enc_algo_rc4": false,
            "auth_algo_sha1": false
        }
    }'
```

---

## Bulk Snippet Deployment Script

### Deploy All SSL/TLS Snippets

```bash
#!/bin/bash

# Configuration
SCM_API_URL="https://api.sase.paloaltonetworks.com/sse/config/v1"
ACCESS_TOKEN="<your-access-token>"

# Maximum Security Profile (TLS 1.3 only)
echo "Deploying fips-ssl-tls-max..."
curl -s -X POST "$SCM_API_URL/ssl-tls-service-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-max",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Maximum Security - TLS 1.3 only",
        "protocol_settings": {
            "min_version": "tls1-3",
            "max_version": "tls1-3"
        }
    }'

# Recommended Profile
echo "Deploying fips-ssl-tls-recommended..."
curl -s -X POST "$SCM_API_URL/ssl-tls-service-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-recommended",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Recommended",
        "protocol_settings": {
            "min_version": "tls1-2",
            "max_version": "tls1-3",
            "keyxchg_algo_rsa": false,
            "keyxchg_algo_dhe": true,
            "keyxchg_algo_ecdhe": true,
            "enc_algo_3des": false,
            "enc_algo_rc4": false,
            "auth_algo_sha1": false
        }
    }'

# GCM Only Profile
echo "Deploying fips-ssl-tls-gcm..."
curl -s -X POST "$SCM_API_URL/ssl-tls-service-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-gcm",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 GCM Only",
        "protocol_settings": {
            "min_version": "tls1-2",
            "max_version": "tls1-3",
            "keyxchg_algo_rsa": false,
            "keyxchg_algo_ecdhe": true,
            "enc_algo_aes_128_cbc": false,
            "enc_algo_aes_256_cbc": false,
            "enc_algo_aes_128_gcm": true,
            "enc_algo_aes_256_gcm": true
        }
    }'

# GlobalProtect Profile
echo "Deploying fips-ssl-tls-gp..."
curl -s -X POST "$SCM_API_URL/ssl-tls-service-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssl-tls-gp",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 for GlobalProtect",
        "protocol_settings": {
            "min_version": "tls1-2",
            "max_version": "tls1-3",
            "keyxchg_algo_rsa": false,
            "enc_algo_3des": false,
            "enc_algo_rc4": false,
            "auth_algo_sha1": false
        }
    }'

echo "All SSL/TLS service profiles deployed."
```

---

## Verification

### List Deployed SSL/TLS Profiles

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ssl-tls-service-profiles?snippet=FIPS-140-3-Crypto" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

### Get Specific Profile

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ssl-tls-service-profiles/fips-ssl-tls-recommended" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

---

## Algorithm Reference

### TLS Versions

| Version | SCM Value | FIPS Status |
|---------|-----------|-------------|
| TLS 1.3 | `tls1-3` | Compliant |
| TLS 1.2 | `tls1-2` | Compliant |
| TLS 1.1 | `tls1-1` | **Non-Compliant** |
| TLS 1.0 | `tls1-0` | **Non-Compliant** |

### Key Exchange Algorithms

| Algorithm | SCM Parameter | FIPS Status | Notes |
|-----------|---------------|-------------|-------|
| ECDHE | `keyxchg_algo_ecdhe` | Compliant | Recommended |
| DHE | `keyxchg_algo_dhe` | Compliant | Good |
| RSA | `keyxchg_algo_rsa` | Compliant | No PFS - avoid |

### Encryption Algorithms

| Algorithm | SCM Parameter | FIPS Status |
|-----------|---------------|-------------|
| AES-256-GCM | `enc_algo_aes_256_gcm` | Compliant |
| AES-128-GCM | `enc_algo_aes_128_gcm` | Compliant |
| AES-256-CBC | `enc_algo_aes_256_cbc` | Compliant |
| AES-128-CBC | `enc_algo_aes_128_cbc` | Compliant |
| 3DES | `enc_algo_3des` | **Non-Compliant** |
| RC4 | `enc_algo_rc4` | **Non-Compliant** |

### Authentication Algorithms

| Algorithm | SCM Parameter | FIPS Status |
|-----------|---------------|-------------|
| SHA-384 | `auth_algo_sha384` | Compliant |
| SHA-256 | `auth_algo_sha256` | Compliant |
| SHA-1 | `auth_algo_sha1` | **Non-Compliant** |
