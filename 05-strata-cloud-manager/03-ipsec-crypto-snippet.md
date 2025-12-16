# IPSec Crypto Profile Snippets - FIPS 140-3 Compliance

## Overview

This document provides Strata Cloud Manager snippets for FIPS 140-3 compliant IPSec crypto profiles. These snippets define the Phase 2 security association parameters for VPN tunnels.

---

## Snippet: Maximum Security (AES-256-GCM)

### JSON Configuration

```json
{
    "name": "fips-ipsec-crypto-max",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Maximum Security - AES-256-GCM with PFS Group 20",
    "esp": {
        "encryption": [
            "aes-256-gcm"
        ]
    },
    "dh_group": "group20",
    "lifetime": {
        "seconds": 3600
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-max",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Maximum Security - AES-256-GCM with PFS Group 20",
        "esp": {"encryption": ["aes-256-gcm"]},
        "dh_group": "group20",
        "lifetime": {"seconds": 3600}
    }'
```

---

## Snippet: Recommended (AES-256-CBC with SHA-512)

### JSON Configuration

```json
{
    "name": "fips-ipsec-crypto-recommended",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Recommended - AES-256-CBC with SHA-512 and PFS",
    "esp": {
        "encryption": [
            "aes-256-gcm",
            "aes-256-cbc",
            "aes-128-gcm",
            "aes-128-cbc"
        ],
        "authentication": [
            "sha512",
            "sha384",
            "sha256"
        ]
    },
    "dh_group": "group20",
    "lifetime": {
        "seconds": 3600
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-recommended",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Recommended - Multiple algorithms with PFS",
        "esp": {
            "encryption": ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
            "authentication": ["sha512", "sha384", "sha256"]
        },
        "dh_group": "group20",
        "lifetime": {"seconds": 3600}
    }'
```

---

## Snippet: Broad Compatibility

### JSON Configuration

```json
{
    "name": "fips-ipsec-crypto-compat",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Compatible - For legacy peer support with PFS",
    "esp": {
        "encryption": [
            "aes-256-cbc",
            "aes-192-cbc",
            "aes-128-cbc"
        ],
        "authentication": [
            "sha512",
            "sha384",
            "sha256"
        ]
    },
    "dh_group": "group14",
    "lifetime": {
        "seconds": 3600
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-compat",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Compatible - For legacy peer support with PFS",
        "esp": {
            "encryption": ["aes-256-cbc", "aes-192-cbc", "aes-128-cbc"],
            "authentication": ["sha512", "sha384", "sha256"]
        },
        "dh_group": "group14",
        "lifetime": {"seconds": 3600}
    }'
```

---

## Snippet: GCM Only (AEAD)

### JSON Configuration

```json
{
    "name": "fips-ipsec-crypto-gcm",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 GCM Only - Authenticated encryption mode",
    "esp": {
        "encryption": [
            "aes-256-gcm",
            "aes-128-gcm"
        ]
    },
    "dh_group": "group19",
    "lifetime": {
        "seconds": 3600
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-gcm",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 GCM Only - Authenticated encryption mode",
        "esp": {"encryption": ["aes-256-gcm", "aes-128-gcm"]},
        "dh_group": "group19",
        "lifetime": {"seconds": 3600}
    }'
```

---

## Snippet: GlobalProtect Optimized

### JSON Configuration

```json
{
    "name": "fips-ipsec-crypto-gp",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 for GlobalProtect - Optimized for remote access",
    "esp": {
        "encryption": [
            "aes-256-gcm",
            "aes-128-gcm"
        ]
    },
    "dh_group": "group19",
    "lifetime": {
        "seconds": 1800
    },
    "lifesize": {
        "gb": 100
    }
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-gp",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 for GlobalProtect - Optimized for remote access",
        "esp": {"encryption": ["aes-256-gcm", "aes-128-gcm"]},
        "dh_group": "group19",
        "lifetime": {"seconds": 1800},
        "lifesize": {"gb": 100}
    }'
```

---

## Bulk Snippet Deployment Script

### Deploy All IPSec Crypto Snippets

```bash
#!/bin/bash

# Configuration
SCM_API_URL="https://api.sase.paloaltonetworks.com/sse/config/v1"
ACCESS_TOKEN="<your-access-token>"

# Maximum Security Profile
echo "Deploying fips-ipsec-crypto-max..."
curl -s -X POST "$SCM_API_URL/ipsec-crypto-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-max",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Maximum Security",
        "esp": {"encryption": ["aes-256-gcm"]},
        "dh_group": "group20",
        "lifetime": {"seconds": 3600}
    }'

# Recommended Profile
echo "Deploying fips-ipsec-crypto-recommended..."
curl -s -X POST "$SCM_API_URL/ipsec-crypto-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-recommended",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Recommended",
        "esp": {
            "encryption": ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
            "authentication": ["sha512", "sha384", "sha256"]
        },
        "dh_group": "group20",
        "lifetime": {"seconds": 3600}
    }'

# Compatible Profile
echo "Deploying fips-ipsec-crypto-compat..."
curl -s -X POST "$SCM_API_URL/ipsec-crypto-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-compat",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Compatible",
        "esp": {
            "encryption": ["aes-256-cbc", "aes-192-cbc", "aes-128-cbc"],
            "authentication": ["sha512", "sha384", "sha256"]
        },
        "dh_group": "group14",
        "lifetime": {"seconds": 3600}
    }'

# GCM Only Profile
echo "Deploying fips-ipsec-crypto-gcm..."
curl -s -X POST "$SCM_API_URL/ipsec-crypto-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-gcm",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 GCM Only",
        "esp": {"encryption": ["aes-256-gcm", "aes-128-gcm"]},
        "dh_group": "group19",
        "lifetime": {"seconds": 3600}
    }'

# GlobalProtect Profile
echo "Deploying fips-ipsec-crypto-gp..."
curl -s -X POST "$SCM_API_URL/ipsec-crypto-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ipsec-crypto-gp",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 for GlobalProtect",
        "esp": {"encryption": ["aes-256-gcm", "aes-128-gcm"]},
        "dh_group": "group19",
        "lifetime": {"seconds": 1800}
    }'

echo "All IPSec crypto profiles deployed."
```

---

## Verification

### List Deployed IPSec Crypto Profiles

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles?snippet=FIPS-140-3-Crypto" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

### Get Specific Profile

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles/fips-ipsec-crypto-max" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

---

## Algorithm Reference

### ESP Encryption Algorithms

| Algorithm | SCM Value | FIPS Status | Notes |
|-----------|-----------|-------------|-------|
| AES-128-CBC | `aes-128-cbc` | Compliant | Requires separate auth |
| AES-192-CBC | `aes-192-cbc` | Compliant | Requires separate auth |
| AES-256-CBC | `aes-256-cbc` | Compliant | Requires separate auth |
| AES-128-GCM | `aes-128-gcm` | Compliant | AEAD - includes auth |
| AES-256-GCM | `aes-256-gcm` | Compliant | AEAD - includes auth |
| 3DES | `3des` | **Non-Compliant** | Do not use |
| DES | `des` | **Non-Compliant** | Do not use |
| NULL | `null` | **Non-Compliant** | No encryption |

### ESP Authentication Algorithms

| Algorithm | SCM Value | FIPS Status | Notes |
|-----------|-----------|-------------|-------|
| HMAC-SHA-256 | `sha256` | Compliant | 128-bit truncation |
| HMAC-SHA-384 | `sha384` | Compliant | |
| HMAC-SHA-512 | `sha512` | Compliant | |
| HMAC-SHA-1 | `sha1` | **Non-Compliant** | |
| HMAC-MD5 | `md5` | **Non-Compliant** | |

### PFS DH Groups

| Group | SCM Value | Key Size | FIPS Status |
|-------|-----------|----------|-------------|
| Group 14 | `group14` | 2048-bit DH | Compliant |
| Group 15 | `group15` | 3072-bit DH | Compliant |
| Group 16 | `group16` | 4096-bit DH | Compliant |
| Group 19 | `group19` | 256-bit ECDH (P-256) | Compliant |
| Group 20 | `group20` | 384-bit ECDH (P-384) | Compliant |
| Group 21 | `group21` | 521-bit ECDH (P-521) | Compliant |
| No PFS | `no-pfs` | None | **Non-Compliant** |
| Group 1 | `group1` | 768-bit DH | **Non-Compliant** |
| Group 2 | `group2` | 1024-bit DH | **Non-Compliant** |
| Group 5 | `group5` | 1536-bit DH | **Non-Compliant** |

---

## Cleanup

### Delete IPSec Crypto Profile

```bash
curl -X DELETE "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles/<profile-id>" \
    -H "Authorization: Bearer <ACCESS_TOKEN>"
```

---

## Integration with IKE Profiles

When deploying, ensure matching IKE and IPSec profiles:

| IKE Profile | Matching IPSec Profile | Use Case |
|-------------|----------------------|----------|
| fips-ike-crypto-max | fips-ipsec-crypto-max | Maximum security |
| fips-ike-crypto-recommended | fips-ipsec-crypto-recommended | Balanced |
| fips-ike-crypto-minimum | fips-ipsec-crypto-compat | Legacy support |
| fips-ike-crypto-ecdh | fips-ipsec-crypto-gcm | Modern peers |
