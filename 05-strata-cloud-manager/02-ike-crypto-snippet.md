# IKE Crypto Profile Snippets - FIPS 140-3 Compliance

## Overview

This document provides Strata Cloud Manager snippets for FIPS 140-3 compliant IKE crypto profiles. These snippets can be deployed across multiple firewalls to ensure consistent, compliant VPN configurations.

---

## Snippet: Maximum Security (AES-256-GCM)

### JSON Configuration

```json
{
    "name": "fips-ike-crypto-max",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Maximum Security - AES-256-GCM with ECDH P-384",
    "encryption": [
        "aes-256-gcm"
    ],
    "hash": [
        "sha512"
    ],
    "dh_group": [
        "group20"
    ],
    "lifetime": {
        "seconds": 28800
    },
    "authentication_multiple": 0
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ike-crypto-max",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Maximum Security - AES-256-GCM with ECDH P-384",
        "encryption": ["aes-256-gcm"],
        "hash": ["sha512"],
        "dh_group": ["group20"],
        "lifetime": {"seconds": 28800}
    }'
```

---

## Snippet: Recommended (AES-256-CBC with Multiple Options)

### JSON Configuration

```json
{
    "name": "fips-ike-crypto-recommended",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Recommended - Balanced security and compatibility",
    "encryption": [
        "aes-256-gcm",
        "aes-256-cbc",
        "aes-128-gcm",
        "aes-128-cbc"
    ],
    "hash": [
        "sha512",
        "sha384",
        "sha256"
    ],
    "dh_group": [
        "group20",
        "group19",
        "group16",
        "group15",
        "group14"
    ],
    "lifetime": {
        "seconds": 28800
    },
    "authentication_multiple": 0
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ike-crypto-recommended",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Recommended - Balanced security and compatibility",
        "encryption": ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
        "hash": ["sha512", "sha384", "sha256"],
        "dh_group": ["group20", "group19", "group16", "group15", "group14"],
        "lifetime": {"seconds": 28800}
    }'
```

---

## Snippet: Minimum Acceptable (Legacy Compatibility)

### JSON Configuration

```json
{
    "name": "fips-ike-crypto-minimum",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Minimum - For legacy peer compatibility",
    "encryption": [
        "aes-256-cbc",
        "aes-192-cbc",
        "aes-128-cbc"
    ],
    "hash": [
        "sha384",
        "sha256"
    ],
    "dh_group": [
        "group16",
        "group15",
        "group14"
    ],
    "lifetime": {
        "seconds": 28800
    },
    "authentication_multiple": 0
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ike-crypto-minimum",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Minimum - For legacy peer compatibility",
        "encryption": ["aes-256-cbc", "aes-192-cbc", "aes-128-cbc"],
        "hash": ["sha384", "sha256"],
        "dh_group": ["group16", "group15", "group14"],
        "lifetime": {"seconds": 28800}
    }'
```

---

## Snippet: ECDH Only (Modern Peers)

### JSON Configuration

```json
{
    "name": "fips-ike-crypto-ecdh",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 ECDH Only - For modern peer devices",
    "encryption": [
        "aes-256-gcm",
        "aes-128-gcm"
    ],
    "hash": [
        "sha512",
        "sha384"
    ],
    "dh_group": [
        "group20",
        "group19"
    ],
    "lifetime": {
        "seconds": 28800
    },
    "authentication_multiple": 0
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ike-crypto-ecdh",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 ECDH Only - For modern peer devices",
        "encryption": ["aes-256-gcm", "aes-128-gcm"],
        "hash": ["sha512", "sha384"],
        "dh_group": ["group20", "group19"],
        "lifetime": {"seconds": 28800}
    }'
```

---

## Bulk Snippet Deployment Script

### Deploy All IKE Crypto Snippets

```bash
#!/bin/bash

# Configuration
SCM_API_URL="https://api.sase.paloaltonetworks.com/sse/config/v1"
ACCESS_TOKEN="<your-access-token>"

# Function to create IKE crypto profile
create_ike_profile() {
    local name=$1
    local description=$2
    local encryption=$3
    local hash=$4
    local dh_group=$5
    local lifetime=${6:-28800}

    curl -s -X POST "$SCM_API_URL/ike-crypto-profiles" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -H "Content-Type: application/json" \
        -d "{
            \"name\": \"$name\",
            \"folder\": \"Shared\",
            \"snippet\": \"FIPS-140-3-Crypto\",
            \"description\": \"$description\",
            \"encryption\": $encryption,
            \"hash\": $hash,
            \"dh_group\": $dh_group,
            \"lifetime\": {\"seconds\": $lifetime}
        }"
}

# Deploy Maximum Security Profile
echo "Deploying fips-ike-crypto-max..."
create_ike_profile \
    "fips-ike-crypto-max" \
    "FIPS 140-3 Maximum Security" \
    '["aes-256-gcm"]' \
    '["sha512"]' \
    '["group20"]'

# Deploy Recommended Profile
echo "Deploying fips-ike-crypto-recommended..."
create_ike_profile \
    "fips-ike-crypto-recommended" \
    "FIPS 140-3 Recommended" \
    '["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"]' \
    '["sha512", "sha384", "sha256"]' \
    '["group20", "group19", "group16", "group15", "group14"]'

# Deploy Minimum Profile
echo "Deploying fips-ike-crypto-minimum..."
create_ike_profile \
    "fips-ike-crypto-minimum" \
    "FIPS 140-3 Minimum" \
    '["aes-256-cbc", "aes-192-cbc", "aes-128-cbc"]' \
    '["sha384", "sha256"]' \
    '["group16", "group15", "group14"]'

# Deploy ECDH Only Profile
echo "Deploying fips-ike-crypto-ecdh..."
create_ike_profile \
    "fips-ike-crypto-ecdh" \
    "FIPS 140-3 ECDH Only" \
    '["aes-256-gcm", "aes-128-gcm"]' \
    '["sha512", "sha384"]' \
    '["group20", "group19"]'

echo "All IKE crypto profiles deployed."
```

---

## Verification

### List Deployed IKE Crypto Profiles

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

### Get Specific Profile

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles/fips-ike-crypto-max" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

### Verify Profile in Folder

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles?folder=Shared&snippet=FIPS-140-3-Crypto" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

---

## Cleanup

### Delete IKE Crypto Profile

```bash
curl -X DELETE "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles/<profile-id>" \
    -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### Delete All FIPS IKE Profiles Script

```bash
#!/bin/bash

SCM_API_URL="https://api.sase.paloaltonetworks.com/sse/config/v1"
ACCESS_TOKEN="<your-access-token>"

# Get all profiles in snippet
profiles=$(curl -s -X GET "$SCM_API_URL/ike-crypto-profiles?snippet=FIPS-140-3-Crypto" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

# Delete each profile
echo "$profiles" | jq -r '.data[].id' | while read id; do
    echo "Deleting profile $id..."
    curl -s -X DELETE "$SCM_API_URL/ike-crypto-profiles/$id" \
        -H "Authorization: Bearer $ACCESS_TOKEN"
done

echo "All FIPS IKE crypto profiles deleted."
```

---

## Algorithm Reference

### Encryption Algorithms Available

| Algorithm | SCM Value | FIPS Status |
|-----------|-----------|-------------|
| AES-128-CBC | `aes-128-cbc` | Compliant |
| AES-192-CBC | `aes-192-cbc` | Compliant |
| AES-256-CBC | `aes-256-cbc` | Compliant |
| AES-128-GCM | `aes-128-gcm` | Compliant |
| AES-256-GCM | `aes-256-gcm` | Compliant |
| 3DES | `3des` | **Non-Compliant** |
| DES | `des` | **Non-Compliant** |

### Hash Algorithms Available

| Algorithm | SCM Value | FIPS Status |
|-----------|-----------|-------------|
| SHA-256 | `sha256` | Compliant |
| SHA-384 | `sha384` | Compliant |
| SHA-512 | `sha512` | Compliant |
| SHA-1 | `sha1` | **Non-Compliant** |
| MD5 | `md5` | **Non-Compliant** |

### DH Groups Available

| Group | SCM Value | FIPS Status |
|-------|-----------|-------------|
| Group 14 (2048-bit) | `group14` | Compliant |
| Group 15 (3072-bit) | `group15` | Compliant |
| Group 16 (4096-bit) | `group16` | Compliant |
| Group 19 (P-256) | `group19` | Compliant |
| Group 20 (P-384) | `group20` | Compliant |
| Group 21 (P-521) | `group21` | Compliant |
| Group 1 (768-bit) | `group1` | **Non-Compliant** |
| Group 2 (1024-bit) | `group2` | **Non-Compliant** |
| Group 5 (1536-bit) | `group5` | **Non-Compliant** |
