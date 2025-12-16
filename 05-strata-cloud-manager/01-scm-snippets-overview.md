# Strata Cloud Manager Snippets - FIPS 140-3 Compliance Overview

## Overview

Strata Cloud Manager (SCM) snippets allow you to create reusable configuration templates that can be shared across multiple firewalls and tenants. This document provides an overview of using SCM snippets for FIPS 140-3 compliant configurations.

## What Are SCM Snippets?

Snippets are modular configuration fragments that can be:
- Created once and reused across multiple devices
- Shared between folders and tenants
- Version controlled
- Applied to specific device groups or individual firewalls
- Exported and imported for backup/migration

## FIPS 140-3 Snippet Categories

| Category | Snippet Contents |
|----------|------------------|
| IKE Crypto | FIPS-compliant IKE crypto profiles |
| IPSec Crypto | FIPS-compliant IPSec crypto profiles |
| SSL/TLS Service | FIPS-compliant TLS service profiles |
| Decryption | FIPS-compliant decryption profiles |
| Certificate Profiles | FIPS-compliant certificate validation |

## Snippet Files in This Toolkit

| File | Description |
|------|-------------|
| `02-ike-crypto-snippet.md` | IKE crypto profile snippets |
| `03-ipsec-crypto-snippet.md` | IPSec crypto profile snippets |
| `04-ssl-tls-snippet.md` | SSL/TLS service profile snippets |
| `05-ssh-snippet.md` | SSH configuration snippets |

---

## SCM API Overview

### Authentication

```bash
# Get access token
curl -X POST "https://auth.apps.paloaltonetworks.com/oauth2/access_token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "client_id=<CLIENT_ID>" \
    -d "client_secret=<CLIENT_SECRET>" \
    -d "scope=tsg_id:<TSG_ID>"
```

### Base URL

```
https://api.sase.paloaltonetworks.com/sse/config/v1
```

### Common Endpoints

| Operation | Endpoint |
|-----------|----------|
| List Snippets | `GET /snippets` |
| Get Snippet | `GET /snippets/{id}` |
| Create Snippet | `POST /snippets` |
| Update Snippet | `PUT /snippets/{id}` |
| Delete Snippet | `DELETE /snippets/{id}` |

---

## Creating Snippets via SCM API

### Create IKE Crypto Profile Snippet

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "ike-crypto-fips-256gcm",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "encryption": ["aes-256-gcm"],
        "hash": ["sha512"],
        "dh_group": ["group20"],
        "lifetime": {
            "seconds": 28800
        }
    }'
```

### Create IPSec Crypto Profile Snippet

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ipsec-crypto-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "ipsec-crypto-fips-256gcm",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "esp": {
            "encryption": ["aes-256-gcm"],
            "authentication": ["sha512"]
        },
        "dh_group": "group20",
        "lifetime": {
            "seconds": 3600
        }
    }'
```

---

## Creating Snippets via SCM Web Console

### Step 1: Navigate to Snippets
1. Log in to Strata Cloud Manager
2. Navigate to: **Manage > Configuration > NGFW and Prisma Access > Snippets**
3. Click **Add Snippet**

### Step 2: Create Snippet Container
1. **Name**: `FIPS-140-3-Crypto`
2. **Description**: FIPS 140-3 compliant cryptographic profiles
3. **Folder**: Shared (or appropriate folder)
4. Click **Create**

### Step 3: Add Configuration to Snippet
1. Select the snippet
2. Navigate to configuration section (e.g., Network Profiles)
3. Create FIPS-compliant profiles within the snippet scope
4. Save changes

### Step 4: Associate Snippet with Folders
1. Navigate to folder/device group
2. Under **Snippets**, add `FIPS-140-3-Crypto`
3. Snippet configurations become available to devices in that folder

---

## Snippet Best Practices

### Naming Conventions

```
<compliance-standard>-<function>-<algorithm>
Examples:
- fips-ike-crypto-256gcm
- fips-ipsec-crypto-multi
- fips-ssl-tls-max
- fips-decryption-profile
```

### Versioning Strategy

1. Include version in snippet name or description
2. Document changes in snippet description
3. Keep previous versions for rollback
4. Test new versions before deployment

```
Snippet Name: FIPS-140-3-Crypto-v1.2
Description:
  Version 1.2 - Updated 2024-01-15
  - Added TLS 1.3 support
  - Removed TLS 1.1 options
  - Updated cipher preferences
```

### Folder Structure

```
Shared/
├── FIPS-140-3-Crypto/
│   ├── IKE Crypto Profiles
│   ├── IPSec Crypto Profiles
│   └── SSL/TLS Service Profiles
│
├── FIPS-140-3-Decryption/
│   ├── Decryption Profiles
│   └── Certificate Profiles
│
Production/
└── (Inherits from Shared)

Development/
└── (Inherits from Shared)
```

---

## Exporting and Importing Snippets

### Export Snippet Configuration

```bash
# Get snippet configuration
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/snippets/<snippet-id>" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -o snippet-export.json
```

### Import Snippet Configuration

```bash
# Create snippet from exported configuration
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/snippets" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d @snippet-export.json
```

### Bulk Export for Backup

```bash
#!/bin/bash
# Export all snippets for backup

ACCESS_TOKEN="<your-token>"
BASE_URL="https://api.sase.paloaltonetworks.com/sse/config/v1"

# Get all snippets
snippets=$(curl -s -X GET "$BASE_URL/snippets" \
    -H "Authorization: Bearer $ACCESS_TOKEN")

# Export each snippet
echo "$snippets" | jq -r '.data[].id' | while read id; do
    curl -s -X GET "$BASE_URL/snippets/$id" \
        -H "Authorization: Bearer $ACCESS_TOKEN" \
        -o "snippet-$id.json"
done
```

---

## Applying Snippets to Devices

### Via SCM Console

1. Navigate to device or folder
2. Select **Configuration > Snippets**
3. Click **Add**
4. Select `FIPS-140-3-Crypto` snippet
5. Set priority (lower = higher priority)
6. Save and push configuration

### Via API

```bash
# Associate snippet with folder
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/folders/<folder-id>/snippets" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "snippet_id": "<snippet-id>",
        "priority": 1
    }'
```

---

## Compliance Verification

### Verify Snippet Deployment

```bash
# Get snippet associations
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/folders/<folder-id>/snippets" \
    -H "Authorization: Bearer <ACCESS_TOKEN>"

# Check device configuration
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/devices/<device-id>/candidate-config" \
    -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### Audit Trail

SCM maintains audit logs for:
- Snippet creation and modification
- Snippet association changes
- Configuration pushes
- User actions

Access audit logs via:
1. **Monitor > Logs > Configuration Logs**
2. API: `GET /audit-logs`

---

## Troubleshooting

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Snippet not visible | Wrong folder | Check snippet folder location |
| Configuration conflicts | Overlapping settings | Adjust snippet priority |
| Push failures | Invalid configuration | Validate snippet syntax |
| Version mismatch | Cached configuration | Force refresh |

### Validate Snippet Syntax

```bash
# Validate snippet before deployment
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/validate" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d @snippet-config.json
```

---

## Integration with CI/CD

### GitOps Workflow

1. Store snippet configurations in Git repository
2. Use CI/CD pipeline to validate and deploy
3. Automate testing before production deployment
4. Maintain version history in Git

### Example GitHub Actions Workflow

```yaml
name: Deploy FIPS Snippets

on:
  push:
    branches: [main]
    paths:
      - 'snippets/**'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Get SCM Token
        run: |
          TOKEN=$(curl -X POST ${{ secrets.SCM_AUTH_URL }} \
            -d "grant_type=client_credentials&client_id=${{ secrets.SCM_CLIENT_ID }}&client_secret=${{ secrets.SCM_CLIENT_SECRET }}")
          echo "ACCESS_TOKEN=$(echo $TOKEN | jq -r '.access_token')" >> $GITHUB_ENV

      - name: Validate Snippets
        run: |
          for file in snippets/*.json; do
            curl -X POST "${{ secrets.SCM_API_URL }}/validate" \
              -H "Authorization: Bearer $ACCESS_TOKEN" \
              -H "Content-Type: application/json" \
              -d @$file
          done

      - name: Deploy Snippets
        run: |
          for file in snippets/*.json; do
            curl -X PUT "${{ secrets.SCM_API_URL }}/snippets" \
              -H "Authorization: Bearer $ACCESS_TOKEN" \
              -H "Content-Type: application/json" \
              -d @$file
          done
```
