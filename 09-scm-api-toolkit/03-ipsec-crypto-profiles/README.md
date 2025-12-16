# IPSec Crypto Profiles API

Manage IPSec (Phase 2) crypto profiles through the Strata Cloud Manager API.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config/v1/ipsec-crypto-profiles` | List all IPSec crypto profiles |
| GET | `/config/v1/ipsec-crypto-profiles/{id}` | Get specific profile |
| POST | `/config/v1/ipsec-crypto-profiles` | Create new profile |
| PUT | `/config/v1/ipsec-crypto-profiles/{id}` | Update existing profile |
| DELETE | `/config/v1/ipsec-crypto-profiles/{id}` | Delete profile |

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `folder` | Query | Configuration folder (e.g., "Shared", "Mobile Users") |

## Profile Schema

```json
{
  "name": "string",
  "esp": {
    "encryption": ["string"],
    "authentication": ["string"]
  },
  "dh_group": "string",
  "lifetime": {
    "hours": 1
  },
  "lifesize": {
    "gb": 100
  }
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Profile name (max 31 chars) |
| `esp.encryption` | array | Yes | ESP encryption algorithms |
| `esp.authentication` | array | Yes | ESP authentication algorithms |
| `dh_group` | string | No | PFS DH group (defaults to no-pfs) |
| `lifetime` | object | No | SA lifetime in time |
| `lifesize` | object | No | SA lifetime in data volume |

### Valid Values

#### ESP Encryption (FIPS 140-3 Compliant)

| Value | Description |
|-------|-------------|
| `aes-128-cbc` | AES 128-bit CBC |
| `aes-192-cbc` | AES 192-bit CBC |
| `aes-256-cbc` | AES 256-bit CBC |
| `aes-128-gcm` | AES 128-bit GCM (includes auth) |
| `aes-256-gcm` | AES 256-bit GCM (includes auth) |

#### ESP Authentication (FIPS 140-3 Compliant)

| Value | Description |
|-------|-------------|
| `sha256` | SHA-256 HMAC |
| `sha384` | SHA-384 HMAC |
| `sha512` | SHA-512 HMAC |

> **Note**: When using GCM encryption, authentication is built-in. Use `none` for authentication or omit it.

#### DH Groups for PFS (FIPS 140-3 Compliant)

| Value | Description |
|-------|-------------|
| `group14` | 2048-bit MODP |
| `group15` | 3072-bit MODP |
| `group16` | 4096-bit MODP |
| `group19` | 256-bit ECP (P-256) |
| `group20` | 384-bit ECP (P-384) |
| `group21` | 521-bit ECP (P-521) |

## API Examples

### List All IPSec Crypto Profiles

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

**Response:**
```json
{
  "data": [
    {
      "id": "87654321-4321-4321-4321-210987654321",
      "name": "fips-ipsec-crypto-max",
      "esp": {
        "encryption": ["aes-256-gcm"],
        "authentication": ["sha512"]
      },
      "dh_group": "group20",
      "lifetime": {
        "hours": 1
      },
      "folder": "Shared"
    }
  ],
  "offset": 0,
  "total": 1,
  "limit": 200
}
```

### Get Single Profile

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create FIPS 140-3 Compliant Profile (Maximum Security)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ipsec-crypto-max",
    "esp": {
      "encryption": ["aes-256-gcm"],
      "authentication": ["sha512"]
    },
    "dh_group": "group20",
    "lifetime": {
      "hours": 1
    },
    "lifesize": {
      "gb": 100
    }
  }'
```

**Response (201 Created):**
```json
{
  "id": "87654321-4321-4321-4321-210987654321",
  "name": "fips-ipsec-crypto-max",
  "esp": {
    "encryption": ["aes-256-gcm"],
    "authentication": ["sha512"]
  },
  "dh_group": "group20",
  "lifetime": {
    "hours": 1
  },
  "lifesize": {
    "gb": 100
  },
  "folder": "Shared"
}
```

### Create FIPS 140-3 Compliant Profile (Recommended)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ipsec-crypto-recommended",
    "esp": {
      "encryption": ["aes-256-gcm", "aes-128-gcm"],
      "authentication": ["sha384", "sha256"]
    },
    "dh_group": "group20",
    "lifetime": {
      "hours": 1
    }
  }'
```

### Create FIPS 140-3 Compliant Profile (Compatible)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ipsec-crypto-compat",
    "esp": {
      "encryption": ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
      "authentication": ["sha512", "sha384", "sha256"]
    },
    "dh_group": "group14",
    "lifetime": {
      "hours": 1
    }
  }'
```

### Create GlobalProtect IPSec Profile

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles?folder=Mobile%20Users" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ipsec-crypto-gp",
    "esp": {
      "encryption": ["aes-256-gcm", "aes-128-gcm"],
      "authentication": ["sha256"]
    },
    "dh_group": "group19",
    "lifetime": {
      "hours": 1
    }
  }'
```

### Update Profile

```bash
curl -X PUT "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ipsec-crypto-max",
    "esp": {
      "encryption": ["aes-256-gcm"],
      "authentication": ["sha512"]
    },
    "dh_group": "group21",
    "lifetime": {
      "hours": 1
    },
    "lifesize": {
      "gb": 50
    }
  }'
```

### Delete Profile

```bash
curl -X DELETE "https://api.strata.paloaltonetworks.com/config/v1/ipsec-crypto-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

## Pushing Configuration

After creating/modifying profiles, push the configuration:

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/config-versions/candidate:push" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "folders": ["Shared"],
    "description": "Deploy FIPS 140-3 IPSec crypto profiles"
  }'
```

## Non-Compliant Values (Avoid)

These values should NOT be used for FIPS 140-3 compliance:

| Type | Non-Compliant Values |
|------|---------------------|
| Encryption | `3des`, `des`, `null` |
| Authentication | `md5`, `sha1` |
| DH Groups | `group1`, `group2`, `group5`, `no-pfs` |

## Lifetime Recommendations

| Use Case | Time | Data |
|----------|------|------|
| High Security | 30 minutes | 10 GB |
| Standard | 1 hour | 100 GB |
| High Volume | 8 hours | 1 TB |

## Error Handling

| Error Code | Description | Resolution |
|------------|-------------|------------|
| 400 | Invalid request body | Check JSON syntax and field values |
| 401 | Unauthorized | Refresh access token |
| 403 | Forbidden | Check role permissions |
| 404 | Profile not found | Verify profile ID |
| 409 | Name conflict | Use unique profile name |
