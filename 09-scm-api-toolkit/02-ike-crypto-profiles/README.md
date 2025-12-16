# IKE Crypto Profiles API

Manage IKE (Internet Key Exchange) Phase 1 crypto profiles through the Strata Cloud Manager API.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config/v1/ike-crypto-profiles` | List all IKE crypto profiles |
| GET | `/config/v1/ike-crypto-profiles/{id}` | Get specific profile |
| POST | `/config/v1/ike-crypto-profiles` | Create new profile |
| PUT | `/config/v1/ike-crypto-profiles/{id}` | Update existing profile |
| DELETE | `/config/v1/ike-crypto-profiles/{id}` | Delete profile |

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `folder` | Query | Configuration folder (e.g., "Shared", "Mobile Users") |

## Profile Schema

```json
{
  "name": "string",
  "authentication": ["string"],
  "encryption": ["string"],
  "dh_group": ["string"],
  "lifetime": {
    "hours": 8
  }
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Profile name (max 31 chars) |
| `authentication` | array | Yes | Hash algorithms |
| `encryption` | array | Yes | Encryption algorithms |
| `dh_group` | array | Yes | Diffie-Hellman groups |
| `lifetime` | object | No | Key lifetime settings |

### Valid Values

#### Encryption (FIPS 140-3 Compliant)

| Value | Description |
|-------|-------------|
| `aes-128-cbc` | AES 128-bit CBC |
| `aes-192-cbc` | AES 192-bit CBC |
| `aes-256-cbc` | AES 256-bit CBC |
| `aes-128-gcm` | AES 128-bit GCM |
| `aes-256-gcm` | AES 256-bit GCM |

#### Authentication (FIPS 140-3 Compliant)

| Value | Description |
|-------|-------------|
| `sha256` | SHA-256 |
| `sha384` | SHA-384 |
| `sha512` | SHA-512 |

#### DH Groups (FIPS 140-3 Compliant)

| Value | Description |
|-------|-------------|
| `group14` | 2048-bit MODP |
| `group15` | 3072-bit MODP |
| `group16` | 4096-bit MODP |
| `group19` | 256-bit ECP (P-256) |
| `group20` | 384-bit ECP (P-384) |
| `group21` | 521-bit ECP (P-521) |

## API Examples

### List All IKE Crypto Profiles

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

**Response:**
```json
{
  "data": [
    {
      "id": "12345678-1234-1234-1234-123456789012",
      "name": "fips-ike-crypto-max",
      "encryption": ["aes-256-gcm"],
      "authentication": ["sha512"],
      "dh_group": ["group20"],
      "lifetime": {
        "hours": 8
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
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

### Create FIPS 140-3 Compliant Profile (Maximum Security)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ike-crypto-max",
    "encryption": ["aes-256-gcm"],
    "authentication": ["sha512"],
    "dh_group": ["group20"],
    "lifetime": {
      "hours": 8
    }
  }'
```

**Response (201 Created):**
```json
{
  "id": "12345678-1234-1234-1234-123456789012",
  "name": "fips-ike-crypto-max",
  "encryption": ["aes-256-gcm"],
  "authentication": ["sha512"],
  "dh_group": ["group20"],
  "lifetime": {
    "hours": 8
  },
  "folder": "Shared"
}
```

### Create FIPS 140-3 Compliant Profile (Recommended)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ike-crypto-recommended",
    "encryption": ["aes-256-cbc", "aes-128-gcm"],
    "authentication": ["sha384", "sha256"],
    "dh_group": ["group20", "group19"],
    "lifetime": {
      "hours": 8
    }
  }'
```

### Create FIPS 140-3 Compliant Profile (Compatible)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ike-crypto-compat",
    "encryption": ["aes-256-cbc", "aes-256-gcm", "aes-128-cbc", "aes-128-gcm"],
    "authentication": ["sha512", "sha384", "sha256"],
    "dh_group": ["group20", "group19", "group16", "group14"],
    "lifetime": {
      "hours": 8
    }
  }'
```

### Update Profile

```bash
curl -X PUT "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ike-crypto-max",
    "encryption": ["aes-256-gcm"],
    "authentication": ["sha512"],
    "dh_group": ["group21", "group20"],
    "lifetime": {
      "hours": 4
    }
  }'
```

### Delete Profile

```bash
curl -X DELETE "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

**Response (200 OK):**
```json
{
  "id": "12345678-1234-1234-1234-123456789012"
}
```

## Pushing Configuration

After creating/modifying profiles, push the configuration:

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/config-versions/candidate:push" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "folders": ["Shared"],
    "description": "Deploy FIPS 140-3 IKE crypto profiles"
  }'
```

**Response:**
```json
{
  "success": true,
  "job_id": "123"
}
```

## Non-Compliant Values (Avoid)

These values should NOT be used for FIPS 140-3 compliance:

| Type | Non-Compliant Values |
|------|---------------------|
| Encryption | `3des`, `des` |
| Authentication | `md5`, `sha1` |
| DH Groups | `group1`, `group2`, `group5` |

## Error Handling

| Error Code | Description | Resolution |
|------------|-------------|------------|
| 400 | Invalid request body | Check JSON syntax and field values |
| 401 | Unauthorized | Refresh access token |
| 403 | Forbidden | Check role permissions |
| 404 | Profile not found | Verify profile ID |
| 409 | Name conflict | Use unique profile name |
