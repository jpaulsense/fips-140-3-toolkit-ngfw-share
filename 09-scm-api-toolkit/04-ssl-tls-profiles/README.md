# SSL/TLS Service Profiles API

Manage SSL/TLS service profiles through the Strata Cloud Manager API for securing management interfaces, GlobalProtect portals/gateways, and other TLS-enabled services.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config/v1/tls-service-profiles` | List all TLS service profiles |
| GET | `/config/v1/tls-service-profiles/{id}` | Get specific profile |
| POST | `/config/v1/tls-service-profiles` | Create new profile |
| PUT | `/config/v1/tls-service-profiles/{id}` | Update existing profile |
| DELETE | `/config/v1/tls-service-profiles/{id}` | Delete profile |

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `folder` | Query | Configuration folder (e.g., "Shared", "Mobile Users") |

## Profile Schema

```json
{
  "name": "string",
  "protocol_settings": {
    "min_version": "tls1-2",
    "max_version": "max",
    "keyxchg_algo_dhe": true,
    "keyxchg_algo_ecdhe": true,
    "keyxchg_algo_rsa": false,
    "enc_algo_aes_128_cbc": true,
    "enc_algo_aes_256_cbc": true,
    "enc_algo_aes_128_gcm": true,
    "enc_algo_aes_256_gcm": true,
    "enc_algo_3des": false,
    "enc_algo_rc4": false,
    "auth_algo_sha256": true,
    "auth_algo_sha384": true,
    "auth_algo_sha1": false,
    "auth_algo_md5": false
  },
  "certificate": "certificate-name"
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Profile name (max 31 chars) |
| `protocol_settings.min_version` | string | Yes | Minimum TLS version |
| `protocol_settings.max_version` | string | No | Maximum TLS version |
| `protocol_settings.keyxchg_algo_*` | boolean | No | Key exchange algorithms |
| `protocol_settings.enc_algo_*` | boolean | No | Encryption algorithms |
| `protocol_settings.auth_algo_*` | boolean | No | Authentication algorithms |
| `certificate` | string | Yes | Certificate name to use |

### TLS Version Values

| Value | Description | FIPS 140-3 |
|-------|-------------|------------|
| `tls1-0` | TLS 1.0 | Non-Compliant |
| `tls1-1` | TLS 1.1 | Non-Compliant |
| `tls1-2` | TLS 1.2 | Compliant |
| `tls1-3` | TLS 1.3 | Compliant |
| `max` | Highest available | Compliant |

### Key Exchange Algorithms (FIPS 140-3 Compliant)

| Field | Algorithm | FIPS 140-3 |
|-------|-----------|------------|
| `keyxchg_algo_ecdhe` | ECDHE | Compliant |
| `keyxchg_algo_dhe` | DHE | Compliant (2048-bit+) |
| `keyxchg_algo_rsa` | RSA | Deprecated |

### Encryption Algorithms

| Field | Algorithm | FIPS 140-3 |
|-------|-----------|------------|
| `enc_algo_aes_256_gcm` | AES-256-GCM | Compliant |
| `enc_algo_aes_128_gcm` | AES-128-GCM | Compliant |
| `enc_algo_aes_256_cbc` | AES-256-CBC | Compliant |
| `enc_algo_aes_128_cbc` | AES-128-CBC | Compliant |
| `enc_algo_3des` | 3DES | Non-Compliant |
| `enc_algo_rc4` | RC4 | Non-Compliant |

### Authentication Algorithms

| Field | Algorithm | FIPS 140-3 |
|-------|-----------|------------|
| `auth_algo_sha384` | SHA-384 | Compliant |
| `auth_algo_sha256` | SHA-256 | Compliant |
| `auth_algo_sha1` | SHA-1 | Non-Compliant |
| `auth_algo_md5` | MD5 | Non-Compliant |

## API Examples

### List All TLS Service Profiles

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/tls-service-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

**Response:**
```json
{
  "data": [
    {
      "id": "abcd1234-ef56-7890-abcd-ef1234567890",
      "name": "fips-ssl-tls-max",
      "protocol_settings": {
        "min_version": "tls1-2",
        "max_version": "max"
      },
      "certificate": "mgmt-cert",
      "folder": "Shared"
    }
  ],
  "offset": 0,
  "total": 1,
  "limit": 200
}
```

### Create FIPS 140-3 Compliant Profile (Maximum Security)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/tls-service-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ssl-tls-max",
    "protocol_settings": {
      "min_version": "tls1-2",
      "max_version": "tls1-3",
      "keyxchg_algo_ecdhe": true,
      "keyxchg_algo_dhe": false,
      "keyxchg_algo_rsa": false,
      "enc_algo_aes_256_gcm": true,
      "enc_algo_aes_128_gcm": false,
      "enc_algo_aes_256_cbc": false,
      "enc_algo_aes_128_cbc": false,
      "enc_algo_3des": false,
      "enc_algo_rc4": false,
      "auth_algo_sha384": true,
      "auth_algo_sha256": false,
      "auth_algo_sha1": false,
      "auth_algo_md5": false
    },
    "certificate": "fips-mgmt-cert"
  }'
```

### Create FIPS 140-3 Compliant Profile (Recommended)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/tls-service-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ssl-tls-recommended",
    "protocol_settings": {
      "min_version": "tls1-2",
      "max_version": "max",
      "keyxchg_algo_ecdhe": true,
      "keyxchg_algo_dhe": true,
      "keyxchg_algo_rsa": false,
      "enc_algo_aes_256_gcm": true,
      "enc_algo_aes_128_gcm": true,
      "enc_algo_aes_256_cbc": true,
      "enc_algo_aes_128_cbc": true,
      "enc_algo_3des": false,
      "enc_algo_rc4": false,
      "auth_algo_sha384": true,
      "auth_algo_sha256": true,
      "auth_algo_sha1": false,
      "auth_algo_md5": false
    },
    "certificate": "fips-mgmt-cert"
  }'
```

### Create TLS 1.3 Only Profile

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/tls-service-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ssl-tls-1-3-only",
    "protocol_settings": {
      "min_version": "tls1-3",
      "max_version": "tls1-3",
      "keyxchg_algo_ecdhe": true,
      "keyxchg_algo_dhe": false,
      "keyxchg_algo_rsa": false,
      "enc_algo_aes_256_gcm": true,
      "enc_algo_aes_128_gcm": true,
      "enc_algo_aes_256_cbc": false,
      "enc_algo_aes_128_cbc": false,
      "enc_algo_3des": false,
      "enc_algo_rc4": false,
      "auth_algo_sha384": true,
      "auth_algo_sha256": true,
      "auth_algo_sha1": false,
      "auth_algo_md5": false
    },
    "certificate": "fips-mgmt-cert"
  }'
```

### Update Profile

```bash
curl -X PUT "https://api.strata.paloaltonetworks.com/config/v1/tls-service-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ssl-tls-max",
    "protocol_settings": {
      "min_version": "tls1-3",
      "max_version": "tls1-3"
    },
    "certificate": "new-cert-name"
  }'
```

### Delete Profile

```bash
curl -X DELETE "https://api.strata.paloaltonetworks.com/config/v1/tls-service-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

## Certificate Management

TLS service profiles require a certificate. See the Certificate APIs for managing certificates:

### List Certificates

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/certificates?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

### Generate Self-Signed Certificate

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/certificates/generate?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-mgmt-cert",
    "common_name": "fw-mgmt.example.com",
    "algorithm": {
      "rsa": {
        "rsa_nbits": "3072"
      }
    },
    "signed_by": "fips-root-ca",
    "digest": "sha384"
  }'
```

## Pushing Configuration

After creating/modifying profiles, push the configuration:

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/config-versions/candidate:push" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "folders": ["Shared"],
    "description": "Deploy FIPS 140-3 TLS service profiles"
  }'
```

## Apply to Management Interface

To apply a TLS profile to the management interface via SCM:

```bash
curl -X PUT "https://api.strata.paloaltonetworks.com/config/v1/device-settings/{device-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "ssl_tls_service_profile": "fips-ssl-tls-recommended"
  }'
```

## Non-Compliant Settings (Avoid)

| Setting | Non-Compliant Values |
|---------|---------------------|
| `min_version` | `tls1-0`, `tls1-1` |
| `enc_algo_3des` | `true` |
| `enc_algo_rc4` | `true` |
| `auth_algo_sha1` | `true` |
| `auth_algo_md5` | `true` |

## FIPS 140-3 Cipher Suite Mapping

| Cipher Suite | TLS Version | Status |
|--------------|-------------|--------|
| TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | TLS 1.2 | Compliant |
| TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | TLS 1.2 | Compliant |
| TLS_AES_256_GCM_SHA384 | TLS 1.3 | Compliant |
| TLS_AES_128_GCM_SHA256 | TLS 1.3 | Compliant |
| TLS_RSA_WITH_3DES_EDE_CBC_SHA | TLS 1.2 | Non-Compliant |
| TLS_RSA_WITH_RC4_128_SHA | TLS 1.2 | Non-Compliant |
