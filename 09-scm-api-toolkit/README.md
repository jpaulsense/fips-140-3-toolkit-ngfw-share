# Strata Cloud Manager (SCM) API Toolkit

This toolkit provides comprehensive documentation and examples for managing Palo Alto Networks firewalls through the Strata Cloud Manager API.

## Overview

Strata Cloud Manager provides a unified API framework for managing:
- **NGFW** (Next-Generation Firewalls)
- **SASE** (Prisma Access)
- **Cloud NGFW** (AWS/Azure managed firewalls)

## Base URL

```
https://api.strata.paloaltonetworks.com
```

> **Note**: The legacy URL `api.sase.paloaltonetworks.com` continues to work but will be deprecated after July 2025.

## Toolkit Contents

| Directory | Description |
|-----------|-------------|
| `00-overview/` | API overview and concepts |
| `01-authentication/` | OAuth2 authentication setup |
| `02-ike-crypto-profiles/` | IKE Phase 1 crypto profile management |
| `03-ipsec-crypto-profiles/` | IPSec Phase 2 crypto profile management |
| `04-ssl-tls-profiles/` | SSL/TLS service profile management |
| `05-interface-management/` | Interface management profile APIs |
| `06-python-sdk/` | Python SDK wrapper and utilities |
| `07-examples/` | Complete working examples |

## Quick Start

### 1. Get Your Credentials

1. Log into Strata Cloud Manager
2. Navigate to **Settings** > **Identity & Access** > **Service Accounts**
3. Create a new service account
4. Note your **Client ID** and **Client Secret**
5. Identify your **Tenant Service Group (TSG) ID**

### 2. Authenticate

```bash
curl -X POST "https://auth.apps.paloaltonetworks.com/oauth2/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "<CLIENT_ID>:<CLIENT_SECRET>" \
  -d "grant_type=client_credentials&scope=tsg_id:<TSG_ID>"
```

### 3. Make API Calls

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json"
```

## API Categories

### Configuration APIs

| Category | Base Path | Description |
|----------|-----------|-------------|
| NGFW Network | `/config/ngfw/v1/` | Network configuration for NGFWs |
| NGFW Objects | `/config/ngfw/v1/` | Address/service objects |
| NGFW Security | `/config/ngfw/v1/` | Security policies and profiles |
| SASE Config | `/config/sase/v1/` | Prisma Access configuration |

### Monitoring APIs

| Category | Base Path | Description |
|----------|-----------|-------------|
| Strata Insights | `/insights/` | Analytics and reporting |
| Aggregate Monitoring | `/mt/monitor/` | Multi-tenant monitoring |

## FIPS 140-3 Integration

This toolkit integrates with the FIPS 140-3 Compliance Toolkit for creating compliant cryptographic profiles via SCM API:

- IKE Crypto Profiles with FIPS-compliant algorithms
- IPSec Crypto Profiles with approved encryption
- SSL/TLS Profiles with TLS 1.2+ minimum

See the individual profile directories for FIPS-compliant configurations.

## Related Documentation

- [SCM API Home](https://pan.dev/scm/docs/home/)
- [Getting Started Guide](https://pan.dev/scm/docs/getstarted/)
- [API Call Reference](https://pan.dev/scm/docs/api-call/)
- [pan-scm-sdk (Python)](https://cdot65.github.io/pan-scm-sdk/sdk/)
- [Release Notes](https://pan.dev/scm/docs/release-notes/)
