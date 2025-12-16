# Strata Cloud Manager API Overview

## What is Strata Cloud Manager?

Strata Cloud Manager (SCM) provides unified management for Palo Alto Networks security infrastructure through a cloud-based platform. It supports:

- **On-premises NGFWs** (PA-Series, VM-Series)
- **Prisma Access** (SASE)
- **Cloud NGFW** (AWS, Azure)
- **Prisma SD-WAN**

## API Architecture

### Authentication Layer
All SCM APIs use OAuth 2.0 client credentials flow for authentication. A single access token can be used across all API services.

### Service Categories

```
Strata Cloud Manager APIs
├── Shared Services
│   ├── Tenancy Service
│   ├── Identity and Access Management
│   ├── Authentication Service
│   └── Subscription Service
│
├── Configuration Services
│   ├── SASE Configuration
│   ├── NGFW Configuration
│   ├── Cloud NGFW Configuration
│   ├── ZTNA Connector APIs
│   └── Prisma SD-WAN
│
└── Monitoring Services
    ├── Strata Insights
    ├── Aggregate Monitoring
    ├── Multitenant Notifications
    └── Autonomous DEM
```

## API Base Paths by Tenant Type

**IMPORTANT**: The API path varies depending on your tenant type:

| Tenant Type | Base Path | Description |
|-------------|-----------|-------------|
| **Prisma Access / SASE** | `/sse/config/v1/` | Prisma Access, Mobile Users, Remote Networks |
| **NGFW** | `/config/ngfw/v1/` | On-premises PA-Series, VM-Series |
| **Cloud NGFW** | `/config/cloudngfw/v1/` | AWS/Azure managed firewalls |

### How to Determine Your Tenant Type

1. Log into Strata Cloud Manager
2. Check available folders:
   - If you see "Prisma Access", "Mobile Users", "Remote Networks" → Use `/sse/config/v1/`
   - If you see "Shared", device groups → Use `/config/ngfw/v1/`

### Example: Listing IKE Profiles

**Prisma Access tenant:**
```bash
GET https://api.strata.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles?folder=Prisma%20Access
```

**NGFW tenant:**
```bash
GET https://api.strata.paloaltonetworks.com/config/ngfw/v1/ike-crypto-profiles?folder=Shared
```

## API Versioning

SCM APIs use versioned paths:

| Version | Path Pattern | Status |
|---------|--------------|--------|
| v1 | `/.../v1/` | Current |
| v2 | `/.../v2/` | Limited endpoints |

## Configuration Hierarchy

SCM uses folders and snippets to organize configuration:

```
├── Shared (Global)
│   └── Applies to all managed devices
├── Mobile Users
│   └── Prisma Access mobile users
├── Remote Networks
│   └── Prisma Access remote networks
├── Service Connections
│   └── Prisma Access service connections
└── Device Groups
    └── Specific firewall groups
```

### Folder Parameter

Most configuration endpoints require a `folder` query parameter:

```bash
GET /config/v1/ike-crypto-profiles?folder=Shared
GET /config/v1/ike-crypto-profiles?folder=Mobile%20Users
```

## Common API Patterns

### List Resources

```bash
GET /config/v1/{resource-type}?folder={folder}
```

Optional parameters:
- `limit` - Maximum results (default varies)
- `offset` - Pagination offset
- `name` - Filter by name

### Get Single Resource

```bash
GET /config/v1/{resource-type}/{id}
```

### Create Resource

```bash
POST /config/v1/{resource-type}?folder={folder}
Content-Type: application/json

{
  "name": "resource-name",
  ...
}
```

### Update Resource

```bash
PUT /config/v1/{resource-type}/{id}
Content-Type: application/json

{
  "name": "resource-name",
  ...
}
```

### Delete Resource

```bash
DELETE /config/v1/{resource-type}/{id}
```

## Configuration Jobs

Unlike direct firewall API calls, SCM configuration changes are:
1. Staged in the candidate configuration
2. Pushed via a configuration job
3. Applied to target devices

### Pushing Configuration

```bash
POST /config/v1/config-versions/candidate:push
Content-Type: application/json

{
  "folders": ["Shared"],
  "description": "FIPS 140-3 compliant profiles"
}
```

### Monitoring Jobs

```bash
GET /config/v1/jobs/{job-id}
```

## Response Codes

| Code | Description |
|------|-------------|
| 200 | Success (GET, PUT) |
| 201 | Created (POST) |
| 204 | Deleted (DELETE) |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - Invalid/expired token |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found |
| 409 | Conflict - Resource already exists |
| 500 | Server Error |

## Rate Limiting

SCM APIs implement rate limiting:
- Requests are throttled per tenant
- 429 responses indicate rate limit exceeded
- Implement exponential backoff for retries

## Regional Headers

Some services require a regional header:

```
X-PANW-Region: americas
```

Valid regions:
- `americas`
- `europe`
- `au` (Australia)
- `ca` (Canada)
- `de` (Germany)
- `in` (India)
- `jp` (Japan)
- `sg` (Singapore)
- `uk` (United Kingdom)

Required for:
- Aggregate Monitoring APIs
- ZTNA Connector APIs
- Autonomous DEM APIs
