# Interface Management Profiles API

Manage interface management profiles through the Strata Cloud Manager API to control which protocols are permitted on firewall interfaces.

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/config/v1/interface-management-profiles` | List all profiles |
| GET | `/config/v1/interface-management-profiles/{id}` | Get specific profile |
| POST | `/config/v1/interface-management-profiles` | Create new profile |
| PUT | `/config/v1/interface-management-profiles/{id}` | Update existing profile |
| DELETE | `/config/v1/interface-management-profiles/{id}` | Delete profile |

## Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `folder` | Query | Configuration folder (e.g., "Shared") |

## Profile Schema

```json
{
  "name": "string",
  "https": true,
  "http": false,
  "ssh": true,
  "telnet": false,
  "ping": true,
  "snmp": false,
  "response_pages": false,
  "http_ocsp": false,
  "userid_service": false,
  "userid_syslog_listener_ssl": false,
  "userid_syslog_listener_udp": false,
  "permitted_ip": [
    "10.0.0.0/8",
    "192.168.1.0/24"
  ]
}
```

### Field Definitions

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Profile name (max 31 chars) |
| `https` | boolean | No | Enable HTTPS management |
| `http` | boolean | No | Enable HTTP management (non-compliant) |
| `ssh` | boolean | No | Enable SSH access |
| `telnet` | boolean | No | Enable Telnet (non-compliant) |
| `ping` | boolean | No | Enable ICMP ping responses |
| `snmp` | boolean | No | Enable SNMP |
| `response_pages` | boolean | No | Enable response pages |
| `http_ocsp` | boolean | No | Enable HTTP OCSP responder |
| `userid_service` | boolean | No | Enable User-ID service |
| `userid_syslog_listener_ssl` | boolean | No | Enable User-ID syslog over SSL |
| `userid_syslog_listener_udp` | boolean | No | Enable User-ID syslog over UDP |
| `permitted_ip` | array | No | List of permitted source IPs/networks |

### FIPS 140-3 Compliance

| Protocol | FIPS Status | Recommendation |
|----------|-------------|----------------|
| HTTPS | Compliant | Enable |
| SSH | Compliant | Enable |
| HTTP | Non-Compliant | Disable |
| Telnet | Non-Compliant | Disable |
| Ping | N/A | Enable as needed |
| SNMP | Depends | Use SNMPv3 only |

## API Examples

### List All Interface Management Profiles

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/interface-management-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

**Response:**
```json
{
  "data": [
    {
      "id": "fedcba98-7654-3210-fedc-ba9876543210",
      "name": "fips-mgmt-profile",
      "https": true,
      "http": false,
      "ssh": true,
      "telnet": false,
      "ping": true,
      "folder": "Shared"
    }
  ],
  "offset": 0,
  "total": 1,
  "limit": 200
}
```

### Create FIPS 140-3 Compliant Profile (Full Management)

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/interface-management-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-mgmt-profile",
    "https": true,
    "http": false,
    "ssh": true,
    "telnet": false,
    "ping": true,
    "snmp": false,
    "response_pages": false,
    "permitted_ip": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ]
  }'
```

### Create HTTPS-Only Profile

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/interface-management-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-https-only",
    "https": true,
    "http": false,
    "ssh": false,
    "telnet": false,
    "ping": true,
    "snmp": false,
    "response_pages": true,
    "permitted_ip": [
      "10.0.0.0/8"
    ]
  }'
```

### Create Monitoring-Only Profile

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/interface-management-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-monitoring-only",
    "https": false,
    "http": false,
    "ssh": false,
    "telnet": false,
    "ping": true,
    "snmp": true,
    "response_pages": false
  }'
```

### Create User-ID Service Profile

```bash
curl -X POST "https://api.strata.paloaltonetworks.com/config/v1/interface-management-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-userid-profile",
    "https": true,
    "http": false,
    "ssh": false,
    "telnet": false,
    "ping": true,
    "snmp": false,
    "userid_service": true,
    "userid_syslog_listener_ssl": true,
    "userid_syslog_listener_udp": false,
    "permitted_ip": [
      "10.1.0.0/24"
    ]
  }'
```

### Update Profile

```bash
curl -X PUT "https://api.strata.paloaltonetworks.com/config/v1/interface-management-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-mgmt-profile",
    "https": true,
    "http": false,
    "ssh": true,
    "telnet": false,
    "ping": true,
    "permitted_ip": [
      "10.0.0.0/8",
      "192.168.1.100/32"
    ]
  }'
```

### Delete Profile

```bash
curl -X DELETE "https://api.strata.paloaltonetworks.com/config/v1/interface-management-profiles/{profile-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}"
```

## Applying to Interfaces

After creating a management profile, apply it to an interface:

### List Ethernet Interfaces

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/ethernet-interfaces?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

### Update Interface with Management Profile

```bash
curl -X PUT "https://api.strata.paloaltonetworks.com/config/v1/ethernet-interfaces/{interface-id}" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ethernet1/1",
    "layer3": {
      "ip": ["192.168.1.1/24"],
      "interface_management_profile": "fips-mgmt-profile"
    }
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
    "description": "Deploy FIPS 140-3 interface management profiles"
  }'
```

## Non-Compliant Settings (Avoid)

| Setting | Reason |
|---------|--------|
| `http: true` | Unencrypted management traffic |
| `telnet: true` | Unencrypted management protocol |
| `userid_syslog_listener_udp: true` | Unencrypted User-ID traffic |

## Best Practices

### 1. Use IP Restrictions

Always specify `permitted_ip` to limit management access:

```json
{
  "permitted_ip": [
    "10.0.0.0/24",
    "192.168.1.100/32"
  ]
}
```

### 2. Separate Profiles by Function

| Profile | HTTPS | SSH | Ping | Use Case |
|---------|-------|-----|------|----------|
| fips-mgmt-profile | Yes | Yes | Yes | Full management |
| fips-https-only | Yes | No | Yes | Web-only management |
| fips-monitoring-only | No | No | Yes | Monitoring only |

### 3. Apply Least Privilege

Only enable protocols that are required for each interface's function.

## Error Handling

| Error Code | Description | Resolution |
|------------|-------------|------------|
| 400 | Invalid request body | Check JSON syntax |
| 401 | Unauthorized | Refresh access token |
| 403 | Forbidden | Check role permissions |
| 404 | Profile not found | Verify profile ID |
| 409 | Name conflict | Use unique profile name |
