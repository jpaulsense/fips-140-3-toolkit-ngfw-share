# PAN-OS API Reference for FIPS 140-3 Configuration

## Overview

This document provides a comprehensive API reference for configuring FIPS 140-3 compliant settings on Palo Alto Networks firewalls. It covers authentication, common endpoints, and API patterns.

---

## API Authentication

### Generate API Key

```bash
# Generate API key using username/password
curl -k -X GET "https://<firewall>/api/?type=keygen&user=<username>&password=<password>"

# Response
<response status="success">
    <result>
        <key>LUFRPT1wdXd...</key>
    </result>
</response>
```

### Use API Key in Requests

```bash
# Include key parameter in all requests
curl -k -X GET "https://<firewall>/api/?type=config&action=get&key=<API_KEY>&xpath=/config/..."
```

---

## API Endpoints and Methods

### Base URL

```
https://<firewall>/api/
```

### Request Types

| Type | Description |
|------|-------------|
| `keygen` | Generate API key |
| `config` | Configuration operations |
| `op` | Operational commands |
| `commit` | Commit configuration |
| `import` | Import files (certs, etc.) |
| `export` | Export files |
| `report` | Generate reports |

### Configuration Actions

| Action | Description |
|--------|-------------|
| `get` | Retrieve configuration |
| `set` | Create/update configuration |
| `edit` | Replace configuration element |
| `delete` | Remove configuration |
| `rename` | Rename element |
| `clone` | Clone element |
| `move` | Move element |
| `show` | Show configuration (includes inherited) |

---

## Common XPath References

### Network Configuration

```
# IKE Crypto Profiles
/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles

# IPSec Crypto Profiles
/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles

# IKE Gateways
/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway

# IPSec Tunnels
/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec

# Tunnel Interfaces
/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units

# GlobalProtect Portal
/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-portal

# GlobalProtect Gateway
/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-gateway
```

### Security Configuration

```
# SSL/TLS Service Profiles
/config/shared/ssl-tls-service-profile

# Certificate Profiles
/config/shared/certificate-profile

# Decryption Profiles
/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/decryption

# SSH Proxy Profiles
/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/ssh-proxy

# Decryption Rules
/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/decryption
```

### Device Configuration

```
# System Settings
/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system

# Management Interface
/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile

# Permitted IPs
/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/permitted-ip

# Interface Management Profiles
/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile
```

### Certificate Management

```
# Certificates
/config/shared/certificate

# OCSP Responders
/config/shared/ocsp-responder
```

---

## FIPS-Specific API Patterns

### Create IKE Crypto Profile

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API_KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='fips-ike-profile']" \
    -d "element=<entry name='fips-ike-profile'><encryption><member>aes-256-gcm</member></encryption><hash><member>sha512</member></hash><dh-group><member>group20</member></dh-group><lifetime><seconds>28800</seconds></lifetime></entry>"
```

### Create IPSec Crypto Profile

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API_KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='fips-ipsec-profile']" \
    -d "element=<entry name='fips-ipsec-profile'><esp><encryption><member>aes-256-gcm</member></encryption></esp><dh-group>group20</dh-group><lifetime><seconds>3600</seconds></lifetime></entry>"
```

### Create SSL/TLS Service Profile

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API_KEY>" \
    -d "xpath=/config/shared/ssl-tls-service-profile/entry[@name='fips-ssl-profile']" \
    -d "element=<entry name='fips-ssl-profile'><certificate>mgmt-cert</certificate><protocol-settings><min-version>tls1-2</min-version><max-version>tls1-3</max-version><keyxchg-algo-rsa>no</keyxchg-algo-rsa><enc-algo-3des>no</enc-algo-3des><enc-algo-rc4>no</enc-algo-rc4><auth-algo-sha1>no</auth-algo-sha1></protocol-settings></entry>"
```

---

## Operational Commands

### Show System Information

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<show><system><info></info></system></show>"
```

### Show VPN Status

```bash
# IKE SA
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<show><vpn><ike-sa></ike-sa></vpn></show>"

# IPSec SA
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<show><vpn><ipsec-sa></ipsec-sa></vpn></show>"
```

### Show Certificate Information

```bash
# Certificate summary
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<show><certificate><summary></summary></certificate></show>"

# Specific certificate
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<show><certificate><name>cert-name</name></certificate></show>"
```

### Show SSH Host Keys

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<show><ssh><system><host-key><fingerprint></fingerprint></host-key></system></ssh></show>"
```

---

## Certificate Operations

### Generate CSR

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<request><certificate><generate-csr><certificate-name>mgmt-cert</certificate-name><name>cn=firewall.example.com,o=Org,c=US</name><algorithm>RSA</algorithm><rsa-nbits>3072</rsa-nbits><digest>sha384</digest></generate-csr></certificate></request>"
```

### Import Certificate

```bash
curl -k -X POST "https://<firewall>/api/" \
    -F "type=import" \
    -F "category=certificate" \
    -F "certificate-name=mgmt-cert" \
    -F "format=pem" \
    -F "key=<API_KEY>" \
    -F "file=@/path/to/cert.pem"
```

### Export Certificate

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<request><certificate><export><certificate-name>mgmt-cert</certificate-name><format>pem</format></export></certificate></request>"
```

### Regenerate SSH Host Keys

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<request><ssh><system><host-key><regenerate></regenerate></host-key></system></ssh></request>"
```

---

## Commit Operations

### Commit Configuration

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=commit" \
    -d "cmd=<commit></commit>" \
    -d "key=<API_KEY>"
```

### Commit with Force

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=commit" \
    -d "cmd=<commit><force></force></commit>" \
    -d "key=<API_KEY>"
```

### Check Commit Status

```bash
# Get job ID from commit response, then:
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API_KEY>" \
    -d "cmd=<show><jobs><id>JOB_ID</id></jobs></show>"
```

---

## Error Handling

### Common Response Codes

| Status | Description |
|--------|-------------|
| `success` | Operation completed successfully |
| `error` | Operation failed |

### Error Response Format

```xml
<response status="error" code="CODE">
    <result>
        <msg>Error message description</msg>
    </result>
</response>
```

### Common Errors

| Code | Description | Resolution |
|------|-------------|------------|
| `400` | Bad request | Check XML syntax |
| `401` | Unauthorized | Verify API key |
| `403` | Forbidden | Check permissions |
| `404` | Not found | Verify xpath |
| `500` | Internal error | Check firewall logs |

---

## Best Practices

1. **Always validate XML syntax** before sending API requests
2. **Use HTTPS** for all API communications
3. **Store API keys securely** - never hardcode in scripts
4. **Implement error handling** in automation scripts
5. **Test in non-production** before deploying changes
6. **Use commit with job tracking** for verification
7. **Log all API operations** for audit trails
8. **Rate limit requests** to avoid overwhelming the firewall
9. **Use operational commands** for verification before commits
10. **Backup configuration** before making bulk changes
