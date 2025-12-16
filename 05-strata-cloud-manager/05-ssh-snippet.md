# SSH Configuration Snippets - FIPS 140-3 Compliance

## Overview

This document provides Strata Cloud Manager snippets for FIPS 140-3 compliant SSH configurations. These snippets cover SSH service settings and SSH proxy profiles for traffic inspection.

**Note:** SSH server algorithm configuration is typically managed at the PAN-OS level rather than through SCM snippets. This document focuses on SSH proxy profiles for decryption and management interface settings that can be deployed via SCM.

---

## SSH Proxy Profile Snippets

### Snippet: Pass-Through Mode (Command Visibility)

```json
{
    "name": "fips-ssh-proxy-passthrough",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 SSH Proxy - Pass-through for command visibility",
    "mode": "pass-through"
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ssh-proxy-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssh-proxy-passthrough",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 SSH Proxy - Pass-through for command visibility",
        "mode": "pass-through"
    }'
```

---

### Snippet: Decrypt Mode (Full Inspection)

```json
{
    "name": "fips-ssh-proxy-decrypt",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 SSH Proxy - Full decryption for inspection",
    "mode": "decrypt",
    "block_partial": true
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ssh-proxy-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssh-proxy-decrypt",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 SSH Proxy - Full decryption for inspection",
        "mode": "decrypt",
        "block_partial": true
    }'
```

---

### Snippet: Restricted Features (Block Tunneling)

```json
{
    "name": "fips-ssh-proxy-restricted",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 SSH Proxy - Block port forwarding and tunneling",
    "mode": "pass-through",
    "block_shell": false,
    "block_exec": false,
    "block_forwarding": true,
    "block_x11": true,
    "block_agent": true
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/ssh-proxy-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssh-proxy-restricted",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 SSH Proxy - Block port forwarding and tunneling",
        "mode": "pass-through",
        "block_shell": false,
        "block_exec": false,
        "block_forwarding": true,
        "block_x11": true,
        "block_agent": true
    }'
```

---

## Interface Management Profile Snippets

### Snippet: FIPS Management Access (SSH + HTTPS Only)

```json
{
    "name": "fips-mgmt-profile",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Management Profile - SSH and HTTPS only",
    "ssh": true,
    "https": true,
    "telnet": false,
    "http": false,
    "ping": true,
    "snmp": false,
    "response_pages": false,
    "userid_service": false,
    "userid_syslog_listener_ssl": false,
    "userid_syslog_listener_udp": false,
    "permitted_ip": [
        {"name": "10.0.0.0/8"},
        {"name": "192.168.0.0/16"}
    ]
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/interface-management-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-mgmt-profile",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Management Profile - SSH and HTTPS only",
        "ssh": true,
        "https": true,
        "telnet": false,
        "http": false,
        "ping": true,
        "permitted_ip": [
            {"name": "10.0.0.0/8"},
            {"name": "192.168.0.0/16"}
        ]
    }'
```

---

### Snippet: Restricted Management (HTTPS Only)

```json
{
    "name": "fips-mgmt-https-only",
    "folder": "Shared",
    "snippet": "FIPS-140-3-Crypto",
    "description": "FIPS 140-3 Management - HTTPS only, no SSH",
    "ssh": false,
    "https": true,
    "telnet": false,
    "http": false,
    "ping": false,
    "permitted_ip": [
        {"name": "10.0.0.0/8"}
    ]
}
```

### SCM API Call

```bash
curl -X POST "https://api.sase.paloaltonetworks.com/sse/config/v1/interface-management-profiles" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-mgmt-https-only",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Management - HTTPS only, no SSH",
        "ssh": false,
        "https": true,
        "telnet": false,
        "http": false,
        "ping": false,
        "permitted_ip": [{"name": "10.0.0.0/8"}]
    }'
```

---

## Bulk Snippet Deployment Script

### Deploy All SSH-Related Snippets

```bash
#!/bin/bash

# Configuration
SCM_API_URL="https://api.sase.paloaltonetworks.com/sse/config/v1"
ACCESS_TOKEN="<your-access-token>"

# SSH Proxy - Pass-through
echo "Deploying fips-ssh-proxy-passthrough..."
curl -s -X POST "$SCM_API_URL/ssh-proxy-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssh-proxy-passthrough",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 SSH Proxy - Pass-through",
        "mode": "pass-through"
    }'

# SSH Proxy - Decrypt
echo "Deploying fips-ssh-proxy-decrypt..."
curl -s -X POST "$SCM_API_URL/ssh-proxy-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssh-proxy-decrypt",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 SSH Proxy - Decrypt",
        "mode": "decrypt",
        "block_partial": true
    }'

# SSH Proxy - Restricted
echo "Deploying fips-ssh-proxy-restricted..."
curl -s -X POST "$SCM_API_URL/ssh-proxy-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-ssh-proxy-restricted",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 SSH Proxy - Restricted",
        "mode": "pass-through",
        "block_forwarding": true,
        "block_x11": true,
        "block_agent": true
    }'

# Management Profile - SSH + HTTPS
echo "Deploying fips-mgmt-profile..."
curl -s -X POST "$SCM_API_URL/interface-management-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-mgmt-profile",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 Management Profile",
        "ssh": true,
        "https": true,
        "telnet": false,
        "http": false,
        "ping": true
    }'

# Management Profile - HTTPS Only
echo "Deploying fips-mgmt-https-only..."
curl -s -X POST "$SCM_API_URL/interface-management-profiles" \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
        "name": "fips-mgmt-https-only",
        "folder": "Shared",
        "snippet": "FIPS-140-3-Crypto",
        "description": "FIPS 140-3 HTTPS Only",
        "ssh": false,
        "https": true,
        "telnet": false,
        "http": false
    }'

echo "All SSH-related snippets deployed."
```

---

## Verification

### List SSH Proxy Profiles

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/ssh-proxy-profiles?snippet=FIPS-140-3-Crypto" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

### List Interface Management Profiles

```bash
curl -X GET "https://api.sase.paloaltonetworks.com/sse/config/v1/interface-management-profiles?snippet=FIPS-140-3-Crypto" \
    -H "Authorization: Bearer <ACCESS_TOKEN>" \
    -H "Content-Type: application/json"
```

---

## On-Device SSH Configuration (CLI Commands)

While SSH server algorithms are typically managed on-device, here are CLI commands that can be scripted or pushed via automation:

### Verify SSH Configuration on Device

```bash
# Connect to firewall and run these commands
show ssh system host-key fingerprint
show system ssh algorithms
show running config deviceconfig system ssh
```

### Configure SSH Settings via CLI

```bash
configure

# Set SSH session timeout (15 minutes)
set deviceconfig system ssh session-timeout 15

# Set maximum SSH sessions
set deviceconfig system ssh session-max 10

# Enable SSH service
set deviceconfig system service disable-ssh no

commit
```

---

## FIPS-Compliant SSH Algorithm Reference

### SSH Encryption (On-Device)

| Algorithm | FIPS Status | Notes |
|-----------|-------------|-------|
| aes128-ctr | Compliant | |
| aes192-ctr | Compliant | |
| aes256-ctr | Compliant | Recommended |
| aes128-gcm@openssh.com | Compliant | Recommended |
| aes256-gcm@openssh.com | Compliant | Highly Recommended |
| 3des-cbc | **Non-Compliant** | |
| arcfour | **Non-Compliant** | |

### SSH Key Exchange (On-Device)

| Algorithm | FIPS Status | Notes |
|-----------|-------------|-------|
| ecdh-sha2-nistp256 | Compliant | |
| ecdh-sha2-nistp384 | Compliant | Recommended |
| ecdh-sha2-nistp521 | Compliant | |
| diffie-hellman-group14-sha256 | Compliant | |
| diffie-hellman-group16-sha512 | Compliant | Recommended |
| diffie-hellman-group1-sha1 | **Non-Compliant** | |
| diffie-hellman-group-exchange-sha1 | **Non-Compliant** | |

### SSH MAC (On-Device)

| Algorithm | FIPS Status | Notes |
|-----------|-------------|-------|
| hmac-sha2-256 | Compliant | |
| hmac-sha2-512 | Compliant | Recommended |
| hmac-sha2-256-etm@openssh.com | Compliant | |
| hmac-sha2-512-etm@openssh.com | Compliant | |
| hmac-sha1 | **Non-Compliant** | |
| hmac-md5 | **Non-Compliant** | |

### SSH Host Key Types (On-Device)

| Key Type | FIPS Status | Requirements |
|----------|-------------|--------------|
| RSA | Compliant | 2048-bit minimum |
| ECDSA (P-256) | Compliant | |
| ECDSA (P-384) | Compliant | Recommended |
| ECDSA (P-521) | Compliant | |
| DSA | **Non-Compliant** | Do not use |
| ED25519 | Not NIST-approved | |

---

## Integration Notes

### SSH Proxy in Decryption Policy

SSH proxy profiles are used in decryption policies:

```json
{
    "name": "ssh-decrypt-outbound",
    "folder": "Shared",
    "from": ["trust"],
    "to": ["untrust"],
    "source": ["any"],
    "destination": ["any"],
    "service": ["service-ssh"],
    "action": "decrypt",
    "type": "ssh-proxy",
    "profile": "fips-ssh-proxy-restricted"
}
```

### Management Profile on Interface

Apply management profile to interface:

```json
{
    "name": "ethernet1/1",
    "folder": "Shared",
    "layer3": {
        "interface_management_profile": "fips-mgmt-profile"
    }
}
```
