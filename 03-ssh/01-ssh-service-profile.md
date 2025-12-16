# SSH Service Profile - FIPS 140-3 Compliant Configuration

## Overview

SSH (Secure Shell) is used for administrative CLI access to Palo Alto Networks firewalls. This document covers FIPS 140-3 compliant configurations for SSH server settings, including encryption algorithms, key exchange, and MAC algorithms.

## FIPS 140-3 Compliant Algorithm Options

### Encryption Algorithms
| Algorithm | Key Size | FIPS Status | Recommendation |
|-----------|----------|-------------|----------------|
| AES-128-CTR | 128-bit | Compliant | Acceptable |
| AES-192-CTR | 192-bit | Compliant | Good |
| AES-256-CTR | 256-bit | Compliant | Recommended |
| AES-128-GCM | 128-bit | Compliant | Recommended |
| AES-256-GCM | 256-bit | Compliant | Highly Recommended |

### Key Exchange Algorithms
| Algorithm | FIPS Status | Recommendation |
|-----------|-------------|----------------|
| diffie-hellman-group14-sha256 | Compliant | Minimum acceptable |
| diffie-hellman-group16-sha512 | Compliant | Recommended |
| ecdh-sha2-nistp256 | Compliant | Recommended |
| ecdh-sha2-nistp384 | Compliant | Highly Recommended |
| ecdh-sha2-nistp521 | Compliant | Maximum Security |

### MAC Algorithms
| Algorithm | FIPS Status | Recommendation |
|-----------|-------------|----------------|
| hmac-sha2-256 | Compliant | Recommended |
| hmac-sha2-512 | Compliant | Highly Recommended |
| hmac-sha2-256-etm | Compliant | Recommended (if supported) |
| hmac-sha2-512-etm | Compliant | Highly Recommended (if supported) |

### Non-Compliant Algorithms (DO NOT USE)
| Algorithm | Status |
|-----------|--------|
| arcfour, arcfour128, arcfour256 | Non-Compliant |
| blowfish-cbc | Non-Compliant |
| cast128-cbc | Non-Compliant |
| 3des-cbc | Non-Compliant |
| aes-cbc (any) | Less Secure (CBC mode) |
| diffie-hellman-group1-sha1 | Non-Compliant |
| diffie-hellman-group-exchange-sha1 | Non-Compliant |
| hmac-md5 | Non-Compliant |
| hmac-sha1 | Non-Compliant |

---

## CLI Configuration

### Configure FIPS-Compliant SSH Server Settings

```bash
# SSH to firewall and enter configuration mode
configure

# Configure SSH service with FIPS-compliant algorithms
# Note: PAN-OS uses a curated set of algorithms based on version

# Set SSH session timeout (recommended: 10-30 minutes)
set deviceconfig system ssh session-timeout 15

# Configure SSH session limits
set deviceconfig system ssh session-max 10

# Enable SSH service on management interface
set deviceconfig system service disable-ssh no

# Set TCP port (default 22, can be changed for additional security)
set deviceconfig system ssh tcp-port 22

commit
```

### Configure SSH Management Profile

```bash
configure

# Create management profile with SSH enabled
set network profiles interface-management-profile ssh-mgmt-fips \
    ssh yes \
    https no \
    ping no \
    telnet no \
    http no

# Apply to management interface
set deviceconfig system interface-management-profile ssh-mgmt-fips

commit
```

### Verify Current SSH Configuration

```bash
# Show SSH server status
show system ssh status

# Show SSH sessions
show system ssh sessions

# Show SSH configuration
show deviceconfig system ssh

# Show supported algorithms (may vary by PAN-OS version)
show system ssh algorithms
```

### Configure SSH for Specific Interface

```bash
configure

# Create interface management profile
set network profiles interface-management-profile mgmt-fips \
    ssh yes \
    https yes \
    permitted-ip 10.0.0.0/8 \
    permitted-ip 192.168.0.0/16

# Apply to interface
set network interface ethernet ethernet1/1 layer3 interface-management-profile mgmt-fips

commit
```

---

## API Configuration

### Configure SSH Settings via XML API

**API Endpoint:** `https://<firewall>/api/`

**XML Element:**
```xml
<ssh>
    <session-timeout>15</session-timeout>
    <session-max>10</session-max>
    <tcp-port>22</tcp-port>
</ssh>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system" \
    -d "element=<ssh><session-timeout>15</session-timeout><session-max>10</session-max><tcp-port>22</tcp-port></ssh>"
```

### Create Management Profile via API

**XML Element:**
```xml
<entry name="ssh-mgmt-fips">
    <ssh>yes</ssh>
    <https>yes</https>
    <telnet>no</telnet>
    <http>no</http>
    <ping>yes</ping>
    <permitted-ip>
        <entry name="10.0.0.0/8"/>
        <entry name="192.168.0.0/16"/>
    </permitted-ip>
</entry>
```

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile/entry[@name='ssh-mgmt-fips']" \
    --data-urlencode "element@mgmt-profile.xml"
```

### Retrieve SSH Configuration via API

```bash
# Get SSH configuration
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssh"

# Get interface management profiles
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile"
```

---

## Web UI Configuration Path

### Configure SSH Service
1. Navigate to: **Device > Setup > Management**
2. Click on **Management Interface Settings** gear icon
3. Configure:
   - **SSH**: Enabled
   - **Permitted IP Addresses**: Restrict to management networks
4. Click **OK**

### Configure Session Settings
1. Navigate to: **Device > Setup > Management**
2. Click on **General Settings** gear icon
3. Configure:
   - **SSH Session Timeout**: 15 minutes
   - **SSH Max Sessions**: 10
4. Click **OK** and **Commit**

### Create Interface Management Profile
1. Navigate to: **Network > Network Profiles > Interface Mgmt**
2. Click **Add**
3. Configure:
   - **Name**: `ssh-mgmt-fips`
   - **SSH**: Checked
   - **HTTPS**: Checked
   - **Telnet**: Unchecked
   - **HTTP**: Unchecked
   - **Permitted IP Addresses**: Add management network ranges

---

## SSH Client Configuration

### Recommended SSH Client Settings

When connecting to a FIPS-compliant firewall, configure your SSH client to use compliant algorithms:

**OpenSSH (~/.ssh/config):**
```
Host pan-firewall
    HostName firewall.example.com
    User admin
    KexAlgorithms ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256
    Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr
    MACs hmac-sha2-512,hmac-sha2-256
    HostKeyAlgorithms ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256
```

**PuTTY:**
1. Connection > SSH > Kex: Prioritize ECDH and DH Group 14+
2. Connection > SSH > Cipher: Prioritize AES-GCM and AES-CTR
3. Connection > SSH > Auth: Use RSA 2048+ or ECDSA keys

---

## Access Control

### Configure SSH Access Restrictions

```bash
configure

# Restrict SSH access to specific networks
set deviceconfig system permitted-ip 10.0.0.0/8
set deviceconfig system permitted-ip 192.168.0.0/16

# Configure login banner
set deviceconfig system login-banner "WARNING: Authorized users only. All access is logged and monitored."

# Configure motd banner
set deviceconfig system motd-and-banner startup-message "This is a FIPS 140-3 compliant system."

commit
```

### Configure Admin Lockout Policy

```bash
configure

# Lock account after failed attempts
set deviceconfig setting management admin-lockout failed-attempts 5
set deviceconfig setting management admin-lockout lockout-time 30

# Configure minimum password complexity
set deviceconfig setting management min-length 14
set deviceconfig setting management complexity enabled yes

commit
```

---

## Compliance Verification Commands

### Check SSH Server Status

```bash
# Show SSH service status
show system services

# Show active SSH sessions
show system ssh sessions

# Show SSH session details
show system ssh session <session-id>

# Show system state for SSH
show system state filter cfg.ssh
```

### Test SSH Configuration Externally

```bash
# From external system - test SSH algorithms
ssh -v -o KexAlgorithms=ecdh-sha2-nistp384 admin@firewall.example.com

# Show negotiated algorithms
ssh -vvv admin@firewall.example.com 2>&1 | grep -i "kex\|cipher\|mac"

# Use nmap to enumerate SSH algorithms
nmap --script ssh2-enum-algos -p 22 firewall.example.com
```

### Verify SSH Configuration Compliance

```bash
# Check for weak algorithms (from admin CLI)
debug system ssh show-algorithms

# Show current SSH configuration
show running config deviceconfig system ssh

# Export configuration for audit
scp export configuration from running-config.xml to user@server:/path/
```

---

## Best Practices

1. **Use key-based authentication** - Stronger than passwords
2. **Disable Telnet** - Non-encrypted, never FIPS-compliant
3. **Restrict permitted IPs** - Only allow from management networks
4. **Set session timeouts** - 10-30 minutes recommended
5. **Limit concurrent sessions** - Prevent resource exhaustion
6. **Use non-standard port** - Defense in depth (not security)
7. **Enable login banner** - Legal notice for compliance
8. **Configure admin lockout** - Prevent brute force attacks
9. **Audit SSH access** - Log all admin sessions
10. **Regular key rotation** - Rotate host keys periodically

---

## Troubleshooting

### SSH Connection Issues

```bash
# Check SSH service status
show system services | match ssh

# Check for blocked connections
show session all filter destination-port 22

# View system logs for SSH
show log system | match -i ssh

# Debug SSH
debug system ssh on debug
# Connect via SSH
debug system ssh off
less mp-log sshd.log
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Connection refused | SSH disabled | Enable SSH in management profile |
| Algorithm mismatch | Client/server incompatibility | Update client or server algorithms |
| Connection timeout | Firewall blocking | Check permitted-ip settings |
| Host key verification | Key changed | Update known_hosts on client |
| Authentication failed | Wrong credentials | Verify username/password |

### SSH Host Key Management

```bash
# Regenerate SSH host keys
request ssh system host-key regenerate

# Show current host keys
show ssh system host-key

# Export host key for distribution
request ssh system host-key export format openssh
```

---

## SSH Decryption (Inbound SSH Inspection)

### Overview
SSH decryption allows inspection of SSH sessions passing through the firewall (not management SSH).

### Configure SSH Decryption

```bash
configure

# Create SSH decryption profile
set profiles ssh-proxy ssh-decrypt-fips \
    decryption mode pass-through

# Configure SSH decryption policy
set rulebase decryption rules ssh-decrypt-rule \
    from internal \
    to external \
    source any \
    destination any \
    service service-ssh \
    action decrypt \
    type ssh-proxy \
    profile ssh-decrypt-fips

commit
```

### Verify SSH Decryption

```bash
# Show SSH decryption statistics
show session all filter application ssh

# Show decrypted SSH sessions
show session all filter ssl-decrypted yes application ssh
```

---

## High Availability Considerations

### SSH in HA Deployments

- Each HA peer has unique SSH host keys
- Management IP can be HA floating IP
- Session state not synchronized for SSH

```bash
# Connect to specific HA peer
ssh admin@<peer-specific-ip>

# Connect to active peer via floating IP
ssh admin@<floating-ip>
```

---

## Audit and Logging

### Enable SSH Access Logging

```bash
configure

# Enable system logging for administrative events
set deviceconfig setting logging operational-logging

# Configure log forwarding for admin access
set log-forwarding-profile admin-log-fips \
    match-list system-log \
    log-type system \
    filter "(subtype eq admin)"

commit
```

### Review SSH Access Logs

```bash
# Show admin access logs
show log system | match -i "logged in\|logged out\|authentication"

# Show configuration changes
show config audit

# Export logs for compliance
scp export log system to user@server:/path/
```
