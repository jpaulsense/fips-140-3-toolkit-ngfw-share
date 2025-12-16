# SSH Decryption (SSH Proxy) - FIPS 140-3 Compliant Configuration

## Overview

SSH Decryption (SSH Proxy) allows the firewall to inspect SSH traffic passing through it (not management SSH). This enables visibility into SSH sessions for threat detection and compliance. This document covers FIPS 140-3 compliant configurations for SSH decryption.

## FIPS 140-3 Requirements for SSH Decryption

### SSH Protocol Requirements
| Parameter | FIPS Requirement |
|-----------|------------------|
| SSH Version | SSH-2 only |
| Encryption | AES-128/256-CTR or AES-128/256-GCM |
| Key Exchange | DH Group 14+ or ECDH P-256+ |
| MAC | HMAC-SHA-256 or HMAC-SHA-512 |

### Certificate Requirements (for SSH Proxy)
| Parameter | FIPS Requirement |
|-----------|------------------|
| Key Size | RSA 2048+ or ECDSA P-256+ |
| Signature | SHA-256 or stronger |

---

## CLI Configuration

### Create SSH Proxy Profile

```bash
# SSH to firewall and enter configuration mode
configure

# Create SSH proxy profile
set profiles ssh-proxy ssh-proxy-fips \
    mode pass-through

# Configure SSH proxy to allow only FIPS-compliant algorithms
# Note: PAN-OS enforces algorithm restrictions at the profile level

# Alternative: Create profile in decrypt mode for full inspection
set profiles ssh-proxy ssh-decrypt-fips \
    mode decrypt \
    block-partial yes

commit
```

### Configure SSH Decryption Policy

```bash
configure

# Create decryption policy for SSH
set rulebase decryption rules ssh-decrypt-outbound \
    from trust \
    to untrust \
    source any \
    destination any \
    source-user any \
    service service-ssh \
    action decrypt \
    type ssh-proxy \
    profile ssh-proxy-fips

# Create no-decrypt rule for specific destinations
set rulebase decryption rules ssh-no-decrypt-exempt \
    from trust \
    to untrust \
    source any \
    destination exempt-ssh-servers \
    source-user any \
    service service-ssh \
    action no-decrypt

# Order matters - exemption rule should be first
move rulebase decryption rules ssh-no-decrypt-exempt before ssh-decrypt-outbound

commit
```

### Create Address Group for SSH Exemptions

```bash
configure

# Create address objects for servers exempt from SSH decryption
set address ssh-server-1 ip-netmask 10.1.1.100/32
set address ssh-server-2 ip-netmask 10.1.1.101/32

# Create address group
set address-group exempt-ssh-servers \
    static ssh-server-1 \
    static ssh-server-2

commit
```

### Configure SSH Security Profile

```bash
configure

# Create security profile for SSH inspection
set security rules allow-ssh-internal \
    from trust \
    to trust \
    source any \
    destination any \
    application ssh \
    service application-default \
    action allow \
    log-end yes \
    profile-setting profiles \
    vulnerability-profile strict

commit
```

---

## API Configuration

### Create SSH Proxy Profile via API

**XML Element (Pass-Through Mode):**
```xml
<entry name="ssh-proxy-fips">
    <mode>pass-through</mode>
</entry>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/ssh-proxy/entry[@name='ssh-proxy-fips']" \
    -d "element=<entry name='ssh-proxy-fips'><mode>pass-through</mode></entry>"
```

**XML Element (Decrypt Mode):**
```xml
<entry name="ssh-decrypt-fips">
    <mode>decrypt</mode>
    <block-partial>yes</block-partial>
</entry>
```

### Create SSH Decryption Policy via API

**XML Element:**
```xml
<entry name="ssh-decrypt-outbound">
    <from>
        <member>trust</member>
    </from>
    <to>
        <member>untrust</member>
    </to>
    <source>
        <member>any</member>
    </source>
    <destination>
        <member>any</member>
    </destination>
    <source-user>
        <member>any</member>
    </source-user>
    <service>
        <member>service-ssh</member>
    </service>
    <action>decrypt</action>
    <type>
        <ssh-proxy/>
    </type>
    <profile>ssh-proxy-fips</profile>
</entry>
```

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/decryption/rules/entry[@name='ssh-decrypt-outbound']" \
    --data-urlencode "element@ssh-decrypt-rule.xml"
```

### Retrieve SSH Proxy Configuration via API

```bash
# Get SSH proxy profiles
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/ssh-proxy"

# Get decryption rules
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/decryption"
```

---

## Web UI Configuration Path

### Create SSH Proxy Profile
1. Navigate to: **Objects > Decryption > SSH Decryption Profile**
2. Click **Add**
3. Configure:
   - **Name**: `ssh-proxy-fips`
   - **Mode**: Pass-Through or Decrypt
   - **Block Partial**: Yes (if decrypt mode)

### Create SSH Decryption Policy
1. Navigate to: **Policies > Decryption**
2. Click **Add**
3. Configure:
   - **Name**: `ssh-decrypt-outbound`
   - **Source Zone**: trust
   - **Destination Zone**: untrust
   - **Service**: service-ssh
   - **Action**: Decrypt
   - **Type**: SSH Proxy
   - **SSH Proxy Profile**: `ssh-proxy-fips`

---

## SSH Proxy Modes

### Pass-Through Mode
- Inspects SSH control channel only
- Identifies SSH commands (shell, exec, sftp, etc.)
- Does not inspect encrypted payload
- Lower resource usage
- Best for command logging and policy enforcement

### Decrypt Mode
- Full man-in-the-middle inspection
- Can inspect file transfers, command output
- Higher resource usage
- Requires certificate management
- Users see firewall's certificate, not server's

---

## SSH Command Filtering

### Block Specific SSH Features

```bash
configure

# Create SSH proxy profile with command restrictions
set profiles ssh-proxy ssh-restricted-fips \
    mode pass-through \
    block shell no \
    block exec no \
    block forwarding yes \
    block x11 yes \
    block agent yes

commit
```

### Monitor SSH Commands

```bash
# View SSH session details in traffic logs
show log traffic | match ssh

# View SSH decryption logs
show log decryption | match ssh

# Real-time monitoring
tail follow yes mp-log ssh_decrypt.log
```

---

## Compliance Verification Commands

### Check SSH Decryption Status

```bash
# Show SSH proxy sessions
show session all filter application ssh

# Show decrypted SSH sessions
show session all filter ssl-decrypted yes application ssh

# Show SSH decryption statistics
show counter global filter delta yes | match -i ssh

# Show decryption policy hit counts
show running rule-hit-count vsys vsys1 decryption-rulebase rules
```

### Verify SSH Session Details

```bash
# Show specific session
show session id <session-id>

# Show session with SSH details
show session id <session-id> | match -i "ssh\|decrypt"

# Monitor SSH sessions in real-time
show session all filter application ssh
```

### Test SSH Decryption

```bash
# From client through firewall
ssh -v user@remote-server.example.com

# Check firewall logs for SSH session
show log traffic | match "ssh"
show log decryption | match "ssh"
```

---

## Best Practices

1. **Use Pass-Through mode by default** - Less intrusive, lower overhead
2. **Decrypt only when necessary** - For high-security environments
3. **Document exemptions** - Some servers may require direct SSH
4. **Monitor SSH sessions** - Log and alert on suspicious commands
5. **Block unnecessary SSH features** - Port forwarding, X11 if not needed
6. **Regular policy review** - Update exemptions as servers change
7. **User awareness** - If using decrypt mode, inform users
8. **Certificate management** - If decrypt mode, manage proxy certificates
9. **Performance testing** - SSH decryption uses CPU resources
10. **Compliance documentation** - Document SSH inspection policy

---

## Troubleshooting

### SSH Decryption Issues

```bash
# Check SSH decryption counters
show counter global filter delta yes | match -i "ssh\|decrypt"

# View SSH decryption logs
show log system | match -i ssh

# Debug SSH proxy
debug dataplane ssh on debug
# Perform SSH connection through firewall
debug dataplane ssh off
less dp-log ssh.log
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| SSH connection fails | Algorithm mismatch | Check SSH proxy supports client algorithms |
| Slow SSH connections | Decryption overhead | Consider pass-through mode |
| Commands not logged | Pass-through mode | Enable decrypt mode for full logging |
| Certificate warnings | Decrypt mode active | Deploy proxy CA to clients |
| Session timeout | Long-running SSH | Adjust session timeout settings |

### Debug Commands

```bash
# Enable SSH proxy debugging
debug dataplane ssh on debug

# Monitor SSH proxy
less dp-log ssh.log

# Check flow for SSH traffic
debug dataplane flow show ssh

# Disable debugging
debug dataplane ssh off
```

---

## Security Considerations

### SSH Proxy vs Direct SSH

| Aspect | With SSH Proxy | Without SSH Proxy |
|--------|----------------|-------------------|
| Visibility | Command/channel awareness | Application-level only |
| Policy control | Can block features | Allow/deny only |
| Threat detection | Can detect tunneling | Limited |
| User experience | May see proxy certificate | Transparent |
| Performance | Additional processing | Lower overhead |

### Detecting SSH Tunneling

```bash
# SSH tunneling can be used to bypass security controls
# Configure SSH proxy to detect and block tunneling

set profiles ssh-proxy ssh-no-tunnel-fips \
    mode pass-through \
    block forwarding yes \
    block agent yes

# Apply to decryption policy
set rulebase decryption rules ssh-decrypt-outbound \
    profile ssh-no-tunnel-fips
```

---

## Integration with Security Profiles

### Apply Vulnerability Protection to SSH

```bash
configure

# Security rule with vulnerability profile for SSH
set rulebase security rules ssh-protected \
    from trust \
    to untrust \
    source any \
    destination any \
    application ssh \
    service application-default \
    action allow \
    log-end yes \
    profile-setting profiles \
    vulnerability-profile strict \
    antivirus strict

commit
```

### SSH in App-ID

```bash
# Show SSH application details
show running application name ssh

# SSH variants identified by App-ID:
# - ssh (standard SSH)
# - ssh-tunnel (SSH tunneling detected)
# - sftp (SSH File Transfer)
# - scp (Secure Copy)

# Create security rule for specific SSH applications
set rulebase security rules allow-sftp-only \
    from trust \
    to untrust \
    source any \
    destination file-servers \
    application sftp scp \
    service application-default \
    action allow
```

---

## Logging and Reporting

### Enable Detailed SSH Logging

```bash
configure

# Enable decryption logging
set deviceconfig setting logging decryption-log

# Configure log forwarding for SSH decryption
set log-forwarding-profile ssh-logs-fips \
    match-list decryption-log \
    log-type decryption \
    filter "(app eq ssh)"

commit
```

### Generate SSH Activity Report

```bash
# Show SSH session summary
show session all filter application ssh | match -i count

# Export SSH logs
scp export log decryption from date from YYYY/MM/DD to YYYY/MM/DD | match ssh

# View top SSH destinations
show session all filter application ssh | group destination-ip
```
