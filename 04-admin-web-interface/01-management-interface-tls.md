# Administrative Web Interface TLS - FIPS 140-3 Compliant Configuration

## Overview

The administrative web interface (HTTPS access to the firewall GUI) must be configured with FIPS 140-3 compliant TLS settings. This document covers TLS configuration for secure administrative access.

## FIPS 140-3 Requirements for Admin Web Interface

### TLS Protocol Versions
| Version | FIPS Status | Recommendation |
|---------|-------------|----------------|
| TLS 1.3 | Compliant | Highly Recommended |
| TLS 1.2 | Compliant | Acceptable |
| TLS 1.1 | Non-Compliant | Do Not Use |
| TLS 1.0 | Non-Compliant | Do Not Use |

### FIPS-Compliant Cipher Suites

**TLS 1.3 Ciphers:**
| Cipher Suite | FIPS Status |
|--------------|-------------|
| TLS-AES-256-GCM-SHA384 | Compliant |
| TLS-AES-128-GCM-SHA256 | Compliant |
| TLS-AES-128-CCM-SHA256 | Compliant |

**TLS 1.2 Ciphers:**
| Cipher Suite | Key Exchange | FIPS Status |
|--------------|--------------|-------------|
| ECDHE-RSA-AES256-GCM-SHA384 | ECDHE | Compliant |
| ECDHE-RSA-AES128-GCM-SHA256 | ECDHE | Compliant |
| ECDHE-ECDSA-AES256-GCM-SHA384 | ECDHE | Compliant |
| DHE-RSA-AES256-GCM-SHA384 | DHE | Compliant |
| RSA-AES256-CBC-SHA256 | RSA | Compliant (No PFS) |

### Certificate Requirements
| Parameter | FIPS Requirement |
|-----------|------------------|
| Key Type | RSA 2048+ or ECDSA P-256+ |
| Signature Algorithm | SHA-256 or stronger |
| Key Usage | Digital Signature, Key Encipherment |

---

## CLI Configuration

### Generate FIPS-Compliant Certificate for Web Interface

```bash
# Generate CSR for management interface certificate
request certificate generate-csr \
    certificate-name mgmt-cert-rsa3072 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384

# Or generate ECDSA certificate
request certificate generate-csr \
    certificate-name mgmt-cert-ecdsa384 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm ECDSA \
    ecdsa-type secp384r1 \
    digest sha384

# Import signed certificate
request certificate import \
    certificate-name mgmt-cert-rsa3072 \
    file-type signed-certificate \
    format pem \
    certificate-file /path/to/signed-cert.pem
```

### Create SSL/TLS Service Profile for Management

```bash
configure

# Create SSL/TLS service profile for management interface
set ssl-tls-service-profile mgmt-ssl-fips \
    certificate mgmt-cert-rsa3072 \
    protocol-settings min-version tls1-2 \
    protocol-settings max-version tls1-3 \
    protocol-settings keyxchg-algo-rsa no \
    protocol-settings keyxchg-algo-dhe yes \
    protocol-settings keyxchg-algo-ecdhe yes \
    protocol-settings enc-algo-3des no \
    protocol-settings enc-algo-rc4 no \
    protocol-settings enc-algo-aes-128-cbc yes \
    protocol-settings enc-algo-aes-256-cbc yes \
    protocol-settings enc-algo-aes-128-gcm yes \
    protocol-settings enc-algo-aes-256-gcm yes \
    protocol-settings auth-algo-sha1 no \
    protocol-settings auth-algo-sha256 yes \
    protocol-settings auth-algo-sha384 yes

commit
```

### Apply SSL/TLS Profile to Management Interface

```bash
configure

# Apply FIPS-compliant TLS profile to management interface
set deviceconfig system ssl-tls-service-profile mgmt-ssl-fips

commit
```

### Configure Management Interface Settings

```bash
configure

# Set management interface to use HTTPS only
set deviceconfig system service disable-http yes
set deviceconfig system service disable-https no

# Configure permitted IP addresses for management
set deviceconfig system permitted-ip 10.0.0.0/8
set deviceconfig system permitted-ip 192.168.0.0/16

# Set session timeout (15 minutes recommended)
set deviceconfig system idle-timeout 15

# Enable certificate authentication (optional)
set deviceconfig system certificate-profile mgmt-cert-profile-fips

commit
```

### Configure Login Banner

```bash
configure

# Set login banner for compliance
set deviceconfig system login-banner "WARNING: This system is for authorized users only. All activities are monitored and logged. Unauthorized access is prohibited and will be prosecuted."

# Set MOTD banner
set deviceconfig system motd-and-banner startup-message "FIPS 140-3 Compliant System - Use only approved cryptographic settings."

commit
```

---

## API Configuration

### Create SSL/TLS Service Profile via API

**XML Element:**
```xml
<entry name="mgmt-ssl-fips">
    <certificate>mgmt-cert-rsa3072</certificate>
    <protocol-settings>
        <min-version>tls1-2</min-version>
        <max-version>tls1-3</max-version>
        <keyxchg-algo-rsa>no</keyxchg-algo-rsa>
        <keyxchg-algo-dhe>yes</keyxchg-algo-dhe>
        <keyxchg-algo-ecdhe>yes</keyxchg-algo-ecdhe>
        <enc-algo-3des>no</enc-algo-3des>
        <enc-algo-rc4>no</enc-algo-rc4>
        <enc-algo-aes-128-cbc>yes</enc-algo-aes-128-cbc>
        <enc-algo-aes-256-cbc>yes</enc-algo-aes-256-cbc>
        <enc-algo-aes-128-gcm>yes</enc-algo-aes-128-gcm>
        <enc-algo-aes-256-gcm>yes</enc-algo-aes-256-gcm>
        <auth-algo-sha1>no</auth-algo-sha1>
        <auth-algo-sha256>yes</auth-algo-sha256>
        <auth-algo-sha384>yes</auth-algo-sha384>
    </protocol-settings>
</entry>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/ssl-tls-service-profile/entry[@name='mgmt-ssl-fips']" \
    --data-urlencode "element@mgmt-ssl-profile.xml"
```

### Apply SSL/TLS Profile to Management via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system" \
    -d "element=<ssl-tls-service-profile>mgmt-ssl-fips</ssl-tls-service-profile>"
```

### Configure Management Access Restrictions via API

**XML Element:**
```xml
<system>
    <ssl-tls-service-profile>mgmt-ssl-fips</ssl-tls-service-profile>
    <service>
        <disable-http>yes</disable-http>
        <disable-https>no</disable-https>
    </service>
    <permitted-ip>
        <entry name="10.0.0.0/8"/>
        <entry name="192.168.0.0/16"/>
    </permitted-ip>
    <idle-timeout>15</idle-timeout>
    <login-banner>WARNING: Authorized users only.</login-banner>
</system>
```

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system" \
    --data-urlencode "element@mgmt-settings.xml"
```

### Retrieve Management Configuration via API

```bash
# Get SSL/TLS profile applied to management
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile"

# Get full management settings
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system"
```

---

## Web UI Configuration Path

### Configure SSL/TLS Service Profile
1. Navigate to: **Device > Certificate Management > SSL/TLS Service Profile**
2. Click **Add**
3. Configure:
   - **Name**: `mgmt-ssl-fips`
   - **Certificate**: Select FIPS-compliant certificate
   - **Min Version**: TLSv1.2
   - **Max Version**: TLSv1.3
4. Under **Protocol Settings**:
   - Uncheck: RSA Key Exchange, 3DES, RC4, SHA1
   - Check: ECDHE, DHE, AES-GCM, SHA256, SHA384

### Apply to Management Interface
1. Navigate to: **Device > Setup > Management**
2. Click on **General Settings** gear icon
3. Under **SSL/TLS Service Profile**: Select `mgmt-ssl-fips`
4. Click **OK**

### Configure Access Restrictions
1. Navigate to: **Device > Setup > Management**
2. Click on **Management Interface Settings** gear icon
3. Configure:
   - **HTTP**: Disabled
   - **HTTPS**: Enabled
   - **Permitted IP Addresses**: Add management networks
4. Click **OK** and **Commit**

---

## Client Certificate Authentication

### Configure Mutual TLS for Admin Access

```bash
configure

# Create certificate profile for admin client certificates
set certificate-profile admin-client-cert-fips \
    CA admin-ca-cert \
    use-crl yes \
    use-ocsp yes \
    block-expired-certificate yes \
    username-field subject common-name

# Apply to management interface
set deviceconfig system certificate-profile admin-client-cert-fips

commit
```

### API Configuration for Client Cert Auth

**XML Element:**
```xml
<certificate-profile>admin-client-cert-fips</certificate-profile>
```

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system" \
    -d "element=<certificate-profile>admin-client-cert-fips</certificate-profile>"
```

---

## Compliance Verification Commands

### Check Current TLS Configuration

```bash
# Show SSL/TLS service profile applied to management
show system state filter cfg.ssl-tls-service-profile

# Show management interface configuration
show system setting management

# Show certificate in use
show certificate name mgmt-cert-rsa3072
```

### Test TLS Configuration Externally

```bash
# From external system - test TLS 1.2
openssl s_client -connect firewall.example.com:443 -tls1_2

# Test TLS 1.3
openssl s_client -connect firewall.example.com:443 -tls1_3

# Show negotiated cipher
openssl s_client -connect firewall.example.com:443 2>/dev/null | grep "Cipher"

# Check certificate details
openssl s_client -connect firewall.example.com:443 2>/dev/null | openssl x509 -noout -text

# Enumerate supported ciphers
nmap --script ssl-enum-ciphers -p 443 firewall.example.com
```

### Verify No Weak Protocols

```bash
# From external system - verify TLS 1.0 is disabled
openssl s_client -connect firewall.example.com:443 -tls1
# Should fail with "handshake failure" or similar

# Verify TLS 1.1 is disabled
openssl s_client -connect firewall.example.com:443 -tls1_1
# Should fail

# Verify SSLv3 is disabled
openssl s_client -connect firewall.example.com:443 -ssl3
# Should fail
```

---

## Best Practices

1. **Use TLS 1.3 where supported** - Best security and performance
2. **Disable TLS 1.0 and 1.1** - Non-compliant versions
3. **Use ECDHE key exchange** - Perfect forward secrecy
4. **Disable RSA key exchange** - No forward secrecy
5. **Use certificates from trusted CA** - Avoid self-signed for production
6. **Implement client certificate auth** - Strongest authentication
7. **Restrict permitted IPs** - Limit management access sources
8. **Set session timeout** - 15 minutes or less recommended
9. **Enable login banner** - Legal notice for compliance
10. **Regular certificate rotation** - Annual renewal at minimum

---

## Troubleshooting

### TLS Connection Issues

```bash
# Check management interface status
show system services

# Check certificate validity
show certificate name mgmt-cert-rsa3072

# Verify certificate chain
request certificate validate certificate-name mgmt-cert-rsa3072

# View system logs for TLS errors
show log system | match -i "ssl\|tls\|certificate"
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Connection refused | HTTPS disabled | Enable HTTPS in management settings |
| Certificate warning | Untrusted CA | Import CA cert to browser/client |
| TLS handshake failure | Version mismatch | Update client or adjust min version |
| Cipher mismatch | No common cipher | Add more cipher options |
| Access denied | IP not permitted | Add client IP to permitted list |

### Browser Compatibility

| Browser | Min TLS Version | Recommended |
|---------|-----------------|-------------|
| Chrome 66+ | TLS 1.2 | TLS 1.3 |
| Firefox 60+ | TLS 1.2 | TLS 1.3 |
| Edge 16+ | TLS 1.2 | TLS 1.3 |
| Safari 12+ | TLS 1.2 | TLS 1.3 |
| IE 11 | TLS 1.2 | N/A |

---

## High Availability Considerations

### Management TLS in HA

- Each HA peer can have unique management certificates
- SSL/TLS profiles sync between peers
- Consider using same CA for both peers

```bash
# Verify TLS profile is synced
show high-availability state-synchronization | match ssl

# Check both peers have valid certificates
# On peer 1
show certificate name mgmt-cert-rsa3072

# On peer 2
show certificate name mgmt-cert-rsa3072
```

---

## Audit and Logging

### Enable Admin Access Logging

```bash
configure

# Ensure configuration logging is enabled
set deviceconfig setting logging config yes

# Enable system logging
set deviceconfig setting logging operational-logging

commit
```

### Review Admin Access

```bash
# Show admin login history
show admins

# Show configuration audit log
show config audit

# Show system logs for authentication
show log system | match -i "authentication\|logged in\|logged out"

# Export admin logs
scp export log system from date from YYYY/MM/DD to YYYY/MM/DD | match admin
```

---

## Compliance Checklist

- [ ] TLS 1.2 minimum version configured
- [ ] TLS 1.0 and 1.1 disabled
- [ ] 3DES and RC4 ciphers disabled
- [ ] RSA key exchange disabled (ECDHE/DHE only)
- [ ] SHA-1 authentication disabled
- [ ] Certificate uses RSA 2048+ or ECDSA P-256+
- [ ] Certificate signed with SHA-256 or stronger
- [ ] HTTP access disabled
- [ ] Management access IP-restricted
- [ ] Session timeout configured (15 min or less)
- [ ] Login banner configured
- [ ] Admin access logging enabled
