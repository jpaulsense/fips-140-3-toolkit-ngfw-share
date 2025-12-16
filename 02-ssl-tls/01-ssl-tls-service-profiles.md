# SSL/TLS Service Profiles - FIPS 140-3 Compliant Configuration

## Overview

SSL/TLS Service Profiles define the cryptographic settings for TLS connections on the firewall, including management interface access, GlobalProtect portals/gateways, and authentication services. This document covers FIPS 140-3 compliant configurations.

## FIPS 140-3 Compliant Algorithm Options

### TLS Protocol Versions
| Version | FIPS Status | Recommendation |
|---------|-------------|----------------|
| TLS 1.3 | Compliant | Highly Recommended |
| TLS 1.2 | Compliant | Recommended |
| TLS 1.1 | Non-Compliant | Do Not Use |
| TLS 1.0 | Non-Compliant | Do Not Use |

### TLS 1.2 Cipher Suites (FIPS-Compliant)
| Cipher Suite | Encryption | Key Exchange | FIPS Status |
|--------------|------------|--------------|-------------|
| ECDHE-RSA-AES256-GCM-SHA384 | AES-256-GCM | ECDHE | Compliant |
| ECDHE-RSA-AES128-GCM-SHA256 | AES-128-GCM | ECDHE | Compliant |
| ECDHE-ECDSA-AES256-GCM-SHA384 | AES-256-GCM | ECDHE | Compliant |
| ECDHE-ECDSA-AES128-GCM-SHA256 | AES-128-GCM | ECDHE | Compliant |
| DHE-RSA-AES256-GCM-SHA384 | AES-256-GCM | DHE | Compliant |
| DHE-RSA-AES128-GCM-SHA256 | AES-128-GCM | DHE | Compliant |
| ECDHE-RSA-AES256-CBC-SHA384 | AES-256-CBC | ECDHE | Compliant |
| ECDHE-RSA-AES128-CBC-SHA256 | AES-128-CBC | ECDHE | Compliant |

### TLS 1.3 Cipher Suites (All FIPS-Compliant)
| Cipher Suite | Encryption | FIPS Status |
|--------------|------------|-------------|
| TLS-AES-256-GCM-SHA384 | AES-256-GCM | Compliant |
| TLS-AES-128-GCM-SHA256 | AES-128-GCM | Compliant |
| TLS-AES-128-CCM-SHA256 | AES-128-CCM | Compliant |

### Elliptic Curves
| Curve | FIPS Status | Recommendation |
|-------|-------------|----------------|
| P-256 (secp256r1) | Compliant | Recommended |
| P-384 (secp384r1) | Compliant | Highly Recommended |
| P-521 (secp521r1) | Compliant | Maximum Security |

### Non-Compliant Options (DO NOT USE)
- TLS 1.0 and TLS 1.1
- RC4 cipher suites
- DES and 3DES cipher suites
- Export cipher suites
- NULL cipher suites
- MD5-based cipher suites
- SHA-1 for signatures in TLS 1.2

---

## CLI Configuration

### Create FIPS-Compliant SSL/TLS Service Profile (Maximum Security)

```bash
# SSH to firewall and enter configuration mode
configure

# Create SSL/TLS Profile with TLS 1.3 only (most secure)
set ssl-tls-service-profile ssl-tls-fips-max \
    certificate tls-cert-rsa3072 \
    protocol-settings min-version tls1-3 \
    protocol-settings max-version tls1-3

# Create SSL/TLS Profile with TLS 1.2-1.3 (broad compatibility)
set ssl-tls-service-profile ssl-tls-fips-compat \
    certificate tls-cert-rsa3072 \
    protocol-settings min-version tls1-2 \
    protocol-settings max-version tls1-3

# Create SSL/TLS Profile for TLS 1.2 with specific cipher suites
set ssl-tls-service-profile ssl-tls-fips-12 \
    certificate tls-cert-rsa3072 \
    protocol-settings min-version tls1-2 \
    protocol-settings max-version tls1-2 \
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

# Commit the configuration
commit
```

### Remove Non-Compliant Algorithms from Existing Profile

```bash
configure

# Disable non-compliant settings
set ssl-tls-service-profile <profile-name> protocol-settings min-version tls1-2
set ssl-tls-service-profile <profile-name> protocol-settings keyxchg-algo-rsa no
set ssl-tls-service-profile <profile-name> protocol-settings enc-algo-3des no
set ssl-tls-service-profile <profile-name> protocol-settings enc-algo-rc4 no
set ssl-tls-service-profile <profile-name> protocol-settings auth-algo-sha1 no
set ssl-tls-service-profile <profile-name> protocol-settings auth-algo-md5 no

commit
```

### Configure Management Interface TLS Profile

```bash
configure

# Apply FIPS-compliant TLS profile to management interface
set deviceconfig system ssl-tls-service-profile ssl-tls-fips-max

commit
```

### Verify SSL/TLS Profile Configuration

```bash
# Show all SSL/TLS service profiles
show ssl-tls-service-profile

# Show specific profile
show ssl-tls-service-profile ssl-tls-fips-max

# Show running configuration
show running config ssl-tls-service-profile
```

---

## API Configuration

### Create SSL/TLS Service Profile via XML API

**API Endpoint:** `https://<firewall>/api/`

**XML Element (TLS 1.3 Only - Maximum Security):**
```xml
<entry name="ssl-tls-fips-max">
    <certificate>tls-cert-rsa3072</certificate>
    <protocol-settings>
        <min-version>tls1-3</min-version>
        <max-version>tls1-3</max-version>
    </protocol-settings>
</entry>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/ssl-tls-service-profile/entry[@name='ssl-tls-fips-max']" \
    -d "element=<entry name='ssl-tls-fips-max'><certificate>tls-cert-rsa3072</certificate><protocol-settings><min-version>tls1-3</min-version><max-version>tls1-3</max-version></protocol-settings></entry>"
```

**XML Element (TLS 1.2-1.3 with Explicit Cipher Control):**
```xml
<entry name="ssl-tls-fips-compat">
    <certificate>tls-cert-rsa3072</certificate>
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

### Apply SSL/TLS Profile to Management Interface via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system" \
    -d "element=<ssl-tls-service-profile>ssl-tls-fips-max</ssl-tls-service-profile>"
```

### Retrieve SSL/TLS Profile Configuration via API

```bash
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/ssl-tls-service-profile"
```

---

## Web UI Configuration Path

### Create SSL/TLS Service Profile
1. Navigate to: **Device > Certificate Management > SSL/TLS Service Profile**
2. Click **Add**
3. Configure:
   - **Name**: `ssl-tls-fips-max`
   - **Certificate**: Select FIPS-compliant certificate
   - **Min Version**: `TLSv1.2` or `TLSv1.3`
   - **Max Version**: `TLSv1.3`
4. Under **Protocol Settings** (if TLS 1.2 enabled):
   - Uncheck: RSA Key Exchange, 3DES, RC4, SHA1
   - Check: ECDHE, DHE, AES-128-GCM, AES-256-GCM, SHA256, SHA384

### Apply to Management Interface
1. Navigate to: **Device > Setup > Management**
2. Click on **General Settings** gear icon
3. Under **SSL/TLS Service Profile**: Select `ssl-tls-fips-max`
4. Click **OK** and **Commit**

---

## Use Cases

### GlobalProtect Portal/Gateway

```bash
configure

# Apply FIPS TLS profile to GlobalProtect portal
set network global-protect global-protect-portal gp-portal \
    portal-config local-address interface ethernet1/1 \
    ssl-tls-service-profile ssl-tls-fips-compat

# Apply FIPS TLS profile to GlobalProtect gateway
set network global-protect global-protect-gateway gp-gateway \
    local-address interface ethernet1/1 \
    ssl-tls-service-profile ssl-tls-fips-compat

commit
```

### Captive Portal

```bash
configure

# Apply FIPS TLS profile to Captive Portal
set network profiles captive-portal captive-portal-fips \
    mode web-form \
    ssl-tls-service-profile ssl-tls-fips-compat

commit
```

### Authentication Portal

```bash
configure

# Apply FIPS TLS profile to Authentication Portal
set authentication-profile <profile-name> \
    method ssl-tls \
    ssl-tls-service-profile ssl-tls-fips-compat

commit
```

---

## Compliance Verification Commands

### Check Active TLS Configuration

```bash
# Show SSL/TLS service profile details
show ssl-tls-service-profile <profile-name>

# Show management interface TLS settings
show system state filter cfg.ssl-tls-service-profile

# Show active connections with TLS info
show session all filter ssl-decrypted yes
```

### Test TLS Configuration Externally

```bash
# From external system, test TLS configuration with OpenSSL
openssl s_client -connect <firewall-ip>:443 -tls1_3

# Test specific cipher
openssl s_client -connect <firewall-ip>:443 -cipher AES256-GCM-SHA384

# Show supported ciphers
nmap --script ssl-enum-ciphers -p 443 <firewall-ip>
```

### Verify Certificate in Use

```bash
# Show certificate bound to profile
show running config ssl-tls-service-profile <profile-name> | match certificate

# Verify certificate details
show certificate name <cert-name>
```

---

## Best Practices

1. **Use TLS 1.3 where possible** - Best security and performance
2. **Disable TLS 1.0 and 1.1** - Non-compliant and deprecated
3. **Prefer GCM cipher suites** - AEAD provides authenticated encryption
4. **Use ECDHE for key exchange** - Better performance than DHE
5. **Disable RSA key exchange** - No forward secrecy
6. **Use certificates with strong keys** - RSA 2048+ or ECDSA P-256+
7. **Document all TLS profiles** - Required for compliance audits
8. **Test after changes** - Verify connectivity with new settings

---

## Troubleshooting

### TLS Connection Failures

```bash
# Check system logs for TLS errors
show log system | match -i "ssl\|tls"

# Debug SSL/TLS
debug dataplane show ssl sessions

# Check certificate validity
show certificate name <cert-name>
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Connection refused | TLS version mismatch | Client may need TLS 1.2+ support |
| Cipher mismatch | No common cipher | Add more cipher options or update client |
| Certificate error | Expired or invalid cert | Renew or replace certificate |
| Handshake failure | Algorithm incompatibility | Check both client and server settings |

### Client Compatibility Matrix

| Client | Minimum TLS | Recommended TLS |
|--------|-------------|-----------------|
| Modern browsers | TLS 1.2 | TLS 1.3 |
| Windows 10+ | TLS 1.2 | TLS 1.3 |
| macOS 10.13+ | TLS 1.2 | TLS 1.3 |
| iOS 12+ | TLS 1.2 | TLS 1.3 |
| Android 10+ | TLS 1.2 | TLS 1.3 |
| GlobalProtect 5.0+ | TLS 1.2 | TLS 1.3 |
