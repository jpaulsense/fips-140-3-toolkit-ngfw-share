# SSL/TLS Decryption Profiles - FIPS 140-3 Compliant Configuration

## Overview

SSL/TLS Decryption Profiles control how the firewall handles encrypted traffic inspection, including forward proxy (outbound) and inbound inspection. This document covers FIPS 140-3 compliant configurations for decryption policies.

## FIPS 140-3 Compliance for Decryption

### Server-Side (Inbound) Requirements
| Parameter | FIPS Requirement |
|-----------|------------------|
| Certificate Key | RSA 2048+ or ECDSA P-256+ |
| TLS Version | TLS 1.2 or TLS 1.3 |
| Cipher Suites | AES-GCM or AES-CBC with SHA-256+ |

### Forward Proxy (Outbound) Requirements
| Parameter | FIPS Requirement |
|-----------|------------------|
| Forward Trust CA | RSA 2048+ or ECDSA P-256+ |
| Forward Untrust CA | RSA 2048+ or ECDSA P-256+ |
| Presented Certs | Generated with compliant algorithms |
| TLS Negotiation | Use only compliant algorithms |

---

## CLI Configuration

### Create FIPS-Compliant Decryption Profile

```bash
# SSH to firewall and enter configuration mode
configure

# Create Decryption Profile with FIPS settings
set profiles decryption fips-decryption-profile \
    ssl-forward-proxy block-client-cert no \
    ssl-forward-proxy block-expired-certificate yes \
    ssl-forward-proxy block-untrusted-issuer yes \
    ssl-forward-proxy block-unknown-cert yes \
    ssl-forward-proxy restrict-cert-exts no \
    ssl-forward-proxy strip-alpn no

# Configure SSL Protocol Settings (FIPS-compliant only)
set profiles decryption fips-decryption-profile \
    ssl-protocol-settings min-version tls1-2 \
    ssl-protocol-settings max-version tls1-3 \
    ssl-protocol-settings keyxchg-algo-rsa no \
    ssl-protocol-settings keyxchg-algo-dhe yes \
    ssl-protocol-settings keyxchg-algo-ecdhe yes \
    ssl-protocol-settings enc-algo-3des no \
    ssl-protocol-settings enc-algo-rc4 no \
    ssl-protocol-settings enc-algo-aes-128-cbc yes \
    ssl-protocol-settings enc-algo-aes-256-cbc yes \
    ssl-protocol-settings enc-algo-aes-128-gcm yes \
    ssl-protocol-settings enc-algo-aes-256-gcm yes \
    ssl-protocol-settings auth-algo-sha1 no \
    ssl-protocol-settings auth-algo-sha256 yes \
    ssl-protocol-settings auth-algo-sha384 yes

# Configure SSL Inbound Inspection settings
set profiles decryption fips-decryption-profile \
    ssl-inbound-proxy block-if-no-resource no \
    ssl-inbound-proxy block-if-hsm-unavailable yes

# Configure SSL No Proxy (sessions not decrypted but validated)
set profiles decryption fips-decryption-profile \
    ssl-no-proxy block-expired-certificate yes \
    ssl-no-proxy block-untrusted-issuer yes

commit
```

### Create Forward Trust/Untrust CA Certificates

```bash
configure

# Generate Forward Trust CA (for trusted sites)
request certificate generate-self-signed \
    certificate-name forward-trust-ca-fips \
    certificate-type root-authority \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384 \
    name cn=Forward-Trust-CA,o=Organization,c=US \
    ca yes

# Generate Forward Untrust CA (for untrusted sites)
request certificate generate-self-signed \
    certificate-name forward-untrust-ca-fips \
    certificate-type root-authority \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384 \
    name cn=Forward-Untrust-CA,o=Organization,c=US \
    ca yes

# Alternatively, use ECDSA
request certificate generate-self-signed \
    certificate-name forward-trust-ca-ecdsa \
    certificate-type root-authority \
    algorithm ECDSA \
    ecdsa-type secp384r1 \
    digest sha384 \
    name cn=Forward-Trust-CA,o=Organization,c=US \
    ca yes
```

### Configure SSL Forward Proxy Settings

```bash
configure

# Set forward proxy certificates
set deviceconfig setting ssl-decrypt forward-proxy-ssl \
    forward-trust-certificate-rsa forward-trust-ca-fips \
    forward-untrust-certificate-rsa forward-untrust-ca-fips

# Enable SSL forward proxy globally
set deviceconfig setting ssl-decrypt ssl-decryption yes

commit
```

### Create Decryption Policy Rule

```bash
configure

# Create decryption policy with FIPS profile
set rulebase decryption rules decrypt-outbound-fips \
    from trust \
    to untrust \
    source any \
    destination any \
    source-user any \
    category any \
    action decrypt \
    type ssl-forward-proxy \
    profile fips-decryption-profile

# Create no-decrypt rule for sensitive sites
set rulebase decryption rules no-decrypt-sensitive \
    from trust \
    to untrust \
    source any \
    destination any \
    source-user any \
    category financial-services health-and-medicine \
    action no-decrypt \
    profile fips-decryption-profile

commit
```

---

## API Configuration

### Create Decryption Profile via XML API

**XML Element:**
```xml
<entry name="fips-decryption-profile">
    <ssl-forward-proxy>
        <block-client-cert>no</block-client-cert>
        <block-expired-certificate>yes</block-expired-certificate>
        <block-untrusted-issuer>yes</block-untrusted-issuer>
        <block-unknown-cert>yes</block-unknown-cert>
        <restrict-cert-exts>no</restrict-cert-exts>
        <strip-alpn>no</strip-alpn>
    </ssl-forward-proxy>
    <ssl-protocol-settings>
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
    </ssl-protocol-settings>
    <ssl-inbound-proxy>
        <block-if-no-resource>no</block-if-no-resource>
        <block-if-hsm-unavailable>yes</block-if-hsm-unavailable>
    </ssl-inbound-proxy>
    <ssl-no-proxy>
        <block-expired-certificate>yes</block-expired-certificate>
        <block-untrusted-issuer>yes</block-untrusted-issuer>
    </ssl-no-proxy>
</entry>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/decryption/entry[@name='fips-decryption-profile']" \
    --data-urlencode "element@decryption-profile.xml"
```

### Create Decryption Policy Rule via API

**XML Element:**
```xml
<entry name="decrypt-outbound-fips">
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
    <category>
        <member>any</member>
    </category>
    <action>decrypt</action>
    <type>
        <ssl-forward-proxy/>
    </type>
    <profile>fips-decryption-profile</profile>
</entry>
```

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/decryption/rules/entry[@name='decrypt-outbound-fips']" \
    --data-urlencode "element@decryption-rule.xml"
```

### Configure Forward Proxy Certificates via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/deviceconfig/setting/ssl-decrypt" \
    -d "element=<ssl-decrypt><forward-proxy-ssl><forward-trust-certificate-rsa>forward-trust-ca-fips</forward-trust-certificate-rsa><forward-untrust-certificate-rsa>forward-untrust-ca-fips</forward-untrust-certificate-rsa></forward-proxy-ssl><ssl-decryption>yes</ssl-decryption></ssl-decrypt>"
```

### Retrieve Decryption Profile via API

```bash
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/decryption"
```

---

## Web UI Configuration Path

### Create Decryption Profile
1. Navigate to: **Objects > Decryption > Decryption Profile**
2. Click **Add**
3. **Name**: `fips-decryption-profile`
4. Under **SSL Forward Proxy**:
   - Block sessions with expired certificates: Yes
   - Block sessions with untrusted issuers: Yes
5. Under **SSL Protocol Settings**:
   - **Min Version**: TLSv1.2
   - **Max Version**: TLSv1.3
   - **Key Exchange Algorithms**: Uncheck RSA, Check DHE and ECDHE
   - **Encryption Algorithms**: Uncheck 3DES and RC4
   - **Authentication Algorithms**: Uncheck SHA1

### Configure Forward Trust/Untrust CA
1. Navigate to: **Device > Certificate Management > Certificates**
2. Generate or import CA certificates with RSA 2048+ or ECDSA P-256+
3. Navigate to: **Device > Setup > Content-ID**
4. Under **SSL Decryption Settings**:
   - **Forward Trust Certificate**: Select FIPS-compliant CA
   - **Forward Untrust Certificate**: Select FIPS-compliant CA

### Create Decryption Policy
1. Navigate to: **Policies > Decryption**
2. Click **Add**
3. Configure rule with zones, sources, destinations
4. **Action**: Decrypt
5. **Type**: SSL Forward Proxy
6. **Decryption Profile**: `fips-decryption-profile`

---

## SSL Inbound Inspection

### Configure Inbound Inspection (Protect Internal Servers)

```bash
configure

# Import server certificate and key
request certificate import \
    certificate-name internal-server-cert \
    format pkcs12 \
    certificate-file /path/to/server.p12 \
    passphrase <password>

# Create inbound inspection rule
set rulebase decryption rules decrypt-inbound-fips \
    from untrust \
    to dmz \
    source any \
    destination internal-server-ip \
    source-user any \
    service service-https \
    action decrypt \
    type ssl-inbound-inspection \
    profile fips-decryption-profile

commit
```

### API Configuration for Inbound Inspection

**XML Element:**
```xml
<entry name="decrypt-inbound-fips">
    <from>
        <member>untrust</member>
    </from>
    <to>
        <member>dmz</member>
    </to>
    <source>
        <member>any</member>
    </source>
    <destination>
        <member>internal-server-ip</member>
    </destination>
    <source-user>
        <member>any</member>
    </source-user>
    <service>
        <member>service-https</member>
    </service>
    <action>decrypt</action>
    <type>
        <ssl-inbound-inspection/>
    </type>
    <profile>fips-decryption-profile</profile>
</entry>
```

---

## Compliance Verification Commands

### Check Decryption Statistics

```bash
# Show decryption statistics
show session all filter ssl-decrypted yes

# Show decryption policy hit counts
show running rule-hit-count vsys vsys1 decryption-rulebase rules

# Show SSL decryption resource usage
show system resources filter ssl

# Show forward proxy certificate status
show certificate name forward-trust-ca-fips
```

### Verify Active Decryption Sessions

```bash
# Show active decrypted sessions
show session all filter application ssl

# Show session details
show session id <session-id>

# Show decryption errors
show log system | match -i "ssl\|decrypt"
```

### Check Protocol Settings in Effect

```bash
# Show decryption profile settings
show profiles decryption fips-decryption-profile

# Show running decryption configuration
show running config rulebase decryption
```

---

## Best Practices

1. **Always use TLS 1.2 or higher** - Block connections using older versions
2. **Block expired and untrusted certificates** - Enhance security posture
3. **Use GCM cipher suites** - Better performance and security
4. **Disable RSA key exchange** - No forward secrecy
5. **Deploy forward trust CA to clients** - Prevent certificate warnings
6. **Use separate CAs for trust and untrust** - Clear visual distinction for users
7. **Exclude sensitive categories** - Healthcare, financial data per regulations
8. **Monitor decryption failures** - May indicate attacks or misconfigurations
9. **Size hardware appropriately** - Decryption is CPU intensive
10. **Document exclusions** - Required for compliance audits

---

## Troubleshooting

### Decryption Failures

```bash
# Check global counters
show counter global filter delta yes | match -i ssl

# Check decryption failure reasons
show log system | match -i "decrypt"

# Debug SSL processing
debug dataplane show ssl sessions
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Connection reset | Cert not trusted | Deploy forward CA to clients |
| Performance impact | Too many sessions | Optimize exclusions, upgrade hardware |
| TLS 1.3 not working | Feature not enabled | Update PAN-OS, enable TLS 1.3 |
| Specific site fails | Cipher mismatch | Check site's supported ciphers |
| Certificate errors | CA not properly configured | Verify CA certificate is valid |

### Debug Commands

```bash
# Enable SSL debugging
debug dataplane ssl on debug

# View SSL logs
less dp-log ssl.log

# Check certificate chain
debug dataplane show pki chain

# Disable debugging
debug dataplane ssl off
```

---

## Capacity Planning

### Decryption Performance Impact

| Factor | Impact | Mitigation |
|--------|--------|------------|
| Key size | Larger keys = more CPU | Balance security vs. performance |
| Cipher type | CBC slower than GCM | Prefer GCM |
| Session volume | Linear scaling | Right-size hardware |
| Certificate validation | CRL/OCSP checks add latency | Use local CRL caching |

### Recommended Hardware Sizing

- Consider decryption throughput when sizing firewalls
- Enable hardware SSL offload where available
- Monitor CPU and session capacity during peak loads
