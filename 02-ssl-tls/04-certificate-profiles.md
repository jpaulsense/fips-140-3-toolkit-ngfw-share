# Certificate Profiles for SSL/TLS - FIPS 140-3 Compliance

## Overview

Certificate Profiles define how the firewall validates client and server certificates during TLS connections. This document covers FIPS 140-3 compliant certificate profile configurations for SSL/TLS services.

## FIPS 140-3 Certificate Profile Requirements

### Certificate Validation Settings
| Setting | FIPS Requirement |
|---------|------------------|
| Key Size Validation | RSA 2048+ or ECDSA P-256+ |
| Signature Algorithm | SHA-256 or stronger |
| Certificate Revocation | CRL or OCSP required |
| Chain Validation | Full chain to trusted root |

### Blocked Algorithms
| Algorithm | Status |
|-----------|--------|
| MD5 signatures | Block |
| SHA-1 signatures | Block |
| RSA < 2048 bits | Block |
| DSA keys | Block |

---

## CLI Configuration

### Create FIPS-Compliant Certificate Profile

```bash
# SSH to firewall and enter configuration mode
configure

# Create certificate profile with FIPS settings
set certificate-profile cert-profile-fips \
    use-crl yes \
    use-ocsp yes \
    crl-receive-timeout 5 \
    ocsp-receive-timeout 5 \
    block-expired-certificate yes \
    block-unknown-certificate yes \
    block-timeout-certificate yes \
    block-certificate-on-crl yes

# Add trusted CA certificates
set certificate-profile cert-profile-fips \
    CA root-ca-cert \
    CA intermediate-ca-cert

# Configure username field (for client certificate authentication)
set certificate-profile cert-profile-fips \
    username-field subject alt-email

commit
```

### Create Certificate Profile for Mutual TLS

```bash
configure

# Create profile requiring client certificates
set certificate-profile mtls-profile-fips \
    use-crl yes \
    use-ocsp yes \
    crl-receive-timeout 5 \
    ocsp-receive-timeout 5 \
    block-expired-certificate yes \
    block-unknown-certificate yes \
    block-timeout-certificate no \
    block-certificate-on-crl yes \
    CA client-ca-cert

commit
```

### Import CA Certificates

```bash
# Import Root CA certificate
request certificate import \
    certificate-name root-ca-cert \
    file-type root-certificate \
    format pem \
    certificate-file /path/to/root-ca.pem

# Import Intermediate CA certificate
request certificate import \
    certificate-name intermediate-ca-cert \
    file-type intermediate-certificate \
    format pem \
    certificate-file /path/to/intermediate-ca.pem

# Import Client CA certificate (for client cert auth)
request certificate import \
    certificate-name client-ca-cert \
    file-type root-certificate \
    format pem \
    certificate-file /path/to/client-ca.pem
```

### Verify CA Certificate Compliance

```bash
# Show certificate details
show certificate name root-ca-cert

# Verify key size (should be 2048+ for RSA)
show certificate name root-ca-cert | match -i "key"

# Verify signature algorithm (should be SHA-256+)
show certificate name root-ca-cert | match -i "signature"

# Validate certificate chain
request certificate validate certificate-name root-ca-cert
```

---

## API Configuration

### Create Certificate Profile via XML API

**XML Element (Standard Profile):**
```xml
<entry name="cert-profile-fips">
    <use-crl>yes</use-crl>
    <use-ocsp>yes</use-ocsp>
    <crl-receive-timeout>5</crl-receive-timeout>
    <ocsp-receive-timeout>5</ocsp-receive-timeout>
    <block-expired-certificate>yes</block-expired-certificate>
    <block-unknown-certificate>yes</block-unknown-certificate>
    <block-timeout-certificate>yes</block-timeout-certificate>
    <CA>
        <member>root-ca-cert</member>
        <member>intermediate-ca-cert</member>
    </CA>
    <username-field>
        <subject>alt-email</subject>
    </username-field>
</entry>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/certificate-profile/entry[@name='cert-profile-fips']" \
    --data-urlencode "element@cert-profile.xml"
```

**XML Element (Mutual TLS Profile):**
```xml
<entry name="mtls-profile-fips">
    <use-crl>yes</use-crl>
    <use-ocsp>yes</use-ocsp>
    <crl-receive-timeout>5</crl-receive-timeout>
    <ocsp-receive-timeout>5</ocsp-receive-timeout>
    <block-expired-certificate>yes</block-expired-certificate>
    <block-unknown-certificate>yes</block-unknown-certificate>
    <block-timeout-certificate>no</block-timeout-certificate>
    <block-certificate-on-crl>yes</block-certificate-on-crl>
    <CA>
        <member>client-ca-cert</member>
    </CA>
    <username-field>
        <subject>common-name</subject>
    </username-field>
</entry>
```

### Import CA Certificate via API

```bash
# Import CA certificate
curl -k -X POST "https://<firewall>/api/" \
    -F "type=import" \
    -F "category=certificate" \
    -F "certificate-name=root-ca-cert" \
    -F "format=pem" \
    -F "key=<API-KEY>" \
    -F "file=@/path/to/root-ca.pem"
```

### Retrieve Certificate Profile via API

```bash
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/certificate-profile"
```

### Delete Certificate Profile via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=delete" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/certificate-profile/entry[@name='old-profile']"
```

---

## Web UI Configuration Path

### Create Certificate Profile
1. Navigate to: **Device > Certificate Management > Certificate Profile**
2. Click **Add**
3. Configure:
   - **Name**: `cert-profile-fips`
   - **CA Certificates**: Add your trusted CA certificates
   - **Use CRL**: Yes
   - **Use OCSP**: Yes
   - **CRL Receive Timeout**: 5 seconds
   - **OCSP Receive Timeout**: 5 seconds
   - **Block Session if Certificate Status is Unknown**: Yes
   - **Block Session if Certificate is Expired**: Yes
   - **Block Session if CRL Status is Unavailable**: Yes (optional)

### Import CA Certificates
1. Navigate to: **Device > Certificate Management > Certificates**
2. Click **Import**
3. Select:
   - **Certificate Name**: `root-ca-cert`
   - **Format**: PEM
   - **Certificate File**: Browse to file
   - **File Type**: Root Certificate Authority

---

## Certificate Revocation Configuration

### Configure CRL Distribution Points

```bash
configure

# Configure automatic CRL retrieval
set deviceconfig setting certificate crl-retrieval-timeout 5

# Configure CRL cache timeout
set deviceconfig setting certificate crl-cache-timeout 1440

# Enable OCSP responder URL from certificate
set deviceconfig setting certificate use-ocsp-from-aia yes

commit
```

### Configure Manual OCSP Responder

```bash
configure

# Create OCSP responder configuration
set shared ocsp-responder ocsp-fips \
    host-name ocsp.example.com \
    protocol http \
    path /ocsp

# Associate with certificate profile
set certificate-profile cert-profile-fips \
    ocsp-responder ocsp-fips

commit
```

### API Configuration for OCSP Responder

**XML Element:**
```xml
<entry name="ocsp-fips">
    <host-name>ocsp.example.com</host-name>
    <protocol>http</protocol>
    <path>/ocsp</path>
</entry>
```

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/ocsp-responder/entry[@name='ocsp-fips']" \
    -d "element=<entry name='ocsp-fips'><host-name>ocsp.example.com</host-name><protocol>http</protocol><path>/ocsp</path></entry>"
```

---

## Use Cases

### GlobalProtect Client Certificate Authentication

```bash
configure

# Configure GlobalProtect to use certificate profile
set network global-protect global-protect-gateway gp-gateway-fips \
    remote-user-tunnel-configs gp-tunnel-fips \
    certificate-profile mtls-profile-fips

commit
```

### SSL Decryption Certificate Validation

```bash
configure

# Configure decryption profile to use certificate profile
set profiles decryption fips-decryption-profile \
    ssl-forward-proxy block-expired-certificate yes \
    ssl-forward-proxy block-untrusted-issuer yes

commit
```

### Admin Web Interface Client Certificate

```bash
configure

# Configure management interface to require client certificates
set deviceconfig system certificate-profile mtls-profile-fips

commit
```

---

## Compliance Verification Commands

### Check Certificate Profile Configuration

```bash
# Show all certificate profiles
show certificate-profile

# Show specific profile
show certificate-profile cert-profile-fips

# Show running configuration
show running config certificate-profile
```

### Verify CA Certificate Details

```bash
# List all certificates
show certificate summary

# Show certificate details
show certificate name root-ca-cert

# Verify certificate chain
request certificate validate certificate-name root-ca-cert

# Check certificate expiration
show certificate name root-ca-cert | match -i "not after"
```

### Check CRL/OCSP Status

```bash
# Show CRL status
show crl-status

# Show OCSP responder status
show ocsp-status

# Force CRL refresh
request certificate refresh-crl certificate-profile cert-profile-fips
```

---

## Best Practices

1. **Always enable CRL and/or OCSP** - Certificate revocation is required for FIPS compliance
2. **Set appropriate timeouts** - Balance security with availability
3. **Block expired certificates** - Expired certs should not be trusted
4. **Use multiple CA certificates** - Include full chain (root + intermediates)
5. **Configure username extraction** - For audit logging of client cert users
6. **Regular CA certificate review** - Ensure CAs are still trustworthy
7. **Monitor revocation failures** - May indicate network or CA issues
8. **Document CA hierarchy** - Required for compliance audits
9. **Backup CA certificates** - Essential for disaster recovery
10. **Test revocation before production** - Verify CRL/OCSP works

---

## Troubleshooting

### Certificate Validation Failures

```bash
# Check certificate chain
request certificate validate certificate-name <cert-name>

# Debug certificate processing
debug dataplane pki on debug
less dp-log ssl.log

# Check CRL download issues
show log system | match -i crl

# Disable debugging
debug dataplane pki off
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Chain validation failed | Missing intermediate CA | Import intermediate certificates |
| CRL download failed | Network connectivity | Verify firewall can reach CRL URL |
| OCSP timeout | Responder unreachable | Check OCSP URL accessibility |
| Unknown certificate | CA not in profile | Add CA to certificate profile |
| Expired certificate | Certificate past validity | Renew certificate |

### CRL/OCSP Debugging

```bash
# Test CRL download manually
request certificate fetch-crl certificate <ca-cert-name>

# Check network connectivity to OCSP
ping host ocsp.example.com

# View CRL contents
debug dataplane show pki crl

# Check OCSP response
debug dataplane show pki ocsp
```

---

## Certificate Lifecycle Management

### Certificate Expiration Monitoring

```bash
# Show all certificates with expiration
show certificate summary

# Check certificates expiring within 30 days
show certificate summary | match -B 2 -A 2 "days"
```

### Certificate Renewal Process

1. Generate new CSR or request new certificate from CA
2. Import new certificate with different name
3. Update certificate references in profiles
4. Verify connectivity with new certificate
5. Delete old certificate after validation

### CA Certificate Update

```bash
# Import new CA certificate
request certificate import \
    certificate-name new-root-ca \
    file-type root-certificate \
    format pem \
    certificate-file /path/to/new-root-ca.pem

# Add to certificate profile
configure
set certificate-profile cert-profile-fips CA new-root-ca
commit

# After transition period, remove old CA
configure
delete certificate-profile cert-profile-fips CA old-root-ca
commit
```
