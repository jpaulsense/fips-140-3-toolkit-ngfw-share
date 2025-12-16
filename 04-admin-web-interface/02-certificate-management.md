# Certificate Management for Administrative Access - FIPS 140-3 Compliance

## Overview

Proper certificate management is essential for FIPS 140-3 compliant administrative access. This document covers generating, importing, and managing certificates for the firewall's management interface.

## FIPS 140-3 Certificate Requirements Summary

| Parameter | Requirement | Recommendation |
|-----------|-------------|----------------|
| RSA Key Size | 2048-bit minimum | 3072-bit or 4096-bit |
| ECDSA Curve | P-256, P-384, P-521 | P-384 |
| Signature Algorithm | SHA-256 minimum | SHA-384 or SHA-512 |
| Validity Period | Organizational policy | 1-2 years max |
| Key Usage | Digital Signature | Digital Signature, Key Encipherment |

---

## CLI Configuration

### Generate Certificate Signing Request (CSR)

**RSA 3072-bit Certificate:**
```bash
# Generate CSR with RSA 3072-bit key
request certificate generate-csr \
    certificate-name mgmt-cert-rsa3072 \
    name cn=firewall.example.com,o=Organization,ou=IT,l=City,st=State,c=US \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384

# View the CSR
request certificate export certificate-name mgmt-cert-rsa3072 format pem type csr
```

**RSA 4096-bit Certificate (Maximum Security):**
```bash
request certificate generate-csr \
    certificate-name mgmt-cert-rsa4096 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm RSA \
    rsa-nbits 4096 \
    digest sha512
```

**ECDSA P-384 Certificate (Recommended):**
```bash
request certificate generate-csr \
    certificate-name mgmt-cert-ecdsa384 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm ECDSA \
    ecdsa-type secp384r1 \
    digest sha384
```

**ECDSA P-521 Certificate:**
```bash
request certificate generate-csr \
    certificate-name mgmt-cert-ecdsa521 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm ECDSA \
    ecdsa-type secp521r1 \
    digest sha512
```

### Import Signed Certificate

```bash
# Import signed certificate from CA
request certificate import \
    certificate-name mgmt-cert-rsa3072 \
    file-type signed-certificate \
    format pem \
    certificate-file /path/to/signed-cert.pem

# Verify import
show certificate name mgmt-cert-rsa3072
```

### Import Certificate Chain

```bash
# Import Root CA certificate
request certificate import \
    certificate-name root-ca \
    file-type root-certificate \
    format pem \
    certificate-file /path/to/root-ca.pem

# Import Intermediate CA certificate
request certificate import \
    certificate-name intermediate-ca \
    file-type intermediate-certificate \
    format pem \
    certificate-file /path/to/intermediate-ca.pem

# Verify chain
show certificate summary
```

### Import PKCS#12 Certificate Bundle

```bash
# Import certificate with private key
request certificate import \
    certificate-name mgmt-cert-import \
    format pkcs12 \
    certificate-file /path/to/certificate.p12 \
    passphrase <p12-password>
```

### Generate Self-Signed Certificate (For Testing Only)

```bash
# Generate self-signed certificate (NOT for production)
request certificate generate-self-signed \
    certificate-name mgmt-cert-self-signed \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384 \
    validity-days 365
```

---

## API Configuration

### Generate CSR via API

```bash
# Generate RSA 3072-bit CSR
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<request><certificate><generate-csr><certificate-name>mgmt-cert-rsa3072</certificate-name><name>cn=firewall.example.com,o=Organization,c=US</name><algorithm>RSA</algorithm><rsa-nbits>3072</rsa-nbits><digest>sha384</digest></generate-csr></certificate></request>"
```

### Export CSR via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<request><certificate><export><certificate-name>mgmt-cert-rsa3072</certificate-name><format>pem</format><type>csr</type></export></certificate></request>"
```

### Import Certificate via API

```bash
# Import signed certificate
curl -k -X POST "https://<firewall>/api/" \
    -F "type=import" \
    -F "category=certificate" \
    -F "certificate-name=mgmt-cert-rsa3072" \
    -F "format=pem" \
    -F "key=<API-KEY>" \
    -F "file=@/path/to/signed-cert.pem"
```

### Import CA Certificate via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -F "type=import" \
    -F "category=certificate" \
    -F "certificate-name=root-ca" \
    -F "format=pem" \
    -F "key=<API-KEY>" \
    -F "file=@/path/to/root-ca.pem"
```

### View Certificate via API

```bash
# Show certificate details
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<show><certificate><name>mgmt-cert-rsa3072</name></certificate></show>"

# Show certificate summary
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<show><certificate><summary></summary></certificate></show>"
```

### Delete Certificate via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=delete" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/certificate/entry[@name='old-certificate']"
```

---

## Web UI Configuration Path

### Generate CSR
1. Navigate to: **Device > Certificate Management > Certificates**
2. Click **Generate** at bottom of page
3. Configure:
   - **Certificate Name**: `mgmt-cert-rsa3072`
   - **Common Name**: `firewall.example.com`
   - **Country**: `US`
   - **Organization**: Your organization name
   - **Algorithm**: RSA
   - **Number of Bits**: 3072
   - **Digest**: SHA384
4. Click **Generate**
5. Export CSR for submission to CA

### Import Signed Certificate
1. Navigate to: **Device > Certificate Management > Certificates**
2. Click **Import**
3. Configure:
   - **Certificate Name**: Select CSR name
   - **Format**: PEM
   - **File Type**: Signed Certificate
   - **Certificate File**: Browse to signed certificate

### Import CA Certificate
1. Navigate to: **Device > Certificate Management > Certificates**
2. Click **Import**
3. Configure:
   - **Certificate Name**: `root-ca`
   - **Format**: PEM
   - **File Type**: Root Certificate Authority
   - **Certificate File**: Browse to CA certificate

---

## Certificate Verification

### Verify Certificate Details

```bash
# Show certificate summary
show certificate summary

# Show specific certificate
show certificate name mgmt-cert-rsa3072

# Verify key size
show certificate name mgmt-cert-rsa3072 | match -i "key"

# Verify signature algorithm
show certificate name mgmt-cert-rsa3072 | match -i "signature"

# Verify validity period
show certificate name mgmt-cert-rsa3072 | match -i "not"
```

### Validate Certificate Chain

```bash
# Validate certificate
request certificate validate certificate-name mgmt-cert-rsa3072

# Check chain status
show certificate name mgmt-cert-rsa3072 | match -i "chain\|issuer"
```

### External Verification

```bash
# From external system - view certificate
openssl s_client -connect firewall.example.com:443 2>/dev/null | \
    openssl x509 -noout -text

# Check key size
openssl s_client -connect firewall.example.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep "Public-Key"

# Check signature algorithm
openssl s_client -connect firewall.example.com:443 2>/dev/null | \
    openssl x509 -noout -text | grep "Signature Algorithm"

# Check validity dates
openssl s_client -connect firewall.example.com:443 2>/dev/null | \
    openssl x509 -noout -dates
```

---

## Certificate Lifecycle Management

### Monitor Certificate Expiration

```bash
# Show all certificates with expiration
show certificate summary

# Check specific certificate expiration
show certificate name mgmt-cert-rsa3072 | match -i "not after"

# Automated check (in days until expiration)
request certificate info certificate-name mgmt-cert-rsa3072
```

### Certificate Renewal Process

1. **60 days before expiration:**
   - Generate new CSR
   - Submit to CA

2. **30 days before expiration:**
   - Import new signed certificate
   - Test in non-production

3. **7 days before expiration:**
   - Update SSL/TLS service profile to use new certificate
   - Commit and test

4. **After successful transition:**
   - Delete old certificate
   - Update documentation

```bash
# Step 1: Generate new CSR
request certificate generate-csr \
    certificate-name mgmt-cert-rsa3072-new \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384

# Step 2: Export and submit to CA
request certificate export certificate-name mgmt-cert-rsa3072-new format pem type csr

# Step 3: Import signed certificate
request certificate import \
    certificate-name mgmt-cert-rsa3072-new \
    file-type signed-certificate \
    format pem \
    certificate-file /path/to/new-cert.pem

# Step 4: Update SSL/TLS profile
configure
set ssl-tls-service-profile mgmt-ssl-fips certificate mgmt-cert-rsa3072-new
commit

# Step 5: Verify and delete old certificate
show certificate name mgmt-cert-rsa3072-new
configure
delete certificate mgmt-cert-rsa3072
commit
```

### Automated Expiration Alerts

```bash
configure

# Create external alert for certificate expiration
# (Requires external monitoring system integration)

# Export certificate info for monitoring
scp export certificate name mgmt-cert-rsa3072 to user@server:/path/

commit
```

---

## Best Practices

1. **Never use self-signed certificates in production** - Use proper CA-signed certificates
2. **Minimum RSA 3072-bit for new deployments** - 2048-bit only for legacy
3. **Prefer ECDSA P-384** - Better performance with equivalent security
4. **Use SHA-384 or SHA-512** - Not SHA-256 for new certificates
5. **Set validity to 1-2 years max** - Shorter validity = better security
6. **Include all required SANs** - Subject Alternative Names for all access methods
7. **Protect private keys** - Never export unless necessary
8. **Document certificate details** - For compliance audits
9. **Implement expiration monitoring** - Automated alerts 60+ days before
10. **Test renewal process** - In non-production environment first

---

## Troubleshooting

### Certificate Issues

```bash
# Check certificate chain completeness
request certificate validate certificate-name mgmt-cert-rsa3072

# View certificate details
show certificate name mgmt-cert-rsa3072

# Check for missing intermediate CA
show certificate summary | match -i "issuer"
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Chain incomplete | Missing intermediate CA | Import intermediate certificate |
| Certificate expired | Past validity period | Renew certificate |
| Key mismatch | CSR and cert don't match | Import to correct CSR name |
| Wrong format | Incorrect file format | Convert to PEM format |
| Private key missing | Imported cert only | Reimport with private key |

### Certificate Format Conversion

```bash
# Convert DER to PEM (external tool)
openssl x509 -inform DER -in cert.der -outform PEM -out cert.pem

# Convert PKCS#7 to PEM (external tool)
openssl pkcs7 -in cert.p7b -print_certs -out cert.pem

# Extract cert from PKCS#12 (external tool)
openssl pkcs12 -in cert.p12 -clcerts -nokeys -out cert.pem
```

---

## Compliance Verification Checklist

- [ ] Certificate key is RSA 2048+ or ECDSA P-256+
- [ ] Certificate signed with SHA-256 or stronger
- [ ] Certificate validity is within policy (1-2 years)
- [ ] Certificate chain is complete
- [ ] Subject matches firewall hostname/IP
- [ ] Key usage includes Digital Signature
- [ ] Certificate is from trusted CA (not self-signed)
- [ ] Expiration monitoring is configured
- [ ] Renewal process is documented
- [ ] Backup of certificate exists

---

## Backup and Recovery

### Export Certificate for Backup

```bash
# Export certificate and private key (secured storage required)
request certificate export certificate-name mgmt-cert-rsa3072 \
    format pkcs12 \
    include-private-key yes \
    passphrase <strong-password> \
    destination /path/to/backup.p12

# Note: Store backup in secure location with access controls
```

### Restore Certificate

```bash
# Import from PKCS#12 backup
request certificate import \
    certificate-name mgmt-cert-rsa3072 \
    format pkcs12 \
    certificate-file /path/to/backup.p12 \
    passphrase <strong-password>
```

### Configuration Backup

Certificates are included in configuration backups:

```bash
# Export full configuration (includes certificates)
scp export configuration from running-config.xml to user@server:/path/

# Restore configuration (restores certificates)
scp import configuration from user@server:/path/running-config.xml
load config from running-config.xml
commit
```
