# Certificate Requirements for IPSec/IKE - FIPS 140-3 Compliance

## Overview

When using certificate-based authentication for IPSec/IKE VPN tunnels, the certificates and keys must meet FIPS 140-3 requirements. This document covers key generation, certificate signing, and profile configuration requirements.

## FIPS 140-3 Certificate Requirements

### RSA Key Requirements
| Parameter | Minimum | Recommended | Maximum |
|-----------|---------|-------------|---------|
| Key Size | 2048-bit | 3072-bit | 4096-bit |
| Signature Algorithm | SHA-256 | SHA-384 | SHA-512 |
| Key Usage | Digital Signature | Digital Signature, Key Encipherment | - |

### ECDSA Key Requirements
| Parameter | Options | Recommendation |
|-----------|---------|----------------|
| Curve | P-256, P-384, P-521 | P-384 |
| Signature Algorithm | ECDSA with SHA-256/384/512 | ECDSA with SHA-384 |
| Key Usage | Digital Signature | Digital Signature |

### Non-Compliant Options (DO NOT USE)
- RSA keys less than 2048 bits
- DSA keys (any size)
- ECDSA with non-NIST curves (e.g., Curve25519, secp256k1)
- SHA-1 for signatures
- MD5 for signatures

---

## CLI Configuration

### Generate FIPS-Compliant RSA Key Pair

```bash
# SSH to firewall and enter configuration mode
configure

# Generate 3072-bit RSA key pair for IKE
request certificate generate-csr \
    certificate-name ike-cert-rsa3072 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384

# Generate 4096-bit RSA key pair (maximum security)
request certificate generate-csr \
    certificate-name ike-cert-rsa4096 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm RSA \
    rsa-nbits 4096 \
    digest sha512
```

### Generate FIPS-Compliant ECDSA Key Pair

```bash
# Generate ECDSA P-384 key pair (recommended)
request certificate generate-csr \
    certificate-name ike-cert-ecdsa384 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm ECDSA \
    ecdsa-type secp384r1 \
    digest sha384

# Generate ECDSA P-256 key pair
request certificate generate-csr \
    certificate-name ike-cert-ecdsa256 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm ECDSA \
    ecdsa-type secp256r1 \
    digest sha256

# Generate ECDSA P-521 key pair (maximum security)
request certificate generate-csr \
    certificate-name ike-cert-ecdsa521 \
    name cn=firewall.example.com,o=Organization,c=US \
    algorithm ECDSA \
    ecdsa-type secp521r1 \
    digest sha512
```

### Import Signed Certificate

```bash
# Import signed certificate (after receiving from CA)
request certificate import \
    certificate-name ike-cert-rsa3072 \
    file-type signed-certificate \
    format pem \
    certificate-file /path/to/signed-cert.pem

# Import CA certificate for chain validation
request certificate import \
    certificate-name root-ca \
    file-type root-certificate \
    format pem \
    certificate-file /path/to/root-ca.pem
```

### Create Certificate Profile for IKE

```bash
configure

# Create certificate profile with FIPS-compliant settings
set certificate-profile ike-cert-profile-fips \
    CA root-ca \
    use-crl yes \
    use-ocsp yes \
    crl-receive-timeout 5 \
    ocsp-receive-timeout 5

# Block specific non-compliant algorithms
set certificate-profile ike-cert-profile-fips \
    block-expired-certificate yes \
    block-unknown-certificate yes

commit
```

### Configure IKE Gateway with Certificate Authentication

```bash
configure

# Create IKE gateway with certificate authentication
set network ike gateway ike-gw-fips-cert \
    authentication certificate \
    local-certificate-profile \
        local-certificate ike-cert-rsa3072 \
    peer-id type fqdn value peer.example.com \
    local-id type fqdn value firewall.example.com \
    protocol ikev2 \
    protocol-common fragmentation enable yes \
    peer-address ip 203.0.113.1 \
    local-address interface ethernet1/1 \
    crypto-profile ike-crypto-fips-256gcm

commit
```

---

## API Configuration

### Generate CSR via API

**API Endpoint:** `https://<firewall>/api/`

**Method:** POST

```bash
# Generate RSA 3072-bit CSR
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<request><certificate><generate-csr><certificate-name>ike-cert-rsa3072</certificate-name><name>cn=firewall.example.com,o=Organization,c=US</name><algorithm>RSA</algorithm><rsa-nbits>3072</rsa-nbits><digest>sha384</digest></generate-csr></certificate></request>"
```

### Import Certificate via API

```bash
# Import signed certificate
curl -k -X POST "https://<firewall>/api/" \
    -d "type=import" \
    -d "category=certificate" \
    -d "certificate-name=ike-cert-rsa3072" \
    -d "format=pem" \
    -d "key=<API-KEY>" \
    --data-urlencode "file@/path/to/signed-cert.pem"
```

### Create Certificate Profile via API

**XML Element:**
```xml
<entry name="ike-cert-profile-fips">
    <CA>
        <member>root-ca</member>
    </CA>
    <use-crl>yes</use-crl>
    <use-ocsp>yes</use-ocsp>
    <crl-receive-timeout>5</crl-receive-timeout>
    <ocsp-receive-timeout>5</ocsp-receive-timeout>
    <block-expired-certificate>yes</block-expired-certificate>
    <block-unknown-certificate>yes</block-unknown-certificate>
</entry>
```

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/certificate-profile/entry[@name='ike-cert-profile-fips']" \
    -d "element=<entry name='ike-cert-profile-fips'><CA><member>root-ca</member></CA><use-crl>yes</use-crl><use-ocsp>yes</use-ocsp><crl-receive-timeout>5</crl-receive-timeout><ocsp-receive-timeout>5</ocsp-receive-timeout><block-expired-certificate>yes</block-expired-certificate><block-unknown-certificate>yes</block-unknown-certificate></entry>"
```

### Configure IKE Gateway with Certificate via API

**XML Element:**
```xml
<entry name="ike-gw-fips-cert">
    <authentication>
        <certificate>
            <local-certificate>ike-cert-rsa3072</local-certificate>
        </certificate>
    </authentication>
    <protocol>
        <ikev2>
            <ike-crypto-profile>ike-crypto-fips-256gcm</ike-crypto-profile>
        </ikev2>
    </protocol>
    <protocol-common>
        <fragmentation>
            <enable>yes</enable>
        </fragmentation>
    </protocol-common>
    <local-address>
        <interface>ethernet1/1</interface>
    </local-address>
    <peer-address>
        <ip>203.0.113.1</ip>
    </peer-address>
    <local-id>
        <type>fqdn</type>
        <id>firewall.example.com</id>
    </local-id>
    <peer-id>
        <type>fqdn</type>
        <id>peer.example.com</id>
    </peer-id>
</entry>
```

---

## Certificate Verification Commands

### View Certificate Details

```bash
# Show all certificates
show certificate summary

# Show detailed certificate information
show certificate name <certificate-name>

# Verify certificate chain
request certificate validate certificate-name <certificate-name>

# Show certificate in PEM format
request certificate export certificate-name <certificate-name> format pem
```

### Check Certificate Compliance

```bash
# Show certificate key information
debug dataplane show pki certificate <certificate-name>

# Verify key size meets requirements
request certificate info certificate-name <certificate-name>
```

### Check IKE Gateway Certificate Status

```bash
# Show IKE gateway status
show vpn ike-sa gateway <gateway-name>

# Show certificate used by IKE gateway
show network ike gateway <gateway-name>

# Debug certificate authentication
debug ike global on debug
less mp-log ikemgr.log | match -i cert
```

---

## Web UI Configuration Path

### Generate Certificate Signing Request
1. Navigate to: **Device > Certificate Management > Certificates**
2. Click **Generate** at bottom of page
3. Configure:
   - **Certificate Name**: `ike-cert-rsa3072`
   - **Common Name**: `firewall.example.com`
   - **Algorithm**: `RSA` or `ECDSA`
   - **Key Size**: `3072` (RSA) or `secp384r1` (ECDSA)
   - **Digest**: `SHA384` or `SHA512`

### Create Certificate Profile
1. Navigate to: **Device > Certificate Management > Certificate Profile**
2. Click **Add**
3. Configure:
   - **Name**: `ike-cert-profile-fips`
   - **CA Certificates**: Add your trusted CA
   - **Use CRL**: `Yes`
   - **Use OCSP**: `Yes`
   - **Block Expired Certificate**: `Yes`

### Configure IKE Gateway with Certificate
1. Navigate to: **Network > Network Profiles > IKE Gateways**
2. Click **Add** or edit existing gateway
3. Under **Authentication**:
   - Select **Certificate**
   - **Local Certificate**: Select your FIPS-compliant certificate
   - **Certificate Profile**: Select `ike-cert-profile-fips`

---

## Best Practices

1. **Generate keys on the firewall** - Don't import private keys unless necessary
2. **Use ECDSA where possible** - Better performance with equivalent security
3. **Minimum RSA 3072-bit for new deployments** - 2048-bit only for legacy compatibility
4. **Enable CRL and OCSP checking** - Ensure revoked certificates are rejected
5. **Document certificate expiration dates** - Set up alerts before expiration
6. **Use separate certificates per purpose** - Don't share IKE certificates with other services
7. **Store root CA certificates offline** - Protect the trust anchor

---

## Certificate Lifecycle Management

### Certificate Expiration Check

```bash
# Show all certificates with expiration dates
show certificate summary

# Check specific certificate expiration
show certificate name <cert-name> | match -i expir
```

### Certificate Renewal Process

1. Generate new CSR before expiration
2. Submit CSR to CA
3. Import new signed certificate
4. Update IKE gateway to use new certificate
5. Monitor tunnel renegotiation
6. Delete old certificate after verification

```bash
# Update IKE gateway to use new certificate
configure
set network ike gateway <gateway-name> authentication certificate local-certificate <new-cert-name>
commit

# Verify new certificate is in use
show vpn ike-sa gateway <gateway-name>

# Delete old certificate (after verification)
delete certificate name <old-cert-name>
commit
```

---

## Troubleshooting Certificate Issues

### Common Errors

| Error | Cause | Resolution |
|-------|-------|------------|
| Certificate chain incomplete | Missing intermediate CA | Import full certificate chain |
| Certificate expired | Certificate past validity | Renew certificate |
| Key size too small | Non-compliant key | Regenerate with compliant key size |
| Signature algorithm weak | Using SHA-1 | Regenerate CSR with SHA-256+ |
| CRL check failed | CRL server unreachable | Verify CRL URL accessibility |

### Debug Commands

```bash
# Enable certificate debugging
debug dataplane pki on debug

# View certificate authentication logs
less mp-log ikemgr.log | match -i "cert|certificate"

# Check CRL/OCSP status
show crl-status
show ocsp-status
```
