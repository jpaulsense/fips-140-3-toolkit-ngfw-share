# IKE Crypto Profiles - FIPS 140-3 Compliant Configuration

## Overview

IKE (Internet Key Exchange) crypto profiles define the cryptographic algorithms used during Phase 1 of VPN tunnel establishment. This document covers FIPS 140-3 compliant configurations for IKEv1 and IKEv2.

## FIPS 140-3 Compliant Algorithm Options

### Encryption Algorithms
| Algorithm | Key Size | FIPS Status | Recommendation |
|-----------|----------|-------------|----------------|
| AES-128-CBC | 128-bit | Compliant | Acceptable |
| AES-192-CBC | 192-bit | Compliant | Good |
| AES-256-CBC | 256-bit | Compliant | Recommended |
| AES-128-GCM | 128-bit | Compliant | Recommended (IKEv2) |
| AES-256-GCM | 256-bit | Compliant | Highly Recommended (IKEv2) |

### Diffie-Hellman Groups
| Group | Key Size | FIPS Status | Recommendation |
|-------|----------|-------------|----------------|
| Group 14 | 2048-bit | Compliant | Minimum acceptable |
| Group 15 | 3072-bit | Compliant | Recommended |
| Group 16 | 4096-bit | Compliant | Highly Recommended |
| Group 19 | 256-bit ECC (P-256) | Compliant | Recommended |
| Group 20 | 384-bit ECC (P-384) | Compliant | Highly Recommended |

### Hash Algorithms
| Algorithm | FIPS Status | Recommendation |
|-----------|-------------|----------------|
| SHA-256 | Compliant | Recommended |
| SHA-384 | Compliant | Highly Recommended |
| SHA-512 | Compliant | Highly Recommended |

### Authentication Methods
| Method | FIPS Status | Key Requirements |
|--------|-------------|------------------|
| RSA Signatures | Compliant | 2048-bit minimum |
| ECDSA Signatures | Compliant | P-256, P-384, or P-521 |
| Pre-Shared Key | Compliant | Use with compliant PRF |

---

## CLI Configuration

### Create FIPS-Compliant IKE Crypto Profile (IKEv2 - Recommended)

```bash
# SSH to firewall and enter configuration mode
configure

# Create IKE Crypto Profile with AES-256-GCM and SHA-512
set network ike crypto-profiles ike-crypto-fips-256gcm \
    hash sha512 \
    dh-group group20 \
    encryption aes-256-gcm \
    lifetime seconds 28800

# Create IKE Crypto Profile with AES-256-CBC (broader compatibility)
set network ike crypto-profiles ike-crypto-fips-256cbc \
    hash sha384 \
    dh-group group16 \
    encryption aes-256-cbc \
    lifetime seconds 28800

# Create IKE Crypto Profile with multiple options (negotiation flexibility)
set network ike crypto-profiles ike-crypto-fips-multi \
    hash sha512 sha384 sha256 \
    dh-group group20 group19 group16 group15 group14 \
    encryption aes-256-gcm aes-256-cbc aes-128-gcm aes-128-cbc \
    lifetime seconds 28800

# Commit the configuration
commit
```

### Verify IKE Crypto Profile Configuration

```bash
# Show all IKE crypto profiles
show network ike crypto-profiles

# Show specific profile details
show network ike crypto-profiles ike-crypto-fips-256gcm

# Operational command to verify active profiles
run show vpn ike-sa
```

### Remove Non-Compliant Algorithms from Existing Profile

```bash
configure

# Remove weak algorithms from existing profile
delete network ike crypto-profiles <profile-name> hash md5
delete network ike crypto-profiles <profile-name> hash sha1
delete network ike crypto-profiles <profile-name> dh-group group1
delete network ike crypto-profiles <profile-name> dh-group group2
delete network ike crypto-profiles <profile-name> dh-group group5
delete network ike crypto-profiles <profile-name> encryption des
delete network ike crypto-profiles <profile-name> encryption 3des

commit
```

---

## API Configuration

### Create IKE Crypto Profile via XML API

**API Endpoint:** `https://<firewall>/api/`

**Method:** POST

**Parameters:**
- `type=config`
- `action=set`
- `xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='ike-crypto-fips-256gcm']`
- `element=<element-xml>`

**XML Element:**
```xml
<entry name="ike-crypto-fips-256gcm">
    <encryption>
        <member>aes-256-gcm</member>
    </encryption>
    <hash>
        <member>sha512</member>
    </hash>
    <dh-group>
        <member>group20</member>
    </dh-group>
    <lifetime>
        <seconds>28800</seconds>
    </lifetime>
</entry>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='ike-crypto-fips-256gcm']" \
    -d "element=<entry name='ike-crypto-fips-256gcm'><encryption><member>aes-256-gcm</member></encryption><hash><member>sha512</member></hash><dh-group><member>group20</member></dh-group><lifetime><seconds>28800</seconds></lifetime></entry>"
```

### Create IKE Crypto Profile with Multiple Algorithms

**XML Element:**
```xml
<entry name="ike-crypto-fips-multi">
    <encryption>
        <member>aes-256-gcm</member>
        <member>aes-256-cbc</member>
        <member>aes-128-gcm</member>
        <member>aes-128-cbc</member>
    </encryption>
    <hash>
        <member>sha512</member>
        <member>sha384</member>
        <member>sha256</member>
    </hash>
    <dh-group>
        <member>group20</member>
        <member>group19</member>
        <member>group16</member>
        <member>group15</member>
        <member>group14</member>
    </dh-group>
    <lifetime>
        <seconds>28800</seconds>
    </lifetime>
</entry>
```

### Retrieve IKE Crypto Profile Configuration via API

```bash
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
```

### Delete Non-Compliant Profile via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=delete" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='non-compliant-profile']"
```

---

## Web UI Configuration Path

1. Navigate to: **Network > Network Profiles > IKE Crypto**
2. Click **Add** to create new profile
3. Configure:
   - **Name**: `ike-crypto-fips-256gcm`
   - **DH Group**: `group20` (or group19, group16, group15, group14)
   - **Encryption**: `aes-256-gcm` (or aes-256-cbc, aes-128-gcm, aes-128-cbc)
   - **Authentication**: `sha512` (or sha384, sha256)
   - **Key Lifetime**: `8 hours` (28800 seconds)

---

## Compliance Verification Commands

### Check Current IKE SA Algorithms in Use

```bash
# Show active IKE Security Associations
show vpn ike-sa

# Show detailed IKE SA information
show vpn ike-sa detail

# Show IKE SA for specific gateway
show vpn ike-sa gateway <gateway-name>
```

### Verify Profile Compliance

```bash
# Show all IKE crypto profiles in running config
show running config network ike crypto-profiles ike-crypto-profiles

# Export configuration for audit
scp export configuration from running-config.xml to <user>@<server>:<path>
```

---

## Best Practices

1. **Prefer IKEv2 over IKEv1** - IKEv2 supports AES-GCM authenticated encryption
2. **Use the strongest algorithms your peers support** - Start with AES-256-GCM + SHA-512 + Group 20
3. **Set appropriate key lifetimes** - 8 hours (28800 seconds) is recommended
4. **Document all peer requirements** - Some peers may only support specific algorithms
5. **Test before production deployment** - Verify connectivity with new profiles in a lab environment
6. **Remove non-compliant profiles** - Don't leave weak profiles available for potential misconfiguration

---

## Troubleshooting

### IKE Negotiation Failures

```bash
# Enable IKE debugging
debug ike global on debug

# View IKE logs
less mp-log ikemgr.log

# Clear IKE SA and renegotiate
clear vpn ike-sa gateway <gateway-name>
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Phase 1 timeout | Algorithm mismatch | Verify both peers have matching compliant algorithms |
| No proposal chosen | No common algorithms | Add additional compliant algorithms to profile |
| Authentication failure | Certificate key too small | Use RSA 2048+ or ECDSA P-256+ certificates |
