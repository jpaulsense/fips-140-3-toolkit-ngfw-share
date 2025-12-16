# IPSec Crypto Profiles - FIPS 140-3 Compliant Configuration

## Overview

IPSec crypto profiles define the cryptographic algorithms used during Phase 2 of VPN tunnel establishment for protecting data traffic. This document covers FIPS 140-3 compliant configurations for ESP (Encapsulating Security Payload).

## FIPS 140-3 Compliant Algorithm Options

### Encryption Algorithms
| Algorithm | Key Size | FIPS Status | Recommendation |
|-----------|----------|-------------|----------------|
| AES-128-CBC | 128-bit | Compliant | Acceptable |
| AES-192-CBC | 192-bit | Compliant | Good |
| AES-256-CBC | 256-bit | Compliant | Recommended |
| AES-128-GCM | 128-bit | Compliant | Recommended |
| AES-256-GCM | 256-bit | Compliant | Highly Recommended |

### Authentication Algorithms (for non-AEAD ciphers)
| Algorithm | FIPS Status | Recommendation |
|-----------|-------------|----------------|
| HMAC-SHA-256-128 | Compliant | Recommended |
| HMAC-SHA-384 | Compliant | Highly Recommended |
| HMAC-SHA-512 | Compliant | Highly Recommended |

### Perfect Forward Secrecy (PFS) Groups
| Group | Key Size | FIPS Status | Recommendation |
|-------|----------|-------------|----------------|
| Group 14 | 2048-bit DH | Compliant | Minimum acceptable |
| Group 15 | 3072-bit DH | Compliant | Recommended |
| Group 16 | 4096-bit DH | Compliant | Highly Recommended |
| Group 19 | 256-bit ECDH (P-256) | Compliant | Recommended |
| Group 20 | 384-bit ECDH (P-384) | Compliant | Highly Recommended |

---

## CLI Configuration

### Create FIPS-Compliant IPSec Crypto Profile (AES-256-GCM - Recommended)

```bash
# SSH to firewall and enter configuration mode
configure

# Create IPSec Crypto Profile with AES-256-GCM (AEAD - no separate auth needed)
set network ike crypto-profiles ipsec-crypto-profiles ipsec-crypto-fips-256gcm \
    esp encryption aes-256-gcm \
    dh-group group20 \
    lifetime seconds 3600

# Create IPSec Crypto Profile with AES-256-CBC + SHA-512
set network ike crypto-profiles ipsec-crypto-profiles ipsec-crypto-fips-256cbc \
    esp encryption aes-256-cbc \
    esp authentication sha512 \
    dh-group group16 \
    lifetime seconds 3600

# Create IPSec Crypto Profile with multiple options (negotiation flexibility)
set network ike crypto-profiles ipsec-crypto-profiles ipsec-crypto-fips-multi \
    esp encryption aes-256-gcm aes-256-cbc aes-128-gcm aes-128-cbc \
    esp authentication sha512 sha384 sha256 \
    dh-group group20 group19 group16 group15 group14 \
    lifetime seconds 3600

# Commit the configuration
commit
```

### Verify IPSec Crypto Profile Configuration

```bash
# Show all IPSec crypto profiles
show network ike crypto-profiles ipsec-crypto-profiles

# Show specific profile details
show network ike crypto-profiles ipsec-crypto-profiles ipsec-crypto-fips-256gcm

# Operational command to verify active tunnels
run show vpn ipsec-sa
```

### Remove Non-Compliant Algorithms from Existing Profile

```bash
configure

# Remove weak algorithms from existing profile
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> esp encryption des
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> esp encryption 3des
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> esp encryption null
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> esp authentication md5
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> esp authentication sha1
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> dh-group group1
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> dh-group group2
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> dh-group group5
delete network ike crypto-profiles ipsec-crypto-profiles <profile-name> dh-group no-pfs

commit
```

---

## API Configuration

### Create IPSec Crypto Profile via XML API

**API Endpoint:** `https://<firewall>/api/`

**Method:** POST

**Parameters:**
- `type=config`
- `action=set`
- `xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='ipsec-crypto-fips-256gcm']`

**XML Element (AES-256-GCM):**
```xml
<entry name="ipsec-crypto-fips-256gcm">
    <esp>
        <encryption>
            <member>aes-256-gcm</member>
        </encryption>
    </esp>
    <dh-group>group20</dh-group>
    <lifetime>
        <seconds>3600</seconds>
    </lifetime>
</entry>
```

**cURL Example:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='ipsec-crypto-fips-256gcm']" \
    -d "element=<entry name='ipsec-crypto-fips-256gcm'><esp><encryption><member>aes-256-gcm</member></encryption></esp><dh-group>group20</dh-group><lifetime><seconds>3600</seconds></lifetime></entry>"
```

**XML Element (AES-256-CBC with Authentication):**
```xml
<entry name="ipsec-crypto-fips-256cbc">
    <esp>
        <encryption>
            <member>aes-256-cbc</member>
        </encryption>
        <authentication>
            <member>sha512</member>
        </authentication>
    </esp>
    <dh-group>group16</dh-group>
    <lifetime>
        <seconds>3600</seconds>
    </lifetime>
</entry>
```

### Create IPSec Crypto Profile with Multiple Algorithms

**XML Element:**
```xml
<entry name="ipsec-crypto-fips-multi">
    <esp>
        <encryption>
            <member>aes-256-gcm</member>
            <member>aes-256-cbc</member>
            <member>aes-128-gcm</member>
            <member>aes-128-cbc</member>
        </encryption>
        <authentication>
            <member>sha512</member>
            <member>sha384</member>
            <member>sha256</member>
        </authentication>
    </esp>
    <dh-group>group20</dh-group>
    <lifetime>
        <seconds>3600</seconds>
    </lifetime>
</entry>
```

### Retrieve IPSec Crypto Profile Configuration via API

```bash
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
```

### Delete Non-Compliant Profile via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=delete" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='non-compliant-profile']"
```

---

## Web UI Configuration Path

1. Navigate to: **Network > Network Profiles > IPSec Crypto**
2. Click **Add** to create new profile
3. Configure:
   - **Name**: `ipsec-crypto-fips-256gcm`
   - **ESP Encryption**: `aes-256-gcm` (or aes-256-cbc, aes-128-gcm, aes-128-cbc)
   - **ESP Authentication**: `sha512` (only for CBC modes; GCM provides built-in authentication)
   - **DH Group**: `group20` (or group19, group16, group15, group14)
   - **Lifetime**: `1 hour` (3600 seconds)

---

## Compliance Verification Commands

### Check Current IPSec SA Algorithms in Use

```bash
# Show active IPSec Security Associations
show vpn ipsec-sa

# Show detailed IPSec SA information
show vpn ipsec-sa detail

# Show IPSec SA for specific tunnel
show vpn ipsec-sa tunnel <tunnel-name>

# Show tunnel statistics
show vpn flow tunnel-id <id>
```

### Verify Profile Compliance

```bash
# Show all IPSec crypto profiles in running config
show running config network ike crypto-profiles ipsec-crypto-profiles

# Show specific tunnel configuration
show running config network tunnel ipsec
```

---

## AES-GCM vs AES-CBC Comparison

| Feature | AES-GCM | AES-CBC + HMAC |
|---------|---------|----------------|
| Type | AEAD (Authenticated Encryption) | Encryption + Separate Auth |
| Authentication | Built-in (128-bit tag) | Requires separate HMAC |
| Performance | Better (single pass) | Slower (two passes) |
| FIPS Status | Compliant | Compliant |
| Compatibility | Requires IKEv2 | Works with IKEv1 and IKEv2 |
| Recommendation | Preferred when supported | Fallback option |

---

## Best Practices

1. **Prefer AES-GCM over AES-CBC** - Better performance and integrated authentication
2. **Always enable PFS** - Use group14 as minimum, group20 preferred
3. **Set appropriate key lifetimes** - 1 hour (3600 seconds) is recommended for data keys
4. **Match profiles with IKE crypto** - Use similar strength algorithms across phases
5. **Don't use NULL encryption** - Even for authentication-only tunnels, this is non-compliant
6. **Avoid DES and 3DES** - Both are deprecated and non-compliant

---

## Troubleshooting

### IPSec Tunnel Issues

```bash
# Show tunnel status
show vpn tunnel

# Enable IPSec debugging
debug ike global on debug

# View IPSec logs
less mp-log ikemgr.log

# Clear IPSec SA and renegotiate
clear vpn ipsec-sa tunnel <tunnel-name>
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| Phase 2 timeout | Algorithm mismatch | Verify both peers have matching compliant algorithms |
| Tunnel up but no traffic | Proxy ID mismatch | Verify local/remote network settings |
| Performance degradation | Using CBC without hardware acceleration | Switch to AES-GCM if supported |
| PFS rekey failure | DH group mismatch | Ensure both peers agree on PFS group |

---

## Security Considerations

### Recommended Minimum Configuration
```bash
# Minimum FIPS-compliant configuration
set network ike crypto-profiles ipsec-crypto-profiles ipsec-fips-minimum \
    esp encryption aes-128-cbc \
    esp authentication sha256 \
    dh-group group14 \
    lifetime seconds 3600
```

### Maximum Security Configuration
```bash
# Maximum security FIPS-compliant configuration
set network ike crypto-profiles ipsec-crypto-profiles ipsec-fips-maximum \
    esp encryption aes-256-gcm \
    dh-group group20 \
    lifetime seconds 1800
```
