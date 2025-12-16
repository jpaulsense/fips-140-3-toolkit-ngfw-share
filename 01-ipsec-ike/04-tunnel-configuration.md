# IPSec Tunnel Configuration - FIPS 140-3 Compliance

## Overview

This document provides complete IPSec tunnel configuration examples using FIPS 140-3 compliant settings. It covers site-to-site VPN tunnels, route-based VPNs, and policy-based VPNs.

## Prerequisites

Before configuring tunnels, ensure you have:
- FIPS-compliant IKE Crypto Profile (see `01-ike-crypto-profiles.md`)
- FIPS-compliant IPSec Crypto Profile (see `02-ipsec-crypto-profiles.md`)
- FIPS-compliant certificates (if using certificate auth) (see `03-certificate-requirements.md`)

---

## Site-to-Site VPN - Route-Based (Recommended)

### CLI Configuration

```bash
# SSH to firewall and enter configuration mode
configure

# Step 1: Create IKE Gateway
set network ike gateway ike-gw-fips-site1 \
    version ikev2 \
    peer-address ip 203.0.113.100 \
    local-address interface ethernet1/1 \
    local-address ip 198.51.100.1 \
    authentication pre-shared-key key "ComplexPSK-Min24Characters!" \
    protocol ikev2 \
    protocol-common nat-traversal enable yes \
    protocol-common fragmentation enable yes \
    crypto-profile ike-crypto-fips-256gcm \
    enable-passive-mode no \
    liveness-check interval 5

# Step 2: Create IPSec Tunnel
set network tunnel ipsec ipsec-tunnel-site1 \
    auto-key ike-gateway ike-gw-fips-site1 \
    auto-key ipsec-crypto-profile ipsec-crypto-fips-256gcm \
    tunnel-interface tunnel.1 \
    anti-replay yes \
    enable-tunnel-monitor yes \
    tunnel-monitor destination-ip 10.2.0.1 \
    tunnel-monitor tunnel-monitor-profile default

# Step 3: Create Tunnel Interface
set network interface tunnel units tunnel.1 \
    ip 10.255.255.1/30 \
    comment "Site-to-Site VPN to Site1"

# Step 4: Add to Virtual Router
set network virtual-router default interface tunnel.1

# Step 5: Add Static Route for Remote Network
set network virtual-router default routing-table ip static-route route-to-site1 \
    destination 10.2.0.0/16 \
    interface tunnel.1 \
    nexthop ip-address 10.255.255.2

# Step 6: Add Tunnel Interface to Zone
set zone vpn-zone network layer3 tunnel.1

# Commit
commit
```

### Verify Configuration

```bash
# Show IKE gateway status
show vpn ike-sa gateway ike-gw-fips-site1

# Show IPSec tunnel status
show vpn ipsec-sa tunnel ipsec-tunnel-site1

# Show tunnel interface status
show interface tunnel.1

# Test connectivity through tunnel
ping source 10.255.255.1 host 10.2.0.1
```

---

## Site-to-Site VPN - Certificate Authentication

### CLI Configuration

```bash
configure

# Step 1: Create IKE Gateway with Certificate Auth
set network ike gateway ike-gw-fips-cert \
    version ikev2 \
    peer-address ip 203.0.113.100 \
    local-address interface ethernet1/1 \
    authentication certificate \
    authentication local-certificate ike-cert-rsa3072 \
    authentication certificate-profile ike-cert-profile-fips \
    local-id type fqdn value firewall.example.com \
    peer-id type fqdn value peer.example.com \
    protocol ikev2 \
    protocol-common nat-traversal enable yes \
    protocol-common fragmentation enable yes \
    crypto-profile ike-crypto-fips-256gcm \
    liveness-check interval 5

# Step 2: Create IPSec Tunnel (same as PSK)
set network tunnel ipsec ipsec-tunnel-cert \
    auto-key ike-gateway ike-gw-fips-cert \
    auto-key ipsec-crypto-profile ipsec-crypto-fips-256gcm \
    tunnel-interface tunnel.2 \
    anti-replay yes

# Step 3: Create Tunnel Interface
set network interface tunnel units tunnel.2 \
    ip 10.255.255.5/30

commit
```

---

## GlobalProtect Gateway - FIPS Configuration

### CLI Configuration

```bash
configure

# Step 1: Create SSL/TLS Profile for GlobalProtect
set ssl-tls-service-profile gp-ssl-fips \
    protocol-settings min-version tls1-2 \
    protocol-settings max-version tls1-3 \
    certificate gp-cert-rsa3072

# Step 2: Configure GlobalProtect Gateway
set network global-protect global-protect-gateway gp-gw-fips \
    local-address interface ethernet1/1 \
    local-address ip 198.51.100.1 \
    ssl-tls-service-profile gp-ssl-fips

# Step 3: Create Tunnel Configuration with FIPS Crypto
set network global-protect global-protect-gateway gp-gw-fips \
    remote-user-tunnel tunnel-config tunnel-fips \
    tunnel-mode yes \
    tunnel-interface tunnel.10 \
    ipsec-crypto-profile ipsec-crypto-fips-256gcm

# Step 4: Configure Client Authentication
set network global-protect global-protect-gateway gp-gw-fips \
    remote-user-tunnel authentication-profile auth-profile-fips \
    authentication-profile local-database \
    certificate-profile gp-cert-profile-fips

commit
```

---

## API Configuration Examples

### Create Complete VPN via API

**IKE Gateway XML:**
```xml
<entry name="ike-gw-fips-site1">
    <protocol-common>
        <nat-traversal>
            <enable>yes</enable>
        </nat-traversal>
        <fragmentation>
            <enable>yes</enable>
        </fragmentation>
    </protocol-common>
    <protocol>
        <ikev2>
            <ike-crypto-profile>ike-crypto-fips-256gcm</ike-crypto-profile>
            <dpd>
                <enable>yes</enable>
                <interval>5</interval>
                <retry>3</retry>
            </dpd>
        </ikev2>
        <version>ikev2</version>
    </protocol>
    <authentication>
        <pre-shared-key>
            <key>ComplexPSK-Min24Characters!</key>
        </pre-shared-key>
    </authentication>
    <local-address>
        <interface>ethernet1/1</interface>
        <ip>198.51.100.1</ip>
    </local-address>
    <peer-address>
        <ip>203.0.113.100</ip>
    </peer-address>
</entry>
```

**cURL - Create IKE Gateway:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='ike-gw-fips-site1']" \
    --data-urlencode "element@ike-gateway.xml"
```

**IPSec Tunnel XML:**
```xml
<entry name="ipsec-tunnel-site1">
    <auto-key>
        <ike-gateway>
            <entry name="ike-gw-fips-site1"/>
        </ike-gateway>
        <ipsec-crypto-profile>ipsec-crypto-fips-256gcm</ipsec-crypto-profile>
    </auto-key>
    <tunnel-interface>tunnel.1</tunnel-interface>
    <anti-replay>yes</anti-replay>
    <tunnel-monitor>
        <enable>yes</enable>
        <destination-ip>10.2.0.1</destination-ip>
        <tunnel-monitor-profile>default</tunnel-monitor-profile>
    </tunnel-monitor>
</entry>
```

**cURL - Create IPSec Tunnel:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='ipsec-tunnel-site1']" \
    --data-urlencode "element@ipsec-tunnel.xml"
```

**Tunnel Interface XML:**
```xml
<entry name="tunnel.1">
    <ip>
        <entry name="10.255.255.1/30"/>
    </ip>
    <comment>Site-to-Site VPN to Site1</comment>
</entry>
```

**cURL - Create Tunnel Interface:**
```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units/entry[@name='tunnel.1']" \
    --data-urlencode "element@tunnel-interface.xml"
```

### Commit Configuration via API

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=commit" \
    -d "cmd=<commit></commit>" \
    -d "key=<API-KEY>"
```

---

## Verification Commands

### IKE Phase 1 Verification

```bash
# Show all IKE SAs
show vpn ike-sa

# Show specific gateway
show vpn ike-sa gateway ike-gw-fips-site1

# Show detailed IKE SA info (verify algorithms)
show vpn ike-sa gateway ike-gw-fips-site1 detail

# Expected output should show:
# - Encryption: AES-256-GCM
# - Hash: SHA-512
# - DH Group: 20 (384-bit ECC)
```

### IPSec Phase 2 Verification

```bash
# Show all IPSec SAs
show vpn ipsec-sa

# Show specific tunnel
show vpn ipsec-sa tunnel ipsec-tunnel-site1

# Show detailed IPSec SA info (verify algorithms)
show vpn ipsec-sa tunnel ipsec-tunnel-site1 detail

# Expected output should show:
# - Encryption: AES-256-GCM
# - PFS Group: 20
```

### Traffic Verification

```bash
# Show tunnel flow statistics
show vpn flow

# Show flow for specific tunnel
show vpn flow tunnel-id <id>

# Monitor tunnel traffic
show vpn flow name ipsec-tunnel-site1

# Test through tunnel
ping source <local-tunnel-ip> host <remote-tunnel-ip>
traceroute source <local-tunnel-ip> host <remote-network-ip>
```

---

## Troubleshooting

### IKE Negotiation Debugging

```bash
# Enable IKE debugging
debug ike global on debug

# View IKE manager logs
less mp-log ikemgr.log

# Filter for specific gateway
less mp-log ikemgr.log | match "ike-gw-fips-site1"

# Disable debugging
debug ike global off
```

### Common Issues and Solutions

| Issue | Symptom | Resolution |
|-------|---------|------------|
| Phase 1 fails | "No proposal chosen" | Ensure both sides have matching FIPS algorithms |
| Phase 2 fails | "No acceptable transform" | Verify IPSec crypto profile match |
| DPD failures | Tunnel flapping | Adjust liveness-check interval |
| NAT-T issues | Phase 1 ok, Phase 2 fails | Ensure NAT-T enabled on both sides |
| PFS mismatch | Rekey failures | Match DH group in IPSec profile |

### Clear and Renegotiate

```bash
# Clear IKE SA (triggers renegotiation)
clear vpn ike-sa gateway ike-gw-fips-site1

# Clear IPSec SA only
clear vpn ipsec-sa tunnel ipsec-tunnel-site1

# Test tunnel recovery
test vpn ike-sa gateway ike-gw-fips-site1
```

---

## High Availability Considerations

### Active/Passive HA

```bash
# Both HA peers must have identical:
# - IKE crypto profiles
# - IPSec crypto profiles
# - IKE gateway configurations
# - IPSec tunnel configurations

# HA sync includes VPN state
# Verify HA sync status
show high-availability state
show high-availability vpn-status
```

### Active/Active HA

```bash
# Floating IP required for tunnel endpoint
set network ike gateway ike-gw-fips-site1 \
    local-address interface ethernet1/1 \
    local-address floating-ip 198.51.100.1
```

---

## Security Best Practices

1. **Use IKEv2 exclusively** - Better security and algorithm support
2. **Prefer certificate authentication** - Stronger than PSK for enterprise
3. **Enable anti-replay protection** - Prevent replay attacks
4. **Use tunnel monitoring** - Detect tunnel failures quickly
5. **Enable NAT-T proactively** - Handles NAT scenarios gracefully
6. **Set appropriate DPD intervals** - 5-10 seconds recommended
7. **Document all tunnel configurations** - Required for compliance audits
8. **Regular key rotation** - Use reasonable lifetimes (8hr IKE, 1hr IPSec)
