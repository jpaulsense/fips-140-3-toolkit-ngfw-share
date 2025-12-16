# GlobalProtect - FIPS 140-3 Compliant Configuration

## Overview

GlobalProtect provides secure remote access VPN connectivity. This document covers FIPS 140-3 compliant configurations for GlobalProtect Portal, Gateway, and client settings.

## FIPS 140-3 Requirements for GlobalProtect

### Portal/Gateway TLS Requirements
| Parameter | FIPS Requirement |
|-----------|------------------|
| TLS Version | TLS 1.2 or TLS 1.3 |
| Cipher Suites | AES-GCM or AES-CBC with SHA-256+ |
| Certificate | RSA 2048+ or ECDSA P-256+ |
| Key Exchange | ECDHE or DHE |

### IPSec Tunnel Requirements
| Parameter | FIPS Requirement |
|-----------|------------------|
| Encryption | AES-128 or AES-256 (CBC or GCM) |
| Authentication | SHA-256, SHA-384, or SHA-512 |
| PFS Group | DH Group 14+ or ECDH P-256+ |

---

## CLI Configuration

### Create FIPS-Compliant SSL/TLS Profile for GlobalProtect

```bash
configure

# Create SSL/TLS service profile for GlobalProtect
set ssl-tls-service-profile gp-ssl-fips \
    certificate gp-cert-rsa3072 \
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

### Generate FIPS-Compliant Certificate for GlobalProtect

```bash
# Generate CSR for GlobalProtect certificate
request certificate generate-csr \
    certificate-name gp-cert-rsa3072 \
    name cn=vpn.example.com,o=Organization,c=US \
    algorithm RSA \
    rsa-nbits 3072 \
    digest sha384

# Or use ECDSA
request certificate generate-csr \
    certificate-name gp-cert-ecdsa384 \
    name cn=vpn.example.com,o=Organization,c=US \
    algorithm ECDSA \
    ecdsa-type secp384r1 \
    digest sha384

# Import signed certificate
request certificate import \
    certificate-name gp-cert-rsa3072 \
    file-type signed-certificate \
    format pem \
    certificate-file /path/to/signed-cert.pem
```

### Configure GlobalProtect Portal with FIPS Settings

```bash
configure

# Create GlobalProtect Portal
set network global-protect global-protect-portal gp-portal-fips \
    portal-config local-address interface ethernet1/1 \
    portal-config local-address ip 198.51.100.1 \
    ssl-tls-service-profile gp-ssl-fips

# Configure portal authentication
set network global-protect global-protect-portal gp-portal-fips \
    portal-config auth-profile \
        client-auth-profile portal-client-auth \
        authentication-profile local-auth-profile \
        os Any \
        allow-authentication-with-user-credentials yes

# Configure portal agent configuration
set network global-protect global-protect-portal gp-portal-fips \
    portal-config agent-config configs agent-fips \
    gateways external-gateway ext-gw-1 \
        address vpn.example.com \
        priority 1

# Configure GlobalProtect app settings
set network global-protect global-protect-portal gp-portal-fips \
    portal-config agent-config configs agent-fips \
    app \
        connect-method pre-logon \
        use-single-sign-on yes \
        allow-user-to-disable-global-protect no

commit
```

### Configure GlobalProtect Gateway with FIPS Settings

```bash
configure

# Create GlobalProtect Gateway
set network global-protect global-protect-gateway gp-gateway-fips \
    local-address interface ethernet1/1 \
    local-address ip 198.51.100.1 \
    ssl-tls-service-profile gp-ssl-fips

# Create FIPS-compliant IPSec crypto profile for GP tunnel
set network ike crypto-profiles ipsec-crypto-profiles gp-ipsec-fips \
    esp encryption aes-256-gcm \
    dh-group group20 \
    lifetime seconds 3600

# Configure gateway remote user tunnel
set network global-protect global-protect-gateway gp-gateway-fips \
    remote-user-tunnel tunnel-config gp-tunnel-fips \
    tunnel-mode yes \
    tunnel-interface tunnel.100 \
    ipsec-crypto-profile gp-ipsec-fips

# Configure IP pool for remote users
set network global-protect global-protect-gateway gp-gateway-fips \
    remote-user-tunnel-configs gp-tunnel-fips \
    ip-pool 10.100.0.0/24

# Configure split tunneling (if needed)
set network global-protect global-protect-gateway gp-gateway-fips \
    remote-user-tunnel-configs gp-tunnel-fips \
    split-tunneling \
    include-domains \
        member example.com

# Configure authentication
set network global-protect global-protect-gateway gp-gateway-fips \
    remote-user-tunnel-configs gp-tunnel-fips \
    authentication-profile local-auth-profile

commit
```

### Create Tunnel Interface for GlobalProtect

```bash
configure

# Create tunnel interface
set network interface tunnel units tunnel.100 \
    ip 10.100.0.1/24 \
    comment "GlobalProtect User Tunnel"

# Add to virtual router
set network virtual-router default interface tunnel.100

# Add to security zone
set zone vpn-users network layer3 tunnel.100

commit
```

---

## API Configuration

### Create SSL/TLS Profile via API

**XML Element:**
```xml
<entry name="gp-ssl-fips">
    <certificate>gp-cert-rsa3072</certificate>
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

```bash
curl -k -X POST "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=set" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/shared/ssl-tls-service-profile/entry[@name='gp-ssl-fips']" \
    --data-urlencode "element@gp-ssl-profile.xml"
```

### Create GlobalProtect Portal via API

**XML Element:**
```xml
<entry name="gp-portal-fips">
    <portal-config>
        <local-address>
            <interface>ethernet1/1</interface>
            <ip>
                <ipv4>198.51.100.1</ipv4>
            </ip>
        </local-address>
        <client-auth>
            <entry name="portal-client-auth">
                <os>Any</os>
                <authentication-profile>local-auth-profile</authentication-profile>
            </entry>
        </client-auth>
        <agent-config>
            <entry name="agent-fips">
                <gateways>
                    <external>
                        <list>
                            <entry name="ext-gw-1">
                                <address>vpn.example.com</address>
                                <priority>1</priority>
                            </entry>
                        </list>
                    </external>
                </gateways>
                <app>
                    <connect-method>pre-logon</connect-method>
                </app>
            </entry>
        </agent-config>
    </portal-config>
    <ssl-tls-service-profile>gp-ssl-fips</ssl-tls-service-profile>
</entry>
```

### Create GlobalProtect Gateway via API

**XML Element:**
```xml
<entry name="gp-gateway-fips">
    <local-address>
        <interface>ethernet1/1</interface>
        <ip>
            <ipv4>198.51.100.1</ipv4>
        </ip>
    </local-address>
    <ssl-tls-service-profile>gp-ssl-fips</ssl-tls-service-profile>
    <remote-user-tunnel>
        <entry name="gp-tunnel-fips">
            <tunnel-mode>yes</tunnel-mode>
            <tunnel-interface>tunnel.100</tunnel-interface>
            <ipsec-crypto-profile>gp-ipsec-fips</ipsec-crypto-profile>
            <ip-pool>
                <member>10.100.0.0/24</member>
            </ip-pool>
            <authentication-profile>local-auth-profile</authentication-profile>
        </entry>
    </remote-user-tunnel>
</entry>
```

### Retrieve GlobalProtect Configuration via API

```bash
# Get Portal configuration
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-portal"

# Get Gateway configuration
curl -k -X GET "https://<firewall>/api/" \
    -d "type=config" \
    -d "action=get" \
    -d "key=<API-KEY>" \
    -d "xpath=/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-gateway"
```

---

## Web UI Configuration Path

### Configure GlobalProtect Portal
1. Navigate to: **Network > GlobalProtect > Portals**
2. Click **Add**
3. **General** Tab:
   - **Name**: `gp-portal-fips`
   - **Interface**: `ethernet1/1`
   - **IP Address**: `198.51.100.1`
   - **SSL/TLS Service Profile**: `gp-ssl-fips`
4. **Authentication** Tab:
   - Add client authentication configuration
   - Select FIPS-compliant authentication profile
5. **Agent** Tab:
   - Configure agent settings and gateway list

### Configure GlobalProtect Gateway
1. Navigate to: **Network > GlobalProtect > Gateways**
2. Click **Add**
3. **General** Tab:
   - **Name**: `gp-gateway-fips`
   - **Interface**: `ethernet1/1`
   - **SSL/TLS Service Profile**: `gp-ssl-fips`
4. **Client Configuration** Tab:
   - Add tunnel configuration
   - **Tunnel Interface**: `tunnel.100`
   - **IPSec Crypto Profile**: `gp-ipsec-fips`
   - **IP Pool**: `10.100.0.0/24`

---

## Compliance Verification Commands

### Check GlobalProtect Status

```bash
# Show GlobalProtect gateway status
show global-protect-gateway statistics

# Show connected users
show global-protect-gateway current-user gateway gp-gateway-fips

# Show tunnel information
show global-protect-gateway tunnel

# Show detailed session info
show global-protect-gateway current-user gateway gp-gateway-fips user all
```

### Verify TLS Configuration

```bash
# Check SSL/TLS profile applied to portal/gateway
show network global-protect global-protect-portal gp-portal-fips | match ssl

# Verify certificate in use
show certificate name gp-cert-rsa3072
```

### Verify IPSec Tunnel Algorithms

```bash
# Show active GlobalProtect tunnels
show vpn ipsec-sa tunnel-interface tunnel.100

# Show tunnel details
show vpn ipsec-sa tunnel-interface tunnel.100 detail
```

### Test External TLS Configuration

```bash
# From external system - test portal TLS
openssl s_client -connect vpn.example.com:443 -tls1_2
openssl s_client -connect vpn.example.com:443 -tls1_3

# Check supported ciphers
nmap --script ssl-enum-ciphers -p 443 vpn.example.com
```

---

## GlobalProtect Client Configuration

### Client-Side FIPS Considerations

While the firewall enforces FIPS-compliant settings, clients must also support:
- TLS 1.2 or TLS 1.3
- AES-GCM cipher suites
- ECDHE key exchange

### Supported Client Versions

| Platform | Minimum Version | TLS 1.3 Support |
|----------|-----------------|-----------------|
| Windows | GP 5.0+ | GP 5.2+ |
| macOS | GP 5.0+ | GP 5.2+ |
| iOS | GP 5.0+ | GP 5.2+ |
| Android | GP 5.0+ | GP 5.2+ |
| Linux | GP 5.0+ | GP 5.2+ |

### Client Connection Verification

Users can verify FIPS-compliant connection in GlobalProtect client:
1. Click on GlobalProtect icon in system tray
2. Click **Settings** (gear icon)
3. View **Connection** details
4. Verify TLS version and cipher suite

---

## Best Practices

1. **Use certificate authentication** - Stronger than password-only
2. **Deploy client certificates** - For mutual TLS authentication
3. **Enable MFA** - Multi-factor authentication for all users
4. **Use TLS 1.3** - Best performance and security
5. **Configure HIP checks** - Verify client security posture
6. **Enable split tunneling judiciously** - Balance security and performance
7. **Monitor connection logs** - Detect anomalous access patterns
8. **Regular certificate rotation** - Annual renewal recommended
9. **Client certificate revocation** - CRL or OCSP for terminated users
10. **Document configurations** - Required for compliance audits

---

## Troubleshooting

### Connection Failures

```bash
# Check GlobalProtect logs
show log system | match -i globalprotect

# Debug GlobalProtect
debug global-protect gateway on debug
less mp-log pan_gp.log

# Check certificate issues
show certificate name gp-cert-rsa3072
request certificate validate certificate-name gp-cert-rsa3072

# Disable debugging
debug global-protect gateway off
```

### Common Issues

| Issue | Cause | Resolution |
|-------|-------|------------|
| TLS handshake failure | Cipher mismatch | Update client or adjust cipher settings |
| Certificate warning | Untrusted CA | Deploy root CA to client |
| Tunnel not established | IPSec profile mismatch | Verify crypto profile settings |
| IP pool exhausted | Too many users | Expand IP pool or stagger connections |
| Slow performance | Encryption overhead | Use AES-GCM, check hardware |

### Client-Side Debugging

**Windows:**
```
C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.log
```

**macOS:**
```
/Library/Logs/PaloAltoNetworks/GlobalProtect/PanGPA.log
```

---

## Security Zones and Policies

### Configure Security Policy for GlobalProtect Users

```bash
configure

# Create security rule for GP users to internal resources
set rulebase security rules gp-to-internal \
    from vpn-users \
    to trust \
    source any \
    destination internal-servers \
    source-user any \
    application any \
    service application-default \
    action allow \
    log-end yes

# Create rule for GP users to internet (if needed)
set rulebase security rules gp-to-internet \
    from vpn-users \
    to untrust \
    source any \
    destination any \
    source-user any \
    application any \
    service application-default \
    action allow \
    log-end yes

commit
```
