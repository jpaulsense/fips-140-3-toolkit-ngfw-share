# SSH Host Keys - FIPS 140-3 Compliant Configuration

## Overview

SSH host keys are used to authenticate the firewall to SSH clients and establish encrypted sessions. This document covers FIPS 140-3 compliant host key generation, management, and distribution.

## FIPS 140-3 Host Key Requirements

### RSA Host Keys
| Parameter | FIPS Requirement | Recommendation |
|-----------|------------------|----------------|
| Key Size | 2048-bit minimum | 3072-bit or 4096-bit |
| Signature | RSA-SHA256 or RSA-SHA512 | RSA-SHA512 |

### ECDSA Host Keys
| Parameter | FIPS Requirement | Recommendation |
|-----------|------------------|----------------|
| Curve | P-256, P-384, or P-521 | P-384 |
| Signature | ECDSA-SHA256/384/512 | ECDSA-SHA384 |

### Non-Compliant Host Keys
| Key Type | Status |
|----------|--------|
| RSA < 2048 bits | Non-Compliant |
| DSA (any size) | Non-Compliant |
| ED25519 | Not NIST-approved |

---

## CLI Configuration

### View Current SSH Host Keys

```bash
# Show SSH host key information
show ssh system host-key

# Show SSH host key fingerprints
show ssh system host-key fingerprint

# Show detailed host key information
debug system ssh show-host-keys
```

### Regenerate SSH Host Keys

```bash
# Regenerate all SSH host keys with FIPS-compliant settings
request ssh system host-key regenerate

# The firewall will generate new RSA and ECDSA keys
# RSA: 2048-bit by default (PAN-OS manages this)
# ECDSA: NIST P-256/P-384 curves

# Verify new keys were generated
show ssh system host-key

# Export new keys for distribution to administrators
request ssh system host-key export format openssh
```

### Generate Specific Key Types

```bash
# Note: PAN-OS automatically generates FIPS-compliant keys
# Key types are managed by the system based on PAN-OS version

# To regenerate only RSA key
request ssh system host-key regenerate type rsa

# To regenerate only ECDSA key
request ssh system host-key regenerate type ecdsa
```

### Export Host Keys for Client Configuration

```bash
# Export host key in OpenSSH format
request ssh system host-key export format openssh

# Export host key fingerprint for verification
show ssh system host-key fingerprint

# Example output:
# RSA key fingerprint: SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# ECDSA key fingerprint: SHA256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

---

## API Configuration

### View Host Key via API

```bash
# Get SSH host key information
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<show><ssh><system><host-key></host-key></system></ssh></show>"

# Get host key fingerprint
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<show><ssh><system><host-key><fingerprint></fingerprint></host-key></system></ssh></show>"
```

### Regenerate Host Key via API

```bash
# Regenerate SSH host keys
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<request><ssh><system><host-key><regenerate></regenerate></host-key></system></ssh></request>"
```

### Export Host Key via API

```bash
# Export host key in OpenSSH format
curl -k -X POST "https://<firewall>/api/" \
    -d "type=op" \
    -d "key=<API-KEY>" \
    -d "cmd=<request><ssh><system><host-key><export><format>openssh</format></export></host-key></system></ssh></request>"
```

---

## Host Key Distribution

### For OpenSSH Clients

Add the firewall's host key to the client's known_hosts file:

**Manual Entry:**
```bash
# Get the host key from the firewall
request ssh system host-key export format openssh

# Add to known_hosts on client
# Example format:
# firewall.example.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQAB...
# firewall.example.com ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYT...

echo "firewall.example.com $(cat exported_key)" >> ~/.ssh/known_hosts
```

**Using ssh-keyscan:**
```bash
# Scan and add to known_hosts (less secure - verify fingerprint!)
ssh-keyscan -t ecdsa,rsa firewall.example.com >> ~/.ssh/known_hosts

# Verify fingerprint matches
ssh-keygen -lf ~/.ssh/known_hosts
```

### For PuTTY Clients

1. Connect to the firewall via PuTTY
2. When prompted about the host key, verify the fingerprint
3. Click "Accept" to cache the key
4. The key is stored in the Windows registry under `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys`

### Enterprise Distribution

**Using SSH Known Hosts File:**
```bash
# Create a centralized known_hosts file
# Distribute to all admin workstations

# /etc/ssh/ssh_known_hosts (system-wide)
# ~/.ssh/known_hosts (user-specific)

# Example enterprise script:
for fw in fw1.example.com fw2.example.com fw3.example.com; do
    ssh-keyscan -t ecdsa,rsa $fw 2>/dev/null
done > /etc/ssh/ssh_known_hosts
```

**Using Certificate Authority for SSH:**
```bash
# Advanced: Use SSH certificates instead of individual host keys
# Sign firewall host keys with an SSH CA
# Clients trust the CA, automatically trusting all signed keys
```

---

## Compliance Verification

### Verify Host Key Strength

```bash
# Show host key details
show ssh system host-key

# Expected output should show:
# - RSA key: 2048 bits or greater
# - ECDSA key: P-256, P-384, or P-521 curve

# Verify from client side
ssh-keygen -lf ~/.ssh/known_hosts

# Expected output:
# 3072 SHA256:xxxx firewall.example.com (RSA)
# 384 SHA256:xxxx firewall.example.com (ECDSA)
```

### Test Host Key Algorithm Negotiation

```bash
# From client - connect with specific host key algorithm
ssh -v -o HostKeyAlgorithms=ecdsa-sha2-nistp384 admin@firewall.example.com

# Should successfully connect if ECDSA P-384 key exists

# Test RSA
ssh -v -o HostKeyAlgorithms=rsa-sha2-512 admin@firewall.example.com
```

### External Verification with nmap

```bash
# Enumerate supported host key algorithms
nmap --script ssh-hostkey -p 22 firewall.example.com

# Output shows host key types and fingerprints
```

---

## Host Key Rotation

### When to Rotate Host Keys

- After suspected key compromise
- During scheduled security maintenance
- After major PAN-OS upgrade
- As part of compliance requirements (annual rotation)

### Host Key Rotation Process

```bash
# Step 1: Document current fingerprints
show ssh system host-key fingerprint > /tmp/old_fingerprints.txt

# Step 2: Notify administrators of upcoming change
# Send communication with new fingerprints after generation

# Step 3: Regenerate host keys
request ssh system host-key regenerate

# Step 4: Document new fingerprints
show ssh system host-key fingerprint

# Step 5: Distribute new fingerprints to administrators
# Update known_hosts files across organization

# Step 6: Verify connectivity with new keys
# Test from multiple admin workstations
```

### Automated Key Rotation Script (Client Side)

```bash
#!/bin/bash
# Update known_hosts for firewall host key rotation

FIREWALL="firewall.example.com"
KNOWN_HOSTS="$HOME/.ssh/known_hosts"

# Remove old entry
ssh-keygen -R $FIREWALL

# Add new entry (verify fingerprint!)
ssh-keyscan -t ecdsa,rsa $FIREWALL >> $KNOWN_HOSTS

echo "Updated host key for $FIREWALL"
echo "Please verify the fingerprint with your security team"
```

---

## Best Practices

1. **Verify fingerprints out-of-band** - Don't trust TOFU (Trust On First Use)
2. **Document and distribute fingerprints** - Make available through secure channels
3. **Use ECDSA when possible** - Better performance, similar security
4. **Rotate keys annually** - Or after any suspected compromise
5. **Centralize known_hosts** - Enterprise management of trusted keys
6. **Use SSH certificates** - For large deployments, consider CA-based trust
7. **Monitor host key changes** - Alert on unexpected fingerprint changes
8. **Backup configuration** - Host keys can be restored from config backup
9. **Coordinate HA pairs** - Each peer has unique keys; document both
10. **Test after rotation** - Verify all admins can still connect

---

## Troubleshooting

### Host Key Verification Failed

**Error:**
```
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
```

**Cause:** Host key changed (rotation or possible attack)

**Resolution:**
1. Verify the new fingerprint is legitimate
2. Remove old entry: `ssh-keygen -R firewall.example.com`
3. Reconnect and accept new key

### No Matching Host Key Type

**Error:**
```
Unable to negotiate with firewall.example.com: no matching host key type found
```

**Cause:** Client doesn't support firewall's host key algorithms

**Resolution:**
```bash
# Explicitly specify host key algorithms
ssh -o HostKeyAlgorithms=+ssh-rsa admin@firewall.example.com

# Or update client configuration
echo "HostKeyAlgorithms +ssh-rsa" >> ~/.ssh/config
```

### Host Key Corruption

**Symptoms:** Unable to connect, key verification errors

**Resolution:**
```bash
# Regenerate host keys
request ssh system host-key regenerate

# Distribute new fingerprints
show ssh system host-key fingerprint
```

---

## High Availability Considerations

### HA Peer Host Keys

Each HA peer has unique SSH host keys. Both sets must be distributed to administrators.

```bash
# On primary peer
show ssh system host-key fingerprint

# On secondary peer
show ssh system host-key fingerprint

# Administrators should have both in known_hosts
# Or use floating management IP with consistent key handling
```

### Floating IP Considerations

When using a floating management IP:
- Host key corresponds to the active peer
- On failover, host key changes (triggers warning)

**Options:**
1. Accept key warnings during failover
2. Add both peer keys for the floating IP
3. Use SSH certificates for seamless failover

```bash
# Add both keys for floating IP
echo "floating-ip.example.com $(cat primary_key)" >> ~/.ssh/known_hosts
echo "floating-ip.example.com $(cat secondary_key)" >> ~/.ssh/known_hosts
```

---

## Audit and Compliance

### Document Host Key Fingerprints

Maintain a record of current host key fingerprints for compliance audits:

```bash
# Generate audit report
echo "SSH Host Key Audit Report" > ssh_audit.txt
echo "Date: $(date)" >> ssh_audit.txt
echo "Firewall: $(show system info | grep hostname)" >> ssh_audit.txt
echo "" >> ssh_audit.txt
echo "Host Key Fingerprints:" >> ssh_audit.txt
show ssh system host-key fingerprint >> ssh_audit.txt
```

### Compliance Checklist

- [ ] RSA host key is 2048 bits or greater
- [ ] ECDSA host key uses NIST P-256, P-384, or P-521
- [ ] DSA keys are not in use
- [ ] Host keys are distributed through secure channel
- [ ] Key fingerprints are documented
- [ ] Key rotation schedule is established
- [ ] HA peer keys are both documented
- [ ] Administrators verify fingerprints before connecting
