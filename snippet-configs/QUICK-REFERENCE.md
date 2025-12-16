# FIPS 140-3 Crypto Profiles - Quick Reference

Use this reference when manually creating profiles in the SCM console.

---

## IKE Crypto Profiles

### fips-ike-crypto-max
| Setting | Value |
|---------|-------|
| **Name** | `fips-ike-crypto-max` |
| **Encryption** | `aes-256-gcm` |
| **Authentication** | `sha512` |
| **DH Group** | `group20` |
| **Lifetime** | `8 hours` |

### fips-ike-crypto-recommended
| Setting | Value |
|---------|-------|
| **Name** | `fips-ike-crypto-recommended` |
| **Encryption** | `aes-256-cbc`, `aes-128-gcm` |
| **Authentication** | `sha384`, `sha256` |
| **DH Group** | `group20`, `group19` |
| **Lifetime** | `8 hours` |

### fips-ike-crypto-compat
| Setting | Value |
|---------|-------|
| **Name** | `fips-ike-crypto-compat` |
| **Encryption** | `aes-256-cbc`, `aes-256-gcm`, `aes-128-cbc`, `aes-128-gcm` |
| **Authentication** | `sha512`, `sha384`, `sha256` |
| **DH Group** | `group20`, `group19`, `group16`, `group14` |
| **Lifetime** | `8 hours` |

---

## IPSec Crypto Profiles

### fips-ipsec-crypto-max
| Setting | Value |
|---------|-------|
| **Name** | `fips-ipsec-crypto-max` |
| **ESP Encryption** | `aes-256-gcm` |
| **ESP Authentication** | `sha512` |
| **DH Group (PFS)** | `group20` |
| **Lifetime** | `1 hour` |
| **Lifesize** | `100 GB` |

### fips-ipsec-crypto-recommended
| Setting | Value |
|---------|-------|
| **Name** | `fips-ipsec-crypto-recommended` |
| **ESP Encryption** | `aes-256-gcm`, `aes-128-gcm` |
| **ESP Authentication** | `sha384`, `sha256` |
| **DH Group (PFS)** | `group20` |
| **Lifetime** | `1 hour` |

### fips-ipsec-crypto-compat
| Setting | Value |
|---------|-------|
| **Name** | `fips-ipsec-crypto-compat` |
| **ESP Encryption** | `aes-256-gcm`, `aes-256-cbc`, `aes-128-gcm`, `aes-128-cbc` |
| **ESP Authentication** | `sha512`, `sha384`, `sha256` |
| **DH Group (PFS)** | `group14` |
| **Lifetime** | `1 hour` |

---

## DH Group Reference

| Group | Algorithm | Key Size | FIPS Status |
|-------|-----------|----------|-------------|
| group14 | MODP | 2048-bit | Compliant |
| group16 | MODP | 4096-bit | Compliant |
| group19 | ECP | P-256 | Compliant |
| group20 | ECP | P-384 | Compliant |
| group21 | ECP | P-521 | Compliant |
| group1 | MODP | 768-bit | **Non-Compliant** |
| group2 | MODP | 1024-bit | **Non-Compliant** |
| group5 | MODP | 1536-bit | **Non-Compliant** |

---

## Snippet Metadata

When creating the snippet in SCM:

- **Snippet Name**: `FIPS-140-3-Crypto-Profiles`
- **Description**: `FIPS 140-3 compliant IKE and IPSec crypto profiles for VPN configurations`
- **Labels**: `fips`, `compliance`, `security`
