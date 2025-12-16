# FIPS 140-3 Snippet Configuration Files

These configuration files can be used to create a FIPS 140-3 compliant snippet in Strata Cloud Manager.

## Files Included

| File | Description |
|------|-------------|
| `ike-crypto-profiles.json` | All 3 FIPS IKE crypto profile configurations |
| `ipsec-crypto-profiles.json` | All 3 FIPS IPSec crypto profile configurations |
| `complete-snippet.json` | Combined configuration for import |

## Creating the Snippet in SCM Console

### Step 1: Navigate to Snippets
1. Log into [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
2. Go to **Manage** > **Configuration** > **NGFW and Prisma Access** > **Snippets**
3. Click **Add Snippet**

### Step 2: Create the Snippet
1. **Name**: `FIPS-140-3-Crypto-Profiles`
2. **Description**: `FIPS 140-3 compliant IKE and IPSec crypto profiles for VPN configurations`
3. **Labels** (optional): `fips`, `compliance`, `security`

### Step 3: Add IKE Crypto Profiles
1. In the snippet, go to **Network** > **Network Profiles** > **IKE Crypto**
2. Click **Add** and create each profile using the values from `ike-crypto-profiles.json`

### Step 4: Add IPSec Crypto Profiles
1. In the snippet, go to **Network** > **Network Profiles** > **IPSec Crypto**
2. Click **Add** and create each profile using the values from `ipsec-crypto-profiles.json`

### Step 5: Save and Share
1. Click **Save** to save the snippet
2. To share with other tenants:
   - Go to **Snippets** list
   - Select the snippet
   - Click **Share**
   - Select target tenants

## Profile Tiers

| Tier | Use Case | Security Level |
|------|----------|----------------|
| **max** | Government, high-security | AES-256-GCM, SHA-512, Group 20 |
| **recommended** | Production environments | AES-256/128, SHA-384/256, Group 20/19 |
| **compat** | Legacy interoperability | Multiple AES, SHA-2, Groups 14-20 |

## Verification

After creating the snippet, verify the profiles are configured correctly:
1. Go to the snippet configuration
2. Check each IKE and IPSec profile
3. Ensure no non-compliant algorithms are present:
   - No 3DES, DES, or NULL encryption
   - No MD5 or SHA-1 hashing
   - No DH Groups 1, 2, or 5
