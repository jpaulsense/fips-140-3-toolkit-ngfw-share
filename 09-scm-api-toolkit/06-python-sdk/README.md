# SCM Python SDK Wrapper

This directory contains a Python wrapper for the Strata Cloud Manager API, focused on FIPS 140-3 compliant profile management.

## Installation

### Using pip (Palo Alto's Official SDK)

```bash
pip install pan-scm-sdk
```

### Using our wrapper

```bash
pip install requests
```

## Official SDK Usage

The [pan-scm-sdk](https://cdot65.github.io/pan-scm-sdk/sdk/) provides an official Python interface:

```python
from scm.client import Scm

# Initialize client
client = Scm(
    client_id="your-client-id",
    client_secret="your-client-secret",
    tsg_id="your-tsg-id"
)

# Create IKE Crypto Profile
ike_profile = {
    "name": "fips-ike-crypto-max",
    "folder": "Shared",
    "encryption": ["aes-256-gcm"],
    "authentication": ["sha512"],
    "dh_group": ["group20"],
    "lifetime": {"hours": 8}
}

client.config.security.ike_crypto_profiles.create(ike_profile)
```

## Custom Wrapper

For more control, use our custom wrapper that includes FIPS 140-3 validation.

## Files

| File | Description |
|------|-------------|
| `scm_client.py` | Main SCM API client class |
| `fips_profiles.py` | FIPS 140-3 compliant profile definitions |
| `requirements.txt` | Python dependencies |

## Usage

```python
from scm_client import SCMClient

# Initialize
client = SCMClient(
    client_id="your-client-id",
    client_secret="your-client-secret",
    tsg_id="your-tsg-id"
)

# Create FIPS-compliant IKE profile
client.create_fips_ike_profile("max")

# Create FIPS-compliant IPSec profile
client.create_fips_ipsec_profile("recommended")

# Create FIPS-compliant TLS profile
client.create_fips_tls_profile("max", certificate="fips-mgmt-cert")

# Push configuration
client.push_config(folders=["Shared"])
```
