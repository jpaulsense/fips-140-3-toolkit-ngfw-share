# SCM API Examples

This directory contains working examples for common SCM API operations.

## Prerequisites

1. Set environment variables:
   ```bash
   export SCM_CLIENT_ID="your-client-id"
   export SCM_CLIENT_SECRET="your-client-secret"
   export SCM_TSG_ID="your-tsg-id"
   ```

2. Install dependencies:
   ```bash
   pip install requests
   ```

## Available Examples

| Script | Description |
|--------|-------------|
| `deploy-fips-profiles.py` | Deploy all FIPS 140-3 compliant profiles |
| `list-profiles.py` | List all crypto profiles |
| `validate-compliance.py` | Validate existing profiles for FIPS compliance |
| `deploy-fips-profiles.sh` | Bash script to deploy profiles via curl |

## Quick Start

### Deploy FIPS Profiles (Python)

```bash
python3 deploy-fips-profiles.py
```

### Deploy FIPS Profiles (Bash)

```bash
chmod +x deploy-fips-profiles.sh
./deploy-fips-profiles.sh
```

### List All Profiles

```bash
python3 list-profiles.py
```

### Validate Compliance

```bash
python3 validate-compliance.py
```
