# FIPS 140-3 Compliance Toolkit for Palo Alto Networks

[![Version](https://img.shields.io/badge/version-1.4.0-blue.svg)](https://github.com/jpaulsense/fips-140-3-toolkit-ngfw-share/releases)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

A comprehensive toolkit for achieving FIPS 140-3 cryptographic compliance on Palo Alto Networks firewalls and Strata Cloud Manager (SCM) tenants **without requiring CC/FIPS-CC mode**.

> **DISCLAIMER**: This is an independent, open-source tool and is **NOT affiliated with, endorsed by, or supported by Palo Alto Networks, Inc.**
>
> **USE AT YOUR OWN RISK.** This software is provided "AS IS" without warranty of any kind. The authors assume no liability for any damages arising from the use of this tool. Always validate configurations in a test environment before deploying to production systems.
>
> By using this tool, you acknowledge that you understand and accept these terms.

## Quick Start (New Users)

```bash
# 1. Clone the repository
git clone https://github.com/jpaulsense/fips-140-3-toolkit-ngfw-share.git
cd fips-140-3-toolkit-ngfw-share

# 2. Install dependencies (only 'requests' is required)
pip install -r requirements.txt
# Or manually: pip install requests

# 3. Run the interactive toolkit
python3 fips-toolkit.py
```

The interactive wizard will guide you through:
- Configuring credentials (SCM and/or firewall)
- Understanding FIPS 140-3 requirements
- Running your first compliance audit

### Dependency Check

The toolkit will warn you if dependencies are missing. To verify your setup:

```bash
python3 -c "import requests; print('All dependencies installed!')"
```

## Overview

This toolkit enables organizations to:

- **Audit** existing configurations for FIPS 140-3 compliance
- **Configure** FIPS 140-3 compliant cryptographic settings on PAN-OS firewalls
- **Deploy** pre-configured compliant profiles via SCM API
- **Generate** compliance reports for audit purposes
- **Automate** compliance checking in CI/CD pipelines

## Why This Toolkit?

FIPS 140-3 compliance typically requires enabling CC/FIPS-CC mode, which:
- Requires a factory reset
- Limits some features
- May not be suitable for all environments

This toolkit provides an alternative approach: **configure only FIPS-compliant cryptographic algorithms** without enabling CC mode. This achieves cryptographic compliance while maintaining full feature availability.

## Key Features

- **Interactive CLI** - Guided wizards for audit, configure, cleanup, and reporting
- **Dual Target Support** - Works with both SCM (Strata Cloud Manager) and direct firewall connections
- **Profile Tiers** - Choose from Max, Recommended, or Compatible security levels
- **Smart Auditing** - Identifies in-use vs unused profiles, highlights high-risk configurations
- **Multi-Format Reports** - Executive summaries, detailed audits, and visual infographics
- **Interactive Cleanup** - Multi-select interface to remove specific profiles (v1.4.0)
- **Debug Capture** - Automatic troubleshooting data collection when errors occur
- **CI/CD Ready** - Environment variable support for automated pipelines

## Table of Contents

- [Quick Start](#quick-start-new-users)
- [Main Toolkit Commands](#main-toolkit-commands)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [FIPS 140-3 Requirements](#fips-140-3-requirements)
- [Toolkit Contents](#toolkit-contents)
- [Advanced Usage](#advanced-usage)
- [SCM API Integration](#scm-api-integration)
- [Troubleshooting](#troubleshooting)

## Main Toolkit Commands

The main entry point is `fips-toolkit.py`. Run it interactively or use direct commands:

```bash
# Interactive mode (recommended for first-time users)
python3 fips-toolkit.py

# Direct commands
python3 fips-toolkit.py audit       # Run compliance audit
python3 fips-toolkit.py configure   # Deploy FIPS profiles
python3 fips-toolkit.py cleanup     # Remove FIPS profiles (interactive multi-select)
python3 fips-toolkit.py report      # Generate compliance report
python3 fips-toolkit.py setup       # Reconfigure credentials
python3 fips-toolkit.py clear       # Clear saved credentials
python3 fips-toolkit.py help        # Show help
```

### Modes

| Mode | Description |
|------|-------------|
| **Audit** | Scan existing IKE, IPSec, TLS, and management profiles for FIPS compliance |
| **Configure** | Deploy pre-built FIPS-compliant profiles (max, recommended, or compat tiers) |
| **Cleanup** | Remove FIPS profiles with interactive multi-select (v1.4.0+) |
| **Report** | Generate compliance reports (Executive, Summary, Detailed, or Complete Package) |
| **Setup** | Configure SCM and/or firewall credentials |

### Report Types

The toolkit generates multiple report formats:

| Report Type | Description |
|-------------|-------------|
| **Executive Report** | 1-2 page management summary for leadership |
| **Summary Report** | Pass/fail overview with counts |
| **Detailed Report** | Full technical audit with all findings |
| **Audit Log** | Complete output with timestamps |
| **Complete Package** | All reports + infographic in one folder |
| **Infographic** | Visual SVG executive summary |

### Configuration Storage

Credentials are stored locally at `~/.fips-toolkit/config.json` with restricted permissions (600). The toolkit never transmits credentials except to authenticate with the configured API endpoints.

### SCM Credential Setup

**New to SCM API?** See our detailed guide: **[docs/SCM-CREDENTIAL-SETUP.md](docs/SCM-CREDENTIAL-SETUP.md)**

Quick role recommendations (Principle of Least Privilege):

| Use Case | Recommended Role | Access Level |
|----------|------------------|--------------|
| Audit only (validate compliance) | **Auditor** | Read-only |
| Deploy IKE, IPSec, TLS profiles | **Security Administrator** | Read + Write |
| Deploy Interface Management profiles | **Network Admin** | Required (in addition to Security Admin) |

> **Note**: Interface management profiles require **Network Admin** role in SCM. Without this role, you'll receive 403 Forbidden errors. The toolkit will automatically offer to deploy these profiles via CLI directly to your firewall as a fallback (most users have superuser access on firewalls).

For step-by-step instructions including screenshots and troubleshooting, see the [full credential setup guide](docs/SCM-CREDENTIAL-SETUP.md).

## Prerequisites

### For NGFW (Firewall) Configuration

| Requirement | Minimum Version |
|-------------|-----------------|
| PAN-OS | 10.1+ (10.2+ recommended) |
| Firewall Access | Admin privileges |
| Network | Management access to firewall |

### For SCM API Toolkit

| Software | Minimum Version | Purpose |
|----------|-----------------|---------|
| **Python** | 3.8+ | Python SDK and scripts |
| **bash** | 4.0+ | Shell scripts |
| **curl** | 7.68+ | API requests |
| **jq** | 1.6+ | JSON parsing (optional) |

### SCM Requirements

- Strata Cloud Manager tenant (Prisma Access, Cloud NGFW, or NGFW)
- Service account with API access
- Tenant Service Group (TSG) ID

## Installation

### Clone the Repository

```bash
git clone https://github.com/jpaulsense/fips-140-3-toolkit-ngfw-share.git
cd fips-140-3-toolkit-ngfw-share
```

### Install Python Dependencies

```bash
# Option 1: Install directly (simplest)
pip install -r requirements.txt

# Option 2: Use virtual environment (recommended for isolation)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Required dependency:** `requests` (for HTTP API calls)

### Verify Installation

```bash
# Check Python version (3.8+ required)
python3 --version

# Verify requests is installed
python3 -c "import requests; print(f'requests {requests.__version__} installed')"

# Run the toolkit
python3 fips-toolkit.py --help
```

### Troubleshooting Dependencies

If you see `ModuleNotFoundError: No module named 'requests'`:

```bash
# Try with pip3 explicitly
pip3 install requests

# Or with python -m pip
python3 -m pip install requests

# On some systems, you may need sudo
sudo pip3 install requests
```

## Advanced Usage

### Direct Firewall Validation (No SCM)

If you prefer to work directly with firewalls without the interactive tool:

```bash
# Run the standalone validator
python3 08-validation-tools/fips-compliance-validator.py \
    -f <firewall_ip> \
    -u <username> \
    -p <password>
```

### SCM with Environment Variables

For CI/CD pipelines or scripted usage:

```bash
# Set environment variables
export SCM_CLIENT_ID="your-service-account@tenant.iam.panserviceaccount.com"
export SCM_CLIENT_SECRET="your-client-secret-uuid"
export SCM_TSG_ID="1234567890"

# Run audit
python3 09-scm-api-toolkit/07-examples/validate-compliance.py

# Deploy profiles
python3 09-scm-api-toolkit/07-examples/deploy-fips-profiles.py
```

### Manual Firewall Configuration

For manual CLI configuration:

```bash
# Review compliant configurations
cat 01-ipsec-ike/README.md

# Apply via CLI (example)
configure
set network ike crypto-profiles ike-crypto-profiles fips-ike-crypto-max \
    encryption aes-256-gcm \
    hash sha512 \
    dh-group group20 \
    lifetime hours 8
commit
```

## Toolkit Contents

```
.
├── fips-toolkit.py              # MAIN ENTRY POINT - Interactive toolkit
├── README.md                    # This file
├── LICENSE                      # MIT License
├── requirements.txt             # Python dependencies
│
├── docs/                        # Documentation
│   ├── SCM-CREDENTIAL-SETUP.md  # Detailed SCM credential & role guide
│   └── EXECUTIVE-OVERVIEW.md    # Executive summary for leadership
│
├── infographic/                 # Visual documentation
│   └── *.svg                    # FIPS compliance infographics
│
├── snippet-configs/             # Ready-to-use configuration snippets
│
├── 00-overview/                 # FIPS 140-3 overview and concepts
├── 01-ipsec-ike/               # IKE and IPSec crypto profiles
├── 02-ssl-tls/                 # SSL/TLS profile configurations
├── 03-ssh/                     # SSH configuration and hardening
├── 04-admin-web-interface/     # Web interface security
├── 05-strata-cloud-manager/    # SCM integration guides
├── 06-verification-scripts/    # Manual verification scripts
├── 07-api-reference/           # PAN-OS API reference
│
├── 08-validation-tools/        # Automated validation tools
│   ├── fips-compliance-validator.py   # Standalone firewall validator
│   ├── fips-profile-cleanup.py        # Profile cleanup utility
│   └── sample-reports/                # Example validation reports
│
└── 09-scm-api-toolkit/         # Strata Cloud Manager API toolkit
    ├── 01-authentication/      # OAuth2 authentication helpers
    ├── 06-python-sdk/          # Python SDK (scm_client.py)
    └── 07-examples/            # Working deployment examples
```

## FIPS 140-3 Requirements

### Compliant Algorithms

| Category | Approved Algorithms |
|----------|---------------------|
| **Encryption** | AES-128-CBC, AES-128-GCM, AES-256-CBC, AES-256-GCM |
| **Hash** | SHA-256, SHA-384, SHA-512 |
| **DH Groups** | Group 14 (2048-bit), Group 16 (4096-bit), Group 19 (P-256), Group 20 (P-384), Group 21 (P-521) |
| **TLS** | TLS 1.2, TLS 1.3 |
| **SSH** | SSH v2 with approved algorithms |

### Non-Compliant Algorithms (Must Avoid)

| Category | Prohibited Algorithms |
|----------|----------------------|
| **Encryption** | DES, 3DES, NULL, RC4 |
| **Hash** | MD5, SHA-1 |
| **DH Groups** | Group 1 (768-bit), Group 2 (1024-bit), Group 5 (1536-bit) |
| **TLS** | TLS 1.0, TLS 1.1, SSLv3 |
| **Protocols** | Telnet, HTTP (unencrypted) |

### Profile Tiers

This toolkit provides three tiers of FIPS-compliant profiles:

| Tier | Security Level | Use Case |
|------|----------------|----------|
| **max** | Highest | Government, high-security environments |
| **recommended** | Balanced | Most production environments |
| **compat** | Compatible | Legacy device interoperability |

## Usage Examples

### Firewall CLI Configuration

```bash
# Configure IKE crypto profile
configure
set network ike crypto-profiles ike-crypto-profiles fips-ike-crypto-max \
    encryption aes-256-gcm \
    hash sha512 \
    dh-group group20 \
    lifetime hours 8

# Configure IPSec crypto profile
set network ike crypto-profiles ipsec-crypto-profiles fips-ipsec-crypto-max \
    esp encryption aes-256-gcm \
    esp authentication sha512 \
    dh-group group20 \
    lifetime hours 1

commit
```

### SCM Python SDK

```python
from sdk.scm_client import SCMClient

# Initialize client (uses environment variables)
client = SCMClient()

# Create FIPS IKE profile
client.create_fips_ike_profile(tier="recommended")

# Create FIPS IPSec profile
client.create_fips_ipsec_profile(tier="recommended")

# Push configuration
client.push_config(folders=["Shared"])
```

### Validation Script

```bash
# Validate firewall compliance
./08-validation-tools/scripts/validate-fips-compliance.sh 10.0.0.1

# Output example:
# ============================================================
# FIPS 140-3 COMPLIANCE VALIDATION
# ============================================================
# [PASS] IKE crypto profile 'fips-ike-crypto-max' is compliant
# [PASS] IPSec crypto profile 'fips-ipsec-crypto-max' is compliant
# [PASS] SSL/TLS minimum version: TLS 1.2
# ============================================================
# OVERALL: PASSED
# ============================================================
```

## SCM API Integration

### Authentication

```bash
# Get OAuth2 access token
curl -X POST "https://auth.apps.paloaltonetworks.com/oauth2/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${SCM_CLIENT_ID}:${SCM_CLIENT_SECRET}" \
  -d "grant_type=client_credentials&scope=tsg_id:${SCM_TSG_ID}"
```

### API Base Paths by Tenant Type

| Tenant Type | API Base Path |
|-------------|---------------|
| **Prisma Access / SASE** | `/sse/config/v1/` |
| **NGFW** | `/config/ngfw/v1/` |
| **Cloud NGFW** | `/config/ngfw/v1/` |

### Creating Profiles via API

```bash
# Create IKE crypto profile
curl -X POST "https://api.strata.paloaltonetworks.com/sse/config/v1/ike-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "fips-ike-crypto-recommended",
    "encryption": ["aes-256-cbc", "aes-128-gcm"],
    "authentication": ["sha384", "sha256"],
    "dh_group": ["group20", "group19"],
    "lifetime": {"hours": 8}
  }'
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SCM_CLIENT_ID` | Yes (SCM) | Service account client ID |
| `SCM_CLIENT_SECRET` | Yes (SCM) | Service account secret |
| `SCM_TSG_ID` | Yes (SCM) | Tenant Service Group ID |
| `FW_HOST` | No | Firewall hostname/IP |
| `FW_API_KEY` | No | Firewall API key |

## Security Considerations

- Never commit credentials to version control
- Use environment variables or secrets management
- Rotate service account credentials periodically
- Grant minimum required permissions
- Audit API access logs regularly
- Review firewall logs after configuration changes

## Troubleshooting

### Common Issues

**Authentication Failed**
```
Error: invalid_client
Solution: Verify CLIENT_ID and CLIENT_SECRET are correct
```

**Wrong API Path**
```
Error: HTTP 404 Not Found
Solution: Check tenant type and use correct API path:
- Prisma Access: /sse/config/v1/
- NGFW: /config/ngfw/v1/
```

**Profile Already Exists**
```
Error: HTTP 409 Conflict
Solution: Profile exists. Delete first or use update endpoint.
```

### Debug Mode

```bash
# Enable verbose output for the main toolkit
export FIPS_TOOLKIT_DEBUG=1
python3 fips-toolkit.py audit

# Enable debug for standalone validator
export DEBUG=1
./08-validation-tools/scripts/validate-fips-compliance.sh <firewall-ip>
```

### Debug Capture (v1.3.0+)

When errors occur during deployment, the toolkit offers to retry with debug capture:

```
Would you like to retry with debug mode enabled? [y/N]: y
```

This automatically:
1. Enables detailed API logging
2. Collects device info (model, serial, PAN-OS version)
3. Saves a debug report to `~/.fips-toolkit/debug_reports/`

Debug reports include timestamps, API responses, and system info for troubleshooting.

## Contributing

Contributions welcome! Please submit issues and pull requests.

## License

MIT License - See LICENSE file for details.

## References

- [FIPS 140-3 Standard (NIST)](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- [Palo Alto Networks Security Certifications](https://www.paloaltonetworks.com/security-certifications)
- [Strata Cloud Manager API Documentation](https://pan.dev/scm/docs/home/)
- [PAN-OS CLI Reference](https://docs.paloaltonetworks.com/pan-os)

## Disclaimer

**This is an independent, open-source project and is NOT affiliated with, endorsed by, or supported by Palo Alto Networks, Inc.**

This software is provided "AS IS" without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.

**USE AT YOUR OWN RISK.** Always:
- Validate configurations in a test environment before deploying to production
- Consult with your security team and compliance officers for specific regulatory requirements
- Review all changes before pushing to production systems
- Maintain backups before making configuration changes

By using this tool, you acknowledge that you understand and accept these terms.
