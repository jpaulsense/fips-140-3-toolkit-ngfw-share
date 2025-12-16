# SCM Authentication Guide

## Overview

Strata Cloud Manager uses OAuth 2.0 Client Credentials flow for API authentication. All API requests require a valid JWT access token.

## What You Need

To make API calls to Strata Cloud Manager, you need three pieces of information:

| Credential | Description | Where to Get It |
|------------|-------------|-----------------|
| **TSG ID** | Tenant Service Group identifier | From URL or Settings |
| **Client ID** | Service account identifier | Generated when creating service account |
| **Client Secret** | Service account password | Generated when creating service account (shown only once!) |

---

## Step-by-Step: Creating a Service Account

### Prerequisites

- Access to [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
- User account with **Write access** to the tenant
- At least one Tenant Service Group (TSG) created

### Step 1: Log into Strata Cloud Manager

1. Open your browser and go to: `https://stratacloudmanager.paloaltonetworks.com`
2. Sign in with your Palo Alto Networks credentials
3. Select your tenant if prompted

### Step 2: Navigate to Identity & Access

1. Click the **Settings** icon (gear) in the left sidebar or top navigation
2. Select **Identity & Access**
3. You'll see a list of all tenants you have access to

```
Settings
└── Identity & Access
    └── Access Management
```

### Step 3: Select Your Tenant

1. In the **All Tenants** list, find and select the tenant where you want to create the service account
2. **Note**: If you add a service account to a **parent tenant**, all child tenants will inherit access

### Step 4: Add a New Service Account

1. Click the **Add Identity** button (or **Add** button)
2. In the popup dialog:

   | Field | Value |
   |-------|-------|
   | **Identity Type** | Select **Service Account** |
   | **Service Account Name** | Enter a descriptive name (e.g., `fips-automation`, `api-automation`, `ci-cd-pipeline`) |
   | **Contact Email** | (Optional) Email for notifications |
   | **Description** | (Optional) Purpose of this service account |

3. Click **Next** or **Add**

### Step 5: Save Your Credentials (CRITICAL!)

After clicking Next/Add, you will see:

```
┌─────────────────────────────────────────────────────────┐
│  Service Account Created Successfully                   │
│                                                         │
│  Client ID:     abc123def456-xxxx-xxxx-xxxx-xxxxxxxxxx │
│  Client Secret: ****************************************│
│                                                         │
│  [Copy Client ID]  [Copy Client Secret]  [Download CSV] │
│                                                         │
│  ⚠️  IMPORTANT: The Client Secret will NOT be shown    │
│     again. Save it now in a secure location!           │
└─────────────────────────────────────────────────────────┘
```

**CRITICAL**:
- Copy the **Client ID** and **Client Secret** immediately
- Click **Download CSV** to save a backup
- The Client Secret is **NEVER shown again** - if you lose it, you must create a new service account

### Step 6: Note Your Display Name (Contains TSG ID)

The system creates a display name in this format:
```
<ServiceAccountName>@<TSG_ID>.iam.panserviceaccount
```

For example:
```
fips-automation@1234567890.iam.panserviceaccount
                └─────────┘
                 Your TSG ID
```

### Step 7: Assign Roles to the Service Account

1. After creating the account, you need to assign permissions
2. Still in **Identity & Access**, find your new service account
3. Click **Add Role** or **Assign Role**
4. Select the appropriate role:

| Role | Permissions | Use Case |
|------|-------------|----------|
| **Superuser** | Full access to all features | Development/Testing only |
| **Security Admin** | Security policies, profiles, objects | FIPS profile management |
| **Network Admin** | Network configuration, VPN | IKE/IPSec configuration |
| **Read Only** | View-only access | Monitoring, compliance checks |

5. Click **Save** or **Assign**

---

## Finding Your TSG ID

### Method 1: From the Browser URL

1. Log into Strata Cloud Manager
2. Look at your browser's address bar:
   ```
   https://stratacloudmanager.paloaltonetworks.com/tsg/1234567890/...
                                                       └─────────┘
                                                        Your TSG ID
   ```

### Method 2: From Service Account Display Name

After creating a service account, the display name shows:
```
myserviceaccount@1234567890.iam.panserviceaccount
                 └─────────┘
                  Your TSG ID
```

### Method 3: From Settings > Tenancy

1. Go to **Settings** > **Tenancy**
2. Select your tenant
3. The TSG ID is displayed in the tenant details

### Method 4: Via API (if you already have a token)

```bash
curl -X GET "https://api.strata.paloaltonetworks.com/tenancy/v1/tenant_service_groups" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

---

## Getting an Access Token

Once you have your Client ID, Client Secret, and TSG ID:

### Token Endpoint

```
POST https://auth.apps.paloaltonetworks.com/oauth2/access_token
```

### cURL Example

```bash
# Set your credentials
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
TSG_ID="1234567890"

# Request access token
curl -X POST "https://auth.apps.paloaltonetworks.com/oauth2/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials&scope=tsg_id:${TSG_ID}"
```

### Successful Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 899
}
```

### Using the Token

```bash
ACCESS_TOKEN="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."

curl -X GET "https://api.strata.paloaltonetworks.com/config/v1/ike-crypto-profiles?folder=Shared" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}" \
  -H "Content-Type: application/json"
```

---

## Quick Reference

### Token Characteristics

| Property | Value |
|----------|-------|
| Token Type | JWT (JSON Web Token) |
| Validity | ~15 minutes (899 seconds) |
| Scope | Single TSG |
| Refresh | Must request new token |

### Environment Variables Setup

```bash
# Add to ~/.bashrc or ~/.zshrc
export SCM_CLIENT_ID="your-client-id"
export SCM_CLIENT_SECRET="your-client-secret"
export SCM_TSG_ID="your-tsg-id"
```

### Using the Authentication Helper Script

This toolkit includes a helper script:

```bash
# Set credentials
export SCM_CLIENT_ID="your-client-id"
export SCM_CLIENT_SECRET="your-client-secret"
export SCM_TSG_ID="your-tsg-id"

# Get a token (automatically cached)
./scm-auth.sh token

# Force token refresh
./scm-auth.sh refresh

# Test authentication
./scm-auth.sh test

# Use in API calls
TOKEN=$(./scm-auth.sh token)
curl -H "Authorization: Bearer $TOKEN" https://api.strata.paloaltonetworks.com/config/v1/...
```

---

## Best Practices

### 1. Secure Credential Storage

Never hardcode credentials in scripts. Use:
- Environment variables
- Secrets managers (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault)
- Encrypted configuration files
- CI/CD secret variables

### 2. Principle of Least Privilege

Create service accounts with minimal required permissions:
- Use **Read Only** for monitoring and compliance scripts
- Use **Security Admin** or **Network Admin** for specific tasks
- Avoid **Superuser** in production

### 3. Token Caching

Tokens are valid for 15 minutes. Cache and reuse them:

```python
import time

class TokenManager:
    def __init__(self, client_id, client_secret, tsg_id):
        self.client_id = client_id
        self.client_secret = client_secret
        self.tsg_id = tsg_id
        self.token = None
        self.expiry = 0

    def get_token(self):
        # Refresh if less than 60 seconds remaining
        if time.time() > self.expiry - 60:
            self._refresh_token()
        return self.token

    def _refresh_token(self):
        # Implementation in scm_client.py
        pass
```

### 4. Rotate Credentials Regularly

- Periodically create new service accounts
- Delete old/unused service accounts
- Audit service account usage

---

## Multi-Tenant Access

For managing multiple TSGs:

1. Create service account in **parent TSG**
2. Child TSGs automatically inherit access
3. Request tokens with specific child TSG scope:

```bash
# Token for child TSG
curl -X POST "https://auth.apps.paloaltonetworks.com/oauth2/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${CLIENT_ID}:${CLIENT_SECRET}" \
  -d "grant_type=client_credentials&scope=tsg_id:${CHILD_TSG_ID}"
```

---

## Troubleshooting

### Token Request Fails

| Symptom | Possible Cause | Solution |
|---------|----------------|----------|
| 401 Unauthorized | Invalid client ID/secret | Verify credentials, check for extra spaces |
| 401 Unauthorized | Inactive service account | Check account status in SCM |
| 400 Bad Request | Invalid TSG ID format | Verify TSG ID is numeric |
| 403 Forbidden | No role assigned | Assign role to service account |

### API Calls Return 401

1. Token may have expired (15 min lifetime)
2. Verify `Authorization: Bearer` header format (note the space)
3. Check for URL encoding issues in token

### API Calls Return 403

1. Service account lacks required role
2. Role assigned to wrong TSG
3. Attempting to access resources outside TSG scope

### Lost Client Secret

If you lose your Client Secret:
1. You **cannot** retrieve it
2. Create a new service account
3. Delete the old service account
4. Update all scripts/applications with new credentials

---

## Official Documentation

- [Add a Service Account (Common Services)](https://docs.paloaltonetworks.com/common-services/identity-and-access-access-management/manage-identity-and-access/add-service-accounts)
- [Service Accounts (pan.dev)](https://pan.dev/scm/docs/service-accounts/)
- [Getting Started with SCM APIs](https://pan.dev/scm/docs/getstarted/)
- [Create an Access Token API](https://pan.dev/scm/api/auth/post-auth-v-1-oauth-2-access-token/)
