# SCM API Credential Setup Guide

> **DISCLAIMER**: This is an independent, open-source tool and is **NOT affiliated with, endorsed by, or supported by Palo Alto Networks, Inc.** Use at your own risk. Always validate in a test environment first.

This guide walks you through creating a Strata Cloud Manager (SCM) service account with the **minimum required permissions** for FIPS 140-3 compliance operations.

> **Principle of Least Privilege**: Always assign the minimum permissions necessary. This guide provides role recommendations for audit-only vs. configuration operations.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Understanding SCM Credentials](#understanding-scm-credentials)
- [Step 1: Find Your TSG ID](#step-1-find-your-tsg-id)
- [Step 2: Create a Service Account](#step-2-create-a-service-account)
- [Step 3: Assign the Appropriate Role](#step-3-assign-the-appropriate-role)
- [Step 4: Save Your Credentials](#step-4-save-your-credentials)
- [Step 5: Test Your Credentials](#step-5-test-your-credentials)
- [Role Reference](#role-reference)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Official Documentation Links](#official-documentation-links)

---

## Prerequisites

Before you begin, ensure you have:

- [ ] Access to Strata Cloud Manager with administrative privileges
- [ ] Permission to create service accounts (requires IAM Administrator or Superuser role)
- [ ] A secure location to store credentials (password manager, secrets vault, etc.)

---

## Understanding SCM Credentials

SCM API access requires three pieces of information:

| Credential | Format | Example |
|------------|--------|---------|
| **Client ID** | `name@tsgid.iam.panserviceaccount.com` | `fips-audit@1234567890.iam.panserviceaccount.com` |
| **Client Secret** | UUID format | `a1b2c3d4-e5f6-7890-abcd-ef1234567890` |
| **TSG ID** | Numeric | `1234567890` |

These credentials authenticate via OAuth 2.0 Client Credentials flow. Access tokens are valid for **15 minutes** and automatically refresh.

---

## Step 1: Find Your TSG ID

The Tenant Service Group (TSG) ID is required for API authentication.

### Option A: From the SCM URL

1. Log in to [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
2. Look at your browser's URL bar
3. The TSG ID appears in the URL path: `https://stratacloudmanager.paloaltonetworks.com/manage/tsg/{TSG_ID}/...`

### Option B: From Identity & Access Settings

1. Navigate to **Settings** > **Identity & Access** > **Tenant Management**
2. Select your tenant
3. The TSG ID is displayed in the tenant details

### Option C: From an Existing Service Account

If you have an existing service account, the TSG ID is part of the Client ID:
```
service-account-name@{TSG_ID}.iam.panserviceaccount.com
                      ^^^^^^^^^^
                      This is your TSG ID
```

---

## Step 2: Create a Service Account

### Navigate to Identity & Access

1. Log in to [Strata Cloud Manager](https://stratacloudmanager.paloaltonetworks.com)
2. Click **Settings** (gear icon) in the left navigation
3. Select **Identity & Access**
4. Click **Access Management**

### Add a New Service Account

1. Click **Add** button
2. Set **Identity Type** to **Service Account**
3. Fill in the required fields:

| Field | Recommendation | Notes |
|-------|----------------|-------|
| **Service Account Name** | `fips-audit` or `fips-toolkit` | Use a descriptive name indicating purpose |
| **Contact Email** | Your email (optional) | For notifications about the account |
| **Description** | `FIPS 140-3 Compliance Toolkit - Audit Only` | Describe the account's purpose and permission level |

4. Click **Next** to proceed

### Save the Client Credentials

**CRITICAL**: The Client Secret is shown **only once**. You cannot retrieve it later.

1. A dialog displays the **Client ID** and **Client Secret**
2. Click **Download CSV File** to save both credentials securely
3. Alternatively, copy each value individually to a password manager
4. Click **Next** to proceed to role assignment

---

## Step 3: Assign the Appropriate Role

### Recommended Roles by Use Case

Choose the role based on what operations you need to perform:

| Use Case | Recommended Role | Permission Level |
|----------|------------------|------------------|
| **Audit Only** (read profiles, validate compliance) | `Auditor` | Read-only |
| **View All Configurations** (comprehensive read access) | `View Only Administrator` | Read-only |
| **Deploy Profiles** (create/modify profiles) | `Security Administrator` | Read + Write (security config) |
| **Full Access** (all operations including push) | `Superuser` | Full access |

### For Audit-Only Operations (Recommended for Most Users)

If you only need to **validate existing configurations** without making changes:

1. In the **Assign Role** step, click **Add Role**
2. Select **Auditor** from the role dropdown
3. For **Scope**, select:
   - **All Apps & Services** for tenant-wide audit access, OR
   - Specific apps if you want to limit scope
4. Click **Save**

The `Auditor` role provides:
- Read-only access to all configurations
- View access to dashboards
- View access to subscriptions and licenses
- **Cannot** modify, create, or delete any configurations
- **Cannot** push configuration changes

### For Configuration Operations (Deploy Profiles)

If you need to **create FIPS profiles and push configurations**:

1. In the **Assign Role** step, click **Add Role**
2. Select **Security Administrator** from the role dropdown
3. For **Scope**, select the appropriate scope:
   - **All Apps & Services** for full access
   - Or limit to specific folders/tenants
4. Click **Save**

The `Security Administrator` role provides:
- Read and write access to security policy configurations
- Read and write access to dashboard functionality
- Read-only access to alerts, licenses, and devices
- Ability to push configuration changes

---

## Step 4: Save Your Credentials

Create a secure record of your credentials. **Never store these in code or version control.**

### Credential Checklist

- [ ] **Client ID**: `_____________________________________`
- [ ] **Client Secret**: `_____________________________________`
- [ ] **TSG ID**: `_____________________________________`
- [ ] **Role Assigned**: `_____________________________________`
- [ ] **Created Date**: `_____________________________________`

### Recommended Storage Options

| Method | Security Level | Best For |
|--------|----------------|----------|
| HashiCorp Vault | High | Enterprise/production |
| AWS Secrets Manager | High | AWS environments |
| Azure Key Vault | High | Azure environments |
| 1Password/LastPass | Medium-High | Individual/team use |
| macOS Keychain | Medium | Local development |
| Encrypted file | Medium | Temporary/testing |

### Environment Variable Setup

For use with the FIPS toolkit, set these environment variables:

```bash
# Add to your shell profile (~/.bashrc, ~/.zshrc, etc.)
export SCM_CLIENT_ID="your-service-account@1234567890.iam.panserviceaccount.com"
export SCM_CLIENT_SECRET="your-client-secret-uuid"
export SCM_TSG_ID="1234567890"
```

---

## Step 5: Test Your Credentials

### Using the FIPS Toolkit

```bash
python3 fips-toolkit.py setup
# Follow prompts to enter credentials
# The toolkit will test the connection automatically
```

### Using curl (Manual Test)

```bash
# Request an access token
curl -X POST "https://auth.apps.paloaltonetworks.com/oauth2/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u "${SCM_CLIENT_ID}:${SCM_CLIENT_SECRET}" \
  -d "grant_type=client_credentials&scope=tsg_id:${SCM_TSG_ID}"
```

**Expected Response (Success):**
```json
{
  "access_token": "eyJhbGciOiJSUzI1...",
  "token_type": "Bearer",
  "expires_in": 899
}
```

**Common Error Responses:**

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_client` | Wrong Client ID or Secret | Verify credentials are correct |
| `invalid_scope` | Wrong TSG ID | Check TSG ID matches your tenant |
| `unauthorized_client` | No role assigned | Assign a role to the service account |

---

## Role Reference

### Read-Only Roles (For Auditing)

| Role | Permissions | Use When |
|------|-------------|----------|
| **Auditor** | Read-only access to all configurations, subscriptions, licenses, dashboards | You only need to validate compliance |
| **View Only Administrator** | Read-only access to all system-wide functions and logs | You need comprehensive read access including logs |
| **SOC Analyst** | Read-only access to logs, reports, and security events | You're focused on security monitoring |

### Read-Write Roles (For Configuration)

| Role | Permissions | Use When |
|------|-------------|----------|
| **Security Administrator** | Read/write for security policies and dashboards; read-only for alerts, licenses, devices | You need to deploy FIPS profiles |
| **Network Administrator** | Read/write for logs, network policies, dashboards | You manage network configurations |
| **Deployment Administrator** | Read/write for deployment functions | You manage deployments |
| **Superuser** | Full read/write access to all functions | You need unrestricted access (avoid if possible) |

### Permission Hierarchy

When multiple roles are assigned, the **most permissive** role applies:
- If you have `Auditor` (read-only) AND `Security Administrator` (read-write), you get read-write access
- Assign only the role you need to follow least-privilege principles

---

## Security Best Practices

### Do's

- **Rotate credentials** every 90 days or per your security policy
- **Use separate accounts** for audit vs. configuration operations
- **Store secrets securely** in a secrets manager or vault
- **Monitor API usage** through SCM audit logs
- **Delete unused accounts** promptly
- **Use descriptive names** that indicate the account's purpose and permissions

### Don'ts

- **Never commit credentials** to version control (git, etc.)
- **Never share credentials** via email, Slack, or other insecure channels
- **Never use Superuser** role unless absolutely necessary
- **Never reuse credentials** across environments (dev/staging/prod)
- **Never store secrets** in plain text files

### Credential Rotation Procedure

1. Create a new service account with the same role
2. Update your toolkit configuration with new credentials
3. Test the new credentials work correctly
4. Delete or disable the old service account
5. Update any documentation or team knowledge

---

## Troubleshooting

### "Authentication failed" or "invalid_client"

**Causes:**
- Incorrect Client ID or Client Secret
- Typo in credentials
- Credentials were rotated or account deleted

**Solutions:**
1. Verify credentials match exactly (no extra spaces)
2. Check the service account still exists in SCM
3. If Client Secret was lost, create a new service account

### "Access denied" or "Forbidden" (403)

**Causes:**
- Service account has no role assigned
- Role doesn't have permission for the requested operation
- Wrong TSG ID (accessing a different tenant)

**Solutions:**
1. Verify a role is assigned to the service account
2. Check the role has appropriate permissions (see Role Reference)
3. Verify TSG ID matches your target tenant

### "invalid_scope" Error

**Causes:**
- TSG ID is incorrect
- TSG ID doesn't exist
- Service account not authorized for this TSG

**Solutions:**
1. Verify the TSG ID in your SCM URL
2. Ensure service account was created in the correct tenant
3. For multi-tenant setups, verify parent-child inheritance

### Token Expired During Long Operations

**Cause:** Access tokens expire after 15 minutes

**Solution:** The FIPS toolkit automatically refreshes tokens. If using manual scripts, implement token refresh logic or re-authenticate before long operations.

---

## Official Documentation Links

Validate all information in this guide against the official Palo Alto Networks documentation:

### Service Accounts & Authentication
- [Getting Started with SCM APIs](https://pan.dev/scm/docs/getstarted/)
- [Service Accounts Overview](https://pan.dev/scm/docs/service-accounts/)
- [Add a Service Account (Common Services)](https://docs.paloaltonetworks.com/common-services/identity-and-access-access-management/manage-identity-and-access/add-service-accounts)
- [Create an Access Token](https://pan.dev/scm/api/auth/post-auth-v-1-oauth-2-access-token/)

### Roles & Permissions
- [Roles Overview](https://pan.dev/scm/docs/roles-overview/)
- [List of All Roles](https://pan.dev/scm/docs/all-roles/)
- [Assign Roles](https://pan.dev/scm/docs/roles-assign/)
- [About Roles and Permissions](https://docs.paloaltonetworks.com/common-services/identity-and-access-access-management/manage-identity-and-access/about-roles-and-permissions)

### Tenant Service Groups
- [Tenant Service Groups](https://pan.dev/scm/docs/tenant-service-groups/)
- [Access Control in SCM](https://docs.paloaltonetworks.com/strata-cloud-manager/getting-started/access-control)

### General SCM Documentation
- [Strata Cloud Manager Documentation](https://docs.paloaltonetworks.com/strata-cloud-manager)
- [SCM API Reference](https://pan.dev/scm/docs/home/)

---

## Quick Reference Card

### Minimum Permissions for FIPS Toolkit

| Operation | Required Role | Can Read | Can Write | Can Push |
|-----------|---------------|----------|-----------|----------|
| `audit` | Auditor | Yes | No | No |
| `configure` | Security Administrator | Yes | Yes | Yes |
| `report` | Auditor | Yes | No | No |

### Credential Format Quick Check

```
Client ID:     name@XXXXXXXXXX.iam.panserviceaccount.com
               ^^^^                  (your chosen name)
                    ^^^^^^^^^^       (your TSG ID)

Client Secret: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
               (UUID format, 36 characters)

TSG ID:        XXXXXXXXXX
               (10+ digit number from your Client ID)
```

---

*Last updated: December 2024*
*For the latest information, always refer to the [official Palo Alto Networks documentation](https://docs.paloaltonetworks.com/strata-cloud-manager).*
