# Sample SCM Validation Reports

This directory contains example outputs from the FIPS 140-3 Compliance Validator for Strata Cloud Manager tenants showing different compliance scenarios.

## Report Examples

### 1. `scm-fully-passed-example.txt`
**Status: PASSED**

A fully compliant SCM tenant where:
- All profiles use FIPS 140-3 approved algorithms
- No legacy or vendor-specific non-compliant profiles exist
- All DH groups are 14 or higher
- No 3DES, SHA-1, or MD5 in use

This represents the ideal state after completing FIPS 140-3 hardening.

### 2. `scm-passed-with-warnings-example.txt`
**Status: PASSED WITH WARNINGS**

An SCM tenant that is operationally compliant but has:
- All actively used profiles are compliant
- Some unused default profiles with weak algorithms
- Warnings about legacy profiles that should be cleaned up

This is common when migrating to compliant profiles without removing defaults.

### 3. `scm-failed-example.txt`
**Status: FAILED**

A comprehensive example showing various findings:
- Multiple profiles with 3DES encryption
- SHA-1 and MD5 hash algorithms in use
- Weak DH groups (group1, group2, group5)
- Detailed remediation priorities

## Report Sections

Each report includes:

1. **Header** - Tenant identification and timestamp
2. **IKE Crypto Profiles** - Phase 1 VPN settings with compliance status
3. **IPSec Crypto Profiles** - Phase 2 VPN settings with compliance status
4. **Compliance Summary** - Pass/Fail counts
5. **Detailed Findings** - Itemized issues with remediation guidance
6. **Remediation Priority** - Organized by severity
7. **Available FIPS Profiles** - Compliant alternatives ready for use
8. **Audit Trail** - Validation metadata

## Using These Examples

### For Training
Use these reports to train security teams on:
- Understanding SCM compliance findings
- Prioritizing remediation efforts
- Interpreting severity levels

### For Documentation
Include in compliance documentation to show:
- Expected report format
- How to interpret findings
- Remediation workflows

### For Testing
Compare actual validator output against these examples to:
- Verify script functionality
- Test report parsing automation
- Validate CI/CD integration
