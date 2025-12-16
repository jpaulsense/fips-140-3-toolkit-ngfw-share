# Sample Validation Reports

This directory contains example outputs from the FIPS 140-3 Compliance Validator showing different compliance scenarios.

## Report Examples

### 1. `fully-passed-example.txt`
**Status: PASSED**

A fully compliant firewall configuration where:
- All profiles in use are FIPS 140-3 compliant
- No non-compliant profiles exist (even unused ones)
- All certificates are valid and use compliant algorithms
- Management interface is properly secured

This represents the ideal state after completing FIPS 140-3 hardening.

### 2. `passed-with-high-risk-example.txt`
**Status: PASSED WITH HIGH RISK**

A firewall where active configurations are compliant, but legacy profiles remain:
- All **in-use** profiles are compliant
- Default/legacy profiles with non-compliant algorithms exist but aren't used
- Operational security is maintained
- Cleanup recommended to prevent accidental use

This is a common state after migrating to compliant profiles without removing old ones.

### 3. `full-audit-example.txt`
**Status: FAILED**

A comprehensive example showing various findings:
- **FAIL**: Non-compliant settings actively in use
- **HIGH RISK**: Non-compliant settings not in use
- **WARN**: Configuration issues needing review
- **PASS**: Compliant settings

Includes:
- Multiple IKE/IPSec profiles with different compliance states
- SSL/TLS profiles with weak TLS versions
- Interface management profiles with insecure protocols
- Expired and expiring certificates
- Detailed remediation priorities

## Report Sections

Each report includes:

1. **Header** - Firewall identification and timestamp
2. **Profile Usage Information** - Which profiles are actively referenced
3. **IKE Crypto Profiles** - Phase 1 VPN settings
4. **IPSec Crypto Profiles** - Phase 2 VPN settings
5. **SSL/TLS Service Profiles** - TLS configuration
6. **Decryption Profiles** - SSL inspection settings
7. **Interface Management Profiles** - Management access settings
8. **Certificate Validation** - Key algorithms and expiration
9. **Management Interface TLS** - Admin UI security
10. **Compliance Summary** - Pass/Fail/High Risk counts
11. **Detailed Findings** - Itemized issues with remediation guidance

## Using These Examples

### For Training
Use these reports to train security teams on:
- Understanding compliance findings
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
