# FIPS 140-3 Audit Report Generator

## Overview

This document provides templates and scripts for generating formal FIPS 140-3 compliance audit reports for Palo Alto Networks firewalls. These reports are suitable for compliance audits, security assessments, and documentation requirements.

---

## Report Template

### Executive Summary Report

```markdown
# FIPS 140-3 Compliance Audit Report

## Document Information
| Field | Value |
|-------|-------|
| Report Date | [DATE] |
| Auditor | [AUDITOR NAME] |
| Organization | [ORGANIZATION] |
| Report ID | FIPS-AUDIT-[YYYY-MM-DD]-[ID] |

## Executive Summary

This report documents the FIPS 140-3 compliance status of the following Palo Alto Networks firewall(s):

| Hostname | IP Address | PAN-OS Version | Compliance Status |
|----------|------------|----------------|-------------------|
| [HOSTNAME] | [IP] | [VERSION] | [COMPLIANT/NON-COMPLIANT] |

### Overall Compliance Status: [COMPLIANT/NON-COMPLIANT]

### Summary Findings
- Total Configuration Items Reviewed: [COUNT]
- Compliant Items: [COUNT]
- Non-Compliant Items: [COUNT]
- Warnings/Recommendations: [COUNT]

---

## Detailed Findings

### 1. IKE Crypto Profiles

| Profile Name | Encryption | Hash | DH Group | Status |
|--------------|------------|------|----------|--------|
| [NAME] | [ALGO] | [ALGO] | [GROUP] | [STATUS] |

**Findings:**
- [FINDING DETAILS]

**Recommendations:**
- [RECOMMENDATION]

### 2. IPSec Crypto Profiles

| Profile Name | Encryption | Authentication | PFS Group | Status |
|--------------|------------|----------------|-----------|--------|
| [NAME] | [ALGO] | [ALGO] | [GROUP] | [STATUS] |

**Findings:**
- [FINDING DETAILS]

**Recommendations:**
- [RECOMMENDATION]

### 3. SSL/TLS Service Profiles

| Profile Name | Min TLS | Max TLS | Key Exchange | Ciphers | Status |
|--------------|---------|---------|--------------|---------|--------|
| [NAME] | [VER] | [VER] | [ALGO] | [CIPHERS] | [STATUS] |

**Findings:**
- [FINDING DETAILS]

**Recommendations:**
- [RECOMMENDATION]

### 4. SSH Configuration

| Setting | Current Value | Required Value | Status |
|---------|---------------|----------------|--------|
| Host Key Type | [TYPE] | RSA 2048+/ECDSA P-256+ | [STATUS] |
| Key Exchange | [ALGOS] | ECDH/DH Group 14+ | [STATUS] |
| Encryption | [ALGOS] | AES-CTR/GCM | [STATUS] |
| MAC | [ALGOS] | HMAC-SHA-256+ | [STATUS] |

**Findings:**
- [FINDING DETAILS]

**Recommendations:**
- [RECOMMENDATION]

### 5. Certificates

| Certificate Name | Key Type | Key Size | Signature | Expiration | Status |
|------------------|----------|----------|-----------|------------|--------|
| [NAME] | [TYPE] | [SIZE] | [ALGO] | [DATE] | [STATUS] |

**Findings:**
- [FINDING DETAILS]

**Recommendations:**
- [RECOMMENDATION]

### 6. Management Interface TLS

| Setting | Current Value | Required Value | Status |
|---------|---------------|----------------|--------|
| TLS Profile | [PROFILE] | FIPS-compliant | [STATUS] |
| Min TLS Version | [VERSION] | TLS 1.2+ | [STATUS] |
| Certificate | [CERT] | RSA 2048+/ECDSA P-256+ | [STATUS] |

**Findings:**
- [FINDING DETAILS]

**Recommendations:**
- [RECOMMENDATION]

---

## Remediation Plan

### High Priority (Immediate)
1. [ACTION ITEM]
2. [ACTION ITEM]

### Medium Priority (Within 30 Days)
1. [ACTION ITEM]
2. [ACTION ITEM]

### Low Priority (Within 90 Days)
1. [ACTION ITEM]
2. [ACTION ITEM]

---

## Attestation

I attest that this audit was conducted according to FIPS 140-3 compliance requirements and the findings accurately reflect the configuration status at the time of audit.

**Auditor Signature:** ________________________

**Date:** ________________________

---

## Appendix A: Configuration Exports

[Attached configuration exports for reference]

## Appendix B: Evidence Screenshots

[Attached screenshots of verification commands]
```

---

## Automated Report Generator Script

### Python Report Generator

```python
#!/usr/bin/env python3
"""
FIPS 140-3 Compliance Audit Report Generator
Generates formal compliance reports from firewall configurations
"""

import requests
import xml.etree.ElementTree as ET
from datetime import datetime
import json
import sys

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()

class FIPSAuditReport:
    def __init__(self, firewall_ip, api_key):
        self.firewall_ip = firewall_ip
        self.api_key = api_key
        self.findings = []
        self.compliant_count = 0
        self.non_compliant_count = 0
        self.system_info = {}

    def api_request(self, params):
        """Make API request to firewall"""
        base_url = f"https://{self.firewall_ip}/api/"
        params['key'] = self.api_key
        response = requests.get(base_url, params=params, verify=False)
        return ET.fromstring(response.content)

    def api_op(self, cmd):
        """Operational API request"""
        return self.api_request({'type': 'op', 'cmd': cmd})

    def api_config(self, xpath):
        """Configuration API request"""
        return self.api_request({'type': 'config', 'action': 'get', 'xpath': xpath})

    def get_system_info(self):
        """Get system information"""
        result = self.api_op("<show><system><info></info></system></show>")
        self.system_info = {
            'hostname': result.find('.//hostname').text if result.find('.//hostname') is not None else 'Unknown',
            'ip_address': result.find('.//ip-address').text if result.find('.//ip-address') is not None else 'Unknown',
            'sw_version': result.find('.//sw-version').text if result.find('.//sw-version') is not None else 'Unknown',
            'model': result.find('.//model').text if result.find('.//model') is not None else 'Unknown'
        }

    def check_ike_profiles(self):
        """Audit IKE crypto profiles"""
        findings = []
        xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
        result = self.api_config(xpath)

        non_compliant_patterns = {
            'encryption': ['3des', 'des'],
            'hash': ['md5', 'sha1'],
            'dh_group': ['group1', 'group2', 'group5']
        }

        for profile in result.findall('.//entry'):
            profile_name = profile.get('name')
            profile_status = 'COMPLIANT'
            profile_issues = []

            # Check encryption
            for enc in profile.findall('.//encryption/member'):
                if any(nc in enc.text.lower() for nc in non_compliant_patterns['encryption']):
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Non-compliant encryption: {enc.text}")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            # Check hash
            for hash_alg in profile.findall('.//hash/member'):
                if any(nc in hash_alg.text.lower() for nc in non_compliant_patterns['hash']):
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Non-compliant hash: {hash_alg.text}")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            # Check DH group
            for dh in profile.findall('.//dh-group/member'):
                if any(nc in dh.text.lower() for nc in non_compliant_patterns['dh_group']):
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Non-compliant DH group: {dh.text}")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            findings.append({
                'profile_name': profile_name,
                'status': profile_status,
                'issues': profile_issues,
                'encryption': [e.text for e in profile.findall('.//encryption/member')],
                'hash': [h.text for h in profile.findall('.//hash/member')],
                'dh_group': [d.text for d in profile.findall('.//dh-group/member')]
            })

        return findings

    def check_ipsec_profiles(self):
        """Audit IPSec crypto profiles"""
        findings = []
        xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
        result = self.api_config(xpath)

        non_compliant_patterns = {
            'encryption': ['3des', 'des', 'null'],
            'authentication': ['md5', 'sha1'],
            'dh_group': ['group1', 'group2', 'group5', 'no-pfs']
        }

        for profile in result.findall('.//entry'):
            profile_name = profile.get('name')
            profile_status = 'COMPLIANT'
            profile_issues = []

            # Check encryption
            for enc in profile.findall('.//esp/encryption/member'):
                if any(nc in enc.text.lower() for nc in non_compliant_patterns['encryption']):
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Non-compliant encryption: {enc.text}")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            # Check authentication
            for auth in profile.findall('.//esp/authentication/member'):
                if any(nc in auth.text.lower() for nc in non_compliant_patterns['authentication']):
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Non-compliant authentication: {auth.text}")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            # Check DH group
            dh = profile.find('.//dh-group')
            if dh is not None:
                if any(nc in dh.text.lower() for nc in non_compliant_patterns['dh_group']):
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Non-compliant PFS group: {dh.text}")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            findings.append({
                'profile_name': profile_name,
                'status': profile_status,
                'issues': profile_issues,
                'encryption': [e.text for e in profile.findall('.//esp/encryption/member')],
                'authentication': [a.text for a in profile.findall('.//esp/authentication/member')],
                'dh_group': dh.text if dh is not None else 'N/A'
            })

        return findings

    def check_ssl_tls_profiles(self):
        """Audit SSL/TLS service profiles"""
        findings = []
        xpath = "/config/shared/ssl-tls-service-profile"
        result = self.api_config(xpath)

        for profile in result.findall('.//entry'):
            profile_name = profile.get('name')
            profile_status = 'COMPLIANT'
            profile_issues = []

            # Check min version
            min_ver = profile.find('.//protocol-settings/min-version')
            if min_ver is not None:
                if 'tls1-0' in min_ver.text or 'tls1-1' in min_ver.text:
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Non-compliant min TLS version: {min_ver.text}")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            # Check for weak algorithms enabled
            for weak_algo in ['enc-algo-3des', 'enc-algo-rc4']:
                elem = profile.find(f'.//protocol-settings/{weak_algo}')
                if elem is not None and elem.text.lower() == 'yes':
                    profile_status = 'NON-COMPLIANT'
                    profile_issues.append(f"Weak algorithm enabled: {weak_algo}")
                    self.non_compliant_count += 1

            findings.append({
                'profile_name': profile_name,
                'status': profile_status,
                'issues': profile_issues,
                'min_version': min_ver.text if min_ver is not None else 'N/A',
                'max_version': profile.find('.//protocol-settings/max-version').text if profile.find('.//protocol-settings/max-version') is not None else 'N/A'
            })

        return findings

    def check_certificates(self):
        """Audit certificates"""
        findings = []
        result = self.api_op("<show><certificate><summary></summary></certificate></show>")

        for cert in result.findall('.//entry'):
            cert_name = cert.find('cert-name')
            if cert_name is None:
                continue

            cert_name = cert_name.text
            cert_status = 'COMPLIANT'
            cert_issues = []

            # Check key size
            key_size = cert.find('public-key-length')
            if key_size is not None:
                size = int(key_size.text)
                if size < 2048:
                    cert_status = 'NON-COMPLIANT'
                    cert_issues.append(f"Key size {size} bits < 2048 bits minimum")
                    self.non_compliant_count += 1
                else:
                    self.compliant_count += 1

            findings.append({
                'cert_name': cert_name,
                'status': cert_status,
                'issues': cert_issues,
                'key_size': key_size.text if key_size is not None else 'Unknown',
                'not_after': cert.find('not-valid-after').text if cert.find('not-valid-after') is not None else 'Unknown',
                'algorithm': cert.find('algorithm').text if cert.find('algorithm') is not None else 'Unknown'
            })

        return findings

    def generate_report(self):
        """Generate the full audit report"""
        self.get_system_info()

        ike_findings = self.check_ike_profiles()
        ipsec_findings = self.check_ipsec_profiles()
        ssl_findings = self.check_ssl_tls_profiles()
        cert_findings = self.check_certificates()

        overall_status = 'COMPLIANT' if self.non_compliant_count == 0 else 'NON-COMPLIANT'

        report = f"""
# FIPS 140-3 Compliance Audit Report

## Document Information
| Field | Value |
|-------|-------|
| Report Date | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} |
| Report ID | FIPS-AUDIT-{datetime.now().strftime('%Y%m%d')}-001 |

## System Information
| Field | Value |
|-------|-------|
| Hostname | {self.system_info.get('hostname', 'Unknown')} |
| IP Address | {self.system_info.get('ip_address', 'Unknown')} |
| PAN-OS Version | {self.system_info.get('sw_version', 'Unknown')} |
| Model | {self.system_info.get('model', 'Unknown')} |

## Executive Summary

### Overall Compliance Status: {overall_status}

| Metric | Count |
|--------|-------|
| Total Items Reviewed | {self.compliant_count + self.non_compliant_count} |
| Compliant Items | {self.compliant_count} |
| Non-Compliant Items | {self.non_compliant_count} |

---

## Detailed Findings

### 1. IKE Crypto Profiles

| Profile Name | Encryption | Hash | DH Group | Status |
|--------------|------------|------|----------|--------|
"""
        for f in ike_findings:
            report += f"| {f['profile_name']} | {', '.join(f['encryption'])} | {', '.join(f['hash'])} | {', '.join(f['dh_group'])} | {f['status']} |\n"

        report += """
### 2. IPSec Crypto Profiles

| Profile Name | Encryption | Authentication | PFS Group | Status |
|--------------|------------|----------------|-----------|--------|
"""
        for f in ipsec_findings:
            report += f"| {f['profile_name']} | {', '.join(f['encryption'])} | {', '.join(f['authentication'])} | {f['dh_group']} | {f['status']} |\n"

        report += """
### 3. SSL/TLS Service Profiles

| Profile Name | Min TLS | Max TLS | Status |
|--------------|---------|---------|--------|
"""
        for f in ssl_findings:
            report += f"| {f['profile_name']} | {f['min_version']} | {f['max_version']} | {f['status']} |\n"

        report += """
### 4. Certificates

| Certificate Name | Key Size | Algorithm | Expiration | Status |
|------------------|----------|-----------|------------|--------|
"""
        for f in cert_findings:
            report += f"| {f['cert_name']} | {f['key_size']} | {f['algorithm']} | {f['not_after']} | {f['status']} |\n"

        report += f"""
---

## Non-Compliant Items Detail
"""
        all_issues = []
        for f in ike_findings + ipsec_findings + ssl_findings + cert_findings:
            if f.get('issues'):
                for issue in f['issues']:
                    name = f.get('profile_name') or f.get('cert_name')
                    all_issues.append(f"- **{name}**: {issue}")

        if all_issues:
            report += "\n".join(all_issues)
        else:
            report += "No non-compliant items found."

        report += f"""

---

## Recommendations

"""
        if self.non_compliant_count > 0:
            report += """
1. Replace all non-compliant encryption algorithms (3DES, DES, NULL) with AES-128 or AES-256
2. Replace all non-compliant hash algorithms (MD5, SHA-1) with SHA-256 or higher
3. Replace all non-compliant DH groups (Group 1, 2, 5) with Group 14 or higher
4. Update TLS minimum version to TLS 1.2 or higher
5. Replace certificates with key sizes less than 2048 bits
"""
        else:
            report += "No immediate remediation required. Continue monitoring for compliance."

        report += f"""
---

## Attestation

This audit was conducted according to FIPS 140-3 compliance requirements.

Report generated: {datetime.now().isoformat()}

---
*Generated by FIPS 140-3 Compliance Audit Tool*
"""
        return report


def main():
    if len(sys.argv) < 3:
        print("Usage: python report_generator.py <firewall_ip> <api_key>")
        sys.exit(1)

    firewall_ip = sys.argv[1]
    api_key = sys.argv[2]

    auditor = FIPSAuditReport(firewall_ip, api_key)
    report = auditor.generate_report()

    # Save report
    filename = f"fips_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    with open(filename, 'w') as f:
        f.write(report)

    print(f"Report generated: {filename}")
    print(report)


if __name__ == "__main__":
    main()
```

---

## Usage Instructions

### Generate Report

```bash
# Python script
python3 report_generator.py 192.168.1.1 LUFRPT...

# Output: fips_audit_report_YYYYMMDD_HHMMSS.md
```

### Convert to PDF (Optional)

```bash
# Using pandoc
pandoc fips_audit_report.md -o fips_audit_report.pdf

# Using markdown-pdf (npm)
npx markdown-pdf fips_audit_report.md
```

---

## Compliance Checklist Template

```markdown
# FIPS 140-3 Compliance Checklist

## Firewall: [HOSTNAME]
## Date: [DATE]
## Auditor: [NAME]

### IKE Crypto Profiles
- [ ] All encryption algorithms are AES (128/192/256)
- [ ] All hash algorithms are SHA-256 or higher
- [ ] All DH groups are Group 14 or higher (or ECDH P-256+)
- [ ] No 3DES, DES, MD5, or SHA-1 in use

### IPSec Crypto Profiles
- [ ] All encryption algorithms are AES (128/192/256)
- [ ] All authentication algorithms are SHA-256 or higher
- [ ] PFS is enabled with Group 14+ or ECDH
- [ ] No NULL encryption profiles in use

### SSL/TLS Profiles
- [ ] Minimum TLS version is 1.2 or higher
- [ ] RC4 and 3DES ciphers are disabled
- [ ] RSA key exchange is disabled (ECDHE/DHE preferred)
- [ ] SHA-1 authentication is disabled

### SSH Configuration
- [ ] RSA host keys are 2048 bits or greater
- [ ] ECDSA host keys use P-256 or higher curves
- [ ] Weak encryption (3DES, arcfour) is disabled
- [ ] Weak MAC algorithms (MD5, SHA-1) are disabled

### Certificates
- [ ] All RSA certificates are 2048 bits or greater
- [ ] All ECDSA certificates use P-256 or higher curves
- [ ] All certificates signed with SHA-256 or higher
- [ ] No expired certificates in use
- [ ] No certificates expiring within 30 days

### Management Interface
- [ ] HTTPS is enabled with TLS 1.2+
- [ ] HTTP is disabled
- [ ] Telnet is disabled
- [ ] Management IP restrictions configured
- [ ] Session timeout configured

### Overall Status
- [ ] COMPLIANT
- [ ] NON-COMPLIANT (see findings)

### Signature
Auditor: ________________________ Date: ____________
```

---

## Scheduled Audit Automation

### Cron Job Example

```bash
# Add to crontab for weekly audits
# crontab -e
0 0 * * 0 /path/to/report_generator.py 192.168.1.1 $API_KEY >> /var/log/fips_audit.log 2>&1
```

### Email Report Script

```bash
#!/bin/bash
# Generate and email FIPS compliance report

FIREWALL="192.168.1.1"
API_KEY="your-api-key"
EMAIL="security-team@example.com"

# Generate report
python3 /path/to/report_generator.py $FIREWALL $API_KEY

# Get latest report file
REPORT=$(ls -t fips_audit_report_*.md | head -1)

# Email report
mail -s "FIPS 140-3 Compliance Report - $(date +%Y-%m-%d)" $EMAIL < $REPORT

echo "Report sent to $EMAIL"
```
