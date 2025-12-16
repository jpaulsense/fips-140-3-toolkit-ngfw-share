#!/usr/bin/env python3
"""
FIPS 140-3 Compliance Validator for Palo Alto Networks Firewalls

This script validates FIPS 140-3 compliance for PAN-OS configurations
WITHOUT requiring CC-mode to be enabled.

Severity Levels:
  - FAIL: Non-compliant settings that are actively IN USE
  - HIGH RISK: Non-compliant settings that exist but are NOT in use
  - WARN: Configuration issues that need review
  - PASS: Compliant settings

Usage:
    python3 fips-compliance-validator.py -f <firewall_ip> -u <username> -p <password>

Requirements:
    - Python 3.6+
    - requests library (pip install requests)
"""

import argparse
import sys
import re
import ssl
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, List, Set, Tuple, Optional

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("Error: requests library required. Install with: pip install requests")
    sys.exit(1)


class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color


class FIPSComplianceValidator:
    """FIPS 140-3 Compliance Validator for PAN-OS"""

    # Non-compliant algorithms - exact match required for DH groups
    NON_COMPLIANT_EXACT = {
        'dh_group': ['group1', 'group2', 'group5', 'no-pfs']
    }

    # Non-compliant algorithm patterns - substring match allowed
    NON_COMPLIANT_PATTERN = {
        'encryption': ['3des', 'des-cbc', 'null', 'rc4'],
        'hash': ['md5', 'sha1'],
        'tls_version': ['tls1-0', 'tls1-1']
    }

    # Compliant algorithm patterns
    COMPLIANT = {
        'encryption': ['aes-128-cbc', 'aes-192-cbc', 'aes-256-cbc',
                       'aes-128-gcm', 'aes-256-gcm'],
        'hash': ['sha256', 'sha384', 'sha512'],
        'dh_group': ['group14', 'group15', 'group16', 'group19', 'group20', 'group21'],
        'tls_version': ['tls1-2', 'tls1-3', 'max']
    }

    def __init__(self, firewall: str, username: str, password: str):
        self.firewall = firewall
        self.username = username
        self.password = password
        self.api_key = None
        self.base_url = f"https://{firewall}/api/"

        # Counters
        self.pass_count = 0
        self.fail_count = 0
        self.high_risk_count = 0
        self.warn_count = 0
        self.results = []

        # Profile usage tracking
        self.ike_profiles_in_use: Set[str] = set()
        self.ipsec_profiles_in_use: Set[str] = set()
        self.ssl_tls_profiles_in_use: Set[str] = set()
        self.decryption_profiles_in_use: Set[str] = set()
        self.mgmt_profiles_in_use: Set[str] = set()

    def print_header(self, title: str):
        """Print a section header"""
        print(f"\n{Colors.BLUE}{'=' * 60}{Colors.NC}")
        print(f"{Colors.BLUE}{title}{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")

    def print_pass(self, message: str):
        """Print a passing result"""
        print(f"{Colors.GREEN}[PASS]{Colors.NC} {message}")
        self.pass_count += 1
        self.results.append(('PASS', message))

    def print_fail(self, message: str):
        """Print a failing result (non-compliant AND in use)"""
        print(f"{Colors.RED}[FAIL]{Colors.NC} {message}")
        self.fail_count += 1
        self.results.append(('FAIL', message))

    def print_high_risk(self, message: str):
        """Print a high risk result (non-compliant but NOT in use)"""
        print(f"{Colors.MAGENTA}[HIGH RISK]{Colors.NC} {message}")
        self.high_risk_count += 1
        self.results.append(('HIGH RISK', message))

    def print_warn(self, message: str):
        """Print a warning"""
        print(f"{Colors.YELLOW}[WARN]{Colors.NC} {message}")
        self.warn_count += 1
        self.results.append(('WARN', message))

    def print_info(self, message: str):
        """Print informational message"""
        print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")

    def get_api_key(self) -> bool:
        """Authenticate and get API key"""
        try:
            response = requests.get(
                f"{self.base_url}",
                params={
                    'type': 'keygen',
                    'user': self.username,
                    'password': self.password
                },
                verify=False,
                timeout=30
            )

            root = ET.fromstring(response.text)
            if root.get('status') == 'success':
                key_elem = root.find('.//key')
                if key_elem is not None:
                    self.api_key = key_elem.text
                    return True
            return False
        except Exception as e:
            print(f"Error authenticating: {e}")
            return False

    def api_call(self, call_type: str, action: str = None,
                 xpath: str = None, cmd: str = None) -> Optional[ET.Element]:
        """Make an API call to the firewall"""
        try:
            params = {
                'type': call_type,
                'key': self.api_key
            }
            if action:
                params['action'] = action
            if xpath:
                params['xpath'] = xpath
            if cmd:
                params['cmd'] = cmd

            response = requests.post(
                self.base_url,
                data=params,
                verify=False,
                timeout=60
            )

            return ET.fromstring(response.text)
        except Exception as e:
            print(f"API call error: {e}")
            return None

    def is_non_compliant_value(self, value: str, category: str) -> bool:
        """Check if a value is non-compliant"""
        value_lower = value.lower()

        # Check exact matches (for DH groups to avoid group1 matching group14, etc.)
        if category in self.NON_COMPLIANT_EXACT:
            return value_lower in self.NON_COMPLIANT_EXACT[category]

        # Check pattern/substring matches
        if category in self.NON_COMPLIANT_PATTERN:
            for pattern in self.NON_COMPLIANT_PATTERN[category]:
                if pattern in value_lower:
                    return True

        return False

    def gather_profile_usage(self):
        """Gather information about which profiles are actively in use"""
        self.print_header("GATHERING PROFILE USAGE INFORMATION")

        # Get IKE gateways to find IKE crypto profiles in use
        self.print_info("Checking IKE gateway configurations...")
        ike_gw_root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway"
        )
        if ike_gw_root is not None:
            for gw in ike_gw_root.findall('.//entry'):
                gw_name = gw.get('name')
                ike_crypto = gw.find('.//ike-crypto-profile')
                if ike_crypto is not None and ike_crypto.text:
                    self.ike_profiles_in_use.add(ike_crypto.text)
                    self.print_info(f"  IKE Gateway '{gw_name}' uses profile: {ike_crypto.text}")

        # Get IPSec tunnels to find IPSec crypto profiles in use
        self.print_info("Checking IPSec tunnel configurations...")
        ipsec_root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec"
        )
        if ipsec_root is not None:
            for tunnel in ipsec_root.findall('.//entry'):
                tunnel_name = tunnel.get('name')
                ipsec_crypto = tunnel.find('.//ipsec-crypto-profile')
                if ipsec_crypto is not None and ipsec_crypto.text:
                    self.ipsec_profiles_in_use.add(ipsec_crypto.text)
                    self.print_info(f"  IPSec Tunnel '{tunnel_name}' uses profile: {ipsec_crypto.text}")

        # Get GlobalProtect gateways for IPSec crypto profiles
        self.print_info("Checking GlobalProtect gateway configurations...")
        gp_gw_root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-gateway"
        )
        if gp_gw_root is not None:
            for gw in gp_gw_root.findall('.//entry'):
                gw_name = gw.get('name')
                ipsec_crypto = gw.find('.//ipsec-crypto-profile')
                if ipsec_crypto is not None and ipsec_crypto.text:
                    self.ipsec_profiles_in_use.add(ipsec_crypto.text)
                    self.print_info(f"  GP Gateway '{gw_name}' uses IPSec profile: {ipsec_crypto.text}")
                ssl_profile = gw.find('.//ssl-tls-service-profile')
                if ssl_profile is not None and ssl_profile.text:
                    self.ssl_tls_profiles_in_use.add(ssl_profile.text)
                    self.print_info(f"  GP Gateway '{gw_name}' uses SSL/TLS profile: {ssl_profile.text}")

        # Get GlobalProtect portals for SSL/TLS profiles
        self.print_info("Checking GlobalProtect portal configurations...")
        gp_portal_root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-portal"
        )
        if gp_portal_root is not None:
            for portal in gp_portal_root.findall('.//entry'):
                portal_name = portal.get('name')
                ssl_profile = portal.find('.//ssl-tls-service-profile')
                if ssl_profile is not None and ssl_profile.text:
                    self.ssl_tls_profiles_in_use.add(ssl_profile.text)
                    self.print_info(f"  GP Portal '{portal_name}' uses SSL/TLS profile: {ssl_profile.text}")

        # Get management interface SSL/TLS profile
        self.print_info("Checking management interface configuration...")
        mgmt_ssl_root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile"
        )
        if mgmt_ssl_root is not None:
            ssl_profile = mgmt_ssl_root.find('.//ssl-tls-service-profile')
            if ssl_profile is not None and ssl_profile.text:
                self.ssl_tls_profiles_in_use.add(ssl_profile.text)
                self.print_info(f"  Management interface uses SSL/TLS profile: {ssl_profile.text}")

        # Get decryption rules for decryption profiles in use
        self.print_info("Checking decryption rule configurations...")
        decrypt_rules_root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/rulebase/decryption"
        )
        if decrypt_rules_root is not None:
            for rule in decrypt_rules_root.findall('.//entry'):
                rule_name = rule.get('name')
                profile = rule.find('.//profile')
                if profile is not None and profile.text:
                    self.decryption_profiles_in_use.add(profile.text)
                    self.print_info(f"  Decryption rule '{rule_name}' uses profile: {profile.text}")

        # Get interfaces for management profiles in use
        self.print_info("Checking interface configurations...")
        for iface_type in ['ethernet', 'loopback', 'tunnel', 'vlan']:
            iface_root = self.api_call(
                'config', 'get',
                f"/config/devices/entry[@name='localhost.localdomain']/network/interface/{iface_type}"
            )
            if iface_root is not None:
                for iface in iface_root.findall('.//entry'):
                    iface_name = iface.get('name')
                    mgmt_profile = iface.find('.//interface-management-profile')
                    if mgmt_profile is not None and mgmt_profile.text:
                        self.mgmt_profiles_in_use.add(mgmt_profile.text)
                        self.print_info(f"  Interface '{iface_name}' uses mgmt profile: {mgmt_profile.text}")

        # Summary
        print()
        self.print_info(f"IKE crypto profiles in use: {len(self.ike_profiles_in_use)}")
        self.print_info(f"IPSec crypto profiles in use: {len(self.ipsec_profiles_in_use)}")
        self.print_info(f"SSL/TLS profiles in use: {len(self.ssl_tls_profiles_in_use)}")
        self.print_info(f"Decryption profiles in use: {len(self.decryption_profiles_in_use)}")
        self.print_info(f"Management profiles in use: {len(self.mgmt_profiles_in_use)}")

    def check_ike_crypto_profiles(self):
        """Validate IKE crypto profiles"""
        self.print_header("IKE CRYPTO PROFILES")

        root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles"
        )

        if root is None:
            self.print_warn("Could not retrieve IKE crypto profiles")
            return

        profiles = root.findall('.//entry')
        if not profiles:
            self.print_info("No IKE crypto profiles found")
            return

        for profile in profiles:
            name = profile.get('name')
            in_use = name in self.ike_profiles_in_use
            usage_status = f"{Colors.CYAN}[IN USE]{Colors.NC}" if in_use else f"{Colors.YELLOW}[NOT USED]{Colors.NC}"
            print(f"\n{Colors.BLUE}[INFO]{Colors.NC} Checking profile: {name} {usage_status}")

            # Track non-compliance for this profile
            profile_non_compliant = False

            # Check encryption
            enc_compliant = True
            non_compliant_enc = []
            for enc in profile.findall('.//encryption/member'):
                if self.is_non_compliant_value(enc.text, 'encryption'):
                    enc_compliant = False
                    non_compliant_enc.append(enc.text)
                    profile_non_compliant = True

            if not enc_compliant:
                for enc in non_compliant_enc:
                    if in_use:
                        self.print_fail(f"Non-compliant encryption: {enc}")
                    else:
                        self.print_high_risk(f"Non-compliant encryption (not in use): {enc}")
            else:
                self.print_pass("Encryption algorithms compliant")

            # Check hash
            hash_compliant = True
            non_compliant_hash = []
            for h in profile.findall('.//hash/member'):
                if self.is_non_compliant_value(h.text, 'hash'):
                    hash_compliant = False
                    non_compliant_hash.append(h.text)
                    profile_non_compliant = True

            if not hash_compliant:
                for h in non_compliant_hash:
                    if in_use:
                        self.print_fail(f"Non-compliant hash: {h}")
                    else:
                        self.print_high_risk(f"Non-compliant hash (not in use): {h}")
            else:
                self.print_pass("Hash algorithms compliant")

            # Check DH groups
            dh_compliant = True
            non_compliant_dh = []
            for dh in profile.findall('.//dh-group/member'):
                if self.is_non_compliant_value(dh.text, 'dh_group'):
                    dh_compliant = False
                    non_compliant_dh.append(dh.text)
                    profile_non_compliant = True

            if not dh_compliant:
                for dh in non_compliant_dh:
                    if in_use:
                        self.print_fail(f"Non-compliant DH group: {dh}")
                    else:
                        self.print_high_risk(f"Non-compliant DH group (not in use): {dh}")
            else:
                self.print_pass("DH groups compliant")

    def check_ipsec_crypto_profiles(self):
        """Validate IPSec crypto profiles"""
        self.print_header("IPSEC CRYPTO PROFILES")

        root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles"
        )

        if root is None:
            self.print_warn("Could not retrieve IPSec crypto profiles")
            return

        profiles = root.findall('.//entry')
        if not profiles:
            self.print_info("No IPSec crypto profiles found")
            return

        for profile in profiles:
            name = profile.get('name')
            in_use = name in self.ipsec_profiles_in_use
            usage_status = f"{Colors.CYAN}[IN USE]{Colors.NC}" if in_use else f"{Colors.YELLOW}[NOT USED]{Colors.NC}"
            print(f"\n{Colors.BLUE}[INFO]{Colors.NC} Checking profile: {name} {usage_status}")

            # Check ESP encryption
            enc_compliant = True
            non_compliant_enc = []
            for enc in profile.findall('.//esp/encryption/member'):
                if self.is_non_compliant_value(enc.text, 'encryption'):
                    enc_compliant = False
                    non_compliant_enc.append(enc.text)

            if not enc_compliant:
                for enc in non_compliant_enc:
                    if in_use:
                        self.print_fail(f"Non-compliant ESP encryption: {enc}")
                    else:
                        self.print_high_risk(f"Non-compliant ESP encryption (not in use): {enc}")
            else:
                self.print_pass("ESP encryption compliant")

            # Check ESP authentication
            auth_compliant = True
            non_compliant_auth = []
            for auth in profile.findall('.//esp/authentication/member'):
                if auth.text != 'none' and self.is_non_compliant_value(auth.text, 'hash'):
                    auth_compliant = False
                    non_compliant_auth.append(auth.text)

            if not auth_compliant:
                for auth in non_compliant_auth:
                    if in_use:
                        self.print_fail(f"Non-compliant ESP authentication: {auth}")
                    else:
                        self.print_high_risk(f"Non-compliant ESP authentication (not in use): {auth}")
            else:
                self.print_pass("ESP authentication compliant")

            # Check DH group (PFS)
            dh_elem = profile.find('.//dh-group')
            if dh_elem is not None and dh_elem.text:
                if self.is_non_compliant_value(dh_elem.text, 'dh_group'):
                    if in_use:
                        self.print_fail(f"Non-compliant DH group (PFS): {dh_elem.text}")
                    else:
                        self.print_high_risk(f"Non-compliant DH group (PFS) (not in use): {dh_elem.text}")
                else:
                    self.print_pass(f"DH group (PFS) compliant: {dh_elem.text}")

    def check_ssl_tls_profiles(self):
        """Validate SSL/TLS service profiles"""
        self.print_header("SSL/TLS SERVICE PROFILES")

        root = self.api_call('config', 'get', "/config/shared/ssl-tls-service-profile")

        if root is None:
            self.print_warn("Could not retrieve SSL/TLS service profiles")
            return

        profiles = root.findall('.//entry')
        if not profiles:
            self.print_warn("No SSL/TLS service profiles found - using defaults")
            return

        for profile in profiles:
            name = profile.get('name')
            in_use = name in self.ssl_tls_profiles_in_use
            usage_status = f"{Colors.CYAN}[IN USE]{Colors.NC}" if in_use else f"{Colors.YELLOW}[NOT USED]{Colors.NC}"
            print(f"\n{Colors.BLUE}[INFO]{Colors.NC} Checking profile: {name} {usage_status}")

            # Check minimum TLS version
            min_ver = profile.find('.//protocol-settings/min-version')
            if min_ver is not None and min_ver.text:
                if self.is_non_compliant_value(min_ver.text, 'tls_version'):
                    if in_use:
                        self.print_fail(f"Non-compliant minimum TLS version: {min_ver.text}")
                    else:
                        self.print_high_risk(f"Non-compliant minimum TLS version (not in use): {min_ver.text}")
                else:
                    self.print_pass(f"Minimum TLS version compliant: {min_ver.text}")
            else:
                self.print_warn("No minimum TLS version specified")

            # Check certificate
            cert = profile.find('.//certificate')
            if cert is not None and cert.text:
                self.print_pass(f"Certificate assigned: {cert.text}")
            else:
                self.print_warn("No certificate assigned to profile")

    def check_decryption_profiles(self):
        """Validate decryption profiles"""
        self.print_header("DECRYPTION PROFILES")

        root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/profiles/decryption"
        )

        if root is None:
            self.print_info("Could not retrieve decryption profiles")
            return

        profiles = root.findall('.//entry')
        if not profiles:
            self.print_info("No decryption profiles found")
            return

        for profile in profiles:
            name = profile.get('name')
            in_use = name in self.decryption_profiles_in_use
            usage_status = f"{Colors.CYAN}[IN USE]{Colors.NC}" if in_use else f"{Colors.YELLOW}[NOT USED]{Colors.NC}"
            print(f"\n{Colors.BLUE}[INFO]{Colors.NC} Checking profile: {name} {usage_status}")

            # Check SSL protocol settings
            min_ver = profile.find('.//ssl-protocol-settings/min-version')
            if min_ver is not None and min_ver.text:
                if self.is_non_compliant_value(min_ver.text, 'tls_version'):
                    if in_use:
                        self.print_fail(f"Non-compliant minimum TLS version: {min_ver.text}")
                    else:
                        self.print_high_risk(f"Non-compliant minimum TLS version (not in use): {min_ver.text}")
                else:
                    self.print_pass(f"Minimum TLS version compliant: {min_ver.text}")

            # Check certificate blocking
            block_expired = profile.find('.//ssl-forward-proxy/block-expired-certificate')
            if block_expired is not None and block_expired.text == 'yes':
                self.print_pass("Blocking expired certificates enabled")
            else:
                self.print_warn("Blocking expired certificates not enabled")

            block_untrusted = profile.find('.//ssl-forward-proxy/block-untrusted-issuer')
            if block_untrusted is not None and block_untrusted.text == 'yes':
                self.print_pass("Blocking untrusted issuers enabled")
            else:
                self.print_warn("Blocking untrusted issuers not enabled")

    def check_interface_mgmt_profiles(self):
        """Validate interface management profiles"""
        self.print_header("INTERFACE MANAGEMENT PROFILES")

        root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile"
        )

        if root is None:
            self.print_info("Could not retrieve interface management profiles")
            return

        profiles = root.findall('.//entry')
        if not profiles:
            self.print_info("No interface management profiles found")
            return

        for profile in profiles:
            name = profile.get('name')
            in_use = name in self.mgmt_profiles_in_use
            usage_status = f"{Colors.CYAN}[IN USE]{Colors.NC}" if in_use else f"{Colors.YELLOW}[NOT USED]{Colors.NC}"
            print(f"\n{Colors.BLUE}[INFO]{Colors.NC} Checking profile: {name} {usage_status}")

            # Check for insecure services
            telnet = profile.find('.//telnet')
            if telnet is not None and telnet.text == 'yes':
                if in_use:
                    self.print_fail("Telnet is enabled (insecure, non-encrypted)")
                else:
                    self.print_high_risk("Telnet is enabled (not in use)")
            else:
                self.print_pass("Telnet is disabled")

            http = profile.find('.//http')
            if http is not None and http.text == 'yes':
                if in_use:
                    self.print_fail("HTTP is enabled (insecure, non-encrypted)")
                else:
                    self.print_high_risk("HTTP is enabled (not in use)")
            else:
                self.print_pass("HTTP is disabled")

            # Check for secure services
            ssh = profile.find('.//ssh')
            https = profile.find('.//https')
            ssh_enabled = ssh is not None and ssh.text == 'yes'
            https_enabled = https is not None and https.text == 'yes'

            if ssh_enabled or https_enabled:
                self.print_pass(f"Secure protocols: SSH={ssh_enabled}, HTTPS={https_enabled}")
            else:
                self.print_warn("No secure management protocols enabled")

    def check_certificates(self):
        """Validate certificates"""
        self.print_header("CERTIFICATE VALIDATION")

        root = self.api_call('config', 'get', "/config/shared/certificate")

        if root is None:
            self.print_info("Could not retrieve certificates")
            return

        certs = root.findall('.//entry')
        if not certs:
            self.print_info("No certificates found")
            return

        current_epoch = int(datetime.now(timezone.utc).timestamp())

        for cert in certs:
            name = cert.get('name')
            print(f"\n{Colors.BLUE}[INFO]{Colors.NC} Checking certificate: {name}")

            # Check algorithm
            algorithm = cert.find('.//algorithm')
            if algorithm is not None:
                if algorithm.text in ['RSA', 'EC', 'ECDSA']:
                    self.print_pass(f"Key algorithm: {algorithm.text}")
                else:
                    self.print_info(f"Key algorithm: {algorithm.text}")

            # Check expiry
            expiry = cert.find('.//expiry-epoch')
            if expiry is not None and expiry.text:
                expiry_epoch = int(expiry.text)
                if expiry_epoch < current_epoch:
                    self.print_fail("Certificate is EXPIRED")
                else:
                    days_left = (expiry_epoch - current_epoch) // 86400
                    if days_left < 30:
                        self.print_warn(f"Certificate expires in {days_left} days")
                    elif days_left < 90:
                        self.print_info(f"Certificate expires in {days_left} days")
                    else:
                        self.print_pass(f"Certificate valid for {days_left} days")

            # Check if CA
            is_ca = cert.find('.//ca')
            if is_ca is not None and is_ca.text == 'yes':
                self.print_info("Certificate type: CA")
            else:
                self.print_info("Certificate type: End-entity")

    def check_management_tls(self):
        """Check management interface TLS configuration"""
        self.print_header("MANAGEMENT INTERFACE TLS")

        root = self.api_call(
            'config', 'get',
            "/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile"
        )

        if root is not None:
            profile = root.find('.//ssl-tls-service-profile')
            if profile is not None and profile.text:
                self.print_pass(f"Management using SSL/TLS profile: {profile.text}")
            else:
                self.print_warn("No SSL/TLS profile assigned to management (using defaults)")
        else:
            self.print_warn("Could not check management TLS configuration")

    def print_summary(self):
        """Print compliance summary"""
        self.print_header("COMPLIANCE SUMMARY")

        print(f"\n{Colors.GREEN}PASSED:{Colors.NC}      {self.pass_count}")
        print(f"{Colors.RED}FAILED:{Colors.NC}      {self.fail_count}  (Non-compliant AND in use)")
        print(f"{Colors.MAGENTA}HIGH RISK:{Colors.NC}   {self.high_risk_count}  (Non-compliant but NOT in use)")
        print(f"{Colors.YELLOW}WARNINGS:{Colors.NC}    {self.warn_count}")

        print()

        # Determine overall status
        if self.fail_count == 0 and self.high_risk_count == 0:
            print(f"{Colors.GREEN}{'=' * 50}{Colors.NC}")
            print(f"{Colors.GREEN}  FIPS 140-3 COMPLIANCE: PASSED                   {Colors.NC}")
            print(f"{Colors.GREEN}{'=' * 50}{Colors.NC}")
            if self.warn_count > 0:
                print(f"\nNote: {self.warn_count} warnings require review")
        elif self.fail_count == 0 and self.high_risk_count > 0:
            print(f"{Colors.MAGENTA}{'=' * 50}{Colors.NC}")
            print(f"{Colors.MAGENTA}  FIPS 140-3 COMPLIANCE: PASSED WITH HIGH RISK   {Colors.NC}")
            print(f"{Colors.MAGENTA}{'=' * 50}{Colors.NC}")
            print(f"\n{Colors.MAGENTA}No active non-compliant configurations, but")
            print(f"{self.high_risk_count} unused non-compliant profile(s) exist.{Colors.NC}")
            print("\nRecommendation: Remove or update unused non-compliant profiles")
            print("to prevent accidental use in future configurations.")
        else:
            print(f"{Colors.RED}{'=' * 50}{Colors.NC}")
            print(f"{Colors.RED}  FIPS 140-3 COMPLIANCE: FAILED                   {Colors.NC}")
            print(f"{Colors.RED}{'=' * 50}{Colors.NC}")
            print(f"\n{self.fail_count} non-compliant configuration(s) actively in use.")
            print("Review the [FAIL] items above and remediate immediately.")
            if self.high_risk_count > 0:
                print(f"\nAdditionally, {self.high_risk_count} unused non-compliant profile(s)")
                print("should be removed or updated.")

        print(f"\nReport generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Firewall: {self.firewall}")

    def run(self) -> int:
        """Run all compliance checks"""
        self.print_header("FIPS 140-3 COMPLIANCE VALIDATION")
        print(f"Firewall: {self.firewall}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        self.print_info("Authenticating to firewall...")
        if not self.get_api_key():
            self.print_fail("Failed to authenticate to firewall")
            return 1

        self.print_pass("Successfully authenticated")

        # First, gather profile usage information
        self.gather_profile_usage()

        # Run all checks
        self.check_ike_crypto_profiles()
        self.check_ipsec_crypto_profiles()
        self.check_ssl_tls_profiles()
        self.check_decryption_profiles()
        self.check_interface_mgmt_profiles()
        self.check_certificates()
        self.check_management_tls()

        # Print summary
        self.print_summary()

        # Return code: 0 = pass, 1 = fail (in use), 2 = high risk only
        if self.fail_count > 0:
            return 1
        elif self.high_risk_count > 0:
            return 2
        return 0


def main():
    parser = argparse.ArgumentParser(
        description='FIPS 140-3 Compliance Validator for PAN-OS'
    )
    parser.add_argument('-f', '--firewall', required=True,
                        help='Firewall IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                        help='Admin username')
    parser.add_argument('-p', '--password', required=True,
                        help='Admin password')
    parser.add_argument('-o', '--output', help='Output file for report')

    args = parser.parse_args()

    validator = FIPSComplianceValidator(
        args.firewall,
        args.username,
        args.password
    )

    return validator.run()


if __name__ == '__main__':
    sys.exit(main())
