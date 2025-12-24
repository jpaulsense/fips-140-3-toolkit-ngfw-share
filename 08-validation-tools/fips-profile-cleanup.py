#!/usr/bin/env python3
"""
FIPS Profile Cleanup Script for Palo Alto Networks Firewalls

Removes ALL FIPS 140-3 profiles deployed by the toolkit for re-testing.

Default profile prefix: ca-ois-fips (customizable via --prefix or interactive prompt)

Profiles removed (with default prefix):
  IKE Crypto:
    - {prefix}-ike-max
    - {prefix}-ike-rec
    - {prefix}-ike-compat

  IPSec Crypto:
    - {prefix}-ipsec-max
    - {prefix}-ipsec-rec
    - {prefix}-ipsec-compat
    - {prefix}-ipsec-gp

  TLS Service:
    - {prefix}-tls-max
    - {prefix}-tls-rec
    - {prefix}-tls-tls1.3

  Interface Management:
    - {prefix}-mgmt
    - {prefix}-https
    - {prefix}-mon

Usage:
    python3 fips-profile-cleanup.py -f <firewall_ip> -u <username> -p <password>

Options:
    --prefix     Profile name prefix (default: ca-ois-fips, or interactive prompt)
    --dry-run    Show what would be deleted without making changes
    --commit     Auto-commit changes after deletion (default: no commit)
"""

import argparse
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import List, Tuple, Set, Optional

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
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    WHITE = '\033[1;37m'
    NC = '\033[0m'  # No Color


# Default profile name prefix
DEFAULT_PREFIX = "ca-ois-fips"


def get_profile_names(prefix: str) -> dict:
    """Generate all profile names based on prefix (short names for 31 char limit)."""
    return {
        'ike': [
            f"{prefix}-ike-max",
            f"{prefix}-ike-rec",
            f"{prefix}-ike-compat",
        ],
        'ipsec': [
            f"{prefix}-ipsec-max",
            f"{prefix}-ipsec-rec",
            f"{prefix}-ipsec-compat",
            f"{prefix}-ipsec-gp",
        ],
        'ssl_tls': [
            f"{prefix}-tls-max",
            f"{prefix}-tls-rec",
            f"{prefix}-tls-tls1.3",
        ],
        'mgmt': [
            f"{prefix}-mgmt",
            f"{prefix}-https",
            f"{prefix}-mon",
        ]
    }


class FIPSProfileCleanup:
    """FIPS Profile Cleanup for PAN-OS"""

    def __init__(self, firewall: str, username: str, password: str,
                 name_prefix: str = None,
                 dry_run: bool = False, auto_commit: bool = False):
        self.firewall = firewall
        self.username = username
        self.password = password
        self.name_prefix = name_prefix or DEFAULT_PREFIX
        self.dry_run = dry_run
        self.auto_commit = auto_commit
        self.api_key = None
        self.base_url = f"https://{firewall}/api/"

        # Generate profile names based on prefix
        self.profiles = get_profile_names(self.name_prefix)

        # Counters by category
        self.stats = {
            'deleted': 0,
            'not_found': 0,
            'in_use': 0,
            'errors': 0,
        }

        # Track what uses each profile type
        self.ike_profiles_in_use: Set[str] = set()
        self.ipsec_profiles_in_use: Set[str] = set()
        self.ssl_tls_profiles_in_use: Set[str] = set()
        self.mgmt_profiles_in_use: Set[str] = set()

    def print_header(self, title: str):
        """Print a section header"""
        print(f"\n{Colors.BLUE}{'=' * 60}{Colors.NC}")
        print(f"{Colors.BLUE}{title}{Colors.NC}")
        print(f"{Colors.BLUE}{'=' * 60}{Colors.NC}")

    def print_subheader(self, title: str):
        """Print a subsection header"""
        print(f"\n{Colors.CYAN}--- {title} ---{Colors.NC}")

    def print_success(self, message: str):
        print(f"{Colors.GREEN}[DELETED]{Colors.NC} {message}")

    def print_error(self, message: str):
        print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")

    def print_warn(self, message: str):
        print(f"{Colors.YELLOW}[WARNING]{Colors.NC} {message}")

    def print_info(self, message: str):
        print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")

    def print_skip(self, message: str):
        print(f"{Colors.CYAN}[SKIP]{Colors.NC} {message}")

    def print_dry_run(self, message: str):
        print(f"{Colors.MAGENTA}[DRY-RUN]{Colors.NC} Would delete: {message}")

    def get_api_key(self) -> bool:
        """Authenticate and get API key"""
        try:
            response = requests.get(
                self.base_url,
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

    def api_get(self, xpath: str) -> Optional[ET.Element]:
        """Make a config get API call"""
        try:
            response = requests.post(
                self.base_url,
                data={
                    'type': 'config',
                    'action': 'get',
                    'xpath': xpath,
                    'key': self.api_key
                },
                verify=False,
                timeout=30
            )
            return ET.fromstring(response.text)
        except Exception:
            return None

    def api_delete(self, xpath: str) -> Tuple[bool, str]:
        """Make a config delete API call"""
        try:
            response = requests.post(
                self.base_url,
                data={
                    'type': 'config',
                    'action': 'delete',
                    'xpath': xpath,
                    'key': self.api_key
                },
                verify=False,
                timeout=30
            )

            root = ET.fromstring(response.text)
            if root.get('status') == 'success':
                return True, "Success"
            else:
                msg = root.find('.//msg')
                return False, msg.text if msg is not None else "Unknown error"
        except Exception as e:
            return False, str(e)

    def gather_profile_usage(self):
        """Gather information about which profiles are actively in use"""
        self.print_header("GATHERING PROFILE USAGE INFORMATION")

        # IKE Gateways -> IKE crypto profiles
        self.print_info("Checking IKE gateway configurations...")
        root = self.api_get("/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway")
        if root is not None:
            for gw in root.findall('.//entry'):
                gw_name = gw.get('name')
                ike_crypto = gw.find('.//ike-crypto-profile')
                if ike_crypto is not None and ike_crypto.text:
                    self.ike_profiles_in_use.add(ike_crypto.text)
                    self.print_info(f"  IKE Gateway '{gw_name}' uses: {ike_crypto.text}")

        # IPSec Tunnels -> IPSec crypto profiles
        self.print_info("Checking IPSec tunnel configurations...")
        root = self.api_get("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec")
        if root is not None:
            for tunnel in root.findall('.//entry'):
                tunnel_name = tunnel.get('name')
                ipsec_crypto = tunnel.find('.//ipsec-crypto-profile')
                if ipsec_crypto is not None and ipsec_crypto.text:
                    self.ipsec_profiles_in_use.add(ipsec_crypto.text)
                    self.print_info(f"  IPSec Tunnel '{tunnel_name}' uses: {ipsec_crypto.text}")

        # GlobalProtect Gateways -> IPSec and SSL/TLS profiles
        self.print_info("Checking GlobalProtect gateway configurations...")
        root = self.api_get("/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-gateway")
        if root is not None:
            for gw in root.findall('.//entry'):
                gw_name = gw.get('name')
                ipsec_crypto = gw.find('.//ipsec-crypto-profile')
                if ipsec_crypto is not None and ipsec_crypto.text:
                    self.ipsec_profiles_in_use.add(ipsec_crypto.text)
                    self.print_info(f"  GP Gateway '{gw_name}' uses IPSec: {ipsec_crypto.text}")
                ssl_profile = gw.find('.//ssl-tls-service-profile')
                if ssl_profile is not None and ssl_profile.text:
                    self.ssl_tls_profiles_in_use.add(ssl_profile.text)
                    self.print_info(f"  GP Gateway '{gw_name}' uses SSL/TLS: {ssl_profile.text}")

        # GlobalProtect Portals -> SSL/TLS profiles
        self.print_info("Checking GlobalProtect portal configurations...")
        root = self.api_get("/config/devices/entry[@name='localhost.localdomain']/network/global-protect/global-protect-portal")
        if root is not None:
            for portal in root.findall('.//entry'):
                portal_name = portal.get('name')
                ssl_profile = portal.find('.//ssl-tls-service-profile')
                if ssl_profile is not None and ssl_profile.text:
                    self.ssl_tls_profiles_in_use.add(ssl_profile.text)
                    self.print_info(f"  GP Portal '{portal_name}' uses SSL/TLS: {ssl_profile.text}")

        # Management interface -> SSL/TLS profile
        self.print_info("Checking management interface configuration...")
        root = self.api_get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system/ssl-tls-service-profile")
        if root is not None:
            ssl_profile = root.find('.//ssl-tls-service-profile')
            if ssl_profile is not None and ssl_profile.text:
                self.ssl_tls_profiles_in_use.add(ssl_profile.text)
                self.print_info(f"  Management interface uses SSL/TLS: {ssl_profile.text}")

        # Interfaces -> Management profiles
        self.print_info("Checking interface configurations...")
        for iface_type in ['ethernet', 'loopback', 'tunnel', 'vlan']:
            root = self.api_get(f"/config/devices/entry[@name='localhost.localdomain']/network/interface/{iface_type}")
            if root is not None:
                for iface in root.findall('.//entry'):
                    iface_name = iface.get('name')
                    mgmt_profile = iface.find('.//interface-management-profile')
                    if mgmt_profile is not None and mgmt_profile.text:
                        self.mgmt_profiles_in_use.add(mgmt_profile.text)
                        self.print_info(f"  Interface '{iface_name}' uses mgmt: {mgmt_profile.text}")

        # Summary
        print()
        self.print_info(f"IKE profiles in use: {len(self.ike_profiles_in_use)}")
        self.print_info(f"IPSec profiles in use: {len(self.ipsec_profiles_in_use)}")
        self.print_info(f"SSL/TLS profiles in use: {len(self.ssl_tls_profiles_in_use)}")
        self.print_info(f"Management profiles in use: {len(self.mgmt_profiles_in_use)}")

    def check_profile_exists(self, xpath: str) -> bool:
        """Check if a profile exists at the given xpath"""
        root = self.api_get(xpath)
        return root is not None and root.get('status') == 'success' and root.find('.//entry') is not None

    def delete_profile(self, profile_type: str, profile_name: str,
                       xpath_template: str, in_use_set: Set[str]) -> bool:
        """Delete a profile of the given type"""
        xpath = xpath_template.format(name=profile_name)
        profile_desc = f"{profile_type} '{profile_name}'"

        # Check if profile exists
        if not self.check_profile_exists(xpath):
            self.print_skip(f"{profile_desc} - not found")
            self.stats['not_found'] += 1
            return True

        # Check if profile is in use
        if profile_name in in_use_set:
            self.print_warn(f"{profile_desc} is IN USE - cannot delete")
            self.print_error(f"Remove from configurations first, then re-run cleanup")
            self.stats['in_use'] += 1
            return False

        # Dry run mode
        if self.dry_run:
            self.print_dry_run(profile_desc)
            self.stats['deleted'] += 1
            return True

        # Delete the profile
        success, msg = self.api_delete(xpath)
        if success:
            self.print_success(profile_desc)
            self.stats['deleted'] += 1
            return True
        else:
            self.print_error(f"Failed to delete {profile_desc}: {msg}")
            self.stats['errors'] += 1
            return False

    def delete_ike_profiles(self):
        """Delete all FIPS IKE crypto profiles"""
        self.print_subheader("IKE Crypto Profiles")
        xpath_template = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='{name}']"

        for profile in self.profiles['ike']:
            self.delete_profile("IKE crypto profile", profile,
                                xpath_template, self.ike_profiles_in_use)

    def delete_ipsec_profiles(self):
        """Delete all FIPS IPSec crypto profiles"""
        self.print_subheader("IPSec Crypto Profiles")
        xpath_template = "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='{name}']"

        for profile in self.profiles['ipsec']:
            self.delete_profile("IPSec crypto profile", profile,
                                xpath_template, self.ipsec_profiles_in_use)

    def delete_ssl_tls_profiles(self):
        """Delete all FIPS SSL/TLS service profiles"""
        self.print_subheader("SSL/TLS Service Profiles")
        xpath_template = "/config/shared/ssl-tls-service-profile/entry[@name='{name}']"

        for profile in self.profiles['ssl_tls']:
            self.delete_profile("SSL/TLS profile", profile,
                                xpath_template, self.ssl_tls_profiles_in_use)

    def delete_mgmt_profiles(self):
        """Delete all FIPS interface management profiles"""
        self.print_subheader("Interface Management Profiles")
        xpath_template = "/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile/entry[@name='{name}']"

        for profile in self.profiles['mgmt']:
            self.delete_profile("Management profile", profile,
                                xpath_template, self.mgmt_profiles_in_use)

    def commit(self) -> bool:
        """Commit changes to the firewall"""
        self.print_info("Committing changes...")
        try:
            response = requests.post(
                self.base_url,
                data={
                    'type': 'commit',
                    'cmd': '<commit></commit>',
                    'key': self.api_key
                },
                verify=False,
                timeout=120
            )

            root = ET.fromstring(response.text)
            if root.get('status') == 'success':
                job_id = root.find('.//job')
                if job_id is not None:
                    self.print_success(f"Commit initiated (Job ID: {job_id.text})")
                    return True
                self.print_success("Commit successful")
                return True
            else:
                msg = root.find('.//msg')
                error_msg = msg.text if msg is not None else "Unknown error"
                self.print_error(f"Commit failed: {error_msg}")
                return False
        except Exception as e:
            self.print_error(f"Commit failed: {e}")
            return False

    def run(self) -> int:
        """Run the cleanup"""
        self.print_header("FIPS PROFILE CLEANUP")
        print(f"Firewall: {self.firewall}")
        print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Profile prefix: {Colors.WHITE}{self.name_prefix}{Colors.NC}")
        if self.dry_run:
            print(f"{Colors.MAGENTA}Mode: DRY-RUN (no changes will be made){Colors.NC}")
        else:
            print(f"Mode: DELETE")

        # Show profiles to be removed
        total_profiles = sum(len(p) for p in self.profiles.values())
        print(f"\n{Colors.CYAN}Profiles to be removed ({total_profiles} total):{Colors.NC}")
        print(f"  IKE:     {', '.join(self.profiles['ike'])}")
        print(f"  IPSec:   {', '.join(self.profiles['ipsec'])}")
        print(f"  SSL/TLS: {', '.join(self.profiles['ssl_tls'])}")
        print(f"  Mgmt:    {', '.join(self.profiles['mgmt'])}")

        # Authenticate
        self.print_info("Authenticating to firewall...")
        if not self.get_api_key():
            self.print_error("Failed to authenticate to firewall")
            return 1
        print(f"{Colors.GREEN}[OK]{Colors.NC} Successfully authenticated")

        # Gather usage information first
        self.gather_profile_usage()

        # Delete profiles by category
        self.print_header("DELETING FIPS PROFILES")

        self.delete_ike_profiles()
        self.delete_ipsec_profiles()
        self.delete_ssl_tls_profiles()
        self.delete_mgmt_profiles()

        # Summary
        self.print_header("CLEANUP SUMMARY")
        print(f"\n{Colors.GREEN}Deleted:{Colors.NC}     {self.stats['deleted']}")
        print(f"{Colors.CYAN}Not found:{Colors.NC}   {self.stats['not_found']}")
        print(f"{Colors.YELLOW}In use:{Colors.NC}      {self.stats['in_use']}")
        print(f"{Colors.RED}Errors:{Colors.NC}      {self.stats['errors']}")

        # Commit if requested and changes were made
        if not self.dry_run and self.stats['deleted'] > 0:
            if self.auto_commit:
                print()
                self.commit()
            else:
                print(f"\n{Colors.YELLOW}Changes are staged but NOT committed.{Colors.NC}")
                print("Run with --commit to auto-commit, or commit manually:")
                print(f"  ssh admin@{self.firewall} 'commit'")

        # Final status
        if self.dry_run:
            print(f"\n{Colors.MAGENTA}Dry-run complete. No changes were made.{Colors.NC}")
            print("Run without --dry-run to delete profiles.")
        elif self.stats['errors'] > 0 or self.stats['in_use'] > 0:
            print(f"\n{Colors.YELLOW}Cleanup completed with issues.{Colors.NC}")
            if self.stats['in_use'] > 0:
                print(f"\n{Colors.YELLOW}To remove profiles that are in use:{Colors.NC}")
                print("  1. Remove the profile reference from the configuration")
                print("  2. Commit the change")
                print("  3. Re-run this cleanup script")
            return 1
        else:
            print(f"\n{Colors.GREEN}Cleanup completed successfully.{Colors.NC}")

        return 0


def main():
    parser = argparse.ArgumentParser(
        description='FIPS Profile Cleanup for PAN-OS',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Profile Naming:
  Profiles are named with a prefix followed by the profile type.
  Default prefix: {DEFAULT_PREFIX}

  Example profiles with default prefix:
    - {DEFAULT_PREFIX}-ike-crypto-max
    - {DEFAULT_PREFIX}-ipsec-crypto-recommended
    - {DEFAULT_PREFIX}-ssl-tls-max
    - {DEFAULT_PREFIX}-mgmt-profile

  Total: 13 profiles (3 IKE + 4 IPSec + 3 SSL/TLS + 3 Mgmt)

Examples:
  # Dry-run with default prefix
  python3 fips-profile-cleanup.py -f 10.0.0.1 -u admin -p password --dry-run

  # Delete profiles with custom prefix
  python3 fips-profile-cleanup.py -f 10.0.0.1 -u admin -p password --prefix my-fips

  # Delete and auto-commit
  python3 fips-profile-cleanup.py -f 10.0.0.1 -u admin -p password --commit
"""
    )
    parser.add_argument('-f', '--firewall', required=True,
                        help='Firewall IP address or hostname')
    parser.add_argument('-u', '--username', required=True,
                        help='Admin username')
    parser.add_argument('-p', '--password', required=True,
                        help='Admin password')
    parser.add_argument('--prefix', default=None,
                        help=f'Profile name prefix (default: {DEFAULT_PREFIX})')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be deleted without making changes')
    parser.add_argument('--commit', action='store_true',
                        help='Auto-commit changes after deletion')

    args = parser.parse_args()

    # If prefix not provided via CLI, ask interactively
    name_prefix = args.prefix
    if not name_prefix:
        print(f"\n{Colors.CYAN}Profile Naming:{Colors.NC}")
        print(f"Enter the profile name prefix used when profiles were created.")
        print(f"Default: {Colors.WHITE}{DEFAULT_PREFIX}{Colors.NC}")
        try:
            user_input = input(f"\nProfile name prefix [{DEFAULT_PREFIX}]: ").strip()
            name_prefix = user_input if user_input else DEFAULT_PREFIX
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            sys.exit(0)

    cleanup = FIPSProfileCleanup(
        args.firewall,
        args.username,
        args.password,
        name_prefix=name_prefix,
        dry_run=args.dry_run,
        auto_commit=args.commit
    )

    return cleanup.run()


if __name__ == '__main__':
    sys.exit(main())
