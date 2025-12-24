#!/usr/bin/env python3
"""
FIPS 140-3 Compliance Toolkit for Palo Alto Networks

A production-ready interactive toolkit for achieving FIPS 140-3 cryptographic
compliance on PAN-OS firewalls and Strata Cloud Manager (SCM) tenants.

This toolkit enables you to:
  - AUDIT existing configurations for FIPS 140-3 compliance
  - CONFIGURE FIPS-compliant cryptographic profiles
  - GENERATE compliance reports for audit purposes
  - DEPLOY pre-configured compliant profiles via SCM API

Usage:
    python3 fips-toolkit.py              # Interactive mode (recommended)
    python3 fips-toolkit.py --help       # Show all options
    python3 fips-toolkit.py audit        # Run audit mode directly
    python3 fips-toolkit.py configure    # Run configure mode directly

Author: FIPS 140-3 Toolkit Project
License: MIT
"""

import os
import sys
import json
import getpass
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

# Version
__version__ = "1.2.1"

# Debug mode - set to True to see detailed API responses
DEBUG = os.environ.get('FIPS_TOOLKIT_DEBUG', '').lower() in ('1', 'true', 'yes')

# Configuration file location
CONFIG_DIR = Path.home() / ".fips-toolkit"
CONFIG_FILE = CONFIG_DIR / "config.json"

# Environment variable names
ENV_VARS = {
    'scm': {
        'client_id': 'SCM_CLIENT_ID',
        'client_secret': 'SCM_CLIENT_SECRET',
        'tsg_id': 'SCM_TSG_ID'
    },
    'firewall': {
        'host': 'PANOS_HOST',
        'username': 'PANOS_USERNAME',
        'password': 'PANOS_PASSWORD'
    }
}


def load_dotenv():
    """Load environment variables from .env file if present."""
    # Check multiple locations for .env file
    env_paths = [
        Path.cwd() / '.env',
        Path(__file__).parent / '.env',
        CONFIG_DIR / '.env',
        Path.home() / '.env'
    ]

    for env_path in env_paths:
        if env_path.exists():
            try:
                with open(env_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if not line or line.startswith('#'):
                            continue
                        # Parse KEY=VALUE
                        if '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip().strip('"').strip("'")
                            # Only set if not already in environment
                            if key and key not in os.environ:
                                os.environ[key] = value
                return env_path
            except Exception:
                pass
    return None


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    CYAN = '\033[0;36m'
    WHITE = '\033[1;37m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color


def print_debug(message: str):
    """Print debug message if DEBUG mode is enabled."""
    if DEBUG:
        print(f"{Colors.MAGENTA}[DEBUG]{Colors.NC} {message}")


def extract_panos_error(response_text: str) -> str:
    """Extract error message from PAN-OS API XML response.

    PAN-OS can return errors in various formats:
    - <response><msg>Error message</msg></response>
    - <response><msg><line>Error line 1</line><line>Error line 2</line></msg></response>
    - <response><result><msg>Error</msg></result></response>
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(response_text)

        # Log the full response in debug mode
        print_debug(f"API Response: {response_text[:500]}...")

        # Check status
        status = root.get('status', 'unknown')
        if status == 'success':
            return 'success'

        # Try various error message locations
        error_parts = []

        # Check for <msg><line> structure (multiple lines)
        msg_elem = root.find('.//msg')
        if msg_elem is not None:
            lines = msg_elem.findall('line')
            if lines:
                for line in lines:
                    if line.text:
                        error_parts.append(line.text.strip())
            elif msg_elem.text:
                error_parts.append(msg_elem.text.strip())

        # Check for <result><msg> structure
        if not error_parts:
            result_msg = root.find('.//result/msg')
            if result_msg is not None and result_msg.text:
                error_parts.append(result_msg.text.strip())

        # Check for direct error text in response
        if not error_parts:
            result = root.find('.//result')
            if result is not None and result.text:
                error_parts.append(result.text.strip())

        if error_parts:
            return '; '.join(error_parts)

        # If we still don't have an error, return the status with truncated response
        return f"API error (status={status}): {response_text[:200]}"

    except ET.ParseError as e:
        print_debug(f"XML Parse error: {e}")
        return f"Invalid XML response: {response_text[:200]}"
    except Exception as e:
        print_debug(f"Error extracting message: {e}")
        return f"Error parsing response: {str(e)}"


def clear_screen():
    """Clear terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')


DISCLAIMER = f"""
{Colors.YELLOW}{'─' * 70}{Colors.NC}
{Colors.YELLOW}DISCLAIMER{Colors.NC}
{Colors.WHITE}This is an independent, open-source tool and is NOT affiliated with,
endorsed by, or supported by Palo Alto Networks, Inc.{Colors.NC}

{Colors.WHITE}USE AT YOUR OWN RISK. This software is provided "AS IS" without warranty
of any kind. The authors assume no liability for any damages arising from
the use of this tool. Always validate configurations in a test environment
before deploying to production systems.{Colors.NC}

{Colors.WHITE}By using this tool, you acknowledge that you understand and accept
these terms.{Colors.NC}
{Colors.YELLOW}{'─' * 70}{Colors.NC}
"""


def print_banner(show_disclaimer: bool = True):
    """Print the toolkit banner."""
    banner = f"""
{Colors.CYAN}{'=' * 70}{Colors.NC}
{Colors.BOLD}{Colors.WHITE}    FIPS 140-3 Compliance Toolkit for Palo Alto Networks{Colors.NC}
{Colors.CYAN}{'=' * 70}{Colors.NC}
{Colors.YELLOW}    Version: {__version__}{Colors.NC}
{Colors.BLUE}    Achieve FIPS 140-3 cryptographic compliance without CC-mode{Colors.NC}
{Colors.CYAN}{'=' * 70}{Colors.NC}
"""
    print(banner)
    if show_disclaimer:
        print(DISCLAIMER)


def print_section(title: str):
    """Print a section header."""
    print(f"\n{Colors.BLUE}{'─' * 70}{Colors.NC}")
    print(f"{Colors.BOLD}{Colors.WHITE}  {title}{Colors.NC}")
    print(f"{Colors.BLUE}{'─' * 70}{Colors.NC}")


def print_success(message: str):
    """Print success message."""
    print(f"{Colors.GREEN}[OK]{Colors.NC} {message}")


def print_error(message: str):
    """Print error message."""
    print(f"{Colors.RED}[ERROR]{Colors.NC} {message}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[WARN]{Colors.NC} {message}")


def print_info(message: str):
    """Print info message."""
    print(f"{Colors.BLUE}[INFO]{Colors.NC} {message}")


def get_secret_input(prompt: str) -> str:
    """Get secret input with asterisk feedback."""
    import sys
    import tty
    import termios

    print(prompt, end='', flush=True)

    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)

    try:
        tty.setraw(fd)
        password = []
        while True:
            char = sys.stdin.read(1)
            if char in ('\r', '\n'):  # Enter pressed
                print()  # New line
                break
            elif char == '\x7f' or char == '\x08':  # Backspace
                if password:
                    password.pop()
                    # Move cursor back, print space, move back again
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            elif char == '\x03':  # Ctrl+C
                print()
                raise KeyboardInterrupt
            elif char == '\x16':  # Ctrl+V (paste) - just continue reading
                continue
            elif ord(char) >= 32:  # Printable character
                password.append(char)
                sys.stdout.write('*')
                sys.stdout.flush()
        return ''.join(password)
    except Exception:
        # Fallback to standard getpass if terminal tricks fail
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        print()  # Clear the line
        return getpass.getpass(prompt)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)


def get_input(prompt: str, default: str = None, required: bool = True,
              secret: bool = False) -> str:
    """Get user input with optional default value."""
    if default:
        display_prompt = f"{prompt} [{default}]: "
    else:
        display_prompt = f"{prompt}: "

    while True:
        if secret:
            try:
                value = get_secret_input(display_prompt)
            except Exception:
                # Fallback for non-Unix systems or errors
                value = getpass.getpass(display_prompt)
        else:
            value = input(display_prompt).strip()

        if not value and default:
            return default
        elif not value and required:
            print_error("This field is required. Please enter a value.")
        else:
            return value


def get_choice(prompt: str, options: List[str], default: int = 1) -> int:
    """Get user choice from numbered options."""
    print(f"\n{prompt}")
    for i, option in enumerate(options, 1):
        marker = f"{Colors.CYAN}>{Colors.NC}" if i == default else " "
        print(f"  {marker} [{i}] {option}")

    while True:
        try:
            choice = input(f"\nEnter choice (1-{len(options)}) [{default}]: ").strip()
            if not choice:
                return default
            choice_int = int(choice)
            if 1 <= choice_int <= len(options):
                return choice_int
            print_error(f"Please enter a number between 1 and {len(options)}")
        except ValueError:
            print_error("Please enter a valid number")


def confirm(prompt: str, default: bool = True) -> bool:
    """Get yes/no confirmation."""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in ['y', 'yes']:
            return True
        if response in ['n', 'no']:
            return False
        print_error("Please enter 'y' or 'n'")


class ConfigManager:
    """Manage toolkit configuration."""

    def __init__(self):
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from file."""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def save_config(self):
        """Save configuration to file."""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(self.config, f, indent=2)
        # Set restrictive permissions
        CONFIG_FILE.chmod(0o600)

    def _get_env_scm(self) -> Dict[str, str]:
        """Get SCM credentials from environment variables."""
        return {
            'client_id': os.environ.get(ENV_VARS['scm']['client_id'], ''),
            'client_secret': os.environ.get(ENV_VARS['scm']['client_secret'], ''),
            'tsg_id': os.environ.get(ENV_VARS['scm']['tsg_id'], '')
        }

    def _get_env_firewall(self) -> Dict[str, str]:
        """Get firewall credentials from environment variables."""
        return {
            'host': os.environ.get(ENV_VARS['firewall']['host'], ''),
            'username': os.environ.get(ENV_VARS['firewall']['username'], ''),
            'password': os.environ.get(ENV_VARS['firewall']['password'], '')
        }

    def has_scm_credentials(self) -> bool:
        """Check if SCM credentials are configured (config file or env vars)."""
        # Check config file first
        scm = self.config.get('scm', {})
        if all([scm.get('client_id'), scm.get('client_secret'), scm.get('tsg_id')]):
            return True
        # Check environment variables
        env_scm = self._get_env_scm()
        return all([env_scm.get('client_id'), env_scm.get('client_secret'), env_scm.get('tsg_id')])

    def has_firewall_credentials(self) -> bool:
        """Check if firewall credentials are configured (config file or env vars)."""
        # Check config file first
        fw = self.config.get('firewall', {})
        if all([fw.get('host'), fw.get('username'), fw.get('password')]):
            return True
        # Check environment variables
        env_fw = self._get_env_firewall()
        return all([env_fw.get('host'), env_fw.get('username'), env_fw.get('password')])

    def get_scm_credentials(self) -> Dict[str, str]:
        """Get SCM credentials (config file takes precedence over env vars)."""
        scm = self.config.get('scm', {})
        if all([scm.get('client_id'), scm.get('client_secret'), scm.get('tsg_id')]):
            return scm
        # Fall back to environment variables
        return self._get_env_scm()

    def get_firewall_credentials(self) -> Dict[str, str]:
        """Get firewall credentials (config file takes precedence over env vars)."""
        fw = self.config.get('firewall', {})
        if all([fw.get('host'), fw.get('username'), fw.get('password')]):
            return fw
        # Fall back to environment variables
        return self._get_env_firewall()

    def get_credential_source(self, cred_type: str) -> str:
        """Get the source of credentials (config, env, or none)."""
        if cred_type == 'scm':
            scm = self.config.get('scm', {})
            if all([scm.get('client_id'), scm.get('client_secret'), scm.get('tsg_id')]):
                return 'config'
            env_scm = self._get_env_scm()
            if all([env_scm.get('client_id'), env_scm.get('client_secret'), env_scm.get('tsg_id')]):
                return 'env'
        elif cred_type == 'firewall':
            fw = self.config.get('firewall', {})
            if all([fw.get('host'), fw.get('username'), fw.get('password')]):
                return 'config'
            env_fw = self._get_env_firewall()
            if all([env_fw.get('host'), env_fw.get('username'), env_fw.get('password')]):
                return 'env'
        return 'none'

    def set_scm_credentials(self, client_id: str, client_secret: str,
                            tsg_id: str):
        """Set SCM credentials."""
        self.config['scm'] = {
            'client_id': client_id,
            'client_secret': client_secret,
            'tsg_id': tsg_id
        }
        self.save_config()

    def set_firewall_credentials(self, host: str, username: str,
                                  password: str):
        """Set firewall credentials."""
        self.config['firewall'] = {
            'host': host,
            'username': username,
            'password': password
        }
        self.save_config()

    def clear_credentials(self):
        """Clear all credentials."""
        self.config = {}
        if CONFIG_FILE.exists():
            CONFIG_FILE.unlink()


class SetupWizard:
    """Interactive setup wizard for first-time configuration."""

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager

    def run(self):
        """Run the setup wizard."""
        clear_screen()
        print_banner()

        print_section("Welcome to the FIPS 140-3 Toolkit Setup")

        print(f"""
{Colors.WHITE}This toolkit helps you achieve FIPS 140-3 cryptographic compliance
on Palo Alto Networks firewalls and Strata Cloud Manager tenants.{Colors.NC}

{Colors.YELLOW}What is FIPS 140-3?{Colors.NC}
FIPS 140-3 is a U.S. government standard that defines requirements for
cryptographic modules. Compliance ensures you're using approved algorithms:
  - AES-128/256-CBC/GCM for encryption
  - SHA-256/384/512 for hashing
  - DH Groups 14, 16, 19-21 for key exchange
  - TLS 1.2 or 1.3 for secure communications

{Colors.YELLOW}What this toolkit does:{Colors.NC}
  - Audits your current configurations for compliance
  - Deploys pre-configured FIPS-compliant profiles
  - Generates compliance reports for auditors
  - Works with both on-premises firewalls and SCM

{Colors.CYAN}Let's configure your environment.{Colors.NC}
""")

        if not confirm("Ready to continue with setup?"):
            print("\nSetup cancelled. Run again when ready.")
            sys.exit(0)

        self._setup_target_type()

    def _setup_target_type(self):
        """Determine target type (SCM or Firewall)."""
        print_section("Target Configuration")

        print(f"""
{Colors.WHITE}This toolkit supports two deployment methods:{Colors.NC}

  {Colors.CYAN}[1] Strata Cloud Manager (SCM){Colors.NC}
      - Manage firewalls via cloud API
      - Deploy profiles to multiple devices
      - Best for Prisma Access, Cloud NGFW, or SCM-managed NGFWs

  {Colors.CYAN}[2] Direct Firewall Access{Colors.NC}
      - Connect directly to a firewall
      - Validate configurations via XML API
      - Best for standalone or Panorama-managed firewalls

  {Colors.CYAN}[3] Both{Colors.NC}
      - Configure credentials for both methods
""")

        choice = get_choice("Select your target type:", [
            "Strata Cloud Manager (SCM)",
            "Direct Firewall Access",
            "Both (SCM and Firewall)"
        ])

        if choice == 1:
            self._setup_scm()
        elif choice == 2:
            self._setup_firewall()
        else:
            self._setup_scm()
            self._setup_firewall()

        self._setup_complete()

    def _setup_scm(self):
        """Configure SCM credentials."""
        print_section("Strata Cloud Manager Configuration")

        print(f"""
{Colors.WHITE}To use SCM, you need a service account with API access.{Colors.NC}

{Colors.YELLOW}Detailed setup guide:{Colors.NC} docs/SCM-CREDENTIAL-SETUP.md

{Colors.YELLOW}Quick steps to create a service account:{Colors.NC}
  1. Log in to Strata Cloud Manager
  2. Go to Settings > Identity & Access > Access Management
  3. Click "Add" and select Identity Type: Service Account
  4. Save the Client ID and Client Secret (shown only once!)
  5. Assign a role based on your needs:

{Colors.CYAN}Role Recommendations (Principle of Least Privilege):{Colors.NC}

  {Colors.GREEN}For AUDIT ONLY (recommended for most users):{Colors.NC}
  Assign: {Colors.BOLD}Auditor{Colors.NC}
  - Read-only access to all configurations
  - Cannot modify or create profiles
  - Cannot push changes

  {Colors.YELLOW}For CONFIGURE operations (deploy FIPS profiles):{Colors.NC}
  Assign: {Colors.BOLD}Security Administrator{Colors.NC}
  - Read/write access to security policies
  - Can create IKE, IPSec, and TLS profiles
  - Can push configuration changes

  {Colors.RED}For INTERFACE MANAGEMENT PROFILES:{Colors.NC}
  Also assign: {Colors.BOLD}Network Admin{Colors.NC}
  - Required in addition to Security Admin
  - Without this role, you'll get 403 Forbidden errors
  - Alternative: Deploy via CLI to firewall (most users have superuser there)

{Colors.CYAN}Enter your SCM credentials below:{Colors.NC}
""")

        # Check for environment variables first
        env_client_id = os.environ.get('SCM_CLIENT_ID', '')
        env_client_secret = os.environ.get('SCM_CLIENT_SECRET', '')
        env_tsg_id = os.environ.get('SCM_TSG_ID', '')

        if env_client_id and env_client_secret and env_tsg_id:
            print_info("Found credentials in environment variables")
            if confirm("Use environment variable credentials?"):
                self.config.set_scm_credentials(
                    env_client_id, env_client_secret, env_tsg_id
                )
                print_success("SCM credentials configured from environment")
                return

        client_id = get_input(
            "Client ID (e.g., name@tenant.iam.panserviceaccount.com)",
            default=env_client_id if env_client_id else None
        )

        client_secret = get_input(
            "Client Secret",
            secret=True
        )

        tsg_id = get_input(
            "TSG ID (numeric)",
            default=env_tsg_id if env_tsg_id else None
        )

        self.config.set_scm_credentials(client_id, client_secret, tsg_id)
        print_success("SCM credentials saved")

        # Test connection
        if confirm("Test SCM connection now?"):
            self._test_scm_connection()

    def _test_scm_connection(self):
        """Test SCM connection."""
        print_info("Testing SCM connection...")

        try:
            # Import here to avoid issues if dependencies not installed
            sys.path.insert(0, os.path.join(
                os.path.dirname(__file__),
                '09-scm-api-toolkit', '06-python-sdk'
            ))
            from scm_client import SCMClient

            creds = self.config.get_scm_credentials()
            client = SCMClient(
                client_id=creds['client_id'],
                client_secret=creds['client_secret'],
                tsg_id=creds['tsg_id']
            )

            # Try to list profiles as a connection test
            _ = client.token  # This triggers authentication
            print_success("SCM connection successful!")

        except ImportError:
            print_error("Missing dependencies. Run: pip install requests")
        except Exception as e:
            print_error(f"Connection failed: {e}")
            if confirm("Would you like to re-enter credentials?"):
                self._setup_scm()

    def _setup_firewall(self):
        """Configure firewall credentials."""
        print_section("Firewall Configuration")

        print(f"""
{Colors.WHITE}Enter credentials for direct firewall access.{Colors.NC}

{Colors.YELLOW}Requirements:{Colors.NC}
  - PAN-OS 10.1 or later (10.2+ recommended)
  - Admin user with API access
  - Network connectivity to management interface

{Colors.CYAN}Enter your firewall credentials below:{Colors.NC}
""")

        host = get_input("Firewall IP or hostname")
        username = get_input("Admin username")
        password = get_input("Admin password", secret=True)

        self.config.set_firewall_credentials(host, username, password)
        print_success("Firewall credentials saved")

        if confirm("Test firewall connection now?"):
            self._test_firewall_connection()

    def _test_firewall_connection(self):
        """Test firewall connection."""
        print_info("Testing firewall connection...")

        try:
            import requests
            requests.packages.urllib3.disable_warnings()

            creds = self.config.get_firewall_credentials()
            response = requests.get(
                f"https://{creds['host']}/api/",
                params={
                    'type': 'keygen',
                    'user': creds['username'],
                    'password': creds['password']
                },
                verify=False,
                timeout=30
            )

            if '<key>' in response.text:
                print_success("Firewall connection successful!")
            else:
                print_error("Authentication failed - check credentials")
                if confirm("Would you like to re-enter credentials?"):
                    self._setup_firewall()

        except ImportError:
            print_error("Missing dependencies. Run: pip install requests")
        except Exception as e:
            print_error(f"Connection failed: {e}")
            if confirm("Would you like to re-enter credentials?"):
                self._setup_firewall()

    def _setup_complete(self):
        """Complete setup."""
        print_section("Setup Complete")

        print(f"""
{Colors.GREEN}Configuration saved to: {CONFIG_FILE}{Colors.NC}

{Colors.WHITE}You can now use the toolkit in the following modes:{Colors.NC}

  {Colors.CYAN}[1] Audit Mode{Colors.NC}
      Scan and validate existing configurations for FIPS compliance

  {Colors.CYAN}[2] Configure Mode{Colors.NC}
      Deploy FIPS-compliant cryptographic profiles

  {Colors.CYAN}[3] Report Mode{Colors.NC}
      Generate detailed compliance reports

{Colors.YELLOW}Quick start:{Colors.NC}
  python3 fips-toolkit.py          # Interactive menu
  python3 fips-toolkit.py audit    # Run audit directly

{Colors.YELLOW}To reconfigure:{Colors.NC}
  python3 fips-toolkit.py setup    # Re-run setup wizard
  python3 fips-toolkit.py clear    # Clear saved credentials
""")

        if confirm("Continue to main menu?"):
            return True
        else:
            print("\nGoodbye!")
            sys.exit(0)


class AuditMode:
    """FIPS 140-3 Compliance Audit Mode."""

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager

    def run(self):
        """Run audit mode."""
        print_section("FIPS 140-3 Compliance Audit")

        if self.config.has_scm_credentials() and self.config.has_firewall_credentials():
            choice = get_choice("Select audit target:", [
                "Strata Cloud Manager (SCM)",
                "Direct Firewall",
                "Both"
            ])

            if choice == 1:
                self._audit_scm()
            elif choice == 2:
                self._audit_firewall()
            else:
                self._audit_scm()
                self._audit_firewall()
        elif self.config.has_scm_credentials():
            self._audit_scm()
        elif self.config.has_firewall_credentials():
            self._audit_firewall()
        else:
            print_error("No credentials configured. Run setup first.")
            return

    def _audit_scm(self):
        """Audit SCM profiles."""
        print_section("Auditing Strata Cloud Manager")

        try:
            sys.path.insert(0, os.path.join(
                os.path.dirname(__file__),
                '09-scm-api-toolkit', '06-python-sdk'
            ))
            from scm_client import SCMClient
            from fips_profiles import (
                validate_ike_profile, validate_ipsec_profile,
                validate_tls_profile, validate_mgmt_profile
            )

            creds = self.config.get_scm_credentials()
            client = SCMClient(
                client_id=creds['client_id'],
                client_secret=creds['client_secret'],
                tsg_id=creds['tsg_id']
            )

            folder = get_input("Configuration folder", default="Shared")

            print_info(f"Scanning profiles in folder: {folder}")
            print()

            pass_count = 0
            fail_count = 0

            # Audit IKE profiles
            print(f"\n{Colors.BOLD}IKE Crypto Profiles:{Colors.NC}")
            ike_profiles = client.list_ike_crypto_profiles(folder=folder)
            for profile in ike_profiles:
                name = profile.get("name", "Unknown")
                findings = validate_ike_profile(profile)
                if findings:
                    print(f"  {Colors.RED}[FAIL]{Colors.NC} {name}")
                    for f in findings:
                        print(f"         - {f}")
                    fail_count += 1
                else:
                    print(f"  {Colors.GREEN}[PASS]{Colors.NC} {name}")
                    pass_count += 1

            if not ike_profiles:
                print_info("  No IKE profiles found")

            # Audit IPSec profiles
            print(f"\n{Colors.BOLD}IPSec Crypto Profiles:{Colors.NC}")
            ipsec_profiles = client.list_ipsec_crypto_profiles(folder=folder)
            for profile in ipsec_profiles:
                name = profile.get("name", "Unknown")
                findings = validate_ipsec_profile(profile)
                if findings:
                    print(f"  {Colors.RED}[FAIL]{Colors.NC} {name}")
                    for f in findings:
                        print(f"         - {f}")
                    fail_count += 1
                else:
                    print(f"  {Colors.GREEN}[PASS]{Colors.NC} {name}")
                    pass_count += 1

            if not ipsec_profiles:
                print_info("  No IPSec profiles found")

            # Audit TLS profiles
            print(f"\n{Colors.BOLD}TLS Service Profiles:{Colors.NC}")
            tls_profiles = client.list_tls_service_profiles(folder=folder)
            for profile in tls_profiles:
                name = profile.get("name", "Unknown")
                findings = validate_tls_profile(profile)
                if findings:
                    print(f"  {Colors.RED}[FAIL]{Colors.NC} {name}")
                    for f in findings:
                        print(f"         - {f}")
                    fail_count += 1
                else:
                    print(f"  {Colors.GREEN}[PASS]{Colors.NC} {name}")
                    pass_count += 1

            if not tls_profiles:
                print_info("  No TLS profiles found")

            # Audit management profiles
            print(f"\n{Colors.BOLD}Interface Management Profiles:{Colors.NC}")
            try:
                mgmt_profiles = client.list_interface_mgmt_profiles(folder=folder)
                for profile in mgmt_profiles:
                    name = profile.get("name", "Unknown")
                    findings = validate_mgmt_profile(profile)
                    if findings:
                        print(f"  {Colors.RED}[FAIL]{Colors.NC} {name}")
                        for f in findings:
                            print(f"         - {f}")
                        fail_count += 1
                    else:
                        print(f"  {Colors.GREEN}[PASS]{Colors.NC} {name}")
                        pass_count += 1

                if not mgmt_profiles:
                    print_info("  No management profiles found")
            except Exception as e:
                if "403" in str(e):
                    print_warning("  Requires Network Admin role in SCM (403 Forbidden)")
                    print_info("  Use 'Audit > Firewall (CLI)' to audit interface management profiles")
                else:
                    print_error(f"  Failed to list profiles: {e}")

            # Summary
            print_section("SCM Audit Summary")
            print(f"  {Colors.GREEN}PASSED:{Colors.NC}  {pass_count}")
            print(f"  {Colors.RED}FAILED:{Colors.NC}  {fail_count}")

            if fail_count == 0:
                print(f"\n  {Colors.GREEN}FIPS 140-3 COMPLIANCE: PASSED{Colors.NC}")
            else:
                print(f"\n  {Colors.RED}FIPS 140-3 COMPLIANCE: FAILED{Colors.NC}")
                print(f"\n  {fail_count} non-compliant profile(s) require remediation.")

        except ImportError as e:
            print_error(f"Missing dependencies: {e}")
            print_info("Run: pip install requests")
        except Exception as e:
            print_error(f"Audit failed: {e}")

    def _audit_firewall(self):
        """Audit firewall directly."""
        print_section("Auditing Firewall")

        try:
            # Use the existing validator
            sys.path.insert(0, os.path.join(
                os.path.dirname(__file__), '08-validation-tools'
            ))

            creds = self.config.get_firewall_credentials()

            print_info(f"Connecting to: {creds['host']}")

            # Import and run validator
            from importlib.util import spec_from_file_location, module_from_spec
            spec = spec_from_file_location(
                "validator",
                os.path.join(os.path.dirname(__file__),
                            '08-validation-tools',
                            'fips-compliance-validator.py')
            )
            validator_module = module_from_spec(spec)
            spec.loader.exec_module(validator_module)

            validator = validator_module.FIPSComplianceValidator(
                creds['host'],
                creds['username'],
                creds['password']
            )

            result = validator.run()
            return result

        except ImportError as e:
            print_error(f"Missing dependencies: {e}")
        except Exception as e:
            print_error(f"Audit failed: {e}")


class ConfigureMode:
    """FIPS 140-3 Profile Configuration Mode."""

    # Default profile name prefix
    DEFAULT_PREFIX = "ca-ois-fips"

    # FIPS-compliant profile configurations
    FIPS_PROFILES = {
        "max": {
            "ike": {
                "encryption": ["aes-256-gcm"],
                "hash": ["sha512"],
                "dh_group": ["group20"],
                "lifetime": {"hours": 8}
            },
            "ipsec": {
                "esp_encryption": ["aes-256-gcm"],
                "esp_authentication": ["sha512"],
                "dh_group": "group20",
                "lifetime": {"hours": 1}
            }
        },
        "recommended": {
            "ike": {
                "encryption": ["aes-256-cbc", "aes-128-gcm"],
                "hash": ["sha384", "sha256"],
                "dh_group": ["group20", "group19"],
                "lifetime": {"hours": 8}
            },
            "ipsec": {
                "esp_encryption": ["aes-256-gcm", "aes-128-gcm"],
                "esp_authentication": ["sha384", "sha256"],
                "dh_group": "group20",
                "lifetime": {"hours": 1}
            }
        },
        "compat": {
            "ike": {
                "encryption": ["aes-256-cbc", "aes-256-gcm", "aes-128-cbc", "aes-128-gcm"],
                "hash": ["sha512", "sha384", "sha256"],
                "dh_group": ["group20", "group19", "group16", "group14"],
                "lifetime": {"hours": 8}
            },
            "ipsec": {
                "esp_encryption": ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
                "esp_authentication": ["sha512", "sha384", "sha256"],
                "dh_group": "group14",
                "lifetime": {"hours": 1}
            }
        }
    }

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.deployment_target = None  # 'scm' or 'firewall'

    def run(self):
        """Run configure mode."""
        print_section("FIPS 140-3 Profile Configuration")

        has_scm = self.config.has_scm_credentials()
        has_fw = self.config.has_firewall_credentials()

        # Check what credentials are available
        if not has_scm and not has_fw:
            print_error("No credentials configured.")
            if confirm("Configure credentials now?"):
                self._setup_credentials()
                has_scm = self.config.has_scm_credentials()
                has_fw = self.config.has_firewall_credentials()
            else:
                return

        # Determine deployment target
        if has_scm and has_fw:
            print(f"""
{Colors.CYAN}Deployment Target:{Colors.NC}
You have both SCM and Firewall credentials configured.
""")
            target_choice = get_choice("Where do you want to deploy profiles?", [
                "Strata Cloud Manager (deploy to SCM, push to devices)",
                "Direct to Firewall (deploy via XML API)"
            ])
            self.deployment_target = 'scm' if target_choice == 1 else 'firewall'
        elif has_scm:
            self.deployment_target = 'scm'
        else:
            self.deployment_target = 'firewall'

        target_name = "Strata Cloud Manager" if self.deployment_target == 'scm' else "Firewall"
        print(f"\n{Colors.GREEN}Deployment target:{Colors.NC} {target_name}")

        print(f"""
{Colors.WHITE}This mode deploys FIPS 140-3 compliant cryptographic profiles.{Colors.NC}

{Colors.YELLOW}Profile Tiers:{Colors.NC}
  {Colors.CYAN}[max]{Colors.NC}         - Highest security (AES-256-GCM, SHA-512, Group 20)
  {Colors.CYAN}[recommended]{Colors.NC} - Balanced security and compatibility
  {Colors.CYAN}[compat]{Colors.NC}      - Maximum compatibility with FIPS algorithms

{Colors.YELLOW}Profile Types:{Colors.NC}
  - IKE Crypto Profiles (Phase 1 VPN)
  - IPSec Crypto Profiles (Phase 2 VPN)
  - TLS Service Profiles (HTTPS/GlobalProtect)
  - Interface Management Profiles
""")

        choice = get_choice("Select configuration action:", [
            "Deploy all FIPS profiles (recommended tier)",
            "Deploy all FIPS profiles (max security tier)",
            "Deploy all FIPS profiles (compatibility tier)",
            "Deploy specific profile type",
            "View current profiles"
        ])

        if choice == 1:
            self._deploy_all("recommended")
        elif choice == 2:
            self._deploy_all("max")
        elif choice == 3:
            self._deploy_all("compat")
        elif choice == 4:
            self._deploy_specific()
        elif choice == 5:
            self._list_profiles()

    def _setup_credentials(self):
        """Quick credential setup."""
        choice = get_choice("Select credential type to configure:", [
            "Strata Cloud Manager (SCM)",
            "Direct Firewall Access"
        ])

        if choice == 1:
            print_section("SCM Credentials")
            client_id = get_input("Client ID")
            client_secret = get_input("Client Secret", secret=True)
            tsg_id = get_input("TSG ID")
            self.config.set_scm_credentials(client_id, client_secret, tsg_id)
            print_success("SCM credentials saved")
        else:
            print_section("Firewall Credentials")
            host = get_input("Firewall IP or hostname")
            username = get_input("Admin username")
            password = get_input("Admin password", secret=True)
            self.config.set_firewall_credentials(host, username, password)
            print_success("Firewall credentials saved")

    def _get_client(self):
        """Get SCM client."""
        sys.path.insert(0, os.path.join(
            os.path.dirname(__file__),
            '09-scm-api-toolkit', '06-python-sdk'
        ))
        from scm_client import SCMClient

        creds = self.config.get_scm_credentials()
        return SCMClient(
            client_id=creds['client_id'],
            client_secret=creds['client_secret'],
            tsg_id=creds['tsg_id']
        )

    def _select_certificate(self, client, folder: str) -> str:
        """
        List available certificates and let user select one for TLS profiles.

        Args:
            client: SCM client instance
            folder: Configuration folder

        Returns:
            Selected certificate name, or None if skipped
        """
        try:
            print_info("Fetching available certificates...")
            certs = client.list_certificates(folder)

            if not certs:
                print_warning("No certificates found in folder")
                manual = get_input("Enter certificate name manually (or press Enter to skip)", required=False)
                return manual if manual else None

            print(f"\n{Colors.CYAN}Available Certificates:{Colors.NC}")
            for i, cert in enumerate(certs, 1):
                cert_name = cert.get('name', 'unnamed')
                print(f"  {Colors.CYAN}[{i}]{Colors.NC} {cert_name}")

            # Add option to skip or enter manually
            print(f"  {Colors.CYAN}[{len(certs) + 1}]{Colors.NC} Enter manually")
            print(f"  {Colors.CYAN}[0]{Colors.NC} Skip TLS profile")

            while True:
                try:
                    choice_str = input(f"\nSelect certificate [1-{len(certs) + 1}, 0 to skip]: ").strip()
                    if not choice_str:
                        choice = 1  # Default to first certificate
                    else:
                        choice = int(choice_str)

                    if choice == 0:
                        return None
                    elif 1 <= choice <= len(certs):
                        selected = certs[choice - 1].get('name')
                        print_success(f"Selected: {selected}")
                        return selected
                    elif choice == len(certs) + 1:
                        manual = get_input("Enter certificate name")
                        return manual if manual else None
                    else:
                        print_error(f"Please enter a number between 0 and {len(certs) + 1}")
                except ValueError:
                    print_error("Please enter a valid number")

        except Exception as e:
            print_warning(f"Could not list certificates: {e}")
            manual = get_input("Enter certificate name manually (or press Enter to skip)", required=False)
            return manual if manual else None

    def _deploy_all(self, tier: str):
        """Deploy all FIPS profiles."""
        print_section(f"Deploying FIPS Profiles ({tier} tier)")

        # Ask for profile name prefix
        print(f"""
{Colors.CYAN}Profile Naming:{Colors.NC}
Profiles will be created with a name prefix followed by the profile type.
Example: {Colors.WHITE}ca-ois-fips{Colors.NC}-ike-rec
""")
        name_prefix = get_input("Profile name prefix", default=self.DEFAULT_PREFIX)

        # Map tier to short name
        tier_short = {"max": "max", "recommended": "rec", "compat": "compat"}.get(tier, tier)

        # Show what will be created
        print(f"""
{Colors.CYAN}Profiles to be created:{Colors.NC}
  - {name_prefix}-ike-{tier_short}
  - {name_prefix}-ipsec-{tier_short}
  - {name_prefix}-tls-{tier_short}
  - {name_prefix}-mgmt
""")

        # Route to appropriate deployment method
        if self.deployment_target == 'scm':
            self._deploy_all_scm(tier, name_prefix)
        else:
            self._deploy_all_firewall(tier, name_prefix)

    def _deploy_all_scm(self, tier: str, name_prefix: str):
        """Deploy all FIPS profiles via SCM."""
        # Map tier to short name for display
        tier_short = {"max": "max", "recommended": "rec", "compat": "compat"}.get(tier, tier)
        folder = get_input("Target folder", default="Shared")

        if not confirm(f"Deploy profiles to SCM folder '{folder}'?"):
            print("Deployment cancelled.")
            return

        try:
            client = self._get_client()

            created = 0
            skipped = 0
            errors = 0

            # Deploy IKE profile
            print_info(f"Creating IKE crypto profile...")
            try:
                client.create_fips_ike_profile(tier=tier, folder=folder, name_prefix=name_prefix)
                print_success(f"Created {name_prefix}-ike-{tier_short}")
                created += 1
            except Exception as e:
                if "409" in str(e) or "exists" in str(e).lower():
                    print_warning(f"{name_prefix}-ike-{tier_short} already exists")
                    skipped += 1
                else:
                    print_error(f"Failed: {e}")
                    errors += 1

            # Deploy IPSec profile
            print_info(f"Creating IPSec crypto profile...")
            try:
                client.create_fips_ipsec_profile(tier=tier, folder=folder, name_prefix=name_prefix)
                print_success(f"Created {name_prefix}-ipsec-{tier_short}")
                created += 1
            except Exception as e:
                if "409" in str(e) or "exists" in str(e).lower():
                    print_warning(f"{name_prefix}-ipsec-{tier_short} already exists")
                    skipped += 1
                else:
                    print_error(f"Failed: {e}")
                    errors += 1

            # Deploy TLS profile (needs certificate selection)
            print_info(f"Creating TLS service profile...")
            print(f"\n{Colors.CYAN}TLS Profile Configuration:{Colors.NC}")
            print("TLS profiles require a certificate. Select from available certificates:")
            cert_name = self._select_certificate(client, folder)
            if cert_name:
                try:
                    client.create_fips_tls_profile(tier=tier,
                                                    certificate=cert_name,
                                                    folder=folder,
                                                    name_prefix=name_prefix)
                    print_success(f"Created {name_prefix}-tls-{tier_short}")
                    created += 1
                except Exception as e:
                    if "409" in str(e) or "exists" in str(e).lower():
                        print_warning(f"{name_prefix}-tls-{tier_short} already exists")
                        skipped += 1
                    else:
                        print_error(f"Failed: {e}")
                        errors += 1
            else:
                print_info("Skipped TLS profile (no certificate)")
                skipped += 1

            # Deploy management profile
            print_info(f"Creating interface management profile...")
            try:
                client.create_fips_mgmt_profile(folder=folder, name_prefix=name_prefix)
                print_success(f"Created {name_prefix}-mgmt")
                created += 1
            except Exception as e:
                if "409" in str(e) or "exists" in str(e).lower():
                    print_warning(f"{name_prefix}-mgmt already exists")
                    skipped += 1
                elif "403" in str(e):
                    # Permission issue - offer CLI fallback
                    print_warning("SCM API returned 403 Forbidden for interface management profile")
                    print_info("This requires Network Admin or Superuser role in SCM.")
                    if self.config.has_firewall_credentials():
                        if confirm("Deploy interface management profile via CLI (direct to firewall) instead?"):
                            mgmt_result = self._deploy_mgmt_via_cli(name_prefix)
                            if mgmt_result == 'created':
                                print_success(f"Created {name_prefix}-mgmt via CLI")
                                created += 1
                            elif mgmt_result == 'exists':
                                print_warning(f"{name_prefix}-mgmt already exists on firewall")
                                skipped += 1
                            else:
                                print_error(f"CLI deployment failed: {mgmt_result}")
                                errors += 1
                        else:
                            print_info("Skipped interface management profile")
                            skipped += 1
                    else:
                        print_info("Configure firewall credentials to use CLI fallback")
                        skipped += 1
                else:
                    print_error(f"Failed: {e}")
                    errors += 1

            # Summary
            print_section("Deployment Summary")
            print(f"  {Colors.GREEN}Created:{Colors.NC}  {created}")
            print(f"  {Colors.YELLOW}Skipped:{Colors.NC}  {skipped}")
            print(f"  {Colors.RED}Errors:{Colors.NC}   {errors}")

            if created > 0 and confirm("\nPush configuration to devices?"):
                try:
                    print_info("Pushing configuration...")
                    job = client.push_config(
                        folders=[folder],
                        description=f"FIPS 140-3 {tier} profile deployment"
                    )
                    print_success(f"Configuration push initiated (Job: {job.get('job_id', 'N/A')})")
                except Exception as e:
                    print_error(f"Push failed: {e}")

        except Exception as e:
            print_error(f"Deployment failed: {e}")

    def _deploy_all_firewall(self, tier: str, name_prefix: str):
        """Deploy all FIPS profiles directly to firewall via XML API."""
        # Map tier to short name for display
        tier_short = {"max": "max", "recommended": "rec", "compat": "compat"}.get(tier, tier)
        creds = self.config.get_firewall_credentials()

        if not confirm(f"Deploy profiles to firewall {creds['host']}?"):
            print("Deployment cancelled.")
            return

        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            import xml.etree.ElementTree as ET

            base_url = f"https://{creds['host']}/api/"

            # Authenticate
            print_info(f"Connecting to {creds['host']}...")
            response = requests.get(
                base_url,
                params={
                    'type': 'keygen',
                    'user': creds['username'],
                    'password': creds['password']
                },
                verify=False,
                timeout=30
            )

            root = ET.fromstring(response.text)
            if root.get('status') != 'success':
                print_error("Failed to authenticate to firewall")
                return

            api_key = root.find('.//key').text
            print_success("Connected to firewall")

            created = 0
            skipped = 0
            errors = 0

            profile_config = self.FIPS_PROFILES[tier]

            # Deploy IKE crypto profile
            print_info("Creating IKE crypto profile...")
            ike_name = f"{name_prefix}-ike-{tier_short}"
            ike_result = self._create_ike_profile_firewall(
                base_url, api_key, ike_name, profile_config['ike']
            )
            if ike_result == 'created':
                print_success(f"Created {ike_name}")
                created += 1
            elif ike_result == 'exists':
                print_warning(f"{ike_name} already exists")
                skipped += 1
            else:
                print_error(f"Failed to create {ike_name}: {ike_result}")
                errors += 1

            # Deploy IPSec crypto profile
            print_info("Creating IPSec crypto profile...")
            ipsec_name = f"{name_prefix}-ipsec-{tier_short}"
            ipsec_result = self._create_ipsec_profile_firewall(
                base_url, api_key, ipsec_name, profile_config['ipsec']
            )
            if ipsec_result == 'created':
                print_success(f"Created {ipsec_name}")
                created += 1
            elif ipsec_result == 'exists':
                print_warning(f"{ipsec_name} already exists")
                skipped += 1
            else:
                print_error(f"Failed to create {ipsec_name}: {ipsec_result}")
                errors += 1

            # Deploy management profile
            print_info("Creating interface management profile...")
            mgmt_name = f"{name_prefix}-mgmt"
            mgmt_result = self._create_mgmt_profile_firewall(base_url, api_key, mgmt_name)
            if mgmt_result == 'created':
                print_success(f"Created {mgmt_name}")
                created += 1
            elif mgmt_result == 'exists':
                print_warning(f"{mgmt_name} already exists")
                skipped += 1
            else:
                print_error(f"Failed to create {mgmt_name}: {mgmt_result}")
                errors += 1

            # Summary
            print_section("Deployment Summary")
            print(f"  {Colors.GREEN}Created:{Colors.NC}  {created}")
            print(f"  {Colors.YELLOW}Skipped:{Colors.NC}  {skipped}")
            print(f"  {Colors.RED}Errors:{Colors.NC}   {errors}")

            # Note: TLS profiles require certificate which may not exist
            print(f"\n{Colors.YELLOW}Note:{Colors.NC} SSL/TLS profiles require a certificate to be configured.")
            print("Use the specific profile deployment option to create TLS profiles.")

            if created > 0 and confirm("\nCommit changes to firewall?"):
                print_info("Committing changes...")
                commit_response = requests.post(
                    base_url,
                    data={
                        'type': 'commit',
                        'cmd': '<commit></commit>',
                        'key': api_key
                    },
                    verify=False,
                    timeout=120
                )
                commit_root = ET.fromstring(commit_response.text)
                if commit_root.get('status') == 'success':
                    job_id = commit_root.find('.//job')
                    if job_id is not None:
                        print_success(f"Commit initiated (Job ID: {job_id.text})")
                    else:
                        print_success("Commit successful")
                else:
                    print_error("Commit failed")

        except ImportError:
            print_error("Missing dependency: requests")
            print_info("Run: pip install requests")
        except Exception as e:
            print_error(f"Deployment failed: {e}")

    def _create_ike_profile_firewall(self, base_url: str, api_key: str,
                                      name: str, config: dict) -> str:
        """Create IKE crypto profile on firewall."""
        import requests
        import xml.etree.ElementTree as ET

        xpath = f"/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='{name}']"

        print_debug(f"Creating IKE profile: {name}")
        print_debug(f"Config: {config}")

        # Check if exists
        check = requests.post(base_url, data={
            'type': 'config', 'action': 'get', 'xpath': xpath, 'key': api_key
        }, verify=False, timeout=30)
        if ET.fromstring(check.text).find('.//entry') is not None:
            return 'exists'

        # Build XML element
        encryption = ''.join(f'<member>{e}</member>' for e in config['encryption'])
        hash_alg = ''.join(f'<member>{h}</member>' for h in config['hash'])
        dh_group = ''.join(f'<member>{g}</member>' for g in config['dh_group'])

        element = f"""
        <entry name="{name}">
            <encryption>{encryption}</encryption>
            <hash>{hash_alg}</hash>
            <dh-group>{dh_group}</dh-group>
            <lifetime><hours>{config['lifetime']['hours']}</hours></lifetime>
        </entry>
        """

        print_debug(f"XML Element: {element}")

        response = requests.post(base_url, data={
            'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': api_key
        }, verify=False, timeout=30)

        result = extract_panos_error(response.text)
        if result == 'success':
            return 'created'
        else:
            return result

    def _create_ipsec_profile_firewall(self, base_url: str, api_key: str,
                                        name: str, config: dict) -> str:
        """Create IPSec crypto profile on firewall."""
        import requests
        import xml.etree.ElementTree as ET

        xpath = f"/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='{name}']"

        print_debug(f"Creating IPSec profile: {name}")
        print_debug(f"Config: {config}")

        # Check if exists
        check = requests.post(base_url, data={
            'type': 'config', 'action': 'get', 'xpath': xpath, 'key': api_key
        }, verify=False, timeout=30)
        if ET.fromstring(check.text).find('.//entry') is not None:
            return 'exists'

        # Build XML element
        encryption = ''.join(f'<member>{e}</member>' for e in config['esp_encryption'])
        authentication = ''.join(f'<member>{a}</member>' for a in config['esp_authentication'])

        element = f"""
        <entry name="{name}">
            <esp>
                <encryption>{encryption}</encryption>
                <authentication>{authentication}</authentication>
            </esp>
            <dh-group>{config['dh_group']}</dh-group>
            <lifetime><hours>{config['lifetime']['hours']}</hours></lifetime>
        </entry>
        """

        print_debug(f"XML Element: {element}")

        response = requests.post(base_url, data={
            'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': api_key
        }, verify=False, timeout=30)

        result = extract_panos_error(response.text)
        if result == 'success':
            return 'created'
        else:
            return result

    def _create_mgmt_profile_firewall(self, base_url: str, api_key: str, name: str) -> str:
        """Create interface management profile on firewall."""
        import requests
        import xml.etree.ElementTree as ET

        xpath = f"/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile/entry[@name='{name}']"

        print_debug(f"Creating management profile: {name}")

        # Check if exists
        check = requests.post(base_url, data={
            'type': 'config', 'action': 'get', 'xpath': xpath, 'key': api_key
        }, verify=False, timeout=30)
        if ET.fromstring(check.text).find('.//entry') is not None:
            return 'exists'

        # FIPS-compliant management profile (HTTPS and SSH only, no HTTP/Telnet)
        element = f"""
        <entry name="{name}">
            <https>yes</https>
            <ssh>yes</ssh>
            <ping>yes</ping>
        </entry>
        """

        print_debug(f"XML Element: {element}")

        response = requests.post(base_url, data={
            'type': 'config', 'action': 'set', 'xpath': xpath, 'element': element, 'key': api_key
        }, verify=False, timeout=30)

        result = extract_panos_error(response.text)
        if result == 'success':
            return 'created'
        else:
            return result

    def _deploy_mgmt_via_cli(self, name_prefix: str) -> str:
        """Deploy interface management profile via CLI when SCM returns 403.

        This is used as a fallback when the SCM service account lacks
        Network Admin role (required for interface management profiles).
        Most users have superuser access on the firewall itself.
        """
        import requests
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        import xml.etree.ElementTree as ET

        creds = self.config.get_firewall_credentials()
        base_url = f"https://{creds['host']}/api/"

        # Authenticate to get API key
        try:
            response = requests.get(
                base_url,
                params={
                    'type': 'keygen',
                    'user': creds['username'],
                    'password': creds['password']
                },
                verify=False,
                timeout=30
            )
            root = ET.fromstring(response.text)
            if root.get('status') != 'success':
                return 'Authentication failed'
            api_key = root.find('.//key').text
        except Exception as e:
            return f'Connection failed: {e}'

        # Use existing method to create the profile
        mgmt_name = f"{name_prefix}-mgmt"
        return self._create_mgmt_profile_firewall(base_url, api_key, mgmt_name)

    def _deploy_specific(self):
        """Deploy specific profile type."""
        choice = get_choice("Select profile type:", [
            "IKE Crypto Profile",
            "IPSec Crypto Profile",
            "TLS Service Profile",
            "Interface Management Profile"
        ])

        tier_choice = get_choice("Select tier:", [
            "max (highest security)",
            "recommended (balanced)",
            "compat (compatibility)"
        ])

        tier_map = {1: "max", 2: "recommended", 3: "compat"}
        tier = tier_map[tier_choice]
        tier_short = {"max": "max", "recommended": "rec", "compat": "compat"}.get(tier, tier)

        name_prefix = get_input("Profile name prefix", default="ca-ois-fips")
        folder = get_input("Target folder", default="Shared")

        try:
            client = self._get_client()

            if choice == 1:
                client.create_fips_ike_profile(tier=tier, folder=folder, name_prefix=name_prefix)
                print_success(f"Created {name_prefix}-ike-{tier_short}")
            elif choice == 2:
                client.create_fips_ipsec_profile(tier=tier, folder=folder, name_prefix=name_prefix)
                print_success(f"Created {name_prefix}-ipsec-{tier_short}")
            elif choice == 3:
                print(f"\n{Colors.CYAN}TLS Profile Configuration:{Colors.NC}")
                print("TLS profiles require a certificate. Select from available certificates:")
                cert = self._select_certificate(client, folder)
                if cert:
                    client.create_fips_tls_profile(tier=tier, certificate=cert,
                                                    folder=folder, name_prefix=name_prefix)
                    print_success(f"Created {name_prefix}-tls-{tier_short}")
                else:
                    print_info("Skipped TLS profile (no certificate selected)")
            elif choice == 4:
                client.create_fips_mgmt_profile(folder=folder, name_prefix=name_prefix)
                print_success(f"Created {name_prefix}-mgmt")

        except Exception as e:
            print_error(f"Failed: {e}")

    def _list_profiles(self):
        """List current profiles."""
        print_section("Current Profiles")

        folder = get_input("Folder to list", default="Shared")

        try:
            client = self._get_client()

            print(f"\n{Colors.BOLD}IKE Crypto Profiles:{Colors.NC}")
            for p in client.list_ike_crypto_profiles(folder=folder):
                print(f"  - {p.get('name')}")

            print(f"\n{Colors.BOLD}IPSec Crypto Profiles:{Colors.NC}")
            for p in client.list_ipsec_crypto_profiles(folder=folder):
                print(f"  - {p.get('name')}")

            print(f"\n{Colors.BOLD}TLS Service Profiles:{Colors.NC}")
            for p in client.list_tls_service_profiles(folder=folder):
                print(f"  - {p.get('name')}")

            print(f"\n{Colors.BOLD}Interface Management Profiles:{Colors.NC}")
            for p in client.list_interface_mgmt_profiles(folder=folder):
                print(f"  - {p.get('name')}")

        except Exception as e:
            print_error(f"Failed: {e}")


class ReportMode:
    """Compliance Report Generation Mode."""

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        # Default to user's Downloads folder
        self.default_dir = Path.home() / "Downloads"

    def _get_default_filename(self, report_type: str) -> Path:
        """Generate default filename with timestamp."""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"fips-compliance-{report_type}-{timestamp}.txt"
        return self.default_dir / filename

    def _save_report(self, content: str, output_file: Path):
        """Save report to file and show location."""
        # Ensure parent directory exists
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            f.write(content)

        print()
        print_success(f"Report saved successfully!")
        print(f"\n{Colors.CYAN}Report location:{Colors.NC}")
        print(f"  {Colors.WHITE}{output_file.absolute()}{Colors.NC}")
        print(f"\n{Colors.YELLOW}To open:{Colors.NC}")
        if sys.platform == 'darwin':
            print(f"  open \"{output_file.absolute()}\"")
        elif sys.platform == 'win32':
            print(f"  start \"{output_file.absolute()}\"")
        else:
            print(f"  cat \"{output_file.absolute()}\"")

    def run(self):
        """Run report mode."""
        print_section("Compliance Report Generation")

        print(f"""
{Colors.WHITE}Generate FIPS 140-3 compliance reports.{Colors.NC}

{Colors.YELLOW}Default save location:{Colors.NC} {self.default_dir}

{Colors.YELLOW}Report Types:{Colors.NC}
  [1] Executive Report  - Management summary (1-2 pages)
  [2] Summary Report    - Pass/fail overview with counts
  [3] Detailed Report   - Full technical audit with findings
  [4] Audit Log         - Complete output with timestamps
  [5] Complete Package  - All reports + infographic in one folder
  [6] Infographic Only  - Visual executive summary (SVG)
""")

        choice = get_choice("Select report type:", [
            "Executive Report (for management)",
            "Summary Report",
            "Detailed Report",
            "Audit Log",
            "Complete Report Package (all reports + infographic)",
            "Infographic Only (SVG visual summary)"
        ])

        # Handle complete package separately
        if choice == 5:
            self._generate_complete_package()
            return

        # Handle infographic separately
        if choice == 6:
            self._generate_standalone_infographic()
            return

        # Determine report type name for filename
        type_names = {1: "executive", 2: "summary", 3: "detailed", 4: "audit-log"}
        default_file = self._get_default_filename(type_names[choice])

        print(f"\n{Colors.CYAN}Default filename:{Colors.NC} {default_file.name}")
        custom_path = get_input(
            "Output file (Enter for default, or specify path)",
            required=False
        )

        if custom_path:
            output_file = Path(custom_path).expanduser()
            # If user just gave a filename, put it in Downloads
            if not output_file.is_absolute() and '/' not in custom_path:
                output_file = self.default_dir / custom_path
        else:
            output_file = default_file

        if choice == 1:
            self._generate_executive(output_file)
        elif choice == 2:
            self._generate_summary(output_file)
        elif choice == 3:
            self._generate_detailed(output_file)
        elif choice == 4:
            self._generate_audit_log(output_file)

    def _strip_ansi(self, text: str) -> str:
        """Remove ANSI color codes from text."""
        import re
        ansi_pattern = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_pattern.sub('', text)

    def _generate_executive(self, output_file: Path):
        """Generate executive summary report for management."""
        import io
        from contextlib import redirect_stdout

        print_info("Running compliance audit...")

        # Capture audit output
        captured = io.StringIO()
        with redirect_stdout(captured):
            if self.config.has_scm_credentials():
                self._run_scm_audit_captured()
            if self.config.has_firewall_credentials():
                self._run_firewall_audit_captured()

        audit_output = captured.getvalue()

        # Count results
        pass_count = audit_output.count('[PASS]')
        fail_count = audit_output.count('[FAIL]')
        high_risk_count = audit_output.count('[HIGH RISK]')
        warn_count = audit_output.count('[WARN]')
        total_scanned = pass_count + fail_count

        # Determine overall status
        if fail_count > 0:
            status = "FAILED"
            status_desc = "Non-compliant configurations are actively in use"
        elif high_risk_count > 0:
            status = "PASSED WITH RISK"
            status_desc = "Compliant, but unused non-compliant profiles exist"
        elif total_scanned == 0:
            status = "NO DATA"
            status_desc = "No profiles were found to scan"
        else:
            status = "PASSED"
            status_desc = "All configurations are FIPS 140-3 compliant"

        # Get target info
        target_info = []
        if self.config.has_scm_credentials():
            scm_creds = self.config.get_scm_credentials()
            target_info.append(f"Strata Cloud Manager (TSG: {scm_creds.get('tsg_id', 'N/A')})")
        if self.config.has_firewall_credentials():
            fw_creds = self.config.get_firewall_credentials()
            target_info.append(f"Firewall: {fw_creds.get('host', 'N/A')}")

        # Build executive report
        r = []
        r.append("=" * 70)
        r.append("FIPS 140-3 COMPLIANCE - EXECUTIVE SUMMARY")
        r.append("=" * 70)
        r.append("")
        r.append(f"Report Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        r.append(f"Target System:  {', '.join(target_info) if target_info else 'Not configured'}")
        r.append("")
        r.append("-" * 70)
        r.append("COMPLIANCE STATUS")
        r.append("-" * 70)
        r.append("")
        r.append(f"    {'*' * 50}")
        r.append(f"    *  OVERALL STATUS: {status:^32} *")
        r.append(f"    {'*' * 50}")
        r.append("")
        r.append(f"    {status_desc}")
        r.append("")
        r.append("-" * 70)
        r.append("SUMMARY METRICS")
        r.append("-" * 70)
        r.append("")
        r.append(f"    Profiles Scanned:        {total_scanned:>5}")
        r.append(f"    Compliant (PASSED):      {pass_count:>5}  {'[OK]' if pass_count > 0 else ''}")
        r.append(f"    Non-Compliant (FAILED):  {fail_count:>5}  {'[ACTION REQUIRED]' if fail_count > 0 else ''}")
        r.append(f"    High Risk (unused):      {high_risk_count:>5}  {'[CLEANUP RECOMMENDED]' if high_risk_count > 0 else ''}")
        r.append(f"    Warnings:                {warn_count:>5}")
        r.append("")

        if fail_count > 0:
            r.append("-" * 70)
            r.append("IMMEDIATE ACTIONS REQUIRED")
            r.append("-" * 70)
            r.append("")
            r.append(f"    {fail_count} configuration(s) are using non-compliant cryptographic")
            r.append("    algorithms and must be remediated to achieve compliance.")
            r.append("")
            r.append("    Recommended Actions:")
            r.append("    1. Review the Detailed Report for specific findings")
            r.append("    2. Replace non-compliant algorithms with FIPS-approved alternatives")
            r.append("    3. Test changes in a non-production environment")
            r.append("    4. Deploy and re-run compliance validation")
            r.append("")

        if high_risk_count > 0:
            r.append("-" * 70)
            r.append("RISK ITEMS (Cleanup Recommended)")
            r.append("-" * 70)
            r.append("")
            r.append(f"    {high_risk_count} non-compliant profile(s) exist but are not currently in use.")
            r.append("    While not an immediate security risk, these should be removed to")
            r.append("    prevent accidental use in future configurations.")
            r.append("")

        if status == "PASSED":
            r.append("-" * 70)
            r.append("COMPLIANCE ATTESTATION")
            r.append("-" * 70)
            r.append("")
            r.append("    This system has been validated for FIPS 140-3 cryptographic")
            r.append("    compliance. All active configurations use approved algorithms:")
            r.append("")
            r.append("    Validated Areas:")
            r.append("      [OK] IKE Phase 1 (IKEv2) Cryptography")
            r.append("      [OK] IPSec Phase 2 Cryptography")
            r.append("      [OK] SSL/TLS Service Profiles")
            r.append("      [OK] Interface Management Profiles")
            r.append("")
            r.append("    Compliant Algorithms Verified:")
            r.append("      - Encryption: AES-128/256-CBC, AES-128/256-GCM")
            r.append("      - Hash: SHA-256, SHA-384, SHA-512")
            r.append("      - Key Exchange: DH Groups 14, 16, 19, 20, 21")
            r.append("      - TLS: 1.2 and 1.3 only")
            r.append("")

        r.append("-" * 70)
        r.append("ABOUT THIS REPORT")
        r.append("-" * 70)
        r.append("")
        r.append("    This report was generated by the FIPS 140-3 Compliance Toolkit,")
        r.append("    an independent open-source tool. This tool is NOT affiliated with")
        r.append("    or endorsed by Palo Alto Networks, Inc.")
        r.append("")
        r.append("    For detailed technical findings, generate a Detailed Report.")
        r.append("")
        r.append("=" * 70)
        r.append("END OF EXECUTIVE SUMMARY")
        r.append("=" * 70)

        report = "\n".join(r)
        self._save_report(report, output_file)

    def _generate_summary(self, output_file: Path):
        """Generate summary report."""
        import io
        from contextlib import redirect_stdout

        print_info("Running compliance audit...")

        # Capture audit output
        captured = io.StringIO()
        with redirect_stdout(captured):
            if self.config.has_scm_credentials():
                self._run_scm_audit_captured()
            if self.config.has_firewall_credentials():
                self._run_firewall_audit_captured()

        audit_output = captured.getvalue()

        # Count results from output
        pass_count = audit_output.count('[PASS]')
        fail_count = audit_output.count('[FAIL]')
        warn_count = audit_output.count('[WARN]')
        error_count = audit_output.count('[ERROR]')
        no_profiles = audit_output.count('No ') + audit_output.count('not found')
        total_scanned = pass_count + fail_count

        # Build report
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("FIPS 140-3 COMPLIANCE SUMMARY REPORT")
        report_lines.append("=" * 70)
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("")

        # Show what was scanned
        report_lines.append("SCAN TARGETS:")
        if self.config.has_scm_credentials():
            scm_creds = self.config.get_scm_credentials()
            report_lines.append(f"  SCM TSG ID: {scm_creds.get('tsg_id', 'N/A')}")
        if self.config.has_firewall_credentials():
            fw_creds = self.config.get_firewall_credentials()
            report_lines.append(f"  Firewall:   {fw_creds.get('host', 'N/A')}")
        report_lines.append("")

        report_lines.append("RESULTS:")
        report_lines.append(f"  Profiles Scanned: {total_scanned}")
        report_lines.append(f"  PASSED:   {pass_count}")
        report_lines.append(f"  FAILED:   {fail_count}")
        report_lines.append(f"  WARNINGS: {warn_count}")
        if error_count > 0:
            report_lines.append(f"  ERRORS:   {error_count}")
        report_lines.append("")

        if error_count > 0:
            report_lines.append("OVERALL STATUS: ERROR")
            report_lines.append("")
            report_lines.append("Errors occurred during the audit. Check credentials and connectivity.")
            report_lines.append("Run a detailed report for error messages.")
        elif total_scanned == 0:
            report_lines.append("OVERALL STATUS: NO PROFILES FOUND")
            report_lines.append("")
            report_lines.append("No cryptographic profiles were found to scan.")
            report_lines.append("This could mean:")
            report_lines.append("  - The 'Shared' folder contains no profiles")
            report_lines.append("  - Profiles exist in a different folder")
            report_lines.append("  - The service account lacks read permissions")
            report_lines.append("")
            report_lines.append("Try running the Audit mode interactively to specify a folder.")
        elif fail_count == 0:
            report_lines.append("OVERALL STATUS: PASSED")
            report_lines.append("")
            report_lines.append(f"All {pass_count} scanned profile(s) use FIPS 140-3 compliant algorithms.")
        else:
            report_lines.append("OVERALL STATUS: FAILED")
            report_lines.append("")
            report_lines.append(f"{fail_count} of {total_scanned} profile(s) contain non-compliant algorithms.")
            report_lines.append("Run a detailed report for specific findings.")

        report_lines.append("")
        report_lines.append("=" * 70)
        report_lines.append("Generated by FIPS 140-3 Compliance Toolkit")
        report_lines.append("=" * 70)

        report = "\n".join(report_lines)
        self._save_report(report, output_file)

    def _generate_detailed(self, output_file: Path):
        """Generate detailed report matching the comprehensive template."""
        print_info("Running comprehensive audit...")

        # Collect all findings
        findings = {
            'pass': 0,
            'fail': 0,
            'high_risk': 0,
            'warn': 0,
            'critical_items': [],
            'high_risk_items': [],
            'warning_items': [],
            'ike_profiles': [],
            'ipsec_profiles': [],
            'tls_profiles': [],
            'mgmt_profiles': [],
            'certificates': [],
            'profile_usage': {
                'ike': {},
                'ipsec': {},
                'tls': {},
                'mgmt': {}
            }
        }

        r = []
        r.append("=" * 60)
        r.append("FIPS 140-3 COMPLIANCE VALIDATION")
        r.append("=" * 60)

        # Run appropriate audit based on configured credentials
        if self.config.has_firewall_credentials():
            self._run_detailed_firewall_audit(r, findings)
        elif self.config.has_scm_credentials():
            self._run_detailed_scm_audit(r, findings)
        else:
            r.append("[ERROR] No credentials configured")
            self._save_report("\n".join(r), output_file)
            return

        # Add compliance summary
        r.append("")
        r.append("=" * 60)
        r.append("COMPLIANCE SUMMARY")
        r.append("=" * 60)
        r.append("")
        r.append(f"PASSED:      {findings['pass']}")
        r.append(f"FAILED:      {findings['fail']}   (Non-compliant AND in use)")
        r.append(f"HIGH RISK:   {findings['high_risk']}   (Non-compliant but NOT in use)")
        r.append(f"WARNINGS:    {findings['warn']}")
        r.append("")

        # Overall status
        r.append("=" * 50)
        if findings['fail'] > 0:
            r.append("  FIPS 140-3 COMPLIANCE: FAILED")
            r.append("=" * 50)
            r.append("")
            r.append(f"{findings['fail']} non-compliant configuration(s) actively in use.")
            r.append("Review the [FAIL] items above and remediate immediately.")
            if findings['high_risk'] > 0:
                r.append("")
                r.append(f"Additionally, {findings['high_risk']} unused non-compliant profile(s)")
                r.append("should be removed or updated.")
        elif findings['high_risk'] > 0:
            r.append("  FIPS 140-3 COMPLIANCE: PASSED WITH HIGH RISK")
            r.append("=" * 50)
            r.append("")
            r.append("No active non-compliant configurations, but")
            r.append(f"{findings['high_risk']} unused non-compliant profile(s) exist.")
            r.append("")
            r.append("Recommendation: Remove or update unused non-compliant profiles")
            r.append("to prevent accidental use in future configurations.")
        else:
            r.append("  FIPS 140-3 COMPLIANCE: PASSED")
            r.append("=" * 50)
            r.append("")
            r.append("All cryptographic configurations are FIPS 140-3 compliant.")
            r.append("No non-compliant profiles found in the configuration.")

        r.append("")
        r.append(f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        if self.config.has_firewall_credentials():
            fw = self.config.get_firewall_credentials()
            r.append(f"Firewall: {fw.get('host', 'N/A')}")

        # Detailed findings breakdown
        if findings['critical_items']:
            r.append("")
            r.append("=" * 60)
            r.append("DETAILED FINDINGS BREAKDOWN")
            r.append("=" * 60)
            r.append("")
            r.append("CRITICAL - Non-Compliant Settings IN USE (Immediate Action Required):")
            r.append("-" * 60)
            for i, item in enumerate(findings['critical_items'], 1):
                r.append(f"{i}. {item['name']}")
                if item.get('used_by'):
                    r.append(f"   Used by: {item['used_by']}")
                for issue in item.get('issues', []):
                    r.append(f"   - {issue}")
                r.append("")

        if findings['high_risk_items']:
            r.append("")
            r.append("HIGH RISK - Non-Compliant Settings NOT in Use (Cleanup Recommended):")
            r.append("-" * 60)
            for i, item in enumerate(findings['high_risk_items'], 1):
                r.append(f"{i}. {item['name']} - {', '.join(item.get('issues', []))}")

        if findings['warning_items']:
            r.append("")
            r.append("WARNINGS (Review Recommended):")
            r.append("-" * 60)
            for i, item in enumerate(findings['warning_items'], 1):
                r.append(f"{i}. {item}")

        # Remediation priority
        if findings['fail'] > 0 or findings['high_risk'] > 0:
            r.append("")
            r.append("=" * 60)
            r.append("REMEDIATION PRIORITY")
            r.append("=" * 60)
            r.append("")
            if findings['fail'] > 0:
                r.append("PRIORITY 1 - Fix Immediately (Security Risk):")
                r.append("  - Replace non-compliant algorithms in active profiles")
                r.append("  - Update IKE/IPSec profiles to use AES-256-GCM, SHA-256+, Group 14+")
                r.append("  - Update SSL/TLS profiles to TLS 1.2 minimum")
                r.append("  - Disable Telnet and HTTP on management profiles")
                r.append("")
            if findings['high_risk'] > 0:
                r.append("PRIORITY 2 - Cleanup (Configuration Hygiene):")
                r.append("  - Delete or update unused non-compliant profiles")
                r.append("  - Remove 'default' profiles if they contain weak algorithms")
                r.append("  - Remove test profiles with weak algorithms")
                r.append("")

        # Compliance attestation for passed
        if findings['fail'] == 0 and findings['high_risk'] == 0 and findings['pass'] > 0:
            r.append("")
            r.append("=" * 60)
            r.append("COMPLIANCE ATTESTATION")
            r.append("=" * 60)
            r.append("")
            r.append("This firewall has been validated for FIPS 140-3 cryptographic")
            r.append("compliance without requiring CC-mode.")
            r.append("")
            r.append("Validated Areas:")
            r.append("  [✓] IKE Phase 1 (IKEv2) Cryptography")
            r.append("  [✓] IPSec Phase 2 Cryptography")
            r.append("  [✓] SSL/TLS Service Profiles")
            r.append("  [✓] Interface Management Profiles")
            r.append("")
            r.append("Compliant Algorithms in Use:")
            r.append("  - Encryption: AES-256-GCM, AES-256-CBC, AES-128-GCM")
            r.append("  - Hash: SHA-512, SHA-384, SHA-256")
            r.append("  - Key Exchange: DH Groups 14, 16, 19, 20, 21")
            r.append("  - TLS: TLS 1.2, TLS 1.3")
            r.append("")
            r.append("Non-Compliant Algorithms Verified Absent:")
            r.append("  [✓] No 3DES, DES, or RC4 encryption")
            r.append("  [✓] No MD5 or SHA-1 hashing")
            r.append("  [✓] No DH Groups 1, 2, or 5")
            r.append("  [✓] No TLS 1.0 or TLS 1.1")
            r.append("  [✓] No Telnet or HTTP management access")

        r.append("")
        r.append("=" * 60)
        r.append("END OF REPORT")
        r.append("=" * 60)

        report = "\n".join(r)
        self._save_report(report, output_file)

    def _run_detailed_firewall_audit(self, r: list, findings: dict):
        """Run comprehensive firewall audit for detailed report."""
        import requests
        import xml.etree.ElementTree as ET
        requests.packages.urllib3.disable_warnings()

        creds = self.config.get_firewall_credentials()
        host = creds.get('host', 'Unknown')
        username = creds.get('username', '')
        password = creds.get('password', '')

        r.append(f"Firewall: {host}")
        r.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # Authenticate
        r.append("[INFO] Authenticating to firewall...")
        api_url = f"https://{host}/api/"

        try:
            response = requests.get(
                api_url,
                params={'type': 'keygen', 'user': username, 'password': password},
                verify=False, timeout=30
            )
            root = ET.fromstring(response.text)
            if root.get('status') != 'success':
                r.append("[FAIL] Authentication failed")
                findings['fail'] += 1
                return

            api_key = root.find('.//key').text
            r.append("[PASS] Successfully authenticated")
            findings['pass'] += 1

        except Exception as e:
            r.append(f"[ERROR] Connection failed: {e}")
            return

        def api_get(xpath):
            try:
                resp = requests.post(api_url, data={
                    'type': 'config', 'action': 'get', 'xpath': xpath, 'key': api_key
                }, verify=False, timeout=60)
                return ET.fromstring(resp.text)
            except:
                return None

        # Non-compliant checks
        NON_COMPLIANT = {
            'encryption': ['3des', 'des', 'des-cbc', 'null', 'rc4'],
            'hash': ['md5', 'sha1'],
            'dh_group': ['group1', 'group2', 'group5', 'no-pfs'],
            'tls': ['tls1-0', 'tls1-1', 'sslv3']
        }

        def is_bad(val, cat):
            if not val:
                return False
            v = val.lower()
            return any(p in v for p in NON_COMPLIANT.get(cat, []))

        # Gather profile usage information
        r.append("")
        r.append("=" * 60)
        r.append("GATHERING PROFILE USAGE INFORMATION")
        r.append("=" * 60)

        ike_usage = {}
        ipsec_usage = {}
        tls_usage = {}
        mgmt_usage = {}

        # Check IKE gateways
        r.append("[INFO] Checking IKE gateway configurations...")
        gw_root = api_get("/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway")
        if gw_root is not None:
            for gw in gw_root.findall('.//entry'):
                name = gw.get('name')
                profile = gw.find('.//ike-crypto-profile')
                if profile is not None and profile.text:
                    ike_usage[profile.text] = ike_usage.get(profile.text, []) + [f"IKE Gateway '{name}'"]
                    r.append(f"[INFO]   IKE Gateway '{name}' uses profile: {profile.text}")

        # Check IPSec tunnels
        r.append("[INFO] Checking IPSec tunnel configurations...")
        tun_root = api_get("/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec")
        if tun_root is not None:
            for tun in tun_root.findall('.//entry'):
                name = tun.get('name')
                profile = tun.find('.//ipsec-crypto-profile')
                if profile is not None and profile.text:
                    ipsec_usage[profile.text] = ipsec_usage.get(profile.text, []) + [f"IPSec Tunnel '{name}'"]
                    r.append(f"[INFO]   IPSec Tunnel '{name}' uses profile: {profile.text}")

        # Check GlobalProtect
        r.append("[INFO] Checking GlobalProtect gateway configurations...")
        r.append("[INFO] Checking GlobalProtect portal configurations...")

        # Check management interface
        r.append("[INFO] Checking management interface configuration...")
        mgmt_root = api_get("/config/devices/entry[@name='localhost.localdomain']/deviceconfig/system")
        if mgmt_root is not None:
            ssl_profile = mgmt_root.find('.//ssl-tls-service-profile')
            if ssl_profile is not None and ssl_profile.text:
                tls_usage[ssl_profile.text] = tls_usage.get(ssl_profile.text, []) + ["Management Interface"]
                r.append(f"[INFO]   Management interface uses SSL/TLS profile: {ssl_profile.text}")

        # Check interfaces for management profiles
        r.append("[INFO] Checking interface configurations...")
        iface_root = api_get("/config/devices/entry[@name='localhost.localdomain']/network/interface")
        if iface_root is not None:
            for iface in iface_root.findall('.//entry'):
                iface_name = iface.get('name')
                layer3 = iface.find('.//layer3')
                if layer3 is not None:
                    mgmt_prof = layer3.find('.//interface-management-profile')
                    if mgmt_prof is not None and mgmt_prof.text:
                        mgmt_usage[mgmt_prof.text] = mgmt_usage.get(mgmt_prof.text, []) + [f"Interface '{iface_name}'"]
                        r.append(f"[INFO]   Interface '{iface_name}' uses mgmt profile: {mgmt_prof.text}")

        r.append("")
        r.append(f"[INFO] IKE crypto profiles in use: {len(ike_usage)}")
        r.append(f"[INFO] IPSec crypto profiles in use: {len(ipsec_usage)}")
        r.append(f"[INFO] SSL/TLS profiles in use: {len(tls_usage)}")
        r.append(f"[INFO] Management profiles in use: {len(mgmt_usage)}")

        # IKE Crypto Profiles
        r.append("")
        r.append("=" * 60)
        r.append("IKE CRYPTO PROFILES")
        r.append("=" * 60)
        r.append("")

        ike_root = api_get("/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles")
        if ike_root is not None:
            for profile in ike_root.findall('.//entry'):
                name = profile.get('name')
                in_use = name in ike_usage
                used_by = ', '.join(ike_usage.get(name, []))
                status = "[IN USE]" if in_use else "[NOT USED]"
                r.append(f"[INFO] Checking profile: {name} {status}")

                issues = []
                for enc in profile.findall('.//encryption/member'):
                    if is_bad(enc.text, 'encryption'):
                        issues.append(f"Non-compliant encryption: {enc.text}")
                for h in profile.findall('.//hash/member'):
                    if is_bad(h.text, 'hash'):
                        issues.append(f"Non-compliant hash: {h.text}")
                for dh in profile.findall('.//dh-group/member'):
                    if is_bad(dh.text, 'dh_group'):
                        issues.append(f"Non-compliant DH group: {dh.text}")

                if issues:
                    if in_use:
                        for issue in issues:
                            r.append(f"[FAIL] {issue}")
                            findings['fail'] += 1
                        findings['critical_items'].append({
                            'name': f"IKE Profile '{name}'",
                            'used_by': used_by,
                            'issues': issues
                        })
                    else:
                        for issue in issues:
                            r.append(f"[HIGH RISK] {issue.replace('Non-compliant', 'Non-compliant')} (not in use)")
                            findings['high_risk'] += 1
                        findings['high_risk_items'].append({
                            'name': f"IKE Profile '{name}'",
                            'issues': issues
                        })
                else:
                    r.append("[PASS] Encryption algorithms compliant")
                    r.append("[PASS] Hash algorithms compliant")
                    r.append("[PASS] DH groups compliant")
                    findings['pass'] += 3
                r.append("")

        # IPSec Crypto Profiles
        r.append("=" * 60)
        r.append("IPSEC CRYPTO PROFILES")
        r.append("=" * 60)
        r.append("")

        ipsec_root = api_get("/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles")
        if ipsec_root is not None:
            for profile in ipsec_root.findall('.//entry'):
                name = profile.get('name')
                in_use = name in ipsec_usage
                used_by = ', '.join(ipsec_usage.get(name, []))
                status = "[IN USE]" if in_use else "[NOT USED]"
                r.append(f"[INFO] Checking profile: {name} {status}")

                issues = []
                for enc in profile.findall('.//esp/encryption/member'):
                    if is_bad(enc.text, 'encryption'):
                        issues.append(f"Non-compliant ESP encryption: {enc.text}")
                for auth in profile.findall('.//esp/authentication/member'):
                    if auth.text and auth.text != 'none' and is_bad(auth.text, 'hash'):
                        issues.append(f"Non-compliant ESP authentication: {auth.text}")
                dh = profile.find('.//dh-group')
                if dh is not None and dh.text and is_bad(dh.text, 'dh_group'):
                    issues.append(f"Non-compliant DH group (PFS): {dh.text}")

                if issues:
                    if in_use:
                        for issue in issues:
                            r.append(f"[FAIL] {issue}")
                            findings['fail'] += 1
                        findings['critical_items'].append({
                            'name': f"IPSec Profile '{name}'",
                            'used_by': used_by,
                            'issues': issues
                        })
                    else:
                        for issue in issues:
                            r.append(f"[HIGH RISK] {issue} (not in use)")
                            findings['high_risk'] += 1
                        findings['high_risk_items'].append({
                            'name': f"IPSec Profile '{name}'",
                            'issues': issues
                        })
                else:
                    r.append("[PASS] ESP encryption compliant")
                    r.append("[PASS] ESP authentication compliant")
                    dh_val = dh.text if dh is not None and dh.text else "group14"
                    r.append(f"[PASS] DH group (PFS) compliant: {dh_val}")
                    findings['pass'] += 3
                r.append("")

        # SSL/TLS Service Profiles
        r.append("=" * 60)
        r.append("SSL/TLS SERVICE PROFILES")
        r.append("=" * 60)
        r.append("")

        tls_root = api_get("/config/shared/ssl-tls-service-profile")
        if tls_root is not None:
            for profile in tls_root.findall('.//entry'):
                name = profile.get('name')
                in_use = name in tls_usage
                used_by = ', '.join(tls_usage.get(name, []))
                status = "[IN USE]" if in_use else "[NOT USED]"
                r.append(f"[INFO] Checking profile: {name} {status}")

                issues = []
                min_ver = profile.find('.//protocol-settings/min-version')
                if min_ver is not None and min_ver.text and is_bad(min_ver.text, 'tls'):
                    issues.append(f"Non-compliant minimum TLS version: {min_ver.text}")

                cert = profile.find('.//certificate')
                if cert is None or not cert.text:
                    r.append("[WARN] No certificate assigned to profile")
                    findings['warn'] += 1
                    findings['warning_items'].append(f"SSL/TLS Profile '{name}' has no certificate assigned")

                if issues:
                    if in_use:
                        for issue in issues:
                            r.append(f"[FAIL] {issue}")
                            findings['fail'] += 1
                        findings['critical_items'].append({
                            'name': f"SSL/TLS Profile '{name}'",
                            'used_by': used_by,
                            'issues': issues
                        })
                    else:
                        for issue in issues:
                            r.append(f"[HIGH RISK] {issue} (not in use)")
                            findings['high_risk'] += 1
                        findings['high_risk_items'].append({
                            'name': f"SSL/TLS Profile '{name}'",
                            'issues': issues
                        })
                else:
                    tls_ver = min_ver.text if min_ver is not None and min_ver.text else "tls1-2"
                    r.append(f"[PASS] Minimum TLS version compliant: {tls_ver}")
                    if cert is not None and cert.text:
                        r.append(f"[PASS] Certificate assigned: {cert.text}")
                    findings['pass'] += 2
                r.append("")
        else:
            r.append("[INFO] No SSL/TLS service profiles found")
            r.append("")

        # Interface Management Profiles
        r.append("=" * 60)
        r.append("INTERFACE MANAGEMENT PROFILES")
        r.append("=" * 60)
        r.append("")

        mgmt_root = api_get("/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile")
        if mgmt_root is not None:
            for profile in mgmt_root.findall('.//entry'):
                name = profile.get('name')
                in_use = name in mgmt_usage
                used_by = ', '.join(mgmt_usage.get(name, []))
                status = "[IN USE]" if in_use else "[NOT USED]"
                r.append(f"[INFO] Checking profile: {name} {status}")

                issues = []
                telnet = profile.find('.//telnet')
                http = profile.find('.//http')
                https = profile.find('.//https')
                ssh = profile.find('.//ssh')

                telnet_on = telnet is not None and telnet.text == 'yes'
                http_on = http is not None and http.text == 'yes'
                https_on = https is not None and https.text == 'yes'
                ssh_on = ssh is not None and ssh.text == 'yes'

                if telnet_on:
                    issues.append("Telnet is enabled (insecure, non-encrypted)")
                if http_on:
                    issues.append("HTTP is enabled (insecure, non-encrypted)")

                if issues:
                    if in_use:
                        for issue in issues:
                            r.append(f"[FAIL] {issue}")
                            findings['fail'] += 1
                        findings['critical_items'].append({
                            'name': f"Interface Mgmt Profile '{name}'",
                            'used_by': used_by,
                            'issues': issues
                        })
                    else:
                        for issue in issues:
                            r.append(f"[HIGH RISK] {issue.replace('is enabled', 'enabled')} (not in use)")
                            findings['high_risk'] += 1
                        findings['high_risk_items'].append({
                            'name': f"Interface Mgmt Profile '{name}'",
                            'issues': issues
                        })
                else:
                    r.append("[PASS] Telnet is disabled")
                    r.append("[PASS] HTTP is disabled")
                    findings['pass'] += 2

                if not https_on and not ssh_on:
                    r.append("[WARN] No secure management protocols enabled")
                    findings['warn'] += 1
                    findings['warning_items'].append(f"Interface Mgmt Profile '{name}' has no SSH/HTTPS enabled")
                else:
                    r.append(f"[PASS] Secure protocols: SSH={ssh_on}, HTTPS={https_on}")
                    findings['pass'] += 1
                r.append("")
        else:
            r.append("[INFO] No interface management profiles found")
            r.append("")

        # Management Interface TLS
        r.append("=" * 60)
        r.append("MANAGEMENT INTERFACE TLS")
        r.append("=" * 60)
        if tls_usage:
            for profile, usage in tls_usage.items():
                if "Management Interface" in usage:
                    r.append(f"[PASS] Management using SSL/TLS profile: {profile}")
                    findings['pass'] += 1
        else:
            r.append("[WARN] No SSL/TLS profile assigned to management (using defaults)")
            findings['warn'] += 1
            findings['warning_items'].append("Management interface has no SSL/TLS service profile assigned")
        r.append("")

    def _run_detailed_scm_audit(self, r: list, findings: dict):
        """Run comprehensive SCM audit for detailed report."""
        # Add SDK path
        sdk_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            '09-scm-api-toolkit', '06-python-sdk'
        )
        if sdk_path not in sys.path:
            sys.path.insert(0, sdk_path)

        from scm_client import SCMClient
        from fips_profiles import (
            validate_ike_profile, validate_ipsec_profile,
            validate_tls_profile, validate_mgmt_profile
        )

        creds = self.config.get_scm_credentials()
        r.append(f"SCM TSG ID: {creds.get('tsg_id', 'N/A')}")
        r.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        r.append("[INFO] Authenticating to SCM...")
        try:
            client = SCMClient(
                client_id=creds['client_id'],
                client_secret=creds['client_secret'],
                tsg_id=creds['tsg_id']
            )
            _ = client.token
            r.append("[PASS] Successfully authenticated")
            findings['pass'] += 1
        except Exception as e:
            r.append(f"[FAIL] Authentication failed: {e}")
            findings['fail'] += 1
            return

        folder = "Shared"
        r.append("")
        r.append("=" * 60)
        r.append("IKE CRYPTO PROFILES")
        r.append("=" * 60)
        r.append("")

        for profile in client.list_ike_crypto_profiles(folder=folder):
            name = profile.get('name', 'Unknown')
            r.append(f"[INFO] Checking profile: {name}")
            issues = validate_ike_profile(profile)
            if issues:
                for issue in issues:
                    r.append(f"[FAIL] {issue}")
                    findings['fail'] += 1
                findings['critical_items'].append({'name': f"IKE Profile '{name}'", 'issues': issues})
            else:
                r.append("[PASS] Encryption algorithms compliant")
                r.append("[PASS] Hash algorithms compliant")
                r.append("[PASS] DH groups compliant")
                findings['pass'] += 3
            r.append("")

        r.append("=" * 60)
        r.append("IPSEC CRYPTO PROFILES")
        r.append("=" * 60)
        r.append("")

        for profile in client.list_ipsec_crypto_profiles(folder=folder):
            name = profile.get('name', 'Unknown')
            r.append(f"[INFO] Checking profile: {name}")
            issues = validate_ipsec_profile(profile)
            if issues:
                for issue in issues:
                    r.append(f"[FAIL] {issue}")
                    findings['fail'] += 1
                findings['critical_items'].append({'name': f"IPSec Profile '{name}'", 'issues': issues})
            else:
                r.append("[PASS] ESP encryption compliant")
                r.append("[PASS] ESP authentication compliant")
                r.append("[PASS] DH group (PFS) compliant")
                findings['pass'] += 3
            r.append("")

        r.append("=" * 60)
        r.append("SSL/TLS SERVICE PROFILES")
        r.append("=" * 60)
        r.append("")

        for profile in client.list_tls_service_profiles(folder=folder):
            name = profile.get('name', 'Unknown')
            r.append(f"[INFO] Checking profile: {name}")
            issues = validate_tls_profile(profile)
            if issues:
                for issue in issues:
                    r.append(f"[FAIL] {issue}")
                    findings['fail'] += 1
                findings['critical_items'].append({'name': f"TLS Profile '{name}'", 'issues': issues})
            else:
                r.append("[PASS] Minimum TLS version compliant")
                findings['pass'] += 1
            r.append("")

        r.append("=" * 60)
        r.append("INTERFACE MANAGEMENT PROFILES")
        r.append("=" * 60)
        r.append("")

        for profile in client.list_interface_mgmt_profiles(folder=folder):
            name = profile.get('name', 'Unknown')
            r.append(f"[INFO] Checking profile: {name}")
            issues = validate_mgmt_profile(profile)
            if issues:
                for issue in issues:
                    r.append(f"[FAIL] {issue}")
                    findings['fail'] += 1
                findings['critical_items'].append({'name': f"Mgmt Profile '{name}'", 'issues': issues})
            else:
                r.append("[PASS] Telnet is disabled")
                r.append("[PASS] HTTP is disabled")
                findings['pass'] += 2
            r.append("")

    def _generate_audit_log(self, output_file: Path):
        """Generate timestamped audit log."""
        import io
        from contextlib import redirect_stdout

        print_info("Running audit with timestamps...")

        start_time = datetime.now()

        # Capture audit output
        captured = io.StringIO()
        with redirect_stdout(captured):
            if self.config.has_scm_credentials():
                self._run_scm_audit_captured()
            if self.config.has_firewall_credentials():
                self._run_firewall_audit_captured()

        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()

        audit_output = captured.getvalue()

        # Build log
        report_lines = []
        report_lines.append("=" * 70)
        report_lines.append("FIPS 140-3 COMPLIANCE AUDIT LOG")
        report_lines.append("=" * 70)
        report_lines.append(f"Audit Start:    {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Audit End:      {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append(f"Duration:       {duration:.2f} seconds")
        report_lines.append("")

        if self.config.has_scm_credentials():
            scm_creds = self.config.get_scm_credentials()
            report_lines.append(f"SCM Client ID:  {scm_creds.get('client_id', 'N/A')}")
            report_lines.append(f"SCM TSG ID:     {scm_creds.get('tsg_id', 'N/A')}")

        if self.config.has_firewall_credentials():
            fw_creds = self.config.get_firewall_credentials()
            report_lines.append(f"Firewall:       {fw_creds.get('host', 'N/A')}")

        report_lines.append("")
        report_lines.append("-" * 70)
        report_lines.append("AUDIT OUTPUT")
        report_lines.append("-" * 70)
        report_lines.append("")
        report_lines.append(self._strip_ansi(audit_output))
        report_lines.append("")
        report_lines.append("=" * 70)
        report_lines.append("END OF AUDIT LOG")
        report_lines.append("=" * 70)

        report = "\n".join(report_lines)
        self._save_report(report, output_file)

    def _generate_complete_package(self):
        """Generate complete report package with all reports and infographic."""
        import shutil
        import zipfile

        print_info("Generating complete compliance report package...")

        # Create timestamped folder
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder_name = f"fips-compliance-report-{timestamp}"
        package_dir = self.default_dir / folder_name

        # Create the directory
        package_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n{Colors.CYAN}Creating report package:{Colors.NC} {package_dir}")

        # Collect audit data once for infographic (runs audit internally)
        print_info("Running compliance audit...")
        audit_data = self._collect_infographic_data()

        pass_count = audit_data['pass_count']
        fail_count = audit_data['fail_count']
        high_risk_count = audit_data['high_risk_count']
        warn_count = audit_data['warn_count']

        # Generate each report
        reports_generated = []

        # 1. Executive Report
        print_info("Generating Executive Report...")
        exec_file = package_dir / "01-executive-report.txt"
        self._generate_executive(exec_file)
        reports_generated.append(exec_file.name)

        # 2. Summary Report
        print_info("Generating Summary Report...")
        summary_file = package_dir / "02-summary-report.txt"
        self._generate_summary(summary_file)
        reports_generated.append(summary_file.name)

        # 3. Detailed Report
        print_info("Generating Detailed Report...")
        detailed_file = package_dir / "03-detailed-report.txt"
        self._generate_detailed(detailed_file)
        reports_generated.append(detailed_file.name)

        # 4. Audit Log
        print_info("Generating Audit Log...")
        audit_file = package_dir / "04-audit-log.txt"
        self._generate_audit_log(audit_file)
        reports_generated.append(audit_file.name)

        # 5. SVG Infographic (with detailed audit data)
        print_info("Generating Executive Infographic (SVG)...")
        svg_file = package_dir / "05-executive-infographic.svg"
        self._generate_infographic(svg_file, pass_count, fail_count, high_risk_count, warn_count, audit_data)
        reports_generated.append(svg_file.name)

        # 6. Create README in package
        readme_content = f"""FIPS 140-3 Compliance Report Package
=====================================
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Contents:
---------
1. 01-executive-report.txt  - Management summary for executives
2. 02-summary-report.txt    - Pass/fail overview with counts
3. 03-detailed-report.txt   - Full technical audit with findings
4. 04-audit-log.txt         - Complete audit output with timestamps
5. 05-executive-infographic.svg - Visual executive summary (open in browser)

Quick Summary:
--------------
  PASSED:    {pass_count}
  FAILED:    {fail_count}
  HIGH RISK: {high_risk_count}
  WARNINGS:  {warn_count}

How to View:
------------
- Text reports: Open in any text editor
- SVG infographic: Open in web browser or image viewer

Generated by FIPS 140-3 Compliance Toolkit (Independent Open-Source Tool)
"""
        readme_file = package_dir / "README.txt"
        with open(readme_file, 'w') as f:
            f.write(readme_content)
        reports_generated.append(readme_file.name)

        # Ask if user wants to create a zip file
        print(f"\n{Colors.GREEN}Report package created successfully!{Colors.NC}")
        print(f"\n{Colors.CYAN}Package location:{Colors.NC}")
        print(f"  {Colors.WHITE}{package_dir.absolute()}{Colors.NC}")
        print(f"\n{Colors.CYAN}Contents:{Colors.NC}")
        for report in reports_generated:
            print(f"  - {report}")

        create_zip = get_input("\nCreate a ZIP archive? (y/n)", default="y", required=False)
        if create_zip.lower() in ['y', 'yes']:
            zip_path = self.default_dir / f"{folder_name}.zip"
            print_info(f"Creating ZIP archive...")
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file in package_dir.iterdir():
                    zipf.write(file, arcname=f"{folder_name}/{file.name}")
            print_success(f"ZIP archive created!")
            print(f"\n{Colors.CYAN}ZIP location:{Colors.NC}")
            print(f"  {Colors.WHITE}{zip_path.absolute()}{Colors.NC}")

        # Provide open commands
        print(f"\n{Colors.YELLOW}To open the package folder:{Colors.NC}")
        if sys.platform == 'darwin':
            print(f"  open \"{package_dir.absolute()}\"")
        elif sys.platform == 'win32':
            print(f"  explorer \"{package_dir.absolute()}\"")
        else:
            print(f"  xdg-open \"{package_dir.absolute()}\"")

    def _generate_infographic(self, output_file: Path, pass_count: int, fail_count: int,
                               high_risk_count: int, warn_count: int, audit_data: dict = None):
        """Generate SVG executive infographic matching the comprehensive template.

        Args:
            output_file: Path to save the SVG
            pass_count: Number of passed checks
            fail_count: Number of failed checks (in use)
            high_risk_count: Number of high risk (not in use)
            warn_count: Number of warnings
            audit_data: Optional dict with detailed audit data including:
                - critical_findings: list of dicts with name, used_by, issues, description
                - category_stats: dict with ike, ipsec, tls, mgmt each having pass/fail counts
        """
        # Get target info
        target_info = "Unknown"
        if self.config.has_firewall_credentials():
            fw_creds = self.config.get_firewall_credentials()
            target_info = fw_creds.get('host', 'Unknown')
        elif self.config.has_scm_credentials():
            scm_creds = self.config.get_scm_credentials()
            target_info = f"SCM TSG: {scm_creds.get('tsg_id', 'Unknown')}"

        # Initialize audit_data if not provided
        if audit_data is None:
            audit_data = {}

        # Get critical findings (up to 6)
        critical_findings = audit_data.get('critical_findings', [])[:6]

        # Get category stats with defaults
        category_stats = audit_data.get('category_stats', {
            'ike': {'pass': 0, 'fail': 0, 'total': 0},
            'ipsec': {'pass': 0, 'fail': 0, 'total': 0},
            'tls': {'pass': 0, 'fail': 0, 'total': 0},
            'mgmt': {'pass': 0, 'fail': 0, 'total': 0}
        })

        # Determine overall status
        if fail_count > 0:
            status = "NON-COMPLIANT"
            status_bg_gradient = "failGrad"
            status_desc = f"{fail_count} critical findings require immediate remediation to achieve FIPS 140-3 compliance"
            status_icon = "!"
        elif high_risk_count > 0:
            status = "PASSED WITH RISK"
            status_bg_gradient = "warnGrad"
            status_desc = f"{high_risk_count} non-compliant profiles exist but are not currently in use"
            status_icon = "!"
        elif pass_count == 0:
            status = "NO DATA"
            status_bg_gradient = "grayGrad"
            status_desc = "No profiles were found to scan"
            status_icon = "?"
        else:
            status = "COMPLIANT"
            status_bg_gradient = "passGrad"
            status_desc = "All configurations are FIPS 140-3 compliant"
            status_icon = "✓"

        date_str = datetime.now().strftime("%B %d, %Y")
        report_id = datetime.now().strftime("FIPS-%Y-%m%d-%H%M")

        # Helper function to calculate progress bar
        def calc_bar(passed, failed, bar_width=600):
            total = passed + failed
            if total == 0:
                return 0, 0, 0
            pct = int(passed / total * 100)
            pass_width = int(bar_width * passed / total)
            fail_width = bar_width - pass_width
            return pct, pass_width, fail_width

        # Build SVG parts
        svg_parts = []

        # Header
        svg_parts.append(f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 1600" width="1200" height="1600">
  <defs>
    <linearGradient id="headerGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#FA582D;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#190000;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="failGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#C84727;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#AA251B;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="passGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#00CC66;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#0F9347;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="warnGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#FFCB06;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#D69F25;stop-opacity:1" />
    </linearGradient>
    <linearGradient id="grayGrad" x1="0%" y1="0%" x2="100%" y2="0%">
      <stop offset="0%" style="stop-color:#718096;stop-opacity:1" />
      <stop offset="100%" style="stop-color:#4A5568;stop-opacity:1" />
    </linearGradient>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="2" dy="2" stdDeviation="3" flood-opacity="0.15"/>
    </filter>
    <filter id="shadowStrong" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="3" dy="3" stdDeviation="5" flood-opacity="0.25"/>
    </filter>
  </defs>

  <!-- Background -->
  <rect width="1200" height="1600" fill="#F7FAFC"/>

  <!-- Header Banner -->
  <rect x="0" y="0" width="1200" height="140" fill="url(#headerGrad)"/>
  <text x="600" y="55" text-anchor="middle" fill="white" font-family="Arial, sans-serif" font-size="36" font-weight="bold">FIPS 140-3 Compliance Assessment</text>
  <text x="600" y="90" text-anchor="middle" fill="#FFBF9C" font-family="Arial, sans-serif" font-size="18">Executive Summary Report</text>
  <text x="600" y="120" text-anchor="middle" fill="#FFBF9C" font-family="Arial, sans-serif" font-size="14">Target: {target_info} | Assessment Date: {date_str}</text>

  <!-- Accent Bar -->
  <rect x="0" y="140" width="1200" height="4" fill="#FFCB06"/>

  <!-- Overall Status Card -->
  <rect x="40" y="170" width="1120" height="160" rx="8" fill="url(#{status_bg_gradient})" filter="url(#shadowStrong)"/>
  <text x="100" y="220" fill="white" font-family="Arial, sans-serif" font-size="14" font-weight="bold" letter-spacing="2">OVERALL COMPLIANCE STATUS</text>
  <text x="100" y="280" fill="white" font-family="Arial, sans-serif" font-size="56" font-weight="bold">{status}</text>
  <text x="100" y="310" fill="#FFD7CF" font-family="Arial, sans-serif" font-size="16">{status_desc}</text>

  <!-- Status Icon -->
  <circle cx="1060" cy="250" r="50" fill="rgba(0,0,0,0.3)" stroke="rgba(255,255,255,0.5)" stroke-width="3"/>
  <text x="1060" y="268" text-anchor="middle" fill="white" font-family="Arial, sans-serif" font-size="48" font-weight="bold">{status_icon}</text>

  <!-- Section: Key Metrics -->
  <rect x="0" y="355" width="1200" height="4" fill="#FA582D"/>
  <text x="60" y="400" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12" font-weight="bold" letter-spacing="2">KEY METRICS</text>

  <!-- Metric Cards Row -->
  <rect x="40" y="420" width="260" height="140" rx="8" fill="white" filter="url(#shadow)" stroke="#DEFEE3" stroke-width="2"/>
  <text x="170" y="480" text-anchor="middle" fill="#0F9347" font-family="Arial, sans-serif" font-size="56" font-weight="bold">{pass_count}</text>
  <text x="170" y="510" text-anchor="middle" fill="#0F9347" font-family="Arial, sans-serif" font-size="14" font-weight="bold">PASSED</text>
  <text x="170" y="540" text-anchor="middle" fill="#718096" font-family="Arial, sans-serif" font-size="12">Compliant Settings</text>

  <rect x="320" y="420" width="260" height="140" rx="8" fill="white" filter="url(#shadow)" stroke="#C84727" stroke-width="3"/>
  {'<rect x="320" y="420" width="260" height="8" rx="8" fill="#C84727"/>' if fail_count > 0 else ''}
  <text x="450" y="485" text-anchor="middle" fill="#C84727" font-family="Arial, sans-serif" font-size="56" font-weight="bold">{fail_count}</text>
  <text x="450" y="515" text-anchor="middle" fill="#C84727" font-family="Arial, sans-serif" font-size="14" font-weight="bold">FAILED</text>
  <text x="450" y="545" text-anchor="middle" fill="#718096" font-family="Arial, sans-serif" font-size="12">Non-Compliant (In Use)</text>

  <rect x="600" y="420" width="260" height="140" rx="8" fill="white" filter="url(#shadow)" stroke="#FFCB06" stroke-width="2"/>
  <text x="730" y="480" text-anchor="middle" fill="#D69F25" font-family="Arial, sans-serif" font-size="56" font-weight="bold">{high_risk_count}</text>
  <text x="730" y="510" text-anchor="middle" fill="#D69F25" font-family="Arial, sans-serif" font-size="14" font-weight="bold">HIGH RISK</text>
  <text x="730" y="540" text-anchor="middle" fill="#718096" font-family="Arial, sans-serif" font-size="12">Non-Compliant (Not In Use)</text>

  <rect x="880" y="420" width="260" height="140" rx="8" fill="white" filter="url(#shadow)" stroke="#E2E8F0" stroke-width="2"/>
  <text x="1010" y="480" text-anchor="middle" fill="#718096" font-family="Arial, sans-serif" font-size="56" font-weight="bold">{warn_count}</text>
  <text x="1010" y="510" text-anchor="middle" fill="#718096" font-family="Arial, sans-serif" font-size="14" font-weight="bold">WARNINGS</text>
  <text x="1010" y="540" text-anchor="middle" fill="#718096" font-family="Arial, sans-serif" font-size="12">Review Recommended</text>''')

        # Section: Critical Findings (if any)
        if fail_count > 0 or critical_findings:
            svg_parts.append('''
  <!-- Section: Critical Findings -->
  <rect x="0" y="590" width="1200" height="4" fill="#FA582D"/>
  <text x="60" y="635" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12" font-weight="bold" letter-spacing="2">CRITICAL FINDINGS REQUIRING IMMEDIATE ACTION</text>''')

            # Generate finding cards (up to 6, 2 rows of 3)
            positions = [
                (40, 655), (420, 655), (800, 655),   # Row 1
                (40, 800), (420, 800), (800, 800)    # Row 2
            ]

            for idx, finding in enumerate(critical_findings[:6]):
                x, y = positions[idx]
                num = f"{idx + 1:02d}"
                name = finding.get('name', 'Unknown')[:30]
                used_by = finding.get('used_by', 'Unknown')[:35]
                issues = finding.get('issues', ['Unknown issue'])
                issue_text = ', '.join(issues)[:35] if issues else 'Unknown'
                desc = finding.get('description', 'Non-compliant configuration')[:40]

                svg_parts.append(f'''
  <!-- Finding {idx + 1} -->
  <rect x="{x}" y="{y}" width="360" height="130" rx="8" fill="white" filter="url(#shadow)"/>
  <rect x="{x}" y="{y}" width="6" height="130" rx="3" fill="#C84727"/>
  <text x="{x + 30}" y="{y + 30}" fill="#FA582D" font-family="Arial, sans-serif" font-size="28" font-weight="bold">{num}</text>
  <text x="{x + 70}" y="{y + 30}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="14" font-weight="bold">{name}</text>
  <text x="{x + 30}" y="{y + 55}" fill="#718096" font-family="Arial, sans-serif" font-size="12">Used by: {used_by}</text>
  <text x="{x + 30}" y="{y + 80}" fill="#C84727" font-family="monospace" font-size="11">{issue_text}</text>
  <text x="{x + 30}" y="{y + 110}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="11">{desc}</text>''')

            # Fill empty slots with placeholder if less than 6 findings
            for idx in range(len(critical_findings), 6):
                x, y = positions[idx]
                svg_parts.append(f'''
  <rect x="{x}" y="{y}" width="360" height="130" rx="8" fill="#F7FAFC" stroke="#E2E8F0" stroke-width="1" stroke-dasharray="5,5"/>
  <text x="{x + 180}" y="{y + 70}" text-anchor="middle" fill="#A0AEC0" font-family="Arial, sans-serif" font-size="12">No additional findings</text>''')

            category_section_y = 960
        else:
            # No critical findings - show compliance message
            svg_parts.append('''
  <!-- Section: Compliance Status -->
  <rect x="0" y="590" width="1200" height="4" fill="#FA582D"/>
  <text x="60" y="635" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12" font-weight="bold" letter-spacing="2">COMPLIANCE STATUS</text>

  <rect x="40" y="655" width="1120" height="280" rx="8" fill="white" filter="url(#shadow)" stroke="#DEFEE3" stroke-width="2"/>
  <text x="600" y="750" text-anchor="middle" fill="#0F9347" font-family="Arial, sans-serif" font-size="48" font-weight="bold">ALL CHECKS PASSED</text>
  <text x="600" y="790" text-anchor="middle" fill="#718096" font-family="Arial, sans-serif" font-size="16">All cryptographic profiles are using FIPS 140-3 approved algorithms</text>
  <text x="600" y="850" text-anchor="middle" fill="#0F9347" font-family="Arial, sans-serif" font-size="72">✓</text>''')
            category_section_y = 960

        # Section: Compliance by Category
        svg_parts.append(f'''
  <!-- Section: Compliance by Category -->
  <rect x="0" y="{category_section_y}" width="1200" height="4" fill="#FA582D"/>
  <text x="60" y="{category_section_y + 45}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12" font-weight="bold" letter-spacing="2">COMPLIANCE BY CATEGORY</text>''')

        # Category progress bars
        categories = [
            ('IKE Crypto Profiles', 'ike'),
            ('IPSec Crypto Profiles', 'ipsec'),
            ('SSL/TLS Service Profiles', 'tls'),
            ('Interface Management Profiles', 'mgmt')
        ]

        bar_y = category_section_y + 65
        for cat_name, cat_key in categories:
            stats = category_stats.get(cat_key, {'pass': 0, 'fail': 0, 'total': 0})
            cat_pass = stats.get('pass', 0)
            cat_fail = stats.get('fail', 0)
            cat_total = cat_pass + cat_fail
            pct, pass_w, fail_w = calc_bar(cat_pass, cat_fail)

            svg_parts.append(f'''
  <rect x="40" y="{bar_y}" width="1120" height="60" rx="6" fill="white" filter="url(#shadow)"/>
  <text x="60" y="{bar_y + 30}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="13" font-weight="bold">{cat_name}</text>
  <text x="60" y="{bar_y + 47}" fill="#718096" font-family="Arial, sans-serif" font-size="11">{cat_total} total: {cat_pass} compliant, {cat_fail} non-compliant</text>
  <rect x="300" y="{bar_y + 20}" width="600" height="20" rx="4" fill="#E2E8F0"/>''')

            if pass_w > 0:
                svg_parts.append(f'  <rect x="300" y="{bar_y + 20}" width="{pass_w}" height="20" rx="4" fill="#00CC66"/>')
            if fail_w > 0:
                svg_parts.append(f'  <rect x="{300 + pass_w}" y="{bar_y + 20}" width="{fail_w}" height="20" rx="4" fill="#C84727"/>')

            svg_parts.append(f'  <text x="920" y="{bar_y + 35}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12" font-weight="bold">{pct}%</text>')
            bar_y += 70

        # Section: Remediation Priorities
        priority_y = bar_y + 30
        svg_parts.append(f'''
  <!-- Section: Remediation Priorities -->
  <rect x="0" y="{priority_y}" width="1200" height="4" fill="#FA582D"/>
  <text x="60" y="{priority_y + 45}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12" font-weight="bold" letter-spacing="2">REMEDIATION PRIORITIES</text>

  <!-- Priority 1 - Immediate -->
  <rect x="40" y="{priority_y + 65}" width="360" height="140" rx="8" fill="white" filter="url(#shadow)" stroke="#C84727" stroke-width="2"/>
  <rect x="40" y="{priority_y + 65}" width="360" height="35" rx="8" fill="#C84727"/>
  <rect x="40" y="{priority_y + 90}" width="360" height="10" fill="#C84727"/>
  <text x="220" y="{priority_y + 90}" text-anchor="middle" fill="white" font-family="Arial, sans-serif" font-size="14" font-weight="bold">PRIORITY 1 - IMMEDIATE</text>
  <text x="60" y="{priority_y + 130}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Replace non-compliant IKE/IPSec profiles</text>
  <text x="60" y="{priority_y + 150}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Update weak encryption algorithms</text>
  <text x="60" y="{priority_y + 170}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Upgrade TLS to 1.2 minimum</text>
  <text x="60" y="{priority_y + 190}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Disable Telnet/HTTP management</text>

  <!-- Priority 2 - Soon -->
  <rect x="420" y="{priority_y + 65}" width="360" height="140" rx="8" fill="white" filter="url(#shadow)" stroke="#FFCB06" stroke-width="2"/>
  <rect x="420" y="{priority_y + 65}" width="360" height="35" rx="8" fill="#FFCB06"/>
  <rect x="420" y="{priority_y + 90}" width="360" height="10" fill="#FFCB06"/>
  <text x="600" y="{priority_y + 90}" text-anchor="middle" fill="#261B01" font-family="Arial, sans-serif" font-size="14" font-weight="bold">PRIORITY 2 - SOON</text>
  <text x="440" y="{priority_y + 130}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Review certificate expiration dates</text>
  <text x="440" y="{priority_y + 150}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Update DH groups to 14 or higher</text>
  <text x="440" y="{priority_y + 170}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Replace SHA-1 with SHA-256+</text>
  <text x="440" y="{priority_y + 190}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Review decryption profile settings</text>

  <!-- Priority 3 - Cleanup -->
  <rect x="800" y="{priority_y + 65}" width="360" height="140" rx="8" fill="white" filter="url(#shadow)" stroke="#E2E8F0" stroke-width="2"/>
  <rect x="800" y="{priority_y + 65}" width="360" height="35" rx="8" fill="#718096"/>
  <rect x="800" y="{priority_y + 90}" width="360" height="10" fill="#718096"/>
  <text x="980" y="{priority_y + 90}" text-anchor="middle" fill="white" font-family="Arial, sans-serif" font-size="14" font-weight="bold">PRIORITY 3 - CLEANUP</text>
  <text x="820" y="{priority_y + 130}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Delete unused non-compliant profiles</text>
  <text x="820" y="{priority_y + 150}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Remove test profiles with weak crypto</text>
  <text x="820" y="{priority_y + 170}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Archive legacy configurations</text>
  <text x="820" y="{priority_y + 190}" fill="#1A1A1A" font-family="Arial, sans-serif" font-size="12">Document any policy exceptions</text>''')

        # Footer
        footer_y = priority_y + 230
        svg_parts.append(f'''
  <!-- Footer -->
  <rect x="0" y="{footer_y}" width="1200" height="50" fill="#0D0D0D"/>
  <text x="60" y="{footer_y + 30}" fill="#FFCB06" font-family="Arial, sans-serif" font-size="12" font-weight="bold">FIPS 140-3 Compliance Toolkit</text>
  <text x="600" y="{footer_y + 30}" text-anchor="middle" fill="#A0AEC0" font-family="Arial, sans-serif" font-size="11">Independent Open-Source Tool | Not affiliated with Palo Alto Networks</text>
  <text x="1140" y="{footer_y + 30}" text-anchor="end" fill="#A0AEC0" font-family="Arial, sans-serif" font-size="11">Report ID: {report_id}</text>
</svg>''')

        # Write SVG to file
        svg = '\n'.join(svg_parts)
        with open(output_file, 'w') as f:
            f.write(svg)

    def _collect_infographic_data(self):
        """Collect detailed audit data for infographic generation.

        Returns a dict with:
            - pass_count, fail_count, high_risk_count, warn_count
            - critical_findings: list of dicts with name, used_by, issues, description
            - category_stats: dict with ike, ipsec, tls, mgmt each having pass/fail counts
        """
        import io
        import re
        from contextlib import redirect_stdout

        # Run audit to collect output
        captured = io.StringIO()
        with redirect_stdout(captured):
            if self.config.has_scm_credentials():
                self._run_scm_audit_captured()
            if self.config.has_firewall_credentials():
                self._run_firewall_audit_captured()

        audit_output = captured.getvalue()

        # Count overall results
        pass_count = audit_output.count('[PASS]')
        fail_count = audit_output.count('[FAIL]')
        high_risk_count = audit_output.count('[HIGH RISK]')
        warn_count = audit_output.count('[WARN]')

        # Parse critical findings from output
        # Format is: [FAIL] profile_name  followed by lines like "         - issue"
        critical_findings = []
        lines = audit_output.split('\n')
        current_profile = None
        current_issues = []
        current_section = None  # Track which section we're in for profile type

        for i, line in enumerate(lines):
            line_lower = line.lower()

            # Track current section for category type
            if 'ike crypto' in line_lower:
                current_section = 'IKE Profile'
            elif 'ipsec crypto' in line_lower:
                current_section = 'IPSec Profile'
            elif 'ssl/tls' in line_lower or 'tls service' in line_lower:
                current_section = 'SSL/TLS Profile'
            elif 'interface management' in line_lower or 'management profile' in line_lower:
                current_section = 'Interface Mgmt'

            # Look for [FAIL] profile_name pattern
            if '[FAIL]' in line:
                # Save previous finding if we had one
                if current_profile and current_issues:
                    profile_type = current_section or 'Profile'
                    critical_findings.append({
                        'name': f"{profile_type}: {current_profile}",
                        'used_by': 'Active Configuration',
                        'issues': current_issues[:2],  # First 2 issues
                        'description': 'Non-compliant algorithms detected'
                    })

                # Extract new profile name from [FAIL] profile_name
                match = re.search(r'\[FAIL\]\s*(.+)', line)
                if match:
                    current_profile = match.group(1).strip()
                    current_issues = []

            # Collect issue lines (indented with "- ")
            elif current_profile and line.strip().startswith('- '):
                issue = line.strip()[2:].strip()  # Remove the "- " prefix
                if issue:
                    current_issues.append(issue[:40])

        # Save last finding if needed
        if current_profile and current_issues:
            profile_type = current_section or 'Profile'
            critical_findings.append({
                'name': f"{profile_type}: {current_profile}",
                'used_by': 'Active Configuration',
                'issues': current_issues[:2],
                'description': 'Non-compliant algorithms detected'
            })

        # Parse category stats from output
        category_stats = {
            'ike': {'pass': 0, 'fail': 0},
            'ipsec': {'pass': 0, 'fail': 0},
            'tls': {'pass': 0, 'fail': 0},
            'mgmt': {'pass': 0, 'fail': 0}
        }

        current_cat = None
        for line in lines:
            line_lower = line.lower()
            if 'ike crypto' in line_lower:
                current_cat = 'ike'
            elif 'ipsec crypto' in line_lower:
                current_cat = 'ipsec'
            elif 'ssl/tls' in line_lower or 'tls service' in line_lower:
                current_cat = 'tls'
            elif 'interface management' in line_lower or 'management profile' in line_lower:
                current_cat = 'mgmt'

            if current_cat:
                if '[PASS]' in line:
                    category_stats[current_cat]['pass'] += 1
                elif '[FAIL]' in line:
                    category_stats[current_cat]['fail'] += 1

        return {
            'pass_count': pass_count,
            'fail_count': fail_count,
            'high_risk_count': high_risk_count,
            'warn_count': warn_count,
            'critical_findings': critical_findings[:6],  # Max 6 for infographic
            'category_stats': category_stats
        }

    def _generate_standalone_infographic(self):
        """Generate standalone infographic SVG file."""
        print_info("Running compliance audit for infographic...")

        # Collect detailed audit data
        audit_data = self._collect_infographic_data()

        # Get output file
        default_file = self._get_default_filename("infographic")
        default_file = default_file.with_suffix('.svg')

        print(f"\n{Colors.CYAN}Default filename:{Colors.NC} {default_file.name}")
        custom_path = get_input(
            "Output file (Enter for default, or specify path)",
            required=False
        )

        if custom_path:
            output_file = Path(custom_path).expanduser()
            if not output_file.is_absolute() and '/' not in custom_path:
                output_file = self.default_dir / custom_path
            # Ensure .svg extension
            if not output_file.suffix.lower() == '.svg':
                output_file = output_file.with_suffix('.svg')
        else:
            output_file = default_file

        print_info("Generating SVG infographic...")
        self._generate_infographic(
            output_file,
            audit_data['pass_count'],
            audit_data['fail_count'],
            audit_data['high_risk_count'],
            audit_data['warn_count'],
            audit_data
        )

        print()
        print_success("Infographic saved successfully!")
        print(f"\n{Colors.CYAN}Infographic location:{Colors.NC}")
        print(f"  {Colors.WHITE}{output_file.absolute()}{Colors.NC}")
        print(f"\n{Colors.YELLOW}To open:{Colors.NC}")
        if sys.platform == 'darwin':
            print(f"  open \"{output_file.absolute()}\"")
        elif sys.platform == 'win32':
            print(f"  start \"{output_file.absolute()}\"")
        else:
            print(f"  firefox \"{output_file.absolute()}\"")

    def _run_scm_audit_captured(self):
        """Run SCM audit for capture."""
        print("=" * 50)
        print("SCM AUDIT")
        print("=" * 50)

        try:
            # Add SDK path
            sdk_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                '09-scm-api-toolkit', '06-python-sdk'
            )
            print(f"[DEBUG] SDK path: {sdk_path}")

            if sdk_path not in sys.path:
                sys.path.insert(0, sdk_path)

            from scm_client import SCMClient
            from fips_profiles import (
                validate_ike_profile, validate_ipsec_profile,
                validate_tls_profile, validate_mgmt_profile
            )
            print("[DEBUG] Imports successful")

            creds = self.config.get_scm_credentials()
            print(f"[DEBUG] Client ID: {creds.get('client_id', 'NOT SET')[:40]}...")
            print(f"[DEBUG] TSG ID: {creds.get('tsg_id', 'NOT SET')}")

            if not creds.get('client_id') or not creds.get('client_secret') or not creds.get('tsg_id'):
                print("[ERROR] Missing SCM credentials")
                return

            print("[DEBUG] Creating SCM client...")
            client = SCMClient(
                client_id=creds['client_id'],
                client_secret=creds['client_secret'],
                tsg_id=creds['tsg_id']
            )
            print("[DEBUG] SCM client created")

            # Test authentication
            print("[DEBUG] Testing authentication...")
            _ = client.token
            print("[DEBUG] Authentication successful")

            folder = "Shared"
            print(f"\nScanning folder: {folder}")
            print("-" * 50)

            # Audit IKE profiles
            print("\nIKE Crypto Profiles:")
            try:
                ike_profiles = client.list_ike_crypto_profiles(folder=folder)
                print(f"  [DEBUG] Found {len(ike_profiles)} IKE profiles")
                for profile in ike_profiles:
                    name = profile.get("name", "Unknown")
                    findings = validate_ike_profile(profile)
                    if findings:
                        print(f"  [FAIL] {name}")
                        for f in findings:
                            print(f"         - {f}")
                    else:
                        print(f"  [PASS] {name}")
                if not ike_profiles:
                    print("  No IKE profiles found in this folder")
            except Exception as e:
                print(f"  [ERROR] Failed to list IKE profiles: {e}")

            # Audit IPSec profiles
            print("\nIPSec Crypto Profiles:")
            try:
                ipsec_profiles = client.list_ipsec_crypto_profiles(folder=folder)
                print(f"  [DEBUG] Found {len(ipsec_profiles)} IPSec profiles")
                for profile in ipsec_profiles:
                    name = profile.get("name", "Unknown")
                    findings = validate_ipsec_profile(profile)
                    if findings:
                        print(f"  [FAIL] {name}")
                        for f in findings:
                            print(f"         - {f}")
                    else:
                        print(f"  [PASS] {name}")
                if not ipsec_profiles:
                    print("  No IPSec profiles found in this folder")
            except Exception as e:
                print(f"  [ERROR] Failed to list IPSec profiles: {e}")

            # Audit TLS profiles
            print("\nTLS Service Profiles:")
            try:
                tls_profiles = client.list_tls_service_profiles(folder=folder)
                print(f"  [DEBUG] Found {len(tls_profiles)} TLS profiles")
                for profile in tls_profiles:
                    name = profile.get("name", "Unknown")
                    findings = validate_tls_profile(profile)
                    if findings:
                        print(f"  [FAIL] {name}")
                        for f in findings:
                            print(f"         - {f}")
                    else:
                        print(f"  [PASS] {name}")
                if not tls_profiles:
                    print("  No TLS profiles found in this folder")
            except Exception as e:
                print(f"  [ERROR] Failed to list TLS profiles: {e}")

            # Audit management profiles
            print("\nInterface Management Profiles:")
            try:
                mgmt_profiles = client.list_interface_mgmt_profiles(folder=folder)
                print(f"  [DEBUG] Found {len(mgmt_profiles)} management profiles")
                for profile in mgmt_profiles:
                    name = profile.get("name", "Unknown")
                    findings = validate_mgmt_profile(profile)
                    if findings:
                        print(f"  [FAIL] {name}")
                        for f in findings:
                            print(f"         - {f}")
                    else:
                        print(f"  [PASS] {name}")
                if not mgmt_profiles:
                    print("  No management profiles found in this folder")
            except Exception as e:
                print(f"  [ERROR] Failed to list management profiles: {e}")

            print("\n" + "=" * 50)
            print("SCM AUDIT COMPLETE")
            print("=" * 50)

        except ImportError as e:
            print(f"[ERROR] Failed to import SCM SDK: {e}")
            print("[ERROR] Make sure you're running from the toolkit directory")
        except Exception as e:
            print(f"[ERROR] SCM audit failed: {e}")
            import traceback
            print(f"[DEBUG] Traceback:\n{traceback.format_exc()}")

    def _run_firewall_audit_captured(self):
        """Run firewall audit for capture."""
        print("=" * 50)
        print("FIREWALL AUDIT")
        print("=" * 50)

        try:
            creds = self.config.get_firewall_credentials()
            host = creds.get('host', 'Unknown')
            username = creds.get('username', '')
            password = creds.get('password', '')

            print(f"Target: {host}")
            print(f"User:   {username}")
            print("-" * 50)

            if not all([host, username, password]):
                print("[ERROR] Missing firewall credentials")
                return

            # Import the validator
            validator_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                '08-validation-tools'
            )

            if validator_path not in sys.path:
                sys.path.insert(0, validator_path)

            # Try to use the existing validator class
            try:
                import requests
                requests.packages.urllib3.disable_warnings()

                # Authenticate
                print("\n[INFO] Authenticating to firewall...")
                api_url = f"https://{host}/api/"

                response = requests.get(
                    api_url,
                    params={
                        'type': 'keygen',
                        'user': username,
                        'password': password
                    },
                    verify=False,
                    timeout=30
                )

                import xml.etree.ElementTree as ET
                root = ET.fromstring(response.text)

                if root.get('status') != 'success':
                    print("[ERROR] Authentication failed")
                    return

                key_elem = root.find('.//key')
                if key_elem is None:
                    print("[ERROR] Could not get API key")
                    return

                api_key = key_elem.text
                print("[INFO] Authentication successful")

                # Define non-compliant patterns
                NON_COMPLIANT_EXACT = {'dh_group': ['group1', 'group2', 'group5', 'no-pfs']}
                NON_COMPLIANT_PATTERN = {
                    'encryption': ['3des', 'des-cbc', 'null', 'rc4'],
                    'hash': ['md5', 'sha1'],
                    'tls_version': ['tls1-0', 'tls1-1']
                }

                def is_non_compliant(value, category):
                    value_lower = value.lower()
                    if category in NON_COMPLIANT_EXACT:
                        return value_lower in NON_COMPLIANT_EXACT[category]
                    if category in NON_COMPLIANT_PATTERN:
                        for pattern in NON_COMPLIANT_PATTERN[category]:
                            if pattern in value_lower:
                                return True
                    return False

                def api_call(xpath):
                    try:
                        resp = requests.post(
                            api_url,
                            data={
                                'type': 'config',
                                'action': 'get',
                                'xpath': xpath,
                                'key': api_key
                            },
                            verify=False,
                            timeout=60
                        )
                        return ET.fromstring(resp.text)
                    except:
                        return None

                # Check IKE Crypto Profiles
                print("\nIKE Crypto Profiles:")
                ike_root = api_call("/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles")
                if ike_root is not None:
                    profiles = ike_root.findall('.//entry')
                    if profiles:
                        for profile in profiles:
                            name = profile.get('name')
                            issues = []

                            for enc in profile.findall('.//encryption/member'):
                                if is_non_compliant(enc.text, 'encryption'):
                                    issues.append(f"Non-compliant encryption: {enc.text}")

                            for h in profile.findall('.//hash/member'):
                                if is_non_compliant(h.text, 'hash'):
                                    issues.append(f"Non-compliant hash: {h.text}")

                            for dh in profile.findall('.//dh-group/member'):
                                if is_non_compliant(dh.text, 'dh_group'):
                                    issues.append(f"Non-compliant DH group: {dh.text}")

                            if issues:
                                print(f"  [FAIL] {name}")
                                for issue in issues:
                                    print(f"         - {issue}")
                            else:
                                print(f"  [PASS] {name}")
                    else:
                        print("  No IKE profiles found")
                else:
                    print("  [ERROR] Could not retrieve IKE profiles")

                # Check IPSec Crypto Profiles
                print("\nIPSec Crypto Profiles:")
                ipsec_root = api_call("/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles")
                if ipsec_root is not None:
                    profiles = ipsec_root.findall('.//entry')
                    if profiles:
                        for profile in profiles:
                            name = profile.get('name')
                            issues = []

                            for enc in profile.findall('.//esp/encryption/member'):
                                if is_non_compliant(enc.text, 'encryption'):
                                    issues.append(f"Non-compliant ESP encryption: {enc.text}")

                            for auth in profile.findall('.//esp/authentication/member'):
                                if auth.text != 'none' and is_non_compliant(auth.text, 'hash'):
                                    issues.append(f"Non-compliant ESP auth: {auth.text}")

                            dh_elem = profile.find('.//dh-group')
                            if dh_elem is not None and dh_elem.text:
                                if is_non_compliant(dh_elem.text, 'dh_group'):
                                    issues.append(f"Non-compliant DH group: {dh_elem.text}")

                            if issues:
                                print(f"  [FAIL] {name}")
                                for issue in issues:
                                    print(f"         - {issue}")
                            else:
                                print(f"  [PASS] {name}")
                    else:
                        print("  No IPSec profiles found")
                else:
                    print("  [ERROR] Could not retrieve IPSec profiles")

                # Check SSL/TLS Service Profiles
                print("\nSSL/TLS Service Profiles:")
                tls_root = api_call("/config/shared/ssl-tls-service-profile")
                if tls_root is not None:
                    profiles = tls_root.findall('.//entry')
                    if profiles:
                        for profile in profiles:
                            name = profile.get('name')
                            issues = []

                            min_ver = profile.find('.//protocol-settings/min-version')
                            if min_ver is not None and min_ver.text:
                                if is_non_compliant(min_ver.text, 'tls_version'):
                                    issues.append(f"Non-compliant min TLS: {min_ver.text}")

                            if issues:
                                print(f"  [FAIL] {name}")
                                for issue in issues:
                                    print(f"         - {issue}")
                            else:
                                print(f"  [PASS] {name}")
                    else:
                        print("  No SSL/TLS profiles found")
                else:
                    print("  [WARN] Could not retrieve SSL/TLS profiles")

                # Check Interface Management Profiles
                print("\nInterface Management Profiles:")
                mgmt_root = api_call("/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile")
                if mgmt_root is not None:
                    profiles = mgmt_root.findall('.//entry')
                    if profiles:
                        for profile in profiles:
                            name = profile.get('name')
                            issues = []

                            telnet = profile.find('.//telnet')
                            if telnet is not None and telnet.text == 'yes':
                                issues.append("Telnet enabled (insecure)")

                            http = profile.find('.//http')
                            if http is not None and http.text == 'yes':
                                issues.append("HTTP enabled (insecure)")

                            if issues:
                                print(f"  [FAIL] {name}")
                                for issue in issues:
                                    print(f"         - {issue}")
                            else:
                                print(f"  [PASS] {name}")
                    else:
                        print("  No management profiles found")
                else:
                    print("  [WARN] Could not retrieve management profiles")

                print("\n" + "=" * 50)
                print("FIREWALL AUDIT COMPLETE")
                print("=" * 50)

            except ImportError as e:
                print(f"[ERROR] Missing dependency: {e}")
                print("[ERROR] Run: pip install requests")

        except Exception as e:
            print(f"[ERROR] Firewall audit failed: {e}")
            import traceback
            print(f"[DEBUG] Traceback:\n{traceback.format_exc()}")


class CleanupMode:
    """FIPS Profile Cleanup Mode - Remove deployed FIPS profiles."""

    # Default profile name prefix
    DEFAULT_PREFIX = "ca-ois-fips"

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager

    def run(self):
        """Run cleanup mode."""
        print_section("FIPS Profile Cleanup")

        print(f"""
{Colors.WHITE}Remove FIPS 140-3 profiles for re-testing.{Colors.NC}

{Colors.YELLOW}This will delete profiles with the specified name prefix:{Colors.NC}
  - IKE Crypto Profiles (3)
  - IPSec Crypto Profiles (4)
  - SSL/TLS Service Profiles (3)
  - Interface Management Profiles (3)

{Colors.RED}WARNING: This operation cannot be undone!{Colors.NC}
""")

        # Determine available cleanup targets
        has_scm = self.config.has_scm_credentials()
        has_fw = self.config.has_firewall_credentials()

        if not has_scm and not has_fw:
            print_error("No credentials configured. Please configure either SCM or Firewall credentials.")
            if confirm("Configure credentials now?"):
                self._setup_credentials()
            else:
                return
            # Re-check after setup
            has_scm = self.config.has_scm_credentials()
            has_fw = self.config.has_firewall_credentials()
            if not has_scm and not has_fw:
                return

        # Show cleanup target options
        print(f"{Colors.CYAN}Select cleanup target:{Colors.NC}")
        options = []

        if has_scm:
            options.append(("SCM (Strata Cloud Manager)", "scm"))
        if has_fw:
            options.append(("Firewall (Direct)", "firewall"))

        if len(options) == 1:
            # Only one option available
            target = options[0][1]
            print(f"  Using: {options[0][0]}")
        else:
            for i, (label, _) in enumerate(options, 1):
                print(f"  {Colors.CYAN}[{i}]{Colors.NC} {label}")

            choice = get_choice("", [opt[0] for opt in options], default=1)
            target = options[choice - 1][1]

        if target == "scm":
            self._cleanup_scm()
        else:
            self._cleanup_firewall()

    def _setup_credentials(self):
        """Quick setup for credentials."""
        print(f"""
{Colors.CYAN}Which credentials do you want to configure?{Colors.NC}
  {Colors.CYAN}[1]{Colors.NC} SCM (Strata Cloud Manager)
  {Colors.CYAN}[2]{Colors.NC} Firewall (Direct)
""")
        choice = get_choice("", ["SCM", "Firewall"], default=1)

        if choice == 1:
            self._setup_scm_credentials()
        else:
            self._setup_firewall_credentials()

    def _setup_scm_credentials(self):
        """Quick setup for SCM credentials."""
        print_section("SCM Credentials")
        print(f"""
{Colors.YELLOW}Role Requirements:{Colors.NC}
  - Auditor: For audit/read operations
  - Security Admin: For creating IKE, IPSec, TLS profiles
  - Network Admin: {Colors.RED}Required{Colors.NC} for interface management profiles
    (Without Network Admin, use CLI fallback to deploy to firewall)
""")
        client_id = get_input("Client ID")
        client_secret = get_input("Client Secret", secret=True)
        tsg_id = get_input("TSG ID")
        self.config.set_scm_credentials(client_id, client_secret, tsg_id)
        print_success("SCM credentials saved")

    def _setup_firewall_credentials(self):
        """Quick setup for firewall credentials."""
        print_section("Firewall Credentials")
        host = get_input("Firewall IP or hostname")
        username = get_input("Admin username")
        password = get_input("Admin password", secret=True)
        self.config.set_firewall_credentials(host, username, password)
        print_success("Firewall credentials saved")

    def _get_profile_names(self, prefix: str) -> dict:
        """Generate all profile names based on prefix."""
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

    def _cleanup_scm(self):
        """Cleanup FIPS profiles from SCM."""
        creds = self.config.get_scm_credentials()

        # Ask for profile prefix
        print(f"""
{Colors.CYAN}Profile Naming:{Colors.NC}
Enter the profile name prefix used when profiles were created.
""")
        name_prefix = get_input("Profile name prefix", default=self.DEFAULT_PREFIX)

        # Ask for folder
        folder = get_input("SCM folder", default="Shared")

        profiles = self._get_profile_names(name_prefix)
        total_profiles = sum(len(p) for p in profiles.values())

        # Show what will be deleted
        print(f"""
{Colors.CYAN}Profiles to be deleted from SCM ({total_profiles} total):{Colors.NC}
  IKE:     {', '.join(profiles['ike'])}
  IPSec:   {', '.join(profiles['ipsec'])}
  SSL/TLS: {', '.join(profiles['ssl_tls'])}
  Mgmt:    {', '.join(profiles['mgmt'])}

{Colors.CYAN}Folder:{Colors.NC} {folder}
""")

        # Dry run first?
        dry_run = confirm("Perform dry-run first (show what would be deleted)?", default=True)

        if not dry_run:
            if not confirm(f"{Colors.RED}Delete these profiles from SCM?{Colors.NC}", default=False):
                print("Cleanup cancelled.")
                return

        try:
            # Add SCM client path
            scm_path = Path(__file__).parent / "09-scm-api-toolkit" / "06-python-sdk"
            if scm_path.exists():
                import sys
                sys.path.insert(0, str(scm_path))

            from scm_client import SCMClient

            # Create SCM client
            print_info("Connecting to SCM...")
            client = SCMClient(
                client_id=creds['client_id'],
                client_secret=creds['client_secret'],
                tsg_id=creds['tsg_id']
            )
            print_success("Connected to SCM")

            # Track stats
            deleted = 0
            not_found = 0
            errors = 0

            # Profile type handlers
            profile_handlers = {
                'ike': {
                    'name': 'IKE Crypto',
                    'list_fn': lambda: client.list_ike_crypto_profiles(folder),
                    'delete_fn': client.delete_ike_crypto_profile
                },
                'ipsec': {
                    'name': 'IPSec Crypto',
                    'list_fn': lambda: client.list_ipsec_crypto_profiles(folder),
                    'delete_fn': client.delete_ipsec_crypto_profile
                },
                'ssl_tls': {
                    'name': 'SSL/TLS Service',
                    'list_fn': lambda: client.list_tls_service_profiles(folder),
                    'delete_fn': client.delete_tls_service_profile
                },
                'mgmt': {
                    'name': 'Interface Management',
                    'list_fn': lambda: client.list_interface_mgmt_profiles(folder),
                    'delete_fn': client.delete_interface_mgmt_profile
                }
            }

            # Process each profile type
            mgmt_403_shown = False
            for profile_type, profile_names in profiles.items():
                handler = profile_handlers[profile_type]
                print(f"\n{Colors.CYAN}--- {handler['name']} Profiles ---{Colors.NC}")

                # Get existing profiles
                try:
                    existing = handler['list_fn']()
                    existing_map = {p.get('name'): p.get('id') for p in existing}
                except Exception as e:
                    if profile_type == 'mgmt' and "403" in str(e):
                        if not mgmt_403_shown:
                            print_warning("Interface management requires Network Admin role in SCM")
                            print_info("Use 'Cleanup > Firewall (CLI)' option instead")
                            mgmt_403_shown = True
                    else:
                        print_error(f"Failed to list profiles: {e}")
                    continue

                for profile_name in profile_names:
                    profile_id = existing_map.get(profile_name)

                    if not profile_id:
                        print(f"{Colors.CYAN}[SKIP]{Colors.NC} {profile_name} - not found")
                        not_found += 1
                        continue

                    if dry_run:
                        print(f"{Colors.MAGENTA}[DRY-RUN]{Colors.NC} Would delete: {profile_name} (ID: {profile_id})")
                        deleted += 1
                    else:
                        try:
                            handler['delete_fn'](profile_id)
                            print(f"{Colors.GREEN}[DELETED]{Colors.NC} {profile_name}")
                            deleted += 1
                        except Exception as e:
                            if profile_type == 'mgmt' and "403" in str(e):
                                if not mgmt_403_shown:
                                    print_warning("Interface management delete requires Network Admin role")
                                    print_info("Use 'Cleanup > Firewall (CLI)' option instead")
                                    mgmt_403_shown = True
                            else:
                                print(f"{Colors.RED}[ERROR]{Colors.NC} {profile_name}: {e}")
                            errors += 1

            # Summary
            print_section("Cleanup Summary")
            print(f"  {Colors.GREEN}Deleted:{Colors.NC}     {deleted}")
            print(f"  {Colors.CYAN}Not found:{Colors.NC}   {not_found}")
            print(f"  {Colors.RED}Errors:{Colors.NC}      {errors}")

            if dry_run:
                print(f"\n{Colors.MAGENTA}Dry-run complete. No changes were made.{Colors.NC}")
                if deleted > 0 and confirm("Proceed with actual deletion?", default=False):
                    # Re-run without dry-run
                    self._cleanup_scm_execute(client, name_prefix, folder)
            elif deleted > 0 and errors == 0:
                # Push changes
                if confirm("Push changes to devices?", default=True):
                    print_info("Pushing configuration...")
                    try:
                        result = client.push_config(folders=[folder], description="FIPS profile cleanup")
                        if result.get('success') or result.get('job_id'):
                            job_id = result.get('job_id', 'N/A')
                            print_success(f"Push initiated (Job ID: {job_id})")
                        else:
                            print_success("Push initiated")
                    except Exception as e:
                        print_warning(f"Push may have failed: {e}")
                        print_info("Please verify in SCM console")

        except ImportError as e:
            print_error(f"Missing dependency: {e}")
            print_info("Make sure scm_client.py is in 09-scm-api-toolkit/06-python-sdk/")
        except Exception as e:
            print_error(f"Cleanup failed: {e}")

    def _cleanup_scm_execute(self, client, name_prefix: str, folder: str):
        """Execute SCM cleanup without dry-run (called after dry-run confirmation)."""
        profiles = self._get_profile_names(name_prefix)
        deleted = 0
        errors = 0

        profile_handlers = {
            'ike': {
                'list_fn': lambda: client.list_ike_crypto_profiles(folder),
                'delete_fn': client.delete_ike_crypto_profile
            },
            'ipsec': {
                'list_fn': lambda: client.list_ipsec_crypto_profiles(folder),
                'delete_fn': client.delete_ipsec_crypto_profile
            },
            'ssl_tls': {
                'list_fn': lambda: client.list_tls_service_profiles(folder),
                'delete_fn': client.delete_tls_service_profile
            },
            'mgmt': {
                'list_fn': lambda: client.list_interface_mgmt_profiles(folder),
                'delete_fn': client.delete_interface_mgmt_profile
            }
        }

        print_info("Deleting profiles...")

        mgmt_403_shown = False
        for profile_type, profile_names in profiles.items():
            handler = profile_handlers[profile_type]

            try:
                existing = handler['list_fn']()
                existing_map = {p.get('name'): p.get('id') for p in existing}
            except Exception as e:
                if profile_type == 'mgmt' and "403" in str(e):
                    if not mgmt_403_shown:
                        print_warning("Interface management profiles require Network Admin role in SCM")
                        print_info("Use firewall cleanup option for interface management profiles")
                        mgmt_403_shown = True
                continue

            for profile_name in profile_names:
                profile_id = existing_map.get(profile_name)
                if not profile_id:
                    continue

                try:
                    handler['delete_fn'](profile_id)
                    print(f"{Colors.GREEN}[DELETED]{Colors.NC} {profile_name}")
                    deleted += 1
                except Exception as e:
                    if profile_type == 'mgmt' and "403" in str(e):
                        if not mgmt_403_shown:
                            print_warning("Interface management delete requires Network Admin role")
                            print_info("Use firewall cleanup option for interface management profiles")
                            mgmt_403_shown = True
                    else:
                        print(f"{Colors.RED}[ERROR]{Colors.NC} {profile_name}")
                    errors += 1

        print(f"\n{Colors.GREEN}Deleted:{Colors.NC} {deleted}  {Colors.RED}Errors:{Colors.NC} {errors}")

        if deleted > 0 and errors == 0:
            if confirm("Push changes to devices?", default=True):
                try:
                    result = client.push_config(folders=[folder], description="FIPS profile cleanup")
                    if result.get('success') or result.get('job_id'):
                        print_success("Push initiated")
                    else:
                        print_success("Push initiated")
                except Exception as e:
                    print_warning(f"Push may have failed: {e}")

    def _cleanup_firewall(self):
        """Cleanup FIPS profiles from firewall."""
        creds = self.config.get_firewall_credentials()

        # Ask for profile prefix
        print(f"""
{Colors.CYAN}Profile Naming:{Colors.NC}
Enter the profile name prefix used when profiles were created.
""")
        name_prefix = get_input("Profile name prefix", default=self.DEFAULT_PREFIX)

        profiles = self._get_profile_names(name_prefix)
        total_profiles = sum(len(p) for p in profiles.values())

        # Show what will be deleted
        print(f"""
{Colors.CYAN}Profiles to be deleted ({total_profiles} total):{Colors.NC}
  IKE:     {', '.join(profiles['ike'])}
  IPSec:   {', '.join(profiles['ipsec'])}
  SSL/TLS: {', '.join(profiles['ssl_tls'])}
  Mgmt:    {', '.join(profiles['mgmt'])}
""")

        # Dry run first?
        dry_run = confirm("Perform dry-run first (show what would be deleted)?", default=True)

        if not dry_run:
            if not confirm(f"{Colors.RED}Delete these profiles from {creds['host']}?{Colors.NC}", default=False):
                print("Cleanup cancelled.")
                return

        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            import xml.etree.ElementTree as ET

            base_url = f"https://{creds['host']}/api/"

            # Authenticate
            print_info(f"Connecting to {creds['host']}...")
            response = requests.get(
                base_url,
                params={
                    'type': 'keygen',
                    'user': creds['username'],
                    'password': creds['password']
                },
                verify=False,
                timeout=30
            )

            root = ET.fromstring(response.text)
            if root.get('status') != 'success':
                print_error("Failed to authenticate to firewall")
                return

            api_key = root.find('.//key').text
            print_success("Connected to firewall")

            # Track stats
            deleted = 0
            not_found = 0
            errors = 0

            # XPath templates for each profile type
            xpath_templates = {
                'ike': "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='{name}']",
                'ipsec': "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='{name}']",
                'ssl_tls': "/config/shared/ssl-tls-service-profile/entry[@name='{name}']",
                'mgmt': "/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile/entry[@name='{name}']"
            }

            type_names = {
                'ike': 'IKE Crypto',
                'ipsec': 'IPSec Crypto',
                'ssl_tls': 'SSL/TLS Service',
                'mgmt': 'Interface Management'
            }

            # Delete each profile type
            for profile_type, profile_list in profiles.items():
                print(f"\n{Colors.CYAN}--- {type_names[profile_type]} Profiles ---{Colors.NC}")

                for profile_name in profile_list:
                    xpath = xpath_templates[profile_type].format(name=profile_name)

                    # Check if exists
                    check_response = requests.post(
                        base_url,
                        data={
                            'type': 'config',
                            'action': 'get',
                            'xpath': xpath,
                            'key': api_key
                        },
                        verify=False,
                        timeout=30
                    )

                    check_root = ET.fromstring(check_response.text)
                    exists = check_root.get('status') == 'success' and check_root.find('.//entry') is not None

                    if not exists:
                        print(f"{Colors.CYAN}[SKIP]{Colors.NC} {profile_name} - not found")
                        not_found += 1
                        continue

                    if dry_run:
                        print(f"{Colors.MAGENTA}[DRY-RUN]{Colors.NC} Would delete: {profile_name}")
                        deleted += 1
                    else:
                        # Delete the profile
                        del_response = requests.post(
                            base_url,
                            data={
                                'type': 'config',
                                'action': 'delete',
                                'xpath': xpath,
                                'key': api_key
                            },
                            verify=False,
                            timeout=30
                        )

                        del_root = ET.fromstring(del_response.text)
                        if del_root.get('status') == 'success':
                            print(f"{Colors.GREEN}[DELETED]{Colors.NC} {profile_name}")
                            deleted += 1
                        else:
                            msg = del_root.find('.//msg')
                            error_msg = msg.text if msg is not None else "Unknown error"
                            print(f"{Colors.RED}[ERROR]{Colors.NC} {profile_name}: {error_msg}")
                            errors += 1

            # Summary
            print_section("Cleanup Summary")
            print(f"  {Colors.GREEN}Deleted:{Colors.NC}     {deleted}")
            print(f"  {Colors.CYAN}Not found:{Colors.NC}   {not_found}")
            print(f"  {Colors.RED}Errors:{Colors.NC}      {errors}")

            if dry_run:
                print(f"\n{Colors.MAGENTA}Dry-run complete. No changes were made.{Colors.NC}")
                if deleted > 0 and confirm("Proceed with actual deletion?", default=False):
                    # Re-run without dry-run
                    self._cleanup_firewall_execute(creds, name_prefix, api_key, base_url)
            elif deleted > 0 and errors == 0:
                # Commit changes
                if confirm("Commit changes to firewall?", default=True):
                    print_info("Committing changes...")
                    commit_response = requests.post(
                        base_url,
                        data={
                            'type': 'commit',
                            'cmd': '<commit></commit>',
                            'key': api_key
                        },
                        verify=False,
                        timeout=120
                    )
                    commit_root = ET.fromstring(commit_response.text)
                    if commit_root.get('status') == 'success':
                        job_id = commit_root.find('.//job')
                        if job_id is not None:
                            print_success(f"Commit initiated (Job ID: {job_id.text})")
                        else:
                            print_success("Commit successful")
                    else:
                        print_error("Commit failed")

        except ImportError:
            print_error("Missing dependency: requests")
            print_info("Run: pip install requests")
        except Exception as e:
            print_error(f"Cleanup failed: {e}")

    def _cleanup_firewall_execute(self, creds, name_prefix, api_key, base_url):
        """Execute cleanup without dry-run (called after dry-run confirmation)."""
        import requests
        import xml.etree.ElementTree as ET

        profiles = self._get_profile_names(name_prefix)
        deleted = 0
        errors = 0

        xpath_templates = {
            'ike': "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ike-crypto-profiles/entry[@name='{name}']",
            'ipsec': "/config/devices/entry[@name='localhost.localdomain']/network/ike/crypto-profiles/ipsec-crypto-profiles/entry[@name='{name}']",
            'ssl_tls': "/config/shared/ssl-tls-service-profile/entry[@name='{name}']",
            'mgmt': "/config/devices/entry[@name='localhost.localdomain']/network/profiles/interface-management-profile/entry[@name='{name}']"
        }

        print_info("Deleting profiles...")

        for profile_type, profile_list in profiles.items():
            for profile_name in profile_list:
                xpath = xpath_templates[profile_type].format(name=profile_name)

                # Check if exists first
                check_response = requests.post(
                    base_url,
                    data={'type': 'config', 'action': 'get', 'xpath': xpath, 'key': api_key},
                    verify=False, timeout=30
                )
                check_root = ET.fromstring(check_response.text)
                if check_root.get('status') != 'success' or check_root.find('.//entry') is None:
                    continue

                # Delete
                del_response = requests.post(
                    base_url,
                    data={'type': 'config', 'action': 'delete', 'xpath': xpath, 'key': api_key},
                    verify=False, timeout=30
                )
                del_root = ET.fromstring(del_response.text)
                if del_root.get('status') == 'success':
                    print(f"{Colors.GREEN}[DELETED]{Colors.NC} {profile_name}")
                    deleted += 1
                else:
                    print(f"{Colors.RED}[ERROR]{Colors.NC} {profile_name}")
                    errors += 1

        print(f"\n{Colors.GREEN}Deleted:{Colors.NC} {deleted}  {Colors.RED}Errors:{Colors.NC} {errors}")

        if deleted > 0 and errors == 0:
            if confirm("Commit changes?", default=True):
                commit_response = requests.post(
                    base_url,
                    data={'type': 'commit', 'cmd': '<commit></commit>', 'key': api_key},
                    verify=False, timeout=120
                )
                commit_root = ET.fromstring(commit_response.text)
                if commit_root.get('status') == 'success':
                    print_success("Commit successful")
                else:
                    print_error("Commit failed")


def main_menu(config_manager: ConfigManager):
    """Display main interactive menu."""
    first_run = True
    while True:
        clear_screen()
        print_banner(show_disclaimer=first_run)
        first_run = False

        # Show credential status
        print(f"{Colors.WHITE}Credential Status:{Colors.NC}")
        if config_manager.has_scm_credentials():
            scm_creds = config_manager.get_scm_credentials()
            scm_source = config_manager.get_credential_source('scm')
            source_label = f"[{scm_source}]" if scm_source == 'env' else ""
            print(f"  SCM: {Colors.GREEN}Configured{Colors.NC} {source_label} ({scm_creds.get('client_id', '')[:30]}...)")
        else:
            print(f"  SCM: {Colors.YELLOW}Not configured{Colors.NC}")

        if config_manager.has_firewall_credentials():
            fw_creds = config_manager.get_firewall_credentials()
            fw_source = config_manager.get_credential_source('firewall')
            source_label = f"[{fw_source}]" if fw_source == 'env' else ""
            print(f"  Firewall: {Colors.GREEN}Configured{Colors.NC} {source_label} ({fw_creds.get('host', '')})")
        else:
            print(f"  Firewall: {Colors.YELLOW}Not configured{Colors.NC}")

        print(f"\n{Colors.WHITE}Select an option:{Colors.NC}")
        print(f"  {Colors.CYAN}[1]{Colors.NC} Audit      - Validate configurations for FIPS compliance")
        print(f"  {Colors.CYAN}[2]{Colors.NC} Configure  - Deploy FIPS-compliant profiles")
        print(f"  {Colors.CYAN}[3]{Colors.NC} Cleanup    - Remove deployed FIPS profiles")
        print(f"  {Colors.CYAN}[4]{Colors.NC} Report     - Generate compliance reports")
        print(f"  {Colors.CYAN}[5]{Colors.NC} Setup      - Configure credentials")
        print(f"  {Colors.CYAN}[6]{Colors.NC} Help       - Show documentation links")
        print(f"  {Colors.CYAN}[0]{Colors.NC} Exit")

        choice = get_choice("", [
            "Audit Mode",
            "Configure Mode",
            "Cleanup Mode",
            "Report Mode",
            "Setup/Reconfigure",
            "Help",
            "Exit"
        ], default=1)

        if choice == 1:
            if not config_manager.has_scm_credentials() and not config_manager.has_firewall_credentials():
                print_error("No credentials configured. Running setup...")
                SetupWizard(config_manager).run()
            else:
                AuditMode(config_manager).run()
                input("\nPress Enter to continue...")
        elif choice == 2:
            ConfigureMode(config_manager).run()
            input("\nPress Enter to continue...")
        elif choice == 3:
            CleanupMode(config_manager).run()
            input("\nPress Enter to continue...")
        elif choice == 4:
            ReportMode(config_manager).run()
            input("\nPress Enter to continue...")
        elif choice == 5:
            SetupWizard(config_manager).run()
        elif choice == 6:
            show_help()
            input("\nPress Enter to continue...")
        elif choice == 7:
            print("\nGoodbye!")
            sys.exit(0)


def show_help():
    """Show help and documentation links."""
    print_section("Help & Documentation")

    print(f"""
{Colors.WHITE}FIPS 140-3 Compliance Toolkit Help{Colors.NC}

{Colors.YELLOW}Quick Start:{Colors.NC}
  1. Run 'python3 fips-toolkit.py' to start interactive mode
  2. Complete the setup wizard to configure credentials
  3. Use Audit mode to check current compliance status
  4. Use Configure mode to deploy FIPS-compliant profiles

{Colors.YELLOW}Command Line Options:{Colors.NC}
  python3 fips-toolkit.py              # Interactive mode
  python3 fips-toolkit.py audit        # Run audit directly
  python3 fips-toolkit.py configure    # Deploy FIPS profiles (SCM or Firewall)
  python3 fips-toolkit.py cleanup      # Remove FIPS profiles (SCM or Firewall)
  python3 fips-toolkit.py report       # Generate reports
  python3 fips-toolkit.py setup        # Run setup wizard
  python3 fips-toolkit.py clear        # Clear saved credentials

{Colors.YELLOW}FIPS 140-3 Compliant Algorithms:{Colors.NC}
  Encryption: AES-128/256-CBC, AES-128/256-GCM
  Hashing:    SHA-256, SHA-384, SHA-512
  DH Groups:  14 (2048-bit), 16 (4096-bit), 19-21 (ECC)
  TLS:        TLS 1.2, TLS 1.3

{Colors.YELLOW}Non-Compliant Algorithms (avoid):{Colors.NC}
  Encryption: 3DES, DES, NULL, RC4
  Hashing:    MD5, SHA-1
  DH Groups:  1, 2, 5, no-pfs
  TLS:        TLS 1.0, TLS 1.1, SSLv3

{Colors.YELLOW}Documentation:{Colors.NC}
  - FIPS 140-3 Standard: https://csrc.nist.gov/publications/detail/fips/140/3/final
  - SCM API Docs: https://pan.dev/scm/docs/home/
  - PAN-OS CLI Reference: https://docs.paloaltonetworks.com/pan-os

{Colors.YELLOW}Credential Setup:{Colors.NC}
  For detailed SCM credential setup, see: docs/SCM-CREDENTIAL-SETUP.md

  Role recommendations:
  - Audit only:  Assign 'Auditor' role (read-only)
  - Configure:   Assign 'Security Administrator' role (read/write)

{Colors.YELLOW}Troubleshooting:{Colors.NC}
  Enable debug mode to see detailed API responses:
    export FIPS_TOOLKIT_DEBUG=1
    python3 fips-toolkit.py

  Common issues:
  - "None" errors: Enable debug mode to see full API response
  - 403 Forbidden (SCM): Add 'Network Admin' role for interface management
  - 404 Not Found: Check API path (use /sse/config/v1/ for Prisma Access)

{Colors.YELLOW}Support:{Colors.NC}
  For issues, please check the README.md or submit an issue on GitHub.
""")


def main():
    """Main entry point."""
    # Load environment variables from .env file (if present)
    env_file = load_dotenv()

    parser = argparse.ArgumentParser(
        description="FIPS 140-3 Compliance Toolkit for Palo Alto Networks",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 fips-toolkit.py              # Interactive mode
  python3 fips-toolkit.py audit        # Run compliance audit
  python3 fips-toolkit.py configure    # Deploy FIPS profiles (SCM or Firewall)
  python3 fips-toolkit.py cleanup      # Remove FIPS profiles (SCM or Firewall)
  python3 fips-toolkit.py setup        # Configure credentials
        """
    )

    parser.add_argument(
        'command',
        nargs='?',
        choices=['audit', 'configure', 'cleanup', 'report', 'setup', 'clear', 'help'],
        help='Command to run (default: interactive menu)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'FIPS 140-3 Toolkit v{__version__}'
    )

    args = parser.parse_args()

    # Initialize configuration manager
    config_manager = ConfigManager()

    # Handle commands
    if args.command == 'clear':
        if confirm("Clear all saved credentials?", default=False):
            config_manager.clear_credentials()
            print_success("Credentials cleared")
        sys.exit(0)

    elif args.command == 'setup':
        SetupWizard(config_manager).run()
        main_menu(config_manager)

    elif args.command == 'audit':
        print_banner()
        if not config_manager.has_scm_credentials() and not config_manager.has_firewall_credentials():
            print_error("No credentials configured. Run setup first.")
            print_info("Run: python3 fips-toolkit.py setup")
            sys.exit(1)
        AuditMode(config_manager).run()

    elif args.command == 'configure':
        print_banner()
        ConfigureMode(config_manager).run()

    elif args.command == 'cleanup':
        print_banner()
        CleanupMode(config_manager).run()

    elif args.command == 'report':
        print_banner()
        ReportMode(config_manager).run()

    elif args.command == 'help':
        print_banner()
        show_help()

    else:
        # Interactive mode
        if not config_manager.has_scm_credentials() and not config_manager.has_firewall_credentials():
            # First run - show setup wizard
            SetupWizard(config_manager).run()

        main_menu(config_manager)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Goodbye!")
        sys.exit(0)
