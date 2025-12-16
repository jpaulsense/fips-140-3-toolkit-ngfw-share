#!/usr/bin/env python3
"""
Validate FIPS 140-3 Compliance of SCM Profiles

Checks all cryptographic profiles in Strata Cloud Manager for
FIPS 140-3 compliance.

Usage:
    export SCM_CLIENT_ID="your-client-id"
    export SCM_CLIENT_SECRET="your-client-secret"
    export SCM_TSG_ID="your-tsg-id"
    python3 validate-compliance.py [--folder Shared]
"""

import os
import sys
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '06-python-sdk'))

from scm_client import SCMClient
from fips_profiles import (
    validate_ike_profile,
    validate_ipsec_profile,
    validate_tls_profile,
    validate_mgmt_profile
)


class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[0;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'


def print_pass(message):
    print(f"  {Colors.GREEN}[PASS]{Colors.NC} {message}")


def print_fail(message):
    print(f"  {Colors.RED}[FAIL]{Colors.NC} {message}")


def print_warn(message):
    print(f"  {Colors.YELLOW}[WARN]{Colors.NC} {message}")


def print_info(message):
    print(f"  {Colors.BLUE}[INFO]{Colors.NC} {message}")


def validate_profiles(client: SCMClient, folder: str = "Shared"):
    """Validate all profiles for FIPS 140-3 compliance."""

    print("=" * 70)
    print("FIPS 140-3 COMPLIANCE VALIDATION")
    print("=" * 70)
    print(f"Folder: {folder}")

    pass_count = 0
    fail_count = 0
    warn_count = 0

    # ==================== IKE Crypto Profiles ====================
    print(f"\n{Colors.BLUE}[IKE CRYPTO PROFILES]{Colors.NC}")
    print("-" * 70)

    ike_profiles = client.list_ike_crypto_profiles(folder=folder)
    for profile in ike_profiles:
        name = profile.get("name", "Unknown")
        findings = validate_ike_profile(profile)

        if findings:
            print_fail(f"{name}")
            for f in findings:
                print(f"       - {f}")
            fail_count += 1
        else:
            print_pass(f"{name}")
            pass_count += 1

    if not ike_profiles:
        print_info("No IKE crypto profiles found")

    # ==================== IPSec Crypto Profiles ====================
    print(f"\n{Colors.BLUE}[IPSEC CRYPTO PROFILES]{Colors.NC}")
    print("-" * 70)

    ipsec_profiles = client.list_ipsec_crypto_profiles(folder=folder)
    for profile in ipsec_profiles:
        name = profile.get("name", "Unknown")
        findings = validate_ipsec_profile(profile)

        if findings:
            print_fail(f"{name}")
            for f in findings:
                print(f"       - {f}")
            fail_count += 1
        else:
            print_pass(f"{name}")
            pass_count += 1

    if not ipsec_profiles:
        print_info("No IPSec crypto profiles found")

    # ==================== TLS Service Profiles ====================
    print(f"\n{Colors.BLUE}[TLS SERVICE PROFILES]{Colors.NC}")
    print("-" * 70)

    tls_profiles = client.list_tls_service_profiles(folder=folder)
    for profile in tls_profiles:
        name = profile.get("name", "Unknown")
        findings = validate_tls_profile(profile)

        if findings:
            print_fail(f"{name}")
            for f in findings:
                print(f"       - {f}")
            fail_count += 1
        else:
            print_pass(f"{name}")
            pass_count += 1

        # Check certificate
        if not profile.get("certificate"):
            print_warn(f"       No certificate assigned")
            warn_count += 1

    if not tls_profiles:
        print_info("No TLS service profiles found")

    # ==================== Interface Management Profiles ====================
    print(f"\n{Colors.BLUE}[INTERFACE MANAGEMENT PROFILES]{Colors.NC}")
    print("-" * 70)

    mgmt_profiles = client.list_interface_mgmt_profiles(folder=folder)
    for profile in mgmt_profiles:
        name = profile.get("name", "Unknown")
        findings = validate_mgmt_profile(profile)

        if findings:
            print_fail(f"{name}")
            for f in findings:
                print(f"       - {f}")
            fail_count += 1
        else:
            print_pass(f"{name}")
            pass_count += 1

        # Check for any management access
        if not profile.get("https") and not profile.get("ssh"):
            print_warn(f"       No secure management protocols enabled")
            warn_count += 1

    if not mgmt_profiles:
        print_info("No interface management profiles found")

    # ==================== Summary ====================
    print("\n" + "=" * 70)
    print("COMPLIANCE SUMMARY")
    print("=" * 70)
    print(f"PASSED:   {pass_count}")
    print(f"FAILED:   {fail_count}")
    print(f"WARNINGS: {warn_count}")

    print("\n" + "=" * 70)
    if fail_count == 0:
        print(f"{Colors.GREEN}FIPS 140-3 COMPLIANCE: PASSED{Colors.NC}")
        return 0
    else:
        print(f"{Colors.RED}FIPS 140-3 COMPLIANCE: FAILED{Colors.NC}")
        print(f"\n{fail_count} non-compliant profile(s) found.")
        print("Review the [FAIL] items above and update with compliant algorithms.")
        return 1


def main():
    parser = argparse.ArgumentParser(description="Validate FIPS 140-3 compliance")
    parser.add_argument("--client-id", default=os.environ.get("SCM_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.environ.get("SCM_CLIENT_SECRET"))
    parser.add_argument("--tsg-id", default=os.environ.get("SCM_TSG_ID"))
    parser.add_argument("--folder", default="Shared", help="Configuration folder")

    args = parser.parse_args()

    if not all([args.client_id, args.client_secret, args.tsg_id]):
        print("ERROR: Missing credentials")
        sys.exit(1)

    client = SCMClient(
        client_id=args.client_id,
        client_secret=args.client_secret,
        tsg_id=args.tsg_id
    )

    exit_code = validate_profiles(client, folder=args.folder)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
