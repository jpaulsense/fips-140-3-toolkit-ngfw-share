#!/usr/bin/env python3
"""
Deploy FIPS 140-3 Compliant Profiles to Strata Cloud Manager

This script creates all FIPS 140-3 compliant cryptographic profiles
and pushes them to managed devices.

Usage:
    export SCM_CLIENT_ID="your-client-id"
    export SCM_CLIENT_SECRET="your-client-secret"
    export SCM_TSG_ID="your-tsg-id"
    python3 deploy-fips-profiles.py
"""

import os
import sys
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '06-python-sdk'))

from scm_client import SCMClient, SCMAPIError


def deploy_fips_profiles(
    client: SCMClient,
    folder: str = "Shared",
    certificate: str = None,
    skip_push: bool = False
):
    """
    Deploy all FIPS 140-3 compliant profiles.

    Args:
        client: SCM client instance
        folder: Target folder
        certificate: Certificate name for TLS profiles
        skip_push: Skip configuration push
    """
    print("=" * 60)
    print("FIPS 140-3 PROFILE DEPLOYMENT")
    print("=" * 60)

    created_profiles = []
    errors = []

    # ==================== IKE Crypto Profiles ====================
    print("\n[IKE CRYPTO PROFILES]")

    ike_tiers = ["max", "recommended", "compat"]
    for tier in ike_tiers:
        try:
            result = client.create_fips_ike_profile(tier=tier, folder=folder)
            print(f"  [CREATED] fips-ike-crypto-{tier}")
            created_profiles.append(f"IKE: fips-ike-crypto-{tier}")
        except SCMAPIError as e:
            if e.status_code == 409:
                print(f"  [EXISTS] fips-ike-crypto-{tier}")
            else:
                print(f"  [ERROR] fips-ike-crypto-{tier}: {e}")
                errors.append(f"IKE {tier}: {e}")

    # ==================== IPSec Crypto Profiles ====================
    print("\n[IPSEC CRYPTO PROFILES]")

    ipsec_tiers = ["max", "recommended", "compat", "gp"]
    for tier in ipsec_tiers:
        try:
            result = client.create_fips_ipsec_profile(tier=tier, folder=folder)
            print(f"  [CREATED] fips-ipsec-crypto-{tier}")
            created_profiles.append(f"IPSec: fips-ipsec-crypto-{tier}")
        except SCMAPIError as e:
            if e.status_code == 409:
                print(f"  [EXISTS] fips-ipsec-crypto-{tier}")
            else:
                print(f"  [ERROR] fips-ipsec-crypto-{tier}: {e}")
                errors.append(f"IPSec {tier}: {e}")

    # ==================== TLS Service Profiles ====================
    print("\n[TLS SERVICE PROFILES]")

    if certificate:
        tls_tiers = ["max", "recommended", "tls13"]
        for tier in tls_tiers:
            try:
                result = client.create_fips_tls_profile(
                    tier=tier,
                    certificate=certificate,
                    folder=folder
                )
                name = f"fips-ssl-tls-{tier}" if tier != "tls13" else "fips-ssl-tls-1-3-only"
                print(f"  [CREATED] {name}")
                created_profiles.append(f"TLS: {name}")
            except SCMAPIError as e:
                if e.status_code == 409:
                    name = f"fips-ssl-tls-{tier}" if tier != "tls13" else "fips-ssl-tls-1-3-only"
                    print(f"  [EXISTS] {name}")
                else:
                    print(f"  [ERROR] fips-ssl-tls-{tier}: {e}")
                    errors.append(f"TLS {tier}: {e}")
    else:
        print("  [SKIPPED] No certificate specified (use --certificate)")

    # ==================== Interface Management Profiles ====================
    print("\n[INTERFACE MANAGEMENT PROFILES]")

    mgmt_configs = [
        ("fips-mgmt-profile", True),
        ("fips-https-only", False)
    ]

    for name, ssh_enabled in mgmt_configs:
        try:
            result = client.create_fips_mgmt_profile(
                name=name,
                ssh=ssh_enabled,
                folder=folder
            )
            print(f"  [CREATED] {name}")
            created_profiles.append(f"Mgmt: {name}")
        except SCMAPIError as e:
            if e.status_code == 409:
                print(f"  [EXISTS] {name}")
            else:
                print(f"  [ERROR] {name}: {e}")
                errors.append(f"Mgmt {name}: {e}")

    # ==================== Summary ====================
    print("\n" + "=" * 60)
    print("DEPLOYMENT SUMMARY")
    print("=" * 60)
    print(f"Profiles created: {len(created_profiles)}")
    print(f"Errors: {len(errors)}")

    if created_profiles:
        print("\nCreated profiles:")
        for p in created_profiles:
            print(f"  - {p}")

    if errors:
        print("\nErrors encountered:")
        for e in errors:
            print(f"  - {e}")

    # ==================== Push Configuration ====================
    if not skip_push and created_profiles:
        print("\n[PUSHING CONFIGURATION]")
        try:
            result = client.push_config(
                folders=[folder],
                description="FIPS 140-3 compliant profiles deployment"
            )
            job_id = result.get("job_id")
            print(f"  Push initiated, job ID: {job_id}")

            if job_id:
                print("  Waiting for job to complete...")
                final_status = client.wait_for_job(job_id, timeout=300)
                print(f"  Job completed: {final_status.get('status_str', 'OK')}")

        except SCMAPIError as e:
            print(f"  [ERROR] Push failed: {e}")

    print("\n" + "=" * 60)
    print("DEPLOYMENT COMPLETE")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Deploy FIPS 140-3 compliant profiles to SCM"
    )
    parser.add_argument(
        "--client-id",
        default=os.environ.get("SCM_CLIENT_ID"),
        help="OAuth client ID"
    )
    parser.add_argument(
        "--client-secret",
        default=os.environ.get("SCM_CLIENT_SECRET"),
        help="OAuth client secret"
    )
    parser.add_argument(
        "--tsg-id",
        default=os.environ.get("SCM_TSG_ID"),
        help="Tenant Service Group ID"
    )
    parser.add_argument(
        "--folder",
        default="Shared",
        help="Configuration folder (default: Shared)"
    )
    parser.add_argument(
        "--certificate",
        help="Certificate name for TLS profiles"
    )
    parser.add_argument(
        "--skip-push",
        action="store_true",
        help="Skip configuration push"
    )

    args = parser.parse_args()

    # Validate credentials
    if not all([args.client_id, args.client_secret, args.tsg_id]):
        print("ERROR: Missing credentials. Set SCM_CLIENT_ID, SCM_CLIENT_SECRET, and SCM_TSG_ID")
        print("       Or provide --client-id, --client-secret, and --tsg-id arguments")
        sys.exit(1)

    # Create client and deploy
    client = SCMClient(
        client_id=args.client_id,
        client_secret=args.client_secret,
        tsg_id=args.tsg_id
    )

    deploy_fips_profiles(
        client=client,
        folder=args.folder,
        certificate=args.certificate,
        skip_push=args.skip_push
    )


if __name__ == "__main__":
    main()
