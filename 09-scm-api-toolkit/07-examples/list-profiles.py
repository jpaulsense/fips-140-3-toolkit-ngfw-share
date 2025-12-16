#!/usr/bin/env python3
"""
List Cryptographic Profiles from Strata Cloud Manager

Usage:
    export SCM_CLIENT_ID="your-client-id"
    export SCM_CLIENT_SECRET="your-client-secret"
    export SCM_TSG_ID="your-tsg-id"
    python3 list-profiles.py [--folder Shared]
"""

import os
import sys
import json
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '06-python-sdk'))

from scm_client import SCMClient


def list_all_profiles(client: SCMClient, folder: str = "Shared"):
    """List all cryptographic profiles."""

    print("=" * 70)
    print(f"CRYPTOGRAPHIC PROFILES - Folder: {folder}")
    print("=" * 70)

    # IKE Crypto Profiles
    print("\n[IKE CRYPTO PROFILES]")
    print("-" * 70)
    ike_profiles = client.list_ike_crypto_profiles(folder=folder)
    if ike_profiles:
        print(f"{'Name':<35} {'Encryption':<20} {'Hash':<15} {'DH Groups'}")
        print("-" * 70)
        for p in ike_profiles:
            enc = ", ".join(p.get("encryption", [])[:2])
            if len(p.get("encryption", [])) > 2:
                enc += "..."
            auth = ", ".join(p.get("authentication", [])[:2])
            dh = ", ".join(p.get("dh_group", [])[:2])
            if len(p.get("dh_group", [])) > 2:
                dh += "..."
            print(f"{p['name']:<35} {enc:<20} {auth:<15} {dh}")
    else:
        print("  No IKE crypto profiles found")

    # IPSec Crypto Profiles
    print("\n[IPSEC CRYPTO PROFILES]")
    print("-" * 70)
    ipsec_profiles = client.list_ipsec_crypto_profiles(folder=folder)
    if ipsec_profiles:
        print(f"{'Name':<35} {'ESP Encryption':<20} {'ESP Auth':<15} {'PFS Group'}")
        print("-" * 70)
        for p in ipsec_profiles:
            esp = p.get("esp", {})
            enc = ", ".join(esp.get("encryption", [])[:2])
            if len(esp.get("encryption", [])) > 2:
                enc += "..."
            auth = ", ".join(esp.get("authentication", [])[:2])
            dh = p.get("dh_group", "none")
            print(f"{p['name']:<35} {enc:<20} {auth:<15} {dh}")
    else:
        print("  No IPSec crypto profiles found")

    # TLS Service Profiles
    print("\n[TLS SERVICE PROFILES]")
    print("-" * 70)
    tls_profiles = client.list_tls_service_profiles(folder=folder)
    if tls_profiles:
        print(f"{'Name':<35} {'Min TLS':<15} {'Max TLS':<15} {'Certificate'}")
        print("-" * 70)
        for p in tls_profiles:
            settings = p.get("protocol_settings", {})
            min_ver = settings.get("min_version", "N/A")
            max_ver = settings.get("max_version", "N/A")
            cert = p.get("certificate", "N/A")[:25]
            print(f"{p['name']:<35} {min_ver:<15} {max_ver:<15} {cert}")
    else:
        print("  No TLS service profiles found")

    # Interface Management Profiles
    print("\n[INTERFACE MANAGEMENT PROFILES]")
    print("-" * 70)
    mgmt_profiles = client.list_interface_mgmt_profiles(folder=folder)
    if mgmt_profiles:
        print(f"{'Name':<35} {'HTTPS':<8} {'SSH':<8} {'HTTP':<8} {'Telnet'}")
        print("-" * 70)
        for p in mgmt_profiles:
            https = "Yes" if p.get("https") else "No"
            ssh = "Yes" if p.get("ssh") else "No"
            http = "Yes" if p.get("http") else "No"
            telnet = "Yes" if p.get("telnet") else "No"
            print(f"{p['name']:<35} {https:<8} {ssh:<8} {http:<8} {telnet}")
    else:
        print("  No interface management profiles found")

    print("\n" + "=" * 70)

    # Summary
    total = len(ike_profiles) + len(ipsec_profiles) + len(tls_profiles) + len(mgmt_profiles)
    print(f"Total profiles: {total}")
    print(f"  IKE: {len(ike_profiles)}")
    print(f"  IPSec: {len(ipsec_profiles)}")
    print(f"  TLS: {len(tls_profiles)}")
    print(f"  Management: {len(mgmt_profiles)}")


def main():
    parser = argparse.ArgumentParser(description="List SCM cryptographic profiles")
    parser.add_argument("--client-id", default=os.environ.get("SCM_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.environ.get("SCM_CLIENT_SECRET"))
    parser.add_argument("--tsg-id", default=os.environ.get("SCM_TSG_ID"))
    parser.add_argument("--folder", default="Shared", help="Configuration folder")
    parser.add_argument("--json", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if not all([args.client_id, args.client_secret, args.tsg_id]):
        print("ERROR: Missing credentials")
        sys.exit(1)

    client = SCMClient(
        client_id=args.client_id,
        client_secret=args.client_secret,
        tsg_id=args.tsg_id
    )

    if args.json:
        output = {
            "ike_crypto_profiles": client.list_ike_crypto_profiles(folder=args.folder),
            "ipsec_crypto_profiles": client.list_ipsec_crypto_profiles(folder=args.folder),
            "tls_service_profiles": client.list_tls_service_profiles(folder=args.folder),
            "interface_mgmt_profiles": client.list_interface_mgmt_profiles(folder=args.folder)
        }
        print(json.dumps(output, indent=2))
    else:
        list_all_profiles(client, folder=args.folder)


if __name__ == "__main__":
    main()
