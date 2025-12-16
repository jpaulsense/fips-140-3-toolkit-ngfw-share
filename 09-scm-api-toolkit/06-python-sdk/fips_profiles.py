#!/usr/bin/env python3
"""
FIPS 140-3 Compliant Profile Definitions for Strata Cloud Manager

This module contains predefined FIPS 140-3 compliant cryptographic profile
configurations for use with the SCM API.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any


# ==================== FIPS 140-3 Algorithm Definitions ====================

class FIPSAlgorithms:
    """FIPS 140-3 approved cryptographic algorithms."""

    # IKE/IPSec Encryption
    ENCRYPTION_COMPLIANT = [
        "aes-128-cbc",
        "aes-192-cbc",
        "aes-256-cbc",
        "aes-128-gcm",
        "aes-256-gcm"
    ]

    ENCRYPTION_NON_COMPLIANT = [
        "3des",
        "des",
        "null",
        "rc4"
    ]

    # Hash Algorithms
    HASH_COMPLIANT = [
        "sha256",
        "sha384",
        "sha512"
    ]

    HASH_NON_COMPLIANT = [
        "md5",
        "sha1"
    ]

    # Diffie-Hellman Groups
    DH_GROUP_COMPLIANT = [
        "group14",  # 2048-bit MODP
        "group15",  # 3072-bit MODP
        "group16",  # 4096-bit MODP
        "group19",  # 256-bit ECP (P-256)
        "group20",  # 384-bit ECP (P-384)
        "group21"   # 521-bit ECP (P-521)
    ]

    DH_GROUP_NON_COMPLIANT = [
        "group1",
        "group2",
        "group5",
        "no-pfs"
    ]

    # TLS Versions
    TLS_COMPLIANT = ["tls1-2", "tls1-3", "max"]
    TLS_NON_COMPLIANT = ["tls1-0", "tls1-1"]


# ==================== IKE Crypto Profiles ====================

@dataclass
class IKECryptoProfile:
    """IKE Phase 1 crypto profile definition."""
    name: str
    encryption: List[str]
    authentication: List[str]
    dh_group: List[str]
    lifetime_hours: int = 8
    folder: str = "Shared"

    def to_api_payload(self) -> Dict[str, Any]:
        """Convert to SCM API payload format."""
        return {
            "name": self.name,
            "encryption": self.encryption,
            "authentication": self.authentication,
            "dh_group": self.dh_group,
            "lifetime": {"hours": self.lifetime_hours}
        }

    def is_fips_compliant(self) -> bool:
        """Check if profile is FIPS 140-3 compliant."""
        enc_ok = all(e in FIPSAlgorithms.ENCRYPTION_COMPLIANT for e in self.encryption)
        hash_ok = all(h in FIPSAlgorithms.HASH_COMPLIANT for h in self.authentication)
        dh_ok = all(d in FIPSAlgorithms.DH_GROUP_COMPLIANT for d in self.dh_group)
        return enc_ok and hash_ok and dh_ok


# Predefined FIPS-compliant IKE profiles
IKE_PROFILES = {
    "max": IKECryptoProfile(
        name="fips-ike-crypto-max",
        encryption=["aes-256-gcm"],
        authentication=["sha512"],
        dh_group=["group20"],
        lifetime_hours=8
    ),
    "recommended": IKECryptoProfile(
        name="fips-ike-crypto-recommended",
        encryption=["aes-256-cbc", "aes-128-gcm"],
        authentication=["sha384", "sha256"],
        dh_group=["group20", "group19"],
        lifetime_hours=8
    ),
    "compat": IKECryptoProfile(
        name="fips-ike-crypto-compat",
        encryption=["aes-256-cbc", "aes-256-gcm", "aes-128-cbc", "aes-128-gcm"],
        authentication=["sha512", "sha384", "sha256"],
        dh_group=["group20", "group19", "group16", "group14"],
        lifetime_hours=8
    )
}


# ==================== IPSec Crypto Profiles ====================

@dataclass
class IPSecCryptoProfile:
    """IPSec Phase 2 crypto profile definition."""
    name: str
    esp_encryption: List[str]
    esp_authentication: List[str]
    dh_group: str
    lifetime_hours: int = 1
    lifesize_gb: int = None
    folder: str = "Shared"

    def to_api_payload(self) -> Dict[str, Any]:
        """Convert to SCM API payload format."""
        payload = {
            "name": self.name,
            "esp": {
                "encryption": self.esp_encryption,
                "authentication": self.esp_authentication
            },
            "dh_group": self.dh_group,
            "lifetime": {"hours": self.lifetime_hours}
        }
        if self.lifesize_gb:
            payload["lifesize"] = {"gb": self.lifesize_gb}
        return payload

    def is_fips_compliant(self) -> bool:
        """Check if profile is FIPS 140-3 compliant."""
        enc_ok = all(e in FIPSAlgorithms.ENCRYPTION_COMPLIANT for e in self.esp_encryption)
        auth_ok = all(a in FIPSAlgorithms.HASH_COMPLIANT or a == "none" for a in self.esp_authentication)
        dh_ok = self.dh_group in FIPSAlgorithms.DH_GROUP_COMPLIANT
        return enc_ok and auth_ok and dh_ok


# Predefined FIPS-compliant IPSec profiles
IPSEC_PROFILES = {
    "max": IPSecCryptoProfile(
        name="fips-ipsec-crypto-max",
        esp_encryption=["aes-256-gcm"],
        esp_authentication=["sha512"],
        dh_group="group20",
        lifetime_hours=1,
        lifesize_gb=100
    ),
    "recommended": IPSecCryptoProfile(
        name="fips-ipsec-crypto-recommended",
        esp_encryption=["aes-256-gcm", "aes-128-gcm"],
        esp_authentication=["sha384", "sha256"],
        dh_group="group20",
        lifetime_hours=1
    ),
    "compat": IPSecCryptoProfile(
        name="fips-ipsec-crypto-compat",
        esp_encryption=["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
        esp_authentication=["sha512", "sha384", "sha256"],
        dh_group="group14",
        lifetime_hours=1
    ),
    "gp": IPSecCryptoProfile(
        name="fips-ipsec-crypto-gp",
        esp_encryption=["aes-256-gcm", "aes-128-gcm"],
        esp_authentication=["sha256"],
        dh_group="group19",
        lifetime_hours=1
    )
}


# ==================== TLS Service Profiles ====================

@dataclass
class TLSServiceProfile:
    """TLS service profile definition."""
    name: str
    min_version: str
    max_version: str = "max"
    certificate: str = None
    folder: str = "Shared"

    def to_api_payload(self) -> Dict[str, Any]:
        """Convert to SCM API payload format."""
        payload = {
            "name": self.name,
            "protocol_settings": {
                "min_version": self.min_version,
                "max_version": self.max_version
            }
        }
        if self.certificate:
            payload["certificate"] = self.certificate
        return payload

    def is_fips_compliant(self) -> bool:
        """Check if profile is FIPS 140-3 compliant."""
        return self.min_version in FIPSAlgorithms.TLS_COMPLIANT


# Predefined FIPS-compliant TLS profiles
TLS_PROFILES = {
    "max": TLSServiceProfile(
        name="fips-ssl-tls-max",
        min_version="tls1-2",
        max_version="tls1-3"
    ),
    "recommended": TLSServiceProfile(
        name="fips-ssl-tls-recommended",
        min_version="tls1-2",
        max_version="max"
    ),
    "tls13": TLSServiceProfile(
        name="fips-ssl-tls-1-3-only",
        min_version="tls1-3",
        max_version="tls1-3"
    )
}


# ==================== Interface Management Profiles ====================

@dataclass
class InterfaceManagementProfile:
    """Interface management profile definition."""
    name: str
    https: bool = True
    ssh: bool = True
    http: bool = False
    telnet: bool = False
    ping: bool = True
    snmp: bool = False
    permitted_ip: List[str] = field(default_factory=list)
    folder: str = "Shared"

    def to_api_payload(self) -> Dict[str, Any]:
        """Convert to SCM API payload format."""
        payload = {
            "name": self.name,
            "https": self.https,
            "ssh": self.ssh,
            "http": self.http,
            "telnet": self.telnet,
            "ping": self.ping,
            "snmp": self.snmp
        }
        if self.permitted_ip:
            payload["permitted_ip"] = self.permitted_ip
        return payload

    def is_fips_compliant(self) -> bool:
        """Check if profile is FIPS 140-3 compliant."""
        # HTTP and Telnet are non-compliant
        return not self.http and not self.telnet


# Predefined FIPS-compliant management profiles
MGMT_PROFILES = {
    "full": InterfaceManagementProfile(
        name="fips-mgmt-profile",
        https=True,
        ssh=True,
        http=False,
        telnet=False,
        ping=True
    ),
    "https_only": InterfaceManagementProfile(
        name="fips-https-only",
        https=True,
        ssh=False,
        http=False,
        telnet=False,
        ping=True
    ),
    "monitoring": InterfaceManagementProfile(
        name="fips-monitoring-only",
        https=False,
        ssh=False,
        http=False,
        telnet=False,
        ping=True,
        snmp=True
    )
}


# ==================== Validation Functions ====================

def validate_ike_profile(profile: Dict) -> List[str]:
    """
    Validate IKE profile for FIPS 140-3 compliance.

    Args:
        profile: Profile dictionary with encryption, authentication, dh_group

    Returns:
        List of non-compliant findings (empty if compliant)
    """
    findings = []

    for enc in profile.get("encryption", []):
        if enc in FIPSAlgorithms.ENCRYPTION_NON_COMPLIANT:
            findings.append(f"Non-compliant encryption: {enc}")

    for hash_alg in profile.get("authentication", []):
        if hash_alg in FIPSAlgorithms.HASH_NON_COMPLIANT:
            findings.append(f"Non-compliant hash: {hash_alg}")

    for dh in profile.get("dh_group", []):
        if dh in FIPSAlgorithms.DH_GROUP_NON_COMPLIANT:
            findings.append(f"Non-compliant DH group: {dh}")

    return findings


def validate_ipsec_profile(profile: Dict) -> List[str]:
    """
    Validate IPSec profile for FIPS 140-3 compliance.

    Args:
        profile: Profile dictionary with esp.encryption, esp.authentication, dh_group

    Returns:
        List of non-compliant findings (empty if compliant)
    """
    findings = []

    esp = profile.get("esp", {})

    for enc in esp.get("encryption", []):
        if enc in FIPSAlgorithms.ENCRYPTION_NON_COMPLIANT:
            findings.append(f"Non-compliant ESP encryption: {enc}")

    for auth in esp.get("authentication", []):
        if auth in FIPSAlgorithms.HASH_NON_COMPLIANT:
            findings.append(f"Non-compliant ESP authentication: {auth}")

    dh_group = profile.get("dh_group", "")
    if dh_group in FIPSAlgorithms.DH_GROUP_NON_COMPLIANT:
        findings.append(f"Non-compliant DH group: {dh_group}")

    return findings


def validate_tls_profile(profile: Dict) -> List[str]:
    """
    Validate TLS profile for FIPS 140-3 compliance.

    Args:
        profile: Profile dictionary with protocol_settings.min_version

    Returns:
        List of non-compliant findings (empty if compliant)
    """
    findings = []

    settings = profile.get("protocol_settings", {})
    min_version = settings.get("min_version", "")

    if min_version in FIPSAlgorithms.TLS_NON_COMPLIANT:
        findings.append(f"Non-compliant TLS version: {min_version}")

    return findings


def validate_mgmt_profile(profile: Dict) -> List[str]:
    """
    Validate management profile for FIPS 140-3 compliance.

    Args:
        profile: Profile dictionary with http, telnet fields

    Returns:
        List of non-compliant findings (empty if compliant)
    """
    findings = []

    if profile.get("http"):
        findings.append("HTTP management enabled (non-encrypted)")

    if profile.get("telnet"):
        findings.append("Telnet enabled (non-encrypted)")

    return findings


if __name__ == "__main__":
    # Print all predefined profiles
    print("=== FIPS 140-3 Compliant IKE Profiles ===")
    for tier, profile in IKE_PROFILES.items():
        print(f"\n{tier.upper()}:")
        print(f"  Name: {profile.name}")
        print(f"  Encryption: {profile.encryption}")
        print(f"  Hash: {profile.authentication}")
        print(f"  DH Groups: {profile.dh_group}")
        print(f"  FIPS Compliant: {profile.is_fips_compliant()}")

    print("\n=== FIPS 140-3 Compliant IPSec Profiles ===")
    for tier, profile in IPSEC_PROFILES.items():
        print(f"\n{tier.upper()}:")
        print(f"  Name: {profile.name}")
        print(f"  ESP Encryption: {profile.esp_encryption}")
        print(f"  ESP Auth: {profile.esp_authentication}")
        print(f"  DH Group (PFS): {profile.dh_group}")
        print(f"  FIPS Compliant: {profile.is_fips_compliant()}")

    print("\n=== FIPS 140-3 Compliant TLS Profiles ===")
    for tier, profile in TLS_PROFILES.items():
        print(f"\n{tier.upper()}:")
        print(f"  Name: {profile.name}")
        print(f"  Min TLS: {profile.min_version}")
        print(f"  Max TLS: {profile.max_version}")
        print(f"  FIPS Compliant: {profile.is_fips_compliant()}")
