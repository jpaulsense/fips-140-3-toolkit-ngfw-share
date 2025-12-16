#!/usr/bin/env python3
"""
Strata Cloud Manager API Client

A Python wrapper for the SCM API with FIPS 140-3 compliant profile management.
"""

import os
import time
import json
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import requests
from requests.auth import HTTPBasicAuth

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SCMConfig:
    """Configuration for SCM client."""
    client_id: str
    client_secret: str
    tsg_id: str
    auth_url: str = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
    api_url: str = "https://api.strata.paloaltonetworks.com"


class SCMAuthError(Exception):
    """Authentication error."""
    pass


class SCMAPIError(Exception):
    """API error."""
    def __init__(self, message: str, status_code: int = None, response: dict = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class SCMClient:
    """
    Strata Cloud Manager API Client.

    Provides methods for managing FIPS 140-3 compliant cryptographic profiles.
    """

    def __init__(
        self,
        client_id: str = None,
        client_secret: str = None,
        tsg_id: str = None,
        config: SCMConfig = None
    ):
        """
        Initialize SCM client.

        Args:
            client_id: OAuth client ID (or set SCM_CLIENT_ID env var)
            client_secret: OAuth client secret (or set SCM_CLIENT_SECRET env var)
            tsg_id: Tenant Service Group ID (or set SCM_TSG_ID env var)
            config: Optional SCMConfig object
        """
        if config:
            self.config = config
        else:
            self.config = SCMConfig(
                client_id=client_id or os.environ.get("SCM_CLIENT_ID", ""),
                client_secret=client_secret or os.environ.get("SCM_CLIENT_SECRET", ""),
                tsg_id=tsg_id or os.environ.get("SCM_TSG_ID", "")
            )

        self._token: Optional[str] = None
        self._token_expiry: float = 0

        # Validate configuration
        if not all([self.config.client_id, self.config.client_secret, self.config.tsg_id]):
            raise ValueError("client_id, client_secret, and tsg_id are required")

    @property
    def token(self) -> str:
        """Get access token, refreshing if necessary."""
        if time.time() >= self._token_expiry - 60:
            self._refresh_token()
        return self._token

    def _refresh_token(self) -> None:
        """Request new access token."""
        logger.info("Requesting new access token...")

        try:
            response = requests.post(
                self.config.auth_url,
                auth=HTTPBasicAuth(self.config.client_id, self.config.client_secret),
                data={
                    "grant_type": "client_credentials",
                    "scope": f"tsg_id:{self.config.tsg_id}"
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=30
            )
            response.raise_for_status()

            data = response.json()
            self._token = data["access_token"]
            self._token_expiry = time.time() + data.get("expires_in", 899)

            logger.info(f"Token obtained, expires in {data.get('expires_in', 899)}s")

        except requests.RequestException as e:
            raise SCMAuthError(f"Authentication failed: {e}")

    def _request(
        self,
        method: str,
        endpoint: str,
        params: Dict = None,
        data: Dict = None,
        headers: Dict = None
    ) -> Dict:
        """
        Make API request.

        Args:
            method: HTTP method
            endpoint: API endpoint (without base URL)
            params: Query parameters
            data: Request body
            headers: Additional headers

        Returns:
            Response JSON
        """
        url = f"{self.config.api_url}{endpoint}"

        request_headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }
        if headers:
            request_headers.update(headers)

        try:
            response = requests.request(
                method=method,
                url=url,
                params=params,
                json=data,
                headers=request_headers,
                timeout=60
            )

            if response.status_code == 204:
                return {}

            result = response.json() if response.text else {}

            if not response.ok:
                raise SCMAPIError(
                    f"API error: {response.status_code}",
                    status_code=response.status_code,
                    response=result
                )

            return result

        except requests.RequestException as e:
            raise SCMAPIError(f"Request failed: {e}")

    # ==================== IKE Crypto Profiles ====================

    def list_ike_crypto_profiles(self, folder: str = "Shared") -> List[Dict]:
        """List all IKE crypto profiles."""
        response = self._request(
            "GET",
            "/config/v1/ike-crypto-profiles",
            params={"folder": folder}
        )
        return response.get("data", [])

    def get_ike_crypto_profile(self, profile_id: str) -> Dict:
        """Get specific IKE crypto profile."""
        return self._request("GET", f"/config/v1/ike-crypto-profiles/{profile_id}")

    def create_ike_crypto_profile(
        self,
        name: str,
        encryption: List[str],
        authentication: List[str],
        dh_group: List[str],
        lifetime_hours: int = 8,
        folder: str = "Shared"
    ) -> Dict:
        """
        Create IKE crypto profile.

        Args:
            name: Profile name
            encryption: List of encryption algorithms
            authentication: List of hash algorithms
            dh_group: List of DH groups
            lifetime_hours: Key lifetime in hours
            folder: Configuration folder

        Returns:
            Created profile
        """
        data = {
            "name": name,
            "encryption": encryption,
            "authentication": authentication,
            "dh_group": dh_group,
            "lifetime": {"hours": lifetime_hours}
        }

        return self._request(
            "POST",
            "/config/v1/ike-crypto-profiles",
            params={"folder": folder},
            data=data
        )

    def delete_ike_crypto_profile(self, profile_id: str) -> Dict:
        """Delete IKE crypto profile."""
        return self._request("DELETE", f"/config/v1/ike-crypto-profiles/{profile_id}")

    # ==================== IPSec Crypto Profiles ====================

    def list_ipsec_crypto_profiles(self, folder: str = "Shared") -> List[Dict]:
        """List all IPSec crypto profiles."""
        response = self._request(
            "GET",
            "/config/v1/ipsec-crypto-profiles",
            params={"folder": folder}
        )
        return response.get("data", [])

    def get_ipsec_crypto_profile(self, profile_id: str) -> Dict:
        """Get specific IPSec crypto profile."""
        return self._request("GET", f"/config/v1/ipsec-crypto-profiles/{profile_id}")

    def create_ipsec_crypto_profile(
        self,
        name: str,
        esp_encryption: List[str],
        esp_authentication: List[str],
        dh_group: str = "group20",
        lifetime_hours: int = 1,
        lifesize_gb: int = None,
        folder: str = "Shared"
    ) -> Dict:
        """
        Create IPSec crypto profile.

        Args:
            name: Profile name
            esp_encryption: List of ESP encryption algorithms
            esp_authentication: List of ESP authentication algorithms
            dh_group: DH group for PFS
            lifetime_hours: SA lifetime in hours
            lifesize_gb: SA lifetime in GB
            folder: Configuration folder

        Returns:
            Created profile
        """
        data = {
            "name": name,
            "esp": {
                "encryption": esp_encryption,
                "authentication": esp_authentication
            },
            "dh_group": dh_group,
            "lifetime": {"hours": lifetime_hours}
        }

        if lifesize_gb:
            data["lifesize"] = {"gb": lifesize_gb}

        return self._request(
            "POST",
            "/config/v1/ipsec-crypto-profiles",
            params={"folder": folder},
            data=data
        )

    def delete_ipsec_crypto_profile(self, profile_id: str) -> Dict:
        """Delete IPSec crypto profile."""
        return self._request("DELETE", f"/config/v1/ipsec-crypto-profiles/{profile_id}")

    # ==================== TLS Service Profiles ====================

    def list_tls_service_profiles(self, folder: str = "Shared") -> List[Dict]:
        """List all TLS service profiles."""
        response = self._request(
            "GET",
            "/config/v1/tls-service-profiles",
            params={"folder": folder}
        )
        return response.get("data", [])

    def get_tls_service_profile(self, profile_id: str) -> Dict:
        """Get specific TLS service profile."""
        return self._request("GET", f"/config/v1/tls-service-profiles/{profile_id}")

    def create_tls_service_profile(
        self,
        name: str,
        certificate: str,
        min_version: str = "tls1-2",
        max_version: str = "max",
        folder: str = "Shared"
    ) -> Dict:
        """
        Create TLS service profile.

        Args:
            name: Profile name
            certificate: Certificate name
            min_version: Minimum TLS version
            max_version: Maximum TLS version
            folder: Configuration folder

        Returns:
            Created profile
        """
        data = {
            "name": name,
            "protocol_settings": {
                "min_version": min_version,
                "max_version": max_version
            },
            "certificate": certificate
        }

        return self._request(
            "POST",
            "/config/v1/tls-service-profiles",
            params={"folder": folder},
            data=data
        )

    def delete_tls_service_profile(self, profile_id: str) -> Dict:
        """Delete TLS service profile."""
        return self._request("DELETE", f"/config/v1/tls-service-profiles/{profile_id}")

    # ==================== Interface Management Profiles ====================

    def list_interface_mgmt_profiles(self, folder: str = "Shared") -> List[Dict]:
        """List all interface management profiles."""
        response = self._request(
            "GET",
            "/config/v1/interface-management-profiles",
            params={"folder": folder}
        )
        return response.get("data", [])

    def create_interface_mgmt_profile(
        self,
        name: str,
        https: bool = True,
        ssh: bool = True,
        http: bool = False,
        telnet: bool = False,
        ping: bool = True,
        permitted_ip: List[str] = None,
        folder: str = "Shared"
    ) -> Dict:
        """
        Create interface management profile.

        Args:
            name: Profile name
            https: Enable HTTPS
            ssh: Enable SSH
            http: Enable HTTP (non-compliant)
            telnet: Enable Telnet (non-compliant)
            ping: Enable ping
            permitted_ip: List of permitted source networks
            folder: Configuration folder

        Returns:
            Created profile
        """
        data = {
            "name": name,
            "https": https,
            "ssh": ssh,
            "http": http,
            "telnet": telnet,
            "ping": ping
        }

        if permitted_ip:
            data["permitted_ip"] = permitted_ip

        return self._request(
            "POST",
            "/config/v1/interface-management-profiles",
            params={"folder": folder},
            data=data
        )

    def delete_interface_mgmt_profile(self, profile_id: str) -> Dict:
        """Delete interface management profile."""
        return self._request(
            "DELETE",
            f"/config/v1/interface-management-profiles/{profile_id}"
        )

    # ==================== Configuration Jobs ====================

    def push_config(
        self,
        folders: List[str] = None,
        description: str = "Configuration push via API"
    ) -> Dict:
        """
        Push candidate configuration to devices.

        Args:
            folders: List of folders to push
            description: Push description

        Returns:
            Job information
        """
        data = {
            "folders": folders or ["Shared"],
            "description": description
        }

        return self._request(
            "POST",
            "/config/v1/config-versions/candidate:push",
            data=data
        )

    def get_job(self, job_id: str) -> Dict:
        """Get job status."""
        return self._request("GET", f"/config/v1/jobs/{job_id}")

    def wait_for_job(self, job_id: str, timeout: int = 300) -> Dict:
        """
        Wait for job to complete.

        Args:
            job_id: Job ID
            timeout: Maximum wait time in seconds

        Returns:
            Final job status
        """
        start_time = time.time()

        while time.time() - start_time < timeout:
            job = self.get_job(job_id)
            status = job.get("status_str", "")

            if status in ["FIN", "OK"]:
                logger.info(f"Job {job_id} completed successfully")
                return job
            elif status in ["FAIL", "ERR"]:
                raise SCMAPIError(f"Job {job_id} failed: {job}")

            logger.info(f"Job {job_id} status: {status}")
            time.sleep(5)

        raise SCMAPIError(f"Job {job_id} timed out after {timeout}s")

    # ==================== FIPS 140-3 Helper Methods ====================

    def create_fips_ike_profile(
        self,
        tier: str = "recommended",
        folder: str = "Shared"
    ) -> Dict:
        """
        Create FIPS 140-3 compliant IKE crypto profile.

        Args:
            tier: Compliance tier (max, recommended, compat)
            folder: Configuration folder

        Returns:
            Created profile
        """
        profiles = {
            "max": {
                "name": "fips-ike-crypto-max",
                "encryption": ["aes-256-gcm"],
                "authentication": ["sha512"],
                "dh_group": ["group20"]
            },
            "recommended": {
                "name": "fips-ike-crypto-recommended",
                "encryption": ["aes-256-cbc", "aes-128-gcm"],
                "authentication": ["sha384", "sha256"],
                "dh_group": ["group20", "group19"]
            },
            "compat": {
                "name": "fips-ike-crypto-compat",
                "encryption": ["aes-256-cbc", "aes-256-gcm", "aes-128-cbc", "aes-128-gcm"],
                "authentication": ["sha512", "sha384", "sha256"],
                "dh_group": ["group20", "group19", "group16", "group14"]
            }
        }

        if tier not in profiles:
            raise ValueError(f"Invalid tier: {tier}. Must be one of: {list(profiles.keys())}")

        config = profiles[tier]
        return self.create_ike_crypto_profile(
            name=config["name"],
            encryption=config["encryption"],
            authentication=config["authentication"],
            dh_group=config["dh_group"],
            folder=folder
        )

    def create_fips_ipsec_profile(
        self,
        tier: str = "recommended",
        folder: str = "Shared"
    ) -> Dict:
        """
        Create FIPS 140-3 compliant IPSec crypto profile.

        Args:
            tier: Compliance tier (max, recommended, compat, gp)
            folder: Configuration folder

        Returns:
            Created profile
        """
        profiles = {
            "max": {
                "name": "fips-ipsec-crypto-max",
                "encryption": ["aes-256-gcm"],
                "authentication": ["sha512"],
                "dh_group": "group20"
            },
            "recommended": {
                "name": "fips-ipsec-crypto-recommended",
                "encryption": ["aes-256-gcm", "aes-128-gcm"],
                "authentication": ["sha384", "sha256"],
                "dh_group": "group20"
            },
            "compat": {
                "name": "fips-ipsec-crypto-compat",
                "encryption": ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
                "authentication": ["sha512", "sha384", "sha256"],
                "dh_group": "group14"
            },
            "gp": {
                "name": "fips-ipsec-crypto-gp",
                "encryption": ["aes-256-gcm", "aes-128-gcm"],
                "authentication": ["sha256"],
                "dh_group": "group19"
            }
        }

        if tier not in profiles:
            raise ValueError(f"Invalid tier: {tier}. Must be one of: {list(profiles.keys())}")

        config = profiles[tier]
        return self.create_ipsec_crypto_profile(
            name=config["name"],
            esp_encryption=config["encryption"],
            esp_authentication=config["authentication"],
            dh_group=config["dh_group"],
            folder=folder
        )

    def create_fips_tls_profile(
        self,
        tier: str = "recommended",
        certificate: str = "mgmt-cert",
        folder: str = "Shared"
    ) -> Dict:
        """
        Create FIPS 140-3 compliant TLS service profile.

        Args:
            tier: Compliance tier (max, recommended, tls13)
            certificate: Certificate name
            folder: Configuration folder

        Returns:
            Created profile
        """
        profiles = {
            "max": {
                "name": "fips-ssl-tls-max",
                "min_version": "tls1-2",
                "max_version": "tls1-3"
            },
            "recommended": {
                "name": "fips-ssl-tls-recommended",
                "min_version": "tls1-2",
                "max_version": "max"
            },
            "tls13": {
                "name": "fips-ssl-tls-1-3-only",
                "min_version": "tls1-3",
                "max_version": "tls1-3"
            }
        }

        if tier not in profiles:
            raise ValueError(f"Invalid tier: {tier}. Must be one of: {list(profiles.keys())}")

        config = profiles[tier]
        return self.create_tls_service_profile(
            name=config["name"],
            certificate=certificate,
            min_version=config["min_version"],
            max_version=config["max_version"],
            folder=folder
        )

    def create_fips_mgmt_profile(
        self,
        name: str = "fips-mgmt-profile",
        ssh: bool = True,
        permitted_ip: List[str] = None,
        folder: str = "Shared"
    ) -> Dict:
        """
        Create FIPS 140-3 compliant interface management profile.

        Args:
            name: Profile name
            ssh: Enable SSH
            permitted_ip: List of permitted source networks
            folder: Configuration folder

        Returns:
            Created profile
        """
        return self.create_interface_mgmt_profile(
            name=name,
            https=True,
            ssh=ssh,
            http=False,
            telnet=False,
            ping=True,
            permitted_ip=permitted_ip,
            folder=folder
        )


if __name__ == "__main__":
    # Example usage
    import argparse

    parser = argparse.ArgumentParser(description="SCM API Client")
    parser.add_argument("--client-id", help="OAuth client ID")
    parser.add_argument("--client-secret", help="OAuth client secret")
    parser.add_argument("--tsg-id", help="Tenant Service Group ID")
    parser.add_argument("--list-ike", action="store_true", help="List IKE profiles")
    parser.add_argument("--list-ipsec", action="store_true", help="List IPSec profiles")

    args = parser.parse_args()

    client = SCMClient(
        client_id=args.client_id,
        client_secret=args.client_secret,
        tsg_id=args.tsg_id
    )

    if args.list_ike:
        profiles = client.list_ike_crypto_profiles()
        print(json.dumps(profiles, indent=2))

    if args.list_ipsec:
        profiles = client.list_ipsec_crypto_profiles()
        print(json.dumps(profiles, indent=2))
