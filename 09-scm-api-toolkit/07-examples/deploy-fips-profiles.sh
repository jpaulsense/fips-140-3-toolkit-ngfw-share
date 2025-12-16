#!/bin/bash
#
# Deploy FIPS 140-3 Compliant Profiles to Strata Cloud Manager
#
# Usage:
#   export SCM_CLIENT_ID="your-client-id"
#   export SCM_CLIENT_SECRET="your-client-secret"
#   export SCM_TSG_ID="your-tsg-id"
#   ./deploy-fips-profiles.sh [--certificate cert-name] [--folder Shared]
#

set -euo pipefail

# Configuration
CLIENT_ID="${SCM_CLIENT_ID:-}"
CLIENT_SECRET="${SCM_CLIENT_SECRET:-}"
TSG_ID="${SCM_TSG_ID:-}"
FOLDER="Shared"
CERTIFICATE=""

# URLs
AUTH_URL="https://auth.apps.paloaltonetworks.com/oauth2/access_token"
API_URL="https://api.strata.paloaltonetworks.com"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_header() {
    echo -e "\n${BLUE}============================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}============================================================${NC}"
}

print_status() {
    local status=$1
    local message=$2
    case $status in
        "CREATED") echo -e "  ${GREEN}[CREATED]${NC} $message" ;;
        "EXISTS")  echo -e "  ${YELLOW}[EXISTS]${NC} $message" ;;
        "ERROR")   echo -e "  ${RED}[ERROR]${NC} $message" ;;
        "INFO")    echo -e "  ${BLUE}[INFO]${NC} $message" ;;
    esac
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --certificate)
            CERTIFICATE="$2"
            shift 2
            ;;
        --folder)
            FOLDER="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [--certificate cert-name] [--folder Shared]"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate credentials
if [[ -z "$CLIENT_ID" || -z "$CLIENT_SECRET" || -z "$TSG_ID" ]]; then
    echo -e "${RED}ERROR: Missing credentials${NC}"
    echo "Set SCM_CLIENT_ID, SCM_CLIENT_SECRET, and SCM_TSG_ID environment variables"
    exit 1
fi

print_header "FIPS 140-3 PROFILE DEPLOYMENT"
echo "Folder: $FOLDER"
echo "Certificate: ${CERTIFICATE:-Not specified}"

# Get access token
echo -e "\n${BLUE}[AUTHENTICATION]${NC}"
TOKEN_RESPONSE=$(curl -s -X POST "$AUTH_URL" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -d "grant_type=client_credentials&scope=tsg_id:${TSG_ID}")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [[ -z "$ACCESS_TOKEN" ]]; then
    echo -e "${RED}ERROR: Failed to get access token${NC}"
    echo "$TOKEN_RESPONSE"
    exit 1
fi

print_status "INFO" "Authentication successful"

# Helper function to create profile
create_profile() {
    local endpoint=$1
    local data=$2
    local name=$3

    response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}${endpoint}?folder=${FOLDER}" \
        -H "Authorization: Bearer ${ACCESS_TOKEN}" \
        -H "Content-Type: application/json" \
        -d "$data")

    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    case $http_code in
        201) print_status "CREATED" "$name" ;;
        409) print_status "EXISTS" "$name" ;;
        *)   print_status "ERROR" "$name (HTTP $http_code): $body" ;;
    esac
}

# ==================== IKE Crypto Profiles ====================
echo -e "\n${BLUE}[IKE CRYPTO PROFILES]${NC}"

# Maximum Security
create_profile "/config/v1/ike-crypto-profiles" '{
    "name": "fips-ike-crypto-max",
    "encryption": ["aes-256-gcm"],
    "authentication": ["sha512"],
    "dh_group": ["group20"],
    "lifetime": {"hours": 8}
}' "fips-ike-crypto-max"

# Recommended
create_profile "/config/v1/ike-crypto-profiles" '{
    "name": "fips-ike-crypto-recommended",
    "encryption": ["aes-256-cbc", "aes-128-gcm"],
    "authentication": ["sha384", "sha256"],
    "dh_group": ["group20", "group19"],
    "lifetime": {"hours": 8}
}' "fips-ike-crypto-recommended"

# Compatible
create_profile "/config/v1/ike-crypto-profiles" '{
    "name": "fips-ike-crypto-compat",
    "encryption": ["aes-256-cbc", "aes-256-gcm", "aes-128-cbc", "aes-128-gcm"],
    "authentication": ["sha512", "sha384", "sha256"],
    "dh_group": ["group20", "group19", "group16", "group14"],
    "lifetime": {"hours": 8}
}' "fips-ike-crypto-compat"

# ==================== IPSec Crypto Profiles ====================
echo -e "\n${BLUE}[IPSEC CRYPTO PROFILES]${NC}"

# Maximum Security
create_profile "/config/v1/ipsec-crypto-profiles" '{
    "name": "fips-ipsec-crypto-max",
    "esp": {
        "encryption": ["aes-256-gcm"],
        "authentication": ["sha512"]
    },
    "dh_group": "group20",
    "lifetime": {"hours": 1},
    "lifesize": {"gb": 100}
}' "fips-ipsec-crypto-max"

# Recommended
create_profile "/config/v1/ipsec-crypto-profiles" '{
    "name": "fips-ipsec-crypto-recommended",
    "esp": {
        "encryption": ["aes-256-gcm", "aes-128-gcm"],
        "authentication": ["sha384", "sha256"]
    },
    "dh_group": "group20",
    "lifetime": {"hours": 1}
}' "fips-ipsec-crypto-recommended"

# Compatible
create_profile "/config/v1/ipsec-crypto-profiles" '{
    "name": "fips-ipsec-crypto-compat",
    "esp": {
        "encryption": ["aes-256-gcm", "aes-256-cbc", "aes-128-gcm", "aes-128-cbc"],
        "authentication": ["sha512", "sha384", "sha256"]
    },
    "dh_group": "group14",
    "lifetime": {"hours": 1}
}' "fips-ipsec-crypto-compat"

# GlobalProtect
create_profile "/config/v1/ipsec-crypto-profiles" '{
    "name": "fips-ipsec-crypto-gp",
    "esp": {
        "encryption": ["aes-256-gcm", "aes-128-gcm"],
        "authentication": ["sha256"]
    },
    "dh_group": "group19",
    "lifetime": {"hours": 1}
}' "fips-ipsec-crypto-gp"

# ==================== TLS Service Profiles ====================
echo -e "\n${BLUE}[TLS SERVICE PROFILES]${NC}"

if [[ -n "$CERTIFICATE" ]]; then
    # Maximum Security
    create_profile "/config/v1/tls-service-profiles" "{
        \"name\": \"fips-ssl-tls-max\",
        \"protocol_settings\": {
            \"min_version\": \"tls1-2\",
            \"max_version\": \"tls1-3\"
        },
        \"certificate\": \"${CERTIFICATE}\"
    }" "fips-ssl-tls-max"

    # Recommended
    create_profile "/config/v1/tls-service-profiles" "{
        \"name\": \"fips-ssl-tls-recommended\",
        \"protocol_settings\": {
            \"min_version\": \"tls1-2\",
            \"max_version\": \"max\"
        },
        \"certificate\": \"${CERTIFICATE}\"
    }" "fips-ssl-tls-recommended"

    # TLS 1.3 Only
    create_profile "/config/v1/tls-service-profiles" "{
        \"name\": \"fips-ssl-tls-1-3-only\",
        \"protocol_settings\": {
            \"min_version\": \"tls1-3\",
            \"max_version\": \"tls1-3\"
        },
        \"certificate\": \"${CERTIFICATE}\"
    }" "fips-ssl-tls-1-3-only"
else
    print_status "INFO" "Skipped - no certificate specified (use --certificate)"
fi

# ==================== Interface Management Profiles ====================
echo -e "\n${BLUE}[INTERFACE MANAGEMENT PROFILES]${NC}"

# Full Management
create_profile "/config/v1/interface-management-profiles" '{
    "name": "fips-mgmt-profile",
    "https": true,
    "ssh": true,
    "http": false,
    "telnet": false,
    "ping": true
}' "fips-mgmt-profile"

# HTTPS Only
create_profile "/config/v1/interface-management-profiles" '{
    "name": "fips-https-only",
    "https": true,
    "ssh": false,
    "http": false,
    "telnet": false,
    "ping": true
}' "fips-https-only"

# ==================== Push Configuration ====================
echo -e "\n${BLUE}[PUSHING CONFIGURATION]${NC}"

push_response=$(curl -s -w "\n%{http_code}" -X POST "${API_URL}/config/v1/config-versions/candidate:push" \
    -H "Authorization: Bearer ${ACCESS_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
        \"folders\": [\"${FOLDER}\"],
        \"description\": \"FIPS 140-3 compliant profiles deployment\"
    }")

push_http_code=$(echo "$push_response" | tail -n1)
push_body=$(echo "$push_response" | sed '$d')

if [[ "$push_http_code" == "200" || "$push_http_code" == "201" ]]; then
    job_id=$(echo "$push_body" | grep -o '"job_id":"[^"]*"' | cut -d'"' -f4)
    if [[ -n "$job_id" ]]; then
        print_status "INFO" "Configuration push initiated (Job ID: $job_id)"
    else
        print_status "INFO" "Configuration push initiated"
    fi
else
    print_status "ERROR" "Push failed (HTTP $push_http_code): $push_body"
fi

print_header "DEPLOYMENT COMPLETE"
