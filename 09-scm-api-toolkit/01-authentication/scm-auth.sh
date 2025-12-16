#!/bin/bash
#
# SCM Authentication Helper Script
# Retrieves and caches OAuth2 access tokens for Strata Cloud Manager API
#

set -euo pipefail

# Configuration - Set these or use environment variables
CLIENT_ID="${SCM_CLIENT_ID:-}"
CLIENT_SECRET="${SCM_CLIENT_SECRET:-}"
TSG_ID="${SCM_TSG_ID:-}"

# Token endpoint
AUTH_URL="https://auth.apps.paloaltonetworks.com/oauth2/access_token"

# Cache file location
TOKEN_CACHE="${HOME}/.scm_token_cache"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS] COMMAND

Strata Cloud Manager Authentication Helper

Commands:
    token       Get an access token (cached if valid)
    refresh     Force token refresh
    test        Test authentication and print token info
    clear       Clear cached token

Options:
    -c, --client-id ID        Client ID (or set SCM_CLIENT_ID env var)
    -s, --client-secret SEC   Client Secret (or set SCM_CLIENT_SECRET env var)
    -t, --tsg-id TSG          TSG ID (or set SCM_TSG_ID env var)
    -h, --help                Show this help message

Environment Variables:
    SCM_CLIENT_ID             Service account client ID
    SCM_CLIENT_SECRET         Service account client secret
    SCM_TSG_ID                Tenant Service Group ID

Examples:
    # Using environment variables
    export SCM_CLIENT_ID="your-client-id"
    export SCM_CLIENT_SECRET="your-client-secret"
    export SCM_TSG_ID="1234567890"
    $0 token

    # Using command line options
    $0 -c "client-id" -s "secret" -t "tsg-id" token

    # Use token in API call
    TOKEN=\$($0 token)
    curl -H "Authorization: Bearer \$TOKEN" https://api.strata.paloaltonetworks.com/config/v1/...
EOF
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

validate_credentials() {
    if [[ -z "$CLIENT_ID" ]]; then
        log_error "Client ID not set. Use -c or set SCM_CLIENT_ID"
        exit 1
    fi
    if [[ -z "$CLIENT_SECRET" ]]; then
        log_error "Client Secret not set. Use -s or set SCM_CLIENT_SECRET"
        exit 1
    fi
    if [[ -z "$TSG_ID" ]]; then
        log_error "TSG ID not set. Use -t or set SCM_TSG_ID"
        exit 1
    fi
}

get_cached_token() {
    if [[ -f "$TOKEN_CACHE" ]]; then
        local cached
        cached=$(cat "$TOKEN_CACHE")
        local token expiry
        token=$(echo "$cached" | cut -d'|' -f1)
        expiry=$(echo "$cached" | cut -d'|' -f2)

        local now
        now=$(date +%s)

        # Return cached token if still valid (with 60s buffer)
        if [[ $expiry -gt $((now + 60)) ]]; then
            echo "$token"
            return 0
        fi
    fi
    return 1
}

request_new_token() {
    validate_credentials

    log_info "Requesting new access token..." >&2

    local response
    response=$(curl -s -X POST "$AUTH_URL" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -u "${CLIENT_ID}:${CLIENT_SECRET}" \
        -d "grant_type=client_credentials&scope=tsg_id:${TSG_ID}" \
        2>&1)

    # Check for errors
    if echo "$response" | grep -q '"error"'; then
        local error_desc
        error_desc=$(echo "$response" | grep -o '"error_description":"[^"]*"' | cut -d'"' -f4)
        log_error "Authentication failed: $error_desc"
        exit 1
    fi

    # Extract token and expiry
    local token expires_in expiry
    token=$(echo "$response" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
    expires_in=$(echo "$response" | grep -o '"expires_in":[0-9]*' | cut -d':' -f2)

    if [[ -z "$token" ]]; then
        log_error "Failed to extract access token from response"
        log_error "Response: $response"
        exit 1
    fi

    # Calculate expiry timestamp
    expiry=$(($(date +%s) + expires_in))

    # Cache the token
    echo "${token}|${expiry}" > "$TOKEN_CACHE"
    chmod 600 "$TOKEN_CACHE"

    log_info "Token obtained, expires in ${expires_in}s" >&2
    echo "$token"
}

get_token() {
    local cached_token
    if cached_token=$(get_cached_token); then
        log_info "Using cached token" >&2
        echo "$cached_token"
    else
        request_new_token
    fi
}

test_token() {
    validate_credentials

    local token
    token=$(get_token)

    echo "Token Preview: ${token:0:50}..."
    echo ""

    log_info "Testing API access..."

    local response
    response=$(curl -s -w "\n%{http_code}" \
        "https://api.strata.paloaltonetworks.com/config/v1/jobs?limit=1" \
        -H "Authorization: Bearer $token" \
        -H "Content-Type: application/json")

    local http_code body
    http_code=$(echo "$response" | tail -n1)
    body=$(echo "$response" | sed '$d')

    case $http_code in
        200)
            log_info "Authentication successful!"
            echo "API Response: $body"
            ;;
        401)
            log_error "Authentication failed - token invalid or expired"
            ;;
        403)
            log_error "Authorization failed - insufficient permissions"
            ;;
        *)
            log_error "Unexpected response: HTTP $http_code"
            echo "$body"
            ;;
    esac
}

clear_cache() {
    if [[ -f "$TOKEN_CACHE" ]]; then
        rm -f "$TOKEN_CACHE"
        log_info "Token cache cleared"
    else
        log_info "No cached token found"
    fi
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--client-id)
            CLIENT_ID="$2"
            shift 2
            ;;
        -s|--client-secret)
            CLIENT_SECRET="$2"
            shift 2
            ;;
        -t|--tsg-id)
            TSG_ID="$2"
            shift 2
            ;;
        -h|--help)
            print_usage
            exit 0
            ;;
        token|refresh|test|clear)
            COMMAND="$1"
            shift
            ;;
        *)
            log_error "Unknown option: $1"
            print_usage
            exit 1
            ;;
    esac
done

# Execute command
case "${COMMAND:-}" in
    token)
        get_token
        ;;
    refresh)
        rm -f "$TOKEN_CACHE" 2>/dev/null || true
        request_new_token
        ;;
    test)
        test_token
        ;;
    clear)
        clear_cache
        ;;
    "")
        log_error "No command specified"
        print_usage
        exit 1
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        print_usage
        exit 1
        ;;
esac
