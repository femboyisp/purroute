#!/bin/bash
# Add a new user with bandwidth limit

API_URL="${API_URL:-http://localhost:6969}"
API_KEY="${API_KEY:-your-secret-api-key-here}"

if [ $# -lt 3 ]; then
    echo "Usage: $0 <username> <password> <bandwidth_limit_gb>"
    echo "Example: $0 alice secret123 10"
    exit 1
fi

USERNAME="$1"
PASSWORD="$2"
BANDWIDTH_GB="$3"

# Convert GB to bytes
BANDWIDTH_BYTES=$((BANDWIDTH_GB * 1024 * 1024 * 1024))
LIMIT_JSON="\"bandwidth_limit\": $BANDWIDTH_BYTES"

curl -X POST "$API_URL/users" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
        \"username\": \"$USERNAME\",
        \"password\": \"$PASSWORD\",
        $LIMIT_JSON
    }" | jq .

echo ""
