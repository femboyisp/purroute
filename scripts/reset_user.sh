#!/bin/bash
# Reset user's bandwidth limit to a new value

API_URL="${API_URL:-http://localhost:6969}"
API_KEY="${API_KEY:-your-secret-api-key-here}"

if [ $# -lt 2 ]; then
    echo "Usage: $0 <username> <bandwidth_limit_gb>"
    echo "Example: $0 alice 5"
    exit 1
fi

USERNAME="$1"
BANDWIDTH_GB="$2"

# Convert GB to bytes
BANDWIDTH_BYTES=$((BANDWIDTH_GB * 1024 * 1024 * 1024))

curl -X POST "$API_URL/users/$USERNAME/reset" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"bandwidth_limit\": $BANDWIDTH_BYTES}" | jq .

echo ""
