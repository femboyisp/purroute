#!/bin/bash
# Get user information and bandwidth usage

API_URL="${API_URL:-http://localhost:6969}"
API_KEY="${API_KEY:-your-secret-api-key-here}"

if [ $# -lt 1 ]; then
    echo "Usage: $0 <username>"
    echo "Example: $0 alice"
    exit 1
fi

USERNAME="$1"

curl -X GET "$API_URL/users/$USERNAME" \
    -H "X-API-Key: $API_KEY" | jq .

echo ""
