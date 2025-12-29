#!/bin/bash
# List all users

API_URL="${API_URL:-http://localhost:6969}"
API_KEY="${API_KEY:-your-secret-api-key-here}"

curl -X GET "$API_URL/users" \
    -H "X-API-Key: $API_KEY" | jq .

echo ""
