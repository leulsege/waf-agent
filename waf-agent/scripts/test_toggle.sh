#!/bin/bash
# Quick test script to toggle WAF for a domain
# Usage: ./test_toggle.sh <domain> <true|false>
# Example: ./test_toggle.sh waf.zergaw.et false

DOMAIN="${1:-waf.zergaw.et}"
ENABLED="${2:-false}"
AGENT_URL="http://localhost:8080"
PRIVATE_KEY="/etc/waf-agent/private_key.pem"

if [ ! -f "$PRIVATE_KEY" ]; then
    echo "Error: Private key not found at $PRIVATE_KEY"
    exit 1
fi

echo "Testing WAF toggle for: $DOMAIN"
echo "Setting enabled to: $ENABLED"
echo ""

# Convert boolean to lowercase string (bash)
ENABLED_STR=$(echo "$ENABLED" | tr '[:upper:]' '[:lower:]')

# Generate signature using Python (pass values via environment variables)
export PYTHON_PRIVATE_KEY="$PRIVATE_KEY"
export PYTHON_DOMAIN="$DOMAIN"
export PYTHON_ENABLED_STR="$ENABLED_STR"

SIGNATURE=$(python3 << 'PYTHON_SCRIPT'
import os
import sys
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# Get values from environment variables
private_key_path = os.environ['PYTHON_PRIVATE_KEY']
domain = os.environ['PYTHON_DOMAIN']
enabled_str = os.environ['PYTHON_ENABLED_STR']

with open(private_key_path, 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

data = f"{domain}|{enabled_str}".encode('utf-8')
print(f"DEBUG: Signing data: '{data.decode('utf-8')}'", file=sys.stderr)
print(f"DEBUG: Data bytes (hex): {data.hex()}", file=sys.stderr)
signature = private_key.sign(
    data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print(base64.b64encode(signature).decode('utf-8'))
PYTHON_SCRIPT
)

# Make the request
echo "Sending request..."
RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$AGENT_URL/waf/toggle" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test-token" \
  -d "{
    \"domain\": \"$DOMAIN\",
    \"enabled\": $ENABLED,
    \"signature\": \"$SIGNATURE\"
  }")

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE" | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '/HTTP_CODE/d')

echo "HTTP Status: $HTTP_CODE"
echo "Response:"
echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"

echo ""
echo "Checking current status..."
curl -s "$AGENT_URL/waf/status/$DOMAIN" | python3 -m json.tool 2>/dev/null || curl -s "$AGENT_URL/waf/status/$DOMAIN"
