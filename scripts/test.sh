#!/bin/bash

# 1. Register a new user (returns TOTP URL)
echo "Registering user..."
REGISTER_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  http://localhost:3000/register)

# Extract TOTP URL
TOTP_URL=$(echo "$REGISTER_RESPONSE" | jq -r '.totp_url')
echo "TOTP URL: $TOTP_URL"
echo "Scan the TOTP URL as a QR code in an authenticator app (e.g., Google Authenticator)"

# 2. Login to get a JWT token
echo -e "\nLogging in..."
LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  http://localhost:3000/login)

# Extract the token
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
echo "JWT Token: $TOKEN"

# 3. Generate a new key (protected route, requires TOTP code)
# Replace TOTP_CODE with the current 6-digit code from your authenticator app
echo -e "\nGenerating key..."
TOTP_CODE="123456"  # Replace with actual TOTP code
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"totp_code\":\"$TOTP_CODE\"}" \
  http://localhost:3000/api/generate_key

# 4. Sign a message (protected route, requires TOTP code)
echo -e "\n\nSigning message..."
TOTP_CODE="123456"  # Replace with actual TOTP code
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"message\":\"Hello World\",\"totp_code\":\"$TOTP_CODE\"}" \
  http://localhost:3000/api/sign

# 5. Forget TOTP secret (protected route, requires TOTP code)
echo -e "\n\nDeleting TOTP secret..."
TOTP_CODE="123456"  # Replace with actual TOTP code
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"totp_code\":\"$TOTP_CODE\"}" \
  http://localhost:3000/api/forget
