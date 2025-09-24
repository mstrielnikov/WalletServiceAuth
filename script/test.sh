#!/bin/bash
set -ex

# 1. Register a new user
echo "Registering user..."
curl -X POST -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  http://localhost:4000/register

# 2. Login to get a JWT token
echo -e "\n\nLogging in..."
LOGIN_RESPONSE=$(curl -s -X POST -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass"}' \
  http://localhost:4000/login)

# Extract the token from the response (requires jq to parse JSON)
TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
echo "JWT Token: $TOKEN"

# 3. Generate a new key (protected route)
echo -e "\nGenerating key..."
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"passphrase":"strongpassphrase"}' \
  http://localhost:4000/api/generate_key

# 4. Sign a message (protected route)
echo -e "\n\nSigning message..."
curl -X POST -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"message":"Hello World","passphrase":"strongpassphrase"}' \
  http://localhost:4000/api/sign

# 5. Forget/delete account (protected route)
echo -e "\n\nDeleting account..."
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:4000/api/forget
