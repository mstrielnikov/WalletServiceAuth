#!/bin/bash

# Variables
BASE_URL="http://0.0.0.0:3000"
USERNAME="testuser"
PASSWORD="testpass"
TOTPCODE=$(cat totp_code.txt 2>/dev/null || echo "022681") # Get from file or default
TOKEN_FILE="token.txt"

# Function to get current TOTP code
get_totp_code() {
    echo "Enter current TOTP code from authenticator (e.g., 022681): " >&2
    read -r input
    local temp_code=$(printf "%s" "$(echo "$input" | grep -oE '[0-9]+' | tr -d '\n')")
    if [ -z "$temp_code" ]; then
        echo "Error: No valid TOTP code entered. Using default: 022681" >&2
        temp_code="022681"
    fi
    echo "Debug: Extracted TOTP code: $temp_code" >&2
    echo "$temp_code" > totp_code.txt
    echo "$temp_code"
}

# 1. Register
echo "Testing Register..."
HTTP_STATUS=$(curl -s -o register_response.json -w "%{http_code}" -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Register Success"
    cat register_response.json
    TOTPCODE=$(get_totp_code)
else
    echo "Register Failed with status $HTTP_STATUS"
    cat register_response.json
    exit 1
fi

# 2. Login
echo "Testing Login..."
HTTP_STATUS=$(curl -s -o login_response.json -w "%{http_code}" -X POST "$BASE_URL/login" \
     -H "Content-Type: application/json" \
     -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
if [ "$HTTP_STATUS" -eq 200 ]; then
    TOKEN=$(jq -r '.token' login_response.json)
    echo "$TOKEN" > "$TOKEN_FILE"
    echo "Login Success, Token Saved"
else
    echo "Login Failed with status $HTTP_STATUS"
    cat login_response.json
    exit 1
fi

# 3. Generate Key
echo "Testing Generate Key..."
JSON_DATA=$(printf '{"totp_code":"%s"}' "$TOTPCODE")
echo "Debug: JSON sent to Generate Key: $JSON_DATA" >&2
HTTP_STATUS=$(curl -s -o generate_key_response.json -w "%{http_code}" -X POST "$BASE_URL/api/generate_key" \
     -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
     -H "Content-Type: application/json" \
     -d "$JSON_DATA")
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Generate Key Success"
    cat generate_key_response.json
else
    echo "Generate Key Failed with status $HTTP_STATUS"
    cat generate_key_response.json
    exit 1
fi

# 4. Sign Message
echo "Testing Sign..."
JSON_DATA=$(printf '{"message":"Hello, Blockchain!","totp_code":"%s"}' "$TOTPCODE")
echo "Debug: JSON sent to Sign: $JSON_DATA" >&2
HTTP_STATUS=$(curl -s -o sign_response.json -w "%{http_code}" -X POST "$BASE_URL/api/sign" \
     -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
     -H "Content-Type: application/json" \
     -d "$JSON_DATA")
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Sign Success"
    cat sign_response.json
else
    echo "Sign Failed with status $HTTP_STATUS"
    cat sign_response.json
    exit 1
fi

# 5. Forget TOTP
echo "Testing Forget..."
JSON_DATA=$(printf '{"totp_code":"%s"}' "$TOTPCODE")
echo "Debug: JSON sent to Forget: $JSON_DATA" >&2
HTTP_STATUS=$(curl -s -o forget_response.json -w "%{http_code}" -X POST "$BASE_URL/api/forget" \
     -H "Authorization: Bearer $(cat $TOKEN_FILE)" \
     -H "Content-Type: application/json" \
     -d "$JSON_DATA")
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Forget Success"
    rm -f "$TOKEN_FILE"
else
    echo "Forget Failed with status $HTTP_STATUS"
    cat forget_response.json
    exit 1
fi

# 6. Re-Register
echo "Testing Re-Register..."
HTTP_STATUS=$(curl -s -o re_register_response.json -w "%{http_code}" -X POST "$BASE_URL/register" \
     -H "Content-Type: application/json" \
     -d "{\"username\":\"$USERNAME\",\"password\":\"$PASSWORD\"}")
if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "Re-Register Success"
    cat re_register_response.json
    TOTPCODE=$(get_totp_code)
elif [ "$HTTP_STATUS" -eq 409 ]; then
    echo "Re-Register Failed: Username already exists"
    cat re_register_response.json
else
    echo "Re-Register Failed with status $HTTP_STATUS"
    cat re_register_response.json
    exit 1
fi

echo "All tests completed. Check response files for details."
