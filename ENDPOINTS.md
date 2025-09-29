## Endpoints

### 1. Register: `/register`
Registers a new user by providing `usenname` & `password`. This bootstraps a TOTP secret for two-factor authentication, which is required for subsequent logins and protected endpoints. The TOTP secret is derived from a salted hash of the password and stored encrypted in the database alongside the username. It's required to bootstrap TOTP which will be prefered for authorized API usage instead of `username` + `password`.
TOTP setup derived from salted hash over password and saved alongside with plain `username`. No password or password has is stored in DB.

Example:
```bash
curl -X POST http://localhost:3000/register \
-H "Content-Type: application/json" \
-d '{"username":"testuser1","password":"testpass1"}'
```

Expected response `(200 OK)`:
```bash
{"totp_url":"otpauth://totp/WalletServiceAuth:testuser1?secret=ZHLDJRKSV7DNGT6BB4J57ZLBMPWZVS4U&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30"}
```

Description:
* The `totp_url` contains a base32-encoded TOTP secret
* Use a TOTP app (e.g., Google Authenticator) to scan the QR code generated from this URL to obtain 6-digit TOTP codes
* If the username already exists, a `409 (Conflict)` response is returned with `{"error":"Username already exists"}`.

### 2. Initiate app session (aka Login): `/login`
Logs in a user by providing `usenname`, `password` and a valid `totp_code`. Returns a JWT token valid for 1 hour (hard-coded) for use with protected endpoints.

```bash
curl -X POST http://localhost:3000/login \
-H "Content-Type: application/json" \
-d '{"username":"testuser1","password":"testpass1","totp_code":"288486"}'
```

Expected response `(200 OK)`:
```bash
{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjMsImV4cCI6MTc1OTA5MzMzN30.6EUX_T4W1d7DQul_qXRxxO3NgAk_VFkcFVzb_uQlqcc"}
```

Description:
* The `totp_code` must match the current 6-digit code from the TOTP app for the user’s secret.
* Returns `401 (Unauthorized)` if the username, password, or TOTP code is invalid.
* The JWT token must be included in the Authorization: Bearer `<token>` header for protected endpoints.

### 3. Generate signature key: `/api/generate_key`
A JWT + TOTP authenticated endpoint for a logged-in user to generate an Ethereum-compatible public/private key pair (for ex.). The private key is encrypted and stored in the database, and the public address is returned.

```bash
curl -X POST http://localhost:3000/api/generate_key \
-H "Content-Type: application/json" \
-H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjMsImV4cCI6MTc1OTA5MzMzN30.6EUX_T4W1d7DQul_qXRxxO3NgAk_VFkcFVzb_uQlqcc" \
-d '{"password":"testpass1","totp_code":"838923"}'
```

Expected response `(200 OK)`:
```bash
{"address":"0x859f34feb9a7e8dde09e678f8b15b8afe017923f"}
```

Description:
* Requires a valid JWT token from `/login` + correct `totp_code`
* The password is used to derive the encryption key for the private key (key wrapping)
* Returns `401 (Unauthorized)` if the JWT token or TOTP code is invalid
* Returns `500 (Internal Server Error)` if encryption or database operations fail

### 4. Message signing: `/api/sign`
JWT + TOTP authenticated endpoint for a logged-in user to sign a message (e.g., for blockchain transactions) using their private key.

```bash
curl -X POST http://localhost:3000/api/sign \
-H "Content-Type: application/json" \
-H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjMsImV4cCI6MTc1OTA5MzMzN30.6EUX_T4W1d7DQul_qXRxxO3NgAk_VFkcFVzb_uQlqcc" \
-d '{"message":"Hello, world!","password":"testpass1","totp_code":"787147"}'
```

Expected response `(200 OK)`:
```bash
{"signature":"0x30440221008b2af540e37f992c8d5c8b037971c619b49f22e0f265ebc8e221495bf1f2a6ff021f5c3cdbca3326c093c55d1646fecf5331eef331a766fd6ccf08751121a15527"}
```

Description:
* Requires a valid JWT token, a correct `totp_code`, and the password used during registration
* The user must have generated a key pair via `/api/generate_key` first
* Returns `401 (Unauthorized)` if the JWT token, TOTP code, or password is invalid, or if no wallet exists
* Returns `500 (Internal Server Error)` if decryption or signing fails

### 5. Deletion of user's TOTP setup: `/api/forget`
Protected API endpoint (JWT token + TOTP) for a logged-in user to delete their TOTP setup and wallet data allowing re-registration or permanent deletion.

```bash
curl -X POST http://localhost:3000/api/forget \
-H "Content-Type: application/json" \
-H "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOjMsImV4cCI6MTc1OTA5MzMzN30.6EUX_T4W1d7DQul_qXRxxO3NgAk_VFkcFVzb_uQlqcc" \
-d '{"password":"testpass1","totp_code":"787147"}'
```

Expected response: `Status 200 OK`.

Description:
* Requires a valid JWT token, a correct `totp_code`, and the `password` used during registration
* Deletes the user’s wallet (if any) and user record from the database
* Returns `401 (Unauthorized)` if the JWT token, TOTP code, or password is invalid
* Returns `500 (Internal Server Error)` if database deletion fails

**Note.** After successful deletion, the user must re-register to use the API again.

### Example
Example of API endpoint testing
![img.png](img.png)

**Comment.**
In real world scenario, user expected to receive `{"totp_url":"otpauth://totp/WalletServiceAuth:testuser1?secret=ZQZ4JLJU5MQ6UXLWDX5PPAOFHSUIFRYQ&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30"}` as a response from `/register` rendered as a QR code by fronted to add it in Google Authenticator, Authy, or other TOTP auth apps. 
