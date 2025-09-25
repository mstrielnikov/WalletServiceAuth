# WalletServiceAuth

Wallet as a service for 'almost' passwordless blockchain wallet authentication backend.

## Design

The application is designed as a RESTful API server that provides wallet services for a blockchain (assuming Ethereum-compatible, using secp256k1 for signatures). The server is implemented in Rust using the Axum framework for handling HTTP requests, SQLx for database interactions (with SQLite for simplicity), and various cryptography libraries for secure key generation, encryption, and signing.

User authentication uses JWT tokens issued after password-based login. Passwords are hashed with Argon2.

Signatures follow Ethereum's EIP-191 personal_sign format for message hashing.


## Endpoints

### 1. Register: `/register`

Register user by providing traditional `usenname` & `password`. It's required to bootstrap TOTP which will be prefered for authorized API usage instead of `username` + `password`.
TOTP setup derived from salted hash over password and saved alongside with plain `username`. No password or password has is stored in DB.

```bash
curl -X POST http://localhost:3000/register \
-H "Content-Type: application/json" \
-d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}"
```

Expected response:
```bash
{"totp_url":"otpauth://totp/WalletServiceAuth:testuser1?secret=<base32_secret>&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30"}
```

### 2. Initiate app session (aka Login): `/login`
Login user by `usenname` & `password` to get session-wide (1h default hard-coded) JWT-token.

```bash
curl -X POST http://localhost:3000/login \
-H "Content-Type: application/json" \
-d "{\"username\":\"$TEST_USER\",\"password\":\"$TEST_PASS\"}"
```

Expected response `200` with:
```bash
{"token":"<jwt_token>"}
```

### 3. Generate signature key: `/api/generate_key`
JWT + TOTP authed & protected endpoint for logined user to generate a public signature as ETH compatible blockchain address.  

```bash
curl -X POST http://localhost:3000/api/generate_key \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d "{\"totp_code\":\"$TOTP\"}"
```

Expected response `200` with:
```bash
{"address":"0x<ethereum_address>"}
```

### 4. Message signing: `/api/sign`
JWT + TOTP authed & protected endpoint f{"signature":"0x<r_value><s_value><v_value>"}or logined user to sign messages (for ex.: Wallet's tx's).

```bash
# For ex.: MSG="Hello, Blockchain!"
curl -X POST http://localhost:3000/api/sign \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d "{\"message\":\"$MSG\",\"totp_code\":\"$TOTP\"}"
```

Expected response:
```bash
{"signature":"0x<r_value><s_value><v_value>"}
```

### 5. Deletion of user's TOTP setup: `/api/forget`
   JWT + TOTP authed & protected endpoint for logined user to delete user's TOTP setup in order to reinstantinate it or delete permanently.

```bash
curl -X POST http://localhost:3000/api/forget \
-H "Authorization: Bearer $TOKEN" \
-H "Content-Type: application/json" \
-d "{\"totp_code\":\"$TOTP\"}"
```

Expected response is status `200`.

## Try
Run `run.sh` script to try the Wallet-as-a-Service auth backend. 
Ensure that `run.sh` is executable via `chmod +x run.sh`.

The script will pack the app using [Dockerfile provided](./Dockerfile) to launch the backend.

### Mandatory ENV vars
There are a couple of ENV vars set:
```Dockerfile
# JWT test token stab
ENV JWT_SECRET=supersecretkey
# Verbosity
ENV RUST_LOG=info
```

Here `JWT_SECRET` is initialized with stab 'supersecretkey' for testing purposes.
In normal flow, `JWT_SECRET` should be returned from backend by `/register` to user for authorized execution within protected auth API's (`/api/generate_key`, `/api/sign`, `/api/forget`).
Example of expected response:
```bash
{"totp_url":"otpauth://totp/WalletServiceAuth:testuser1?secret=LSVXVS26N2ZWMZVBEOYE5FDKHFPKWQWD&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30"} 
```

### Mandatory files
1. Ensure `./data` dir exist in the root of repo: `mkdir ./data`
2. Ensure sqlite in-file db exists within `./data`: `touch ./data/wallet.db # exact db name required`

You can see these files are created automatically within test [Dockerfile provided](./Dockerfile). 

### Full testing scenario example

1. Up the [demo dockerfile](./Dockerfile) with `run.sh` [script provided](./run.sh)
2. Run the [test script](./tests/scripts/test.sh) or `curl` queries manually (examples provided above) 

The example of out logs for the backend:
```bash
RUST_BACKTRACE=1 RUST_LOG=info cargo run
Server running on http://0.0.0.0:3000
# Triggered endpoint /register 
# Triggered endpoint /login
[2025-09-25T22:05:13Z INFO  WalletServiceAuth] Generated TOTP for testuser: code=287623
```

Result of test script running:
```bash
./test.sh 
Testing Register...
Register Success
{"totp_url":"otpauth://totp/WalletServiceAuth:testuser?secret=QL4SSWSNQX46DK5WHP7FPM3ZDGXI7QZX&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30"}Enter current TOTP code from authenticator (e.g., 022681): 
287623
Debug: Extracted TOTP code: 287623
Testing Login...
Login Success, Token Saved
Testing Generate Key...
Debug: JSON sent to Generate Key: {"totp_code":"287623"}
Generate Key Success
{"address":"0xc32b6977199756d26ba5d97c7dad4cb8f5ef0ceb"}Testing Sign...
Debug: JSON sent to Sign: {"message":"Hello, Blockchain!","totp_code":"287623"}
Sign Success
{"signature":"0x0974dff4b59a9ee8f4054f13358504360a2d1348797d3c0dd026087919d02503386d860454a5c4f7b797487b3025d87d3a4575f075ee7e630b6cb6ba6063ba521b"}Testing Forget...
Debug: JSON sent to Forget: {"totp_code":"287623"}
Forget Success
Testing Re-Register...
Re-Register Failed: Username already exists
Username already exists
All tests completed. Check response files for details.

# if repeated for different uset 
[2025-09-25T22:14:56Z INFO  WalletServiceAuth] Generated TOTP for testuser1: code=218495
```

**Comment.**
In real world scenario, user expected to receive `{"totp_url":"otpauth://totp/WalletServiceAuth:testuser1?secret=ZQZ4JLJU5MQ6UXLWDX5PPAOFHSUIFRYQ&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30"}` as a response from `/login` rendered as a QR code by fronted to add it in Google Authenticator, Authy, or other TOTP auth apps. 

## Challenges
### 1. Security of network communications
The following design decisions impacted a
* JWT tokens are used to prevent reply attacks using intercepted user prompts or expired sessions
* TOTP implemented additionally to generate dynamic short-living passwords to authorize user requests

### 2. Secure storage of the sensitive data
The main security issue is the persistence of sensitive data in memory. This issue is partially mitigated by:
* Usage of a DB (sqlite) without direct exposure to the network, making "this particular machine" is the last line of defence and side channel-attacks to steal the data from memory 
* No explicit password stored in memory. The salted hash of the password does not stored either and used only to generate TOTP setup. TOTP params with corresponding usernames are stored in DB. Potential leakage of DB content exposes TOTP codes but not allows to steal "user's identity" or reuse them if expired.
* The DB's content is not encrypted. 

### 3. Software implementation 
* Usage of JWT, TOTP, Signatures introduces a lot of complexity to the code on its own
* Careful management of database transactions in order to track user's TOTP setup and relevant state changes

## Improvements & TODO
### 1. Security of network communications
The backend provided interacts with user a lot. Despite the fact, there is minimum sensitive information transfered, protection of initial `/register` & `/login` routes against Men-in-the-Middle attacks is still crucial. Standard TLS can be apply. No rate limiting or advanced auth.

### 2. Frontend
The presence of user friendly fronted would be handy especially to vizualize the whole flow: `Register -> Login -> Generate Key -> Sign` and provide QR-code to user for login.

### 3. Flexible login methods
The integration different login methods would be beneficial to improve user experience and suitability to different scenarios using:
* Optional integration with Mail or SMS based factors for potential reset functionality
* Full fledged OAuth integration like in [Sui blockchain](https://docs.sui.io/concepts/cryptography/zklogin) or other zkLogin implementations
* PassKeys stored on user provided devices, cloud disks or hardware keys
* Login with existing wallets or WalletConnect

### 4. Integrations with existing blockchains
* For the backend provided only simulates assignation of ETH compatible wallet address. It would be more practical to allow user plug-in and auth own wallet. For example, via WalletConnect or TrustWallet integration etc.
* Considering integration with different chains, the given Wallet-as-a-Service backend could be extended to authenticate user in dApps without exposing own wallets in multiple chains

### 5. No recovery
No recovery for the lost passphrase (standard for wallets) if no MPC-based solutions considered or until OAuth compatibility / zk Login.

## Previous version
There is old version [available in  branch](https://github.com/mstrielnikov/WalletServiceAuth/blob/master/src/main.rs) using password.
It authorizes protected API routes with signed JWTs. Each signature made with user's password.