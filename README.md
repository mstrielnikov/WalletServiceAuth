# WalletServiceAuth

Wallet as a service for 'almost' passwordless blockchain wallet authentication backend.

## Design

WalletServiceAuth application is a RESTful API server designed to provide secure wallet services for Ethereum-compatible blockchains (for ex.), using the `secp256k1` elliptic curve for key generation and message signing ([EIP-191](https://eips.ethereum.org/EIPS/eip-191) personal_sign format). Implemented in Rust using the `Axum` framework for HTTP request handling, `SQLx` for database interactions with PostgreSQL, and cryptography libraries (`aes-gcm`, `argon2`, `totp-rs`, `secp256k1`) for secure operations, the application prioritizes security and simplicity. It runs in a Dockerized environment with a docker-compose.yml configuration for easy deployment and testing.

## Security focus
* User Authentication: Uses JWT tokens issued via the `/login` endpoint, validated with a static `JWT_SECRET` (set to `your-secure-jwt-secret` in `docker-compose.yml`). Tokens expire after 1 hour
* Two-Factor Authentication (TOTP): Requires a TOTP code for `/login` and protected endpoints (`/api/generate_key`, `/api/sign`, `/api/forget`), generated from a secret stored encrypted in the database. The TOTP secret is returned as a `totp_url` during `/register`
* Password Hashing: Passwords are hashed with Argon2 and stored in the users table as password_hash. The password is not stored in plaintext and is used to derive encryption keys
* Key Encryption: Private keys and TOTP secrets are encrypted with `AES-256-GCM` using a key derived from the user’s password. A random salt is stored per record for key derivation
* Ephemeral Keys: Decrypted private keys and TOTP secrets are held in memory only during operations (signing or TOTP verification) and discarded afterward
* Signature Format: Signatures follow Ethereum’s EIP-191 personal_sign format, as seen in the `/api/sign` response

## Features
1. Securely Connect:
   1. Register: The `/register` endpoint creates a user with a unique username, password_hash, encrypted TOTP secret, and salt in the users table. Returns a totp_url for TOTP setup.
   2. Login: The `/login` endpoint verifies the username, password, and totp_code, issuing a JWT token valid for 1 hour.
2. Securely Generate Signature Key:
   1. The `/api/generate_key` endpoint generates a secp256k1 key pair, computes an Ethereum address (e.g., 0x859f34feb9a7e8dde09e678f8b15b8afe017923f), encrypts the private key with a password-derived key, and stores it in the wallets table.
3. Securely Generate Signatures:
   1. The `/api/sign` endpoint decrypts the private key using the provided password and totp_code, signs a message (e.g., Hello, world!), and returns an EIP-191-compliant signature.
4. Securely Be Forgotten:
   1.The `/api/forget` endpoint deletes the user’s records from both users and wallets tables, allowing re-registration.

See [ENDPOINTS.md](./ENDPOINTS.md) for detailed API endpoints description and request examples.

See [SCHEMA.md](./SCHEMA.md) for detailed description of Postgresql DB schema and SQL actions performed per API endpoint above.

## Try wallet-as-a-service
### Prerequisites
* Docker (20.10.0+)
* Docker-compose (3.5+)
* curl
* (optional) TOTP authenticator (Google Authenticator, Authy, qrencode (CLI),  etc)

### Deployment
The `docker-compose.yaml` defines two services:
* `wallet-service` (Rust app)
* `postgres` (PostgreSQL database) as a persistence layer

Run:
```bash
docker-compose down -v  # Clear existing containers and volumes for PG fresh start
docker-compose up --build --force-recreate
```

Check logs:
```bash
docker logs walletserviceauth_wallet-service_1 
```

Verify DB:
```
docker exec -it walletserviceauth_postgres_1 psql -U wallet_user -d wallet -c "SELECT * FROM users;"
docker exec -it walletserviceauth_postgres_1 psql -U wallet_user -d wallet -c "SELECT * FROM wallets;"
```

### Mandatory ENV vars
There are a couple of ENV vars set:
```yaml
services:
  wallet-service:
    environment:
#     - RUST_BACKTRACE=1  (optional)
      - RUST_LOG=info
      - DATABASE_URL=postgres://wallet_user:wallet_pass@postgres:5432/wallet
      - JWT_SECRET=your-secure-jwt-secret
  postgres:
    environment:
      - POSTGRES_USER=wallet_user
      - POSTGRES_PASSWORD=wallet_pass
      - POSTGRES_DB=wallet
```

## Challenges
### 1. Security of network communications
The following secure design decisions impacted the complexity of software implementation
* Implementing JWT tokens to prevent replay attacks and manage session expiry introduced complexity
* Implementing TOTP (Time-Based One-Time Password) for protected endpoints added security related to management of sensitive data in database, tracking updates and encryption of the TOTP state

### 2. Secure storage of the sensitive data
The main security issue is the persistence of sensitive data in memory. This issue is partially mitigated by: 
* Used the aes-gcm crate for encryption, with a random salt (16 bytes) stored per record to derive encryption keys. No passwords are stored in plaintext, except their corresponded salted password hashes password_hash (Argon2) are stored in the users table. Decrypted secrets and keys are held in memory only during operations (e.g., TOTP verification, signing) and discarded afterward
* Additional encryption on the volume level in production is necessary or a dedicated secret management solution

### 3. Software implementation
* Careful management of database transactions in order to track user's TOTP setup and relevant state changes
* Selection and integration of dependencies

## Improvements & TODO
### 1. Security of network communications
* The backend provided interacts with the user a lot. Despite the fact that there is minimal sensitive information transferred, protection of initial `/register` & `/login` routes against Men-in-the-Middle attacks is still crucial. Standard TLS can be applied. * No rate limiting or advanced auth

### 2. Frontend
The presence of a user-friendly front-end would be handy, especially for visualizing the entire flow: `Register -> Login -> Generate Key -> Sign`, and providing a QR code to the user for login.

### 3. Flexible login methods
The integration of different login methods would be beneficial to improve user experience and suitability to different scenarios using:
* Optional integration with Mail or SMS based factors for potential reset functionality
* Full-fledged OAuth integration like in [Sui blockchain](https://docs.sui.io/concepts/cryptography/zklogin) or other zkLogin implementations
* PassKeys stored on user-provided devices, cloud disks, or hardware keys etc
* Login with existing wallets or WalletConnect

### 4. Integrations with existing blockchains
* The backend only simulates the assignment of an ETH-compatible wallet address. It would be more practical to allow users to plug in and authenticate their own wallets. For example, via WalletConnect or TrustWallet integration etc.
* Considering integration with different chains, the given Wallet-as-a-Service backend could be extended to authenticate users in dApps without exposing their own wallets in multiple chains

### 5. No recovery
No recovery for the lost passphrase (standard for wallets) if no MPC-based solutions are considered or until OAuth compatibility / zk Login.

### Use in production
* Requires rate limiting to prevent abuse of endpoints or attacks  
* Enable TLS for PostgreSQL
* Single node deployment. The production may require scaling of application instances and enabling PostgreSQL replication
* For the cases of high load and/or high availability, read- and write-heavy workloads may be separated. Still advise using PostgreSQL for looking up user and wallet data, while the message bus may be used for event processing, such as message signing, address assignment, and JWT emission.  

## Previous version
There is an old version [available in the branch](https://github.com/mstrielnikov/WalletServiceAuth/blob/master/src/main.rs) without 2FA.
