# SCHEMA 

Schema Database Actions

## DB TABLES
The WalletServiceAuth application interacts with a PostgreSQL database containing two tables: users and wallets. Below are the database actions performed by each API endpoint, as derived from the application code and logs.
Database Schema

*  Table `users`. Stores user data with a unique username, hashed password, encrypted TOTP secret, and salt.
```sql
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,                -- id: Auto-incrementing primary key (SERIAL, maps to INT4)
    username TEXT NOT NULL UNIQUE,        -- username: Unique user identifier
    password_hash TEXT NOT NULL,          -- password_hash: Argon2 hash of the password
    encrypted_totp_secret BYTEA NOT NULL, -- encrypted_totp_secret: AES-256-GCM encrypted TOTP secret
    salt BYTEA NOT NULL                   -- salt: Random salt for password hashing and encryption
)
```

* Table `wallets`. Stores encrypted private keys for users, linked to `users.id`.
```sql
CREATE TABLE IF NOT EXISTS wallets (
    user_id BIGINT PRIMARY KEY REFERENCES users(id),    -- user_id: Foreign key referencing users(id) (SQL BIGINT mapped to Rust i32)
    encrypted_privkey BYTEA NOT NULL,                   -- encrypted_privkey: AES-256-GCM encrypted private key
    salt BYTEA NOT NULL                                 -- salt: Random salt for private key encryption
)
```

## 1. Register: `/register`
Description: Registers a new user by storing their username, hashed password, encrypted TOTP secret, and salt in the users table.
Database Actions:
```sql
INSERT INTO users (username, password_hash, encrypted_totp_secret, salt) VALUES ($1, $2, $3, $4) RETURNING id: Failed due to duplicate key value violates unique constraint "users_username_key" for testuser (rows_affected=0)
```

Parameters:
`$1`: username (e.g., testuser1).
`$2`: `Argon2` hashed password (e.g., hashed `testpass1`).
`$3`: `AES-256-GCM` encrypted TOTP secret (20 random bytes, base32-encoded for response).
`$4`: Random salt (16 bytes) for hashing and encryption.


Effect: Creates a new row in the users table with a unique id. Returns the id for confirmation.
Error Handling:
If username already exists, returns `409 (Conflict)` with Username already exists.

## 2. Login: `/login`

Description: Authenticates a user by retrieving its data to verify the password and TOTP code, then issues a JWT token.
Database Actions:

```sql
SELECT id, password_hash, encrypted_totp_secret, salt FROM users WHERE username = $1
```

Parameters:
`$1`: username (e.g., `testuser1`).


Effect: Retrieves the user’s `id`, `password_hash`, `encrypted_totp_secret`, and `salt` for authentication.
Error Handling:
If no user is found, returns `401 (Unauthorized)`.

## Generate Signature Key: `/api/generate_key`
 
Description: Generates an Ethereum-compatible key pair, stores the encrypted private key in the wallets table, and returns the public address.

Database Actions:
1. 
```sql
INSERT INTO wallets (user_id, encrypted_privkey, salt) VALUES ($1, $2, $3)  -- Created wallet record
```

Parameters:
`$1`: User ID from JWT sub field (e.g., 3 for `testuser1`).

Effect: Retrieves `encrypted_totp_secret` and `salt` to verify the TOTP code and password.

2.
```sql
SELECT encrypted_totp_secret, salt FROM users WHERE id = $1                 -- Verified user
```

Parameters:
`$1`: User ID from JWT sub field.
`$2`: `AES-256-GCM` encrypted private key (32 random bytes).
`$3`: Random salt (16 bytes) for encryption.

Effect: Creates a new row in the wallets table linked to the user.
Error Handling:
Returns `401 (Unauthorized)` if TOTP or password verification fails.
Returns `500 (Internal Server Error)` if encryption or insertion fails.


## Message Signing: `/api/sign`
Description: Signs a message using the user’s private key, retrieved from the wallets table.
Database Actions:

Schema action:
```sql
SELECT encrypted_totp_secret, salt FROM users WHERE id = $1     -- Verified user (rows_affected=1, rows_returned=1)
```

Parameters:
`$1`: User ID from JWT `sub` field

Effect: Retrieves encrypted_totp_secret and salt to verify TOTP and password.


2.
```sql
SELECT encrypted_privkey, salt FROM wallets WHERE user_id = $1  -- Retrieved wallet data (rows_affected=1, rows_returned=1)
```

Parameters:
`$1`: User ID from JWT sub field.

Effect: Retrieves encrypted_privkey and salt to decrypt the private key for signing.
Error Handling:
Returns `401 (Unauthorized)` if no wallet exists or TOTP/password is invalid.
Returns `500 (Internal Server Error)` if decryption or signing fails.

## Deletion of User’s TOTP Setup: `/api/forget`
Description: Deletes the user’s wallet and user record from the database, allowing re-registration.
Database Actions:

1. Start transaction: `BEGIN`
Effect: Starts a transaction to ensure atomic deletion.

2.
```sql
DELETE FROM users WHERE id = $1         -- Delete user from users table
```

Parameters:
`$1`: User ID from JWT sub field.

Effect: Deletes the user’s wallet record (if it exists).

3.
```sql
DELETE FROM wallets WHERE user_id = $1  -- Delete wallet from wallets table by user_id
```

Parameters:
`$1`: User ID from JWT sub field.

Effect: Deletes the user’s record from the users table.

4. Commit transaction: `COMMIT`

Effect: Commits the transaction to finalize deletions.
Error Handling:
Returns `401 (Unauthorized)` if TOTP or password verification fails.
Returns `500 (Internal Server Error)` if deletion or transaction fails.
