# SCHEMA

> **Database:** Turso / libSQL (SQLite wire-compatible, horizontally scalable, encrypted-at-rest)  
> **Migration strategy:** `CREATE TABLE IF NOT EXISTS` executed at startup via `DbClient::init_schema()`  
> **Previous engine:** PostgreSQL (retired — see git history)

---

## Architecture Overview

The schema implements a **Hedera-inspired Meta-Account model**: identity is fully decoupled from payment addresses. A single canonical user (`meta_accounts`) can own many one-time or reusable proxy addresses (`ephemeral_addresses`) across any number of chains, with no raw private key material ever stored server-side (key shards live in the MPC network).

```
┌─────────────────────────────┐        ┌──────────────────────────────────────┐
│        meta_accounts        │ 1 ───▶ N│         ephemeral_addresses          │
│─────────────────────────────│        │──────────────────────────────────────│
│ id (PK)                     │        │ id (PK)                               │
│ canonical_identifier UNIQUE │        │ meta_account_id (FK)                  │
│ auth_methods_json           │        │ chain_id                              │
│ created_at                  │        │ public_address UNIQUE                 │
└─────────────────────────────┘        │ encrypted_key_shard (MPC network ID) │
                                       │ pqc_signature_capable                 │
                                       │ status  ('active'|'used'|'revoked')   │
                                       │ created_at                            │
                                       └──────────────────────────────────────┘
```

---

## Table Definitions

### `meta_accounts`

Stores the canonical user identity. Authentication credentials (WebAuthn passkeys) are serialised as JSON into `auth_methods_json` — no passwords or password hashes are stored anywhere.

```sql
CREATE TABLE IF NOT EXISTS meta_accounts (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    canonical_identifier TEXT    NOT NULL UNIQUE, -- username / email / DID
    auth_methods_json    TEXT    NOT NULL,         -- serialised webauthn_rs::Passkey
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

| Column | Type | Notes |
|--------|------|-------|
| `id` | `INTEGER` | Auto-increment PK, maps to Rust `i64` |
| `canonical_identifier` | `TEXT UNIQUE` | The user's stable identifier (e.g. email, DID) |
| `auth_methods_json` | `TEXT` | JSON-serialised `webauthn_rs::Passkey`; future: array for multi-device support |
| `created_at` | `DATETIME` | Server-side wall-clock insert time |

---

### `ephemeral_addresses`

One-to-many proxy addresses spawned from a Meta-Account via the MPC network. The actual private key **never** leaves the MPC enclave — only the network key identifier is stored here as `encrypted_key_shard`.

```sql
CREATE TABLE IF NOT EXISTS ephemeral_addresses (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    meta_account_id      INTEGER NOT NULL,
    chain_id             TEXT    NOT NULL,        -- 'ethereum', 'solana', 'starknet', …
    public_address       TEXT    NOT NULL UNIQUE, -- 0x… or Base58
    encrypted_key_shard  BLOB    NOT NULL,        -- MPC network key ID (UTF-8 bytes)
    pqc_signature_capable BOOLEAN DEFAULT 0,      -- false = Track A (ECDSA)
                                                  -- true  = Track B (PQC / SPHINCS+)
    status               TEXT    DEFAULT 'active', -- 'active' | 'used' | 'revoked'
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (meta_account_id) REFERENCES meta_accounts(id)
);
```

| Column | Type | Notes |
|--------|------|-------|
| `id` | `INTEGER` | Auto-increment PK |
| `meta_account_id` | `INTEGER` | FK → `meta_accounts.id` |
| `chain_id` | `TEXT` | Chain namespace string |
| `public_address` | `TEXT UNIQUE` | The routable on-chain address |
| `encrypted_key_shard` | `BLOB` | MPC network key ID stored as UTF-8 bytes; in Track A this is a UUID string issued by Turnkey/Lit Protocol |
| `pqc_signature_capable` | `BOOLEAN` | Flags addresses minted using Track B PQC key generation (mock SPHINCS+) |
| `status` | `TEXT` | Lifecycle: addresses move `active → used/revoked`; revocation via `UPDATE … SET status = 'revoked'` |
| `created_at` | `DATETIME` | Server-side insert time |

---

## DB Operations Reference

All operations are executed asynchronously by `DbClient` (`src/db.rs`) over a libSQL connection. The connection supports both local SQLite files and remote Turso replicas with automatic local caching.

### Identity Management

#### `create_meta_account`

Called by `POST /meta_account/register_finish` after WebAuthn attestation succeeds.

```sql
INSERT INTO meta_accounts (canonical_identifier, auth_methods_json)
VALUES (?1, ?2);
```

| Param | Value |
|-------|-------|
| `?1` | `canonical_identifier` from request |
| `?2` | JSON-serialised `webauthn_rs::Passkey` |

Returns: `last_insert_rowid()` → `meta_account_id`

---

#### `get_meta_account_by_identifier`

Called by `POST /auth/login_start` to retrieve the stored passkey for challenge generation, and by `POST /auth/login_finish` to resolve the `meta_account_id` for JWT issuance.

```sql
SELECT id, canonical_identifier, auth_methods_json, created_at
FROM   meta_accounts
WHERE  canonical_identifier = ?1;
```

Returns: `Option<MetaAccount>` — `None` produces `401 Unauthorized`.

---

### Ephemeral Address Lifecycle

#### `create_ephemeral_address`

Called by `POST /wallet/ephemeral/generate` and internally by `POST /paymaster/swap_intent` to create the one-time execution proxy.

```sql
INSERT INTO ephemeral_addresses
    (meta_account_id, chain_id, public_address, encrypted_key_shard, pqc_signature_capable)
VALUES (?1, ?2, ?3, ?4, ?5);
```

| Param | Value |
|-------|-------|
| `?1` | `meta_account_id` |
| `?2` | `chain_id` (e.g. `"ethereum"`) |
| `?3` | Public address returned by MPC network |
| `?4` | MPC network key ID bytes |
| `?5` | `pqc_signature_capable` flag |

Returns: `last_insert_rowid()` → `ephemeral_address_id`

---

#### `get_ephemeral_addresses_for_account`

Called by `POST /wallet/ephemeral/list`.

```sql
SELECT id, meta_account_id, chain_id, public_address,
       encrypted_key_shard, pqc_signature_capable, status, created_at
FROM   ephemeral_addresses
WHERE  meta_account_id = ?1
AND    status = 'active';
```

Returns: `Vec<EphemeralAddress>`

---

#### `revoke_ephemeral_address`

Soft-deletes an address by updating its lifecycle status. The historical record is preserved.

```sql
UPDATE ephemeral_addresses
SET    status = 'revoked'
WHERE  id = ?1;
```

---

## Rust Domain Types

These types are defined in `src/models/domain.rs` and imported where needed. They are the single source of truth.

```rust
pub struct MetaAccount {
    pub id:                   i64,
    pub canonical_identifier: String,
    pub auth_methods_json:    String,
    pub created_at:           String,
}

pub struct EphemeralAddress {
    pub id:                    i64,
    pub meta_account_id:       i64,
    pub chain_id:              String,
    pub public_address:        String,
    pub encrypted_key_shard:   Vec<u8>,
    pub pqc_signature_capable: bool,
    pub status:                String,
    pub created_at:            String,
}

pub struct Claims {       // JWT payload
    pub sub: i64,         // meta_account_id
    pub exp: i64,         // Unix timestamp
}
```

---

## Migration Notes

| Aspect | Legacy (PostgreSQL) | Current (Turso / libSQL) |
|--------|--------------------|-----------------------|
| Identity | `users` table: username + Argon2 hash + TOTP secret | `meta_accounts`: canonical ID + serialised WebAuthn passkey |
| Keys | `wallets`: AES-GCM encrypted private key in DB | `ephemeral_addresses`: only MPC network key ID stored |
| Auth | Password + TOTP | Passwordless FIDO2 / WebAuthn |
| Scalability | Single-node Postgres | Multi-DC libSQL with local replica |
| PQC | None | `pqc_signature_capable` flag; Track B mock SPHINCS+ via MPC |
