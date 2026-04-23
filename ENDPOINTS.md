# API Endpoints Reference

> **Platform:** WalletServiceAuth — Chain-Agnostic, Post-Quantum WaaS  
> **Auth Model:** Passwordless FIDO2/WebAuthn Passkeys → JWT session tokens  
> **Key Management:** Off-server MPC network (Track A: ECDSA · Track B: PQC/SPHINCS+)  
> **Database:** Turso/libSQL (horizontally scalable, encrypted-at-rest)

---

## Data Models

### `MetaAccount`
Canonical user identity. Decoupled from any payment address (Hedera-inspired).

| Field | Type | Description |
|-------|------|-------------|
| `id` | `i64` | Auto-increment primary key |
| `canonical_identifier` | `String` | Unique username / email / DID |
| `auth_methods_json` | `String` | Serialized registered `Passkey` credential |
| `created_at` | `String` | ISO-8601 timestamp |

### `EphemeralAddress`
One-time or reusable proxy address routed through the MPC network. Many-to-one with `MetaAccount`.

| Field | Type | Description |
|-------|------|-------------|
| `id` | `i64` | Auto-increment primary key |
| `meta_account_id` | `i64` | FK → `meta_accounts.id` |
| `chain_id` | `String` | e.g. `"ethereum"`, `"solana"`, `"starknet"` |
| `public_address` | `String` | `0x…` or Base58 address |
| `encrypted_key_shard` | `bytes` | MPC network key ID (UTF-8 encoded) |
| `pqc_signature_capable` | `bool` | `true` = Track B (SPHINCS+), `false` = ECDSA |
| `status` | `String` | `"active"` \| `"used"` \| `"revoked"` |
| `created_at` | `String` | ISO-8601 timestamp |

### `Claims` (JWT Payload)

| Field | Type | Description |
|-------|------|-------------|
| `sub` | `i64` | `meta_account_id` |
| `exp` | `i64` | Unix timestamp (1 hour from issue) |

---

## Auth Engine — Typestate Pipeline

All auth flows pass through the compile-time enforced **`AuthProvider`** typestate machine:

```
Init  ──challenge()──▶  Challenged  ──verify()──▶  Verified
```

Adding a provider (TOTP, OAuth) requires implementing `AuthProvider<Challenge, Response, SessionState>` — handler code is not touched.

---

## Endpoints

### 1. Passkey Registration

#### `POST /meta_account/register_start`

Initiates a WebAuthn passkey registration ceremony. Returns a FIDO2 challenge for the browser's `navigator.credentials.create()` call.

**Request**
```json
{ "canonical_identifier": "alice@example.com" }
```

**Response `200 OK`**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "challenge": { /* CreationChallengeResponse (CBOR/JSON per WebAuthn spec) */ }
}
```

**Errors**
| Code | Reason |
|------|--------|
| `500` | WebAuthn challenge generation failed |

---

#### `POST /meta_account/register_finish`

Completes registration. Cryptographically verifies the device's signed attestation, serialises the `Passkey`, and creates the `MetaAccount` in Turso.

**Request**
```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "canonical_identifier": "alice@example.com",
  "credential": { /* RegisterPublicKeyCredential from navigator.credentials.create() */ }
}
```

**Response `200 OK`**
```json
{ "meta_account_id": 42 }
```

**Errors**
| Code | Reason |
|------|--------|
| `400` | Session expired or not found (5 min TTL) |
| `401` | Invalid passkey signature / attestation |
| `500` | DB write error or JSON encoding failure |

**User Sequence**
```
Client                        Server
  │──POST register_start────▶│  generate challenge + store PasskeyRegistration in moka cache
  │◀──session_id + challenge──│
  │  [device signs challenge] │
  │──POST register_finish───▶│  verify signature, create MetaAccount in Turso
  │◀──{ meta_account_id }────│
```

---

### 2. Passkey Authentication → JWT

#### `POST /auth/login_start`

Issues a WebAuthn authentication challenge for an existing `MetaAccount`. The client passes this to `navigator.credentials.get()`.

**Request**
```json
{ "canonical_identifier": "alice@example.com" }
```

**Response `200 OK`**
```json
{
  "session_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "challenge": { /* RequestChallengeResponse (WebAuthn assertion options) */ }
}
```

**Errors**
| Code | Reason |
|------|--------|
| `401` | User not found |
| `500` | DB error or corrupt passkey data |

---

#### `POST /auth/login_finish`

Verifies the signed assertion. Returns a JWT token (`sub` = `meta_account_id`, TTL 1 hour).

**Request**
```json
{
  "session_id": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
  "canonical_identifier": "alice@example.com",
  "credential": { /* PublicKeyCredential from navigator.credentials.get() */ }
}
```

**Response `200 OK`**
```json
{ "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9…" }
```

**Errors**
| Code | Reason |
|------|--------|
| `400` | Session expired or not found (5 min TTL) |
| `401` | Invalid passkey assertion |
| `500` | JWT encoding failure |

**User Sequence**
```
Client                        Server
  │──POST login_start───────▶│  fetch MetaAccount + stored Passkey, generate assertion challenge
  │◀──session_id + challenge──│
  │  [device signs challenge] │
  │──POST login_finish──────▶│  verify signature → issue JWT
  │◀──{ token }──────────────│
```

---

### 3. Ephemeral Wallet Management

All wallet endpoints require a FIDO `auth_assertion` carrying the user's intent approval. JWT auth will be enforced here in a future middleware layer.

#### `POST /wallet/ephemeral/generate`

Provisions a new one-time proxy address via the MPC network (Lit Protocol / Turnkey model). Supports both Track A (ECDSA) and Track B (PQC / SPHINCS+).

**Request**
```json
{
  "meta_account_id": 42,
  "chain_id": "ethereum",
  "use_pqc": false,
  "auth_assertion": "<fido-assertion-token>"
}
```

**Response `200 OK`**
```json
{
  "ephemeral_address_id": 7,
  "public_address": "0x4a9d2c8f1e3b0571ca8e650d24f9a3c7b02d1e84"
}
```

**Errors**
| Code | Reason |
|------|--------|
| `500` | MPC network provisioning failure or DB write error |

---

#### `POST /wallet/ephemeral/sign`

Requests a distributed MPC signature over an arbitrary payload hash. The shard key is resolved from the stored `encrypted_key_shard` field and forwarded to the MPC network.

**Request**
```json
{
  "ephemeral_address_id": 7,
  "payload_hash_hex": "0xabc123…",
  "auth_assertion": "<fido-assertion-token>"
}
```

**Response `200 OK`**
```json
{
  "signature": "0x3044…"
}
```

> When `use_pqc = true`, the signature is prefixed `0xPQC_MOCK_…` (mock SPHINCS+ block; real implementation produces ~40 KB output).

**Errors**
| Code | Reason |
|------|--------|
| `400` | Invalid hex payload |
| `500` | MPC signing failure |

---

#### `POST /wallet/ephemeral/list`

Returns all currently **active** ephemeral addresses for a given Meta-Account.

**Request**
```json
{ "meta_account_id": 42 }
```

**Response `200 OK`**
```json
[
  {
    "id": 7,
    "meta_account_id": 42,
    "chain_id": "ethereum",
    "public_address": "0x4a9d2c8f…",
    "encrypted_key_shard": [/* bytes */],
    "pqc_signature_capable": false,
    "status": "active",
    "created_at": "2026-04-23T00:00:00Z"
  }
]
```

---

### 4. Cross-Chain Paymaster

#### `POST /paymaster/swap_intent`

Submits a chain-agnostic atomic swap intent. The platform provisions a dedicated one-time proxy address on the destination chain, links it to the caller's `MetaAccount`, and queues the swap for execution — abstracting bridging complexity from the user.

**Request**
```json
{
  "meta_account_id": 42,
  "destination_chain": "solana",
  "destination_asset": "USDC",
  "amount_required": 100.0,
  "collateral_chain": "ethereum",
  "collateral_asset": "ETH",
  "user_auth_assertion": "<fido-assertion-token>"
}
```

**Response `200 OK`**
```json
{
  "intent_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "status": "queued",
  "assigned_proxy_ephemeral_address": "0x9f21bc…",
  "expected_network_fee": 0.3
}
```

**Errors**
| Code | Reason |
|------|--------|
| `401` | Missing or empty FIDO assertion |
| `500` | MPC proxy provisioning or DB error |

**Swap Sequence**
```
Client                           Server                      MPC Network
  │──POST swap_intent──────────▶│                               │
  │                              │──provision_key(dest_chain)──▶│
  │                              │◀──(proxy_addr, key_id)───────│
  │                              │──create_ephemeral_address()──▶ DB
  │◀──{ intent_id, proxy_addr } ─│
  │                              │  [Atomic swap executor picks up intent]
```

---

### 5. Health Check

#### `GET /health`

**Response `200 OK`**: `OK`

---

## Status Code Reference

| Code | Meaning |
|------|---------|
| `200` | Success |
| `400` | Bad request (expired session, malformed input) |
| `401` | Unauthorized (invalid passkey, missing assertion) |
| `500` | Internal server error (DB, MPC, or crypto failure) |

---

## Session Cache

Registration and login sessions are stored in an embedded **moka** cache (async, TTL-based):

| Cache | Key | TTL |
|-------|-----|-----|
| `auth_reg_sessions` | `session_id (UUID)` | 5 minutes |
| `auth_login_sessions` | `session_id (UUID)` | 5 minutes |

Sessions are automatically evicted after TTL expiry. For multi-instance deployments, replace with a Redis-backed store.
