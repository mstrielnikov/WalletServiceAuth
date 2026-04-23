# PQWaaS

**Chain-agnostic, Post-Quantum-Ready Wallet-as-a-Service (WaaS) platform.**  
Passwordless authentication · MPC-distributed key management · Cross-chain intent routing

---

## Overview

A modular, horizontally scalable WaaS platform written in Rust (`Axum` + `Tokio`). The platform separates **identity** from **payment routing** and delegates private key custody entirely to an external MPC network — no secret material is stored on the server.

| Aspect         |                                                                |
| -------------- | -------------------------------------------------------------- |
| Auth           | Passwordless **FIDO2 / WebAuthn** Passkeys                     |
| Storage        | **Turso / libSQL** (multi-DC, horizontally scalable)           |
| Key custody    | **MPC network** (Lit Protocol / Turnkey model)                 |
| Identity model | **Meta-Account** (identity ↔ N ephemeral addresses)            |
| PQC readiness  | **Track B** – mock SPHINCS+ path, `pqc_signature_capable` flag |
| Chains         | Chain-agnostic (`chain_id` field, any EVM / Solana / Starknet) |

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                          Axum HTTP Layer                         │
│   /meta_account/*   /auth/*   /wallet/ephemeral/*   /paymaster/* │
└────────────────────────┬─────────────────────────────────────────┘
                         │
          ┌──────────────┼───────────────────┐
          ▼              ▼                   ▼
   ┌─────────────┐ ┌──────────┐    ┌─────────────────┐
   │  state.rs   │ │ auth.rs  │    │   handlers/     │
   │  AppState   │ │Typestate │    │ auth / wallet / │
   │  + moka TTL │ │pipeline  │    │  paymaster      │
   └──────┬──────┘ └──────────┘    └────────┬────────┘
          │                                  │
     ┌────┴────┐                      ┌──────┴──────┐
     │  db.rs  │                      │   mpc.rs    │
     │ DbClient│                      │ MpcProvider │
     │ (libSQL)│                      │  (trait)    │
     └────┬────┘                      └──────┬──────┘
          │                                  │
     Turso / libSQL               MPC Network (Lit / Turnkey)
     (local replica +             off-server key custody
      remote sync)
```

**Module layout:**

```
src/
├── main.rs              # Server bootstrap only (44 lines)
├── state.rs             # AppState + build()
├── auth.rs              # Typestate auth engine (Init→Challenged→Verified)
├── mpc.rs               # MpcProvider trait + MockLitTurnkeyApi
├── db.rs                # DbClient (libSQL async)
├── models/
│   ├── domain.rs        # MetaAccount, EphemeralAddress, Claims
│   └── dto.rs           # All request/response DTOs
└── handlers/
    ├── auth.rs          # WebAuthn register + login handlers
    ├── wallet.rs        # Ephemeral wallet handlers
    └── paymaster.rs     # Cross-chain swap intent handler
```

---

## Features

### Passwordless Authentication (WebAuthn / FIDO2)

- Two-step passkey registration (`register_start` / `register_finish`)
- Two-step passkey login (`login_start` / `login_finish`) returning a signed JWT
- Session challenges stored in an embedded **moka** async cache with 5-minute TTL; ready to swap for Redis in multi-node deployments
- Auth state machine enforced at compile time via the **typestate pattern** (`Init → Challenged → Verified`) — impossible to call `verify` before `challenge`
- Pluggable `AuthProvider` trait: adding TOTP, OAuth, or hardware-key providers requires only a new struct, no handler changes

### MPC-Backed Ephemeral Wallets

- **Track A (ECDSA):** Delegates key generation to the MPC network; only the network key ID is persisted server-side
- **Track B (PQC):** `use_pqc: true` triggers a mock SPHINCS+ key path — address derivation and signing are routed through the PQC branch; ready for a real `pqc` crate integration
- Addresses are linked to the caller's `MetaAccount` with full lifecycle tracking (`active → used → revoked`)
- Distributed signing via `MpcProvider::sign_payload` — ECDSA and mocked PQC signing paths both functional

### Turso / libSQL Database

- Schema initialised at startup; no migration tool required
- Supports Turso remote replica + local sync (set `TURSO_DATABASE_URL` + `TURSO_AUTH_TOKEN`); falls back to a local SQLite file
- `DbClient` provides typed async methods for all CRUD operations against `meta_accounts` and `ephemeral_addresses`
- Domain types defined once in `src/models/domain.rs`, imported everywhere

### Cross-Chain Paymaster Intent

- `POST /paymaster/swap_intent` accepts a chain-agnostic intent (collateral chain/asset → destination chain/asset)
- Provisions a one-time proxy address on the destination chain via the MPC network and records it under the caller's `MetaAccount`
- Returns an `intent_id`, estimated fee (0.3 % mock slippage), and the assigned proxy address
- Execution queue is a stub — designed for integration with an atomic swap or bridge protocol

---

## Running Locally

### Prerequisites

- Rust 1.75+
- `JWT_SECRET` environment variable set
- (Optional) Turso account for remote DB: `TURSO_DATABASE_URL` + `TURSO_AUTH_TOKEN`

### Local SQLite mode (fastest)

```bash
export JWT_SECRET=dev-secret
export RUST_LOG=info
cargo run
# Server starts on http://0.0.0.0:3000
# SQLite DB created at ./wallet.db
```

### Remote Turso mode

```bash
export JWT_SECRET=your-production-secret
export TURSO_DATABASE_URL=libsql://your-db.turso.io
export TURSO_AUTH_TOKEN=your-token
export RUST_LOG=info
cargo run
```

### Verify

```bash
curl http://localhost:3000/health
# → OK
```

---

## Environment Variables

| Variable             | Required | Default                 | Description                                            |
| -------------------- | -------- | ----------------------- | ------------------------------------------------------ |
| `JWT_SECRET`         | **Yes**  | —                       | HMAC-SHA256 signing secret for JWT tokens              |
| `TURSO_DATABASE_URL` | No       | `wallet.db`             | Turso remote URL or `file:./wallet.db`                 |
| `TURSO_AUTH_TOKEN`   | No       | `""`                    | Auth token for Turso remote connections                |
| `TURSO_LOCAL_URL`    | No       | `local_sync.db`         | Local replica path for remote sync mode                |
| `WEBAUTHN_RP_ID`     | No       | `localhost`             | WebAuthn relying party ID (set to your domain in prod) |
| `WEBAUTHN_ORIGIN`    | No       | `http://localhost:3000` | WebAuthn origin (must match browser origin exactly)    |
| `RUST_LOG`           | No       | `info`                  | Log level (`trace`, `debug`, `info`, `warn`, `error`)  |

---

## Documentation

| Document                       | Description                                                                       |
| ------------------------------ | --------------------------------------------------------------------------------- |
| [ENDPOINTS.md](./ENDPOINTS.md) | Full API reference: request/response schemas, user sequence diagrams, error codes |
| [SCHEMA.md](./SCHEMA.md)       | Database schema, DDL, DB operation reference, Rust domain types, migration notes  |

---

## Security Notes

- **No passwords stored** — ever. Authentication relies entirely on hardware-bound passkey signatures
- **No private keys stored** — only MPC network key IDs are persisted; the actual key material stays in the enclave
- **Challenge TTL** — registration and login sessions expire after 5 minutes via moka cache eviction
- **JWT expiry** — tokens are valid for 1 hour (`exp` claim)
- **PQC flag** — addresses can be tagged `pqc_signature_capable` in preparation for quantum-resistant signing pipelines

---

### Mocked / In-Progress

| Feature                                        | Status         | Notes                                                                                   |
| ---------------------------------------------- | -------------- | --------------------------------------------------------------------------------------- |
| MPC network calls                              | **Mocked**     | `MockLitTurnkeyApi` simulates Turnkey/Lit Protocol; replace with real HTTP client       |
| PQC signing (SPHINCS+)                         | **Mocked**     | Returns `0xPQC_MOCK_…` prefixed Keccak hash; plug in `pqc` or `oqs` crate               |
| `sign_ephemeral` key lookup                    | **Stub**       | `get_ephemeral_address_by_id` not yet in `DbClient`; `network_key_id` is empty string   |
| FIDO assertion enforcement on wallet endpoints | **Stub**       | `auth_assertion` field present in DTOs; verification not yet wired                      |
| JWT middleware guard                           | **Planned**    | JWT issued at login; `Authorization: Bearer` validation on `/wallet/*` not yet enforced |
| Atomic swap executor                           | **Planned**    | Intent queued but no swap/bridge execution engine                                       |
| Multi-device passkeys                          | **Planned**    | `auth_methods_json` stores a single `Passkey`; extend to `Vec<Passkey>`                 |
| TOTP provider                                  | **Scaffolded** | `TotpProvider` struct in `src/auth.rs`; challenge/verify logic is a placeholder         |
| Session store (Redis)                          | **Planned**    | moka cache works for single-node; swap to `deadpool-redis` for cluster mode             |

---

### Roadmap

#### Phase 1 — Foundation

- [x] Turso/libSQL migration with Meta-Account schema
- [x] WebAuthn passkey registration + login
- [x] JWT session issuance
- [x] MPC provider trait + mock implementation
- [x] Ephemeral address generation (Track A ECDSA + Track B PQC mock)
- [x] Cross-chain paymaster intent stub
- [x] Typestate auth engine
- [x] Domain-driven module layout

#### Phase 2 — Production Hardening

- [ ] Real Lit Protocol / Turnkey HTTP client (replaces `MockLitTurnkeyApi`)
- [ ] `get_ephemeral_address_by_id` DB query + sign flow completion
- [ ] Axum JWT middleware (`Authorization: Bearer` guard on `/wallet/*` and `/paymaster/*`)
- [ ] FIDO assertion verification on all mutation endpoints
- [ ] Redis session store for multi-instance deployments
- [ ] Rate limiting (`tower-governor`) on all public endpoints
- [ ] TLS termination

#### Phase 3 — Post-Quantum & Multi-Chain

- [ ] Integrate `oqs` / `liboqs` for real SPHINCS+ / Dilithium key generation and signing
- [ ] ZKvm bridge for PQC ↔ legacy chain compatibility
- [ ] Multi-device passkey support (`Vec<Passkey>` in `auth_methods_json`)
- [ ] One-time address enforcement (`status = 'used'` after first transaction)
- [ ] TOTP provider completion (RFC 6238 via `totp-rs`)
- [ ] Atomic swap executor integration (e.g., Across Protocol, Connext)
- [ ] Distributed MPC coordinator (proprietary PQC-threshold signing)

---

> The current build is a **platform scaffold**. Mocked endpoints (see table above) must be replaced before production use. Rate limiting, TLS, and a Redis session store are required for any multi-user deployment.
