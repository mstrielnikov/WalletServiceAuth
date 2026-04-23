//! Cryptographic primitives for key generation, address derivation, and signing.
//!
//! This module owns all raw cryptography so that `mpc.rs` only handles
//! network orchestration.  When a real PQC library (e.g. `slh-dsa`,
//! `ml-dsa` from RustCrypto) reaches audit status, implement `PqcSigner`
//! and drop the Keccak mock below.

use hex::encode as hex_encode;
use rand::{rngs::OsRng, RngCore};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

// ═══════════════════════════════════════════════════════════════════════════════
// PQC readiness trait
// ═══════════════════════════════════════════════════════════════════════════════

/// Trait abstraction for post-quantum signature schemes.
///
/// Implementors plug into the `MockedKey::Pqc` variant via
/// `CryptoProvider::sign_pqc`.  When a production PQC crate is added,
/// swap the mock for a real implementation without touching MPC or handler
/// code.
pub trait PqcSigner: Send + Sync {
    /// NIST algorithm identifier, e.g. `"SLH-DSA-SHA2-128s"`.
    fn algorithm(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    fn verify(&self, message: &[u8], sig: &[u8]) -> bool;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ECDSA (secp256k1) helpers
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a fresh secp256k1 keypair.
/// Returns `(secret_key, ethereum-style 0x-address)`.
pub fn generate_ecdsa_keypair() -> (SecretKey, String) {
    let secp = Secp256k1::new();
    let mut priv_key = [0u8; 32];
    OsRng.fill_bytes(&mut priv_key);

    let secret_key = SecretKey::from_slice(&priv_key)
        .expect("32-byte random slice is always a valid secp256k1 secret key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize_uncompressed();

    let address = format!(
        "0x{}",
        hex_encode(&Keccak256::digest(&public_key_bytes[1..])[12..])
    );

    (secret_key, address)
}

/// Sign a 32-byte digest with a secp256k1 secret key.
/// Returns a DER-encoded ECDSA signature as a hex string.
pub fn sign_ecdsa(secret_key: &SecretKey, digest: &[u8]) -> Result<String, String> {
    let secp = Secp256k1::new();
    let message = Message::from_digest_slice(digest).map_err(|_| "Invalid 32-byte hash")?;
    let signature = secp.sign_ecdsa(&message, secret_key);
    Ok(format!("0x{}", hex_encode(signature.serialize_der())))
}

// ═══════════════════════════════════════════════════════════════════════════════
// PQC mock (Keccak-based deterministic stub)
// ═══════════════════════════════════════════════════════════════════════════════

/// Generate a mocked PQC keypair (64-byte seed + Keccak-derived address).
pub fn generate_pqc_keypair() -> (Vec<u8>, String) {
    let mut seed = vec![0u8; 64];
    OsRng.fill_bytes(&mut seed);

    let mut hasher = Keccak256::new();
    hasher.update(b"PQC_PUBLIC_ABSTRACTION:");
    hasher.update(&seed);

    let address = format!("0x{}", hex_encode(&hasher.finalize()[12..]));
    (seed, address)
}

/// Produce a mocked PQC signature (Keccak hash of seed ‖ payload).
///
/// A real SPHINCS+ / SLH-DSA signature would be ~8–40 KB.
pub fn sign_pqc_mock(seed: &[u8], payload_hash: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(b"PQC_SIGNATURE_MOCK");
    hasher.update(seed);
    hasher.update(payload_hash);
    format!("0xPQC_MOCK_{}", hex_encode(hasher.finalize()))
}
