//! MPC network provider abstraction.
//!
//! This module owns the *network* side of key management:
//! provisioning distributed keys and requesting threshold signatures.
//! All raw cryptography lives in [`crate::crypto`].

use crate::crypto;
use async_trait::async_trait;
use log::info;
use secp256k1::SecretKey;
use std::collections::HashMap;
use tokio::sync::Mutex;
use uuid::Uuid;

// ═══════════════════════════════════════════════════════════════════════════════
// Key material stored in the mock vault
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Clone)]
pub enum MockedKey {
    Ecdsa(SecretKey),
    Pqc(Vec<u8>), // 64-byte seed/key material
}

// ═══════════════════════════════════════════════════════════════════════════════
// Provider trait
// ═══════════════════════════════════════════════════════════════════════════════

#[async_trait]
pub trait MpcProvider: Send + Sync {
    /// Provision a new distributed key on the MPC network.
    /// Returns: `(public_address, network_key_id)`.
    async fn provision_key(
        &self,
        chain_id: &str,
        use_pqc: bool,
        user_auth_material: &str,
    ) -> Result<(String, String), String>;

    /// Request a threshold signature from the MPC network.
    async fn sign_payload(
        &self,
        network_key_id: &str,
        payload_hash: &[u8],
        user_auth_material: &str,
    ) -> Result<String, String>;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Mock implementation (Lit / Turnkey stand-in)
// ═══════════════════════════════════════════════════════════════════════════════

pub struct MockLitTurnkeyApi {
    vault: Mutex<HashMap<String, MockedKey>>,
}

impl MockLitTurnkeyApi {
    pub fn new() -> Self {
        Self {
            vault: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl MpcProvider for MockLitTurnkeyApi {
    async fn provision_key(
        &self,
        _chain_id: &str,
        use_pqc: bool,
        user_auth_material: &str,
    ) -> Result<(String, String), String> {
        info!(
            ">>> [Network Request] Calling MPC Provider to provision distributed key (PQC: {})...",
            use_pqc
        );

        if user_auth_material.is_empty() {
            return Err("Missing FIDO Auth Material".to_string());
        }

        let (mocked_key, address) = if use_pqc {
            info!("MINTING TRACK B: Post-Quantum Hash-Based Signature Keys (Mocked SPHINCS+)");
            let (seed, addr) = crypto::generate_pqc_keypair();
            (MockedKey::Pqc(seed), addr)
        } else {
            info!("MINTING TRACK A: Standard ECDSA Keys");
            let (sk, addr) = crypto::generate_ecdsa_keypair();
            (MockedKey::Ecdsa(sk), addr)
        };

        let network_key_id = Uuid::new_v4().to_string();

        let mut vault = self.vault.lock().await;
        vault.insert(network_key_id.clone(), mocked_key);

        info!("<<< [Network Response] Key Provisioned! Address: {}", address);
        Ok((address, network_key_id))
    }

    async fn sign_payload(
        &self,
        network_key_id: &str,
        payload_hash: &[u8],
        user_auth_material: &str,
    ) -> Result<String, String> {
        info!(">>> [Network Request] Requesting Distributed Network Signature...");

        if user_auth_material.is_empty() {
            return Err("Missing FIDO Auth Material".to_string());
        }

        let vault = self.vault.lock().await;
        let mocked_key = vault
            .get(network_key_id)
            .ok_or("Key not found in external network")?;

        let signature_hex = match mocked_key {
            MockedKey::Ecdsa(secret_key) => crypto::sign_ecdsa(secret_key, payload_hash)?,
            MockedKey::Pqc(seed) => {
                info!("Executing PQC Hash-Based Signature Routine over payload...");
                crypto::sign_pqc_mock(seed, payload_hash)
            }
        };

        info!("<<< [Network Response] Network computed signature securely!");
        Ok(signature_hex)
    }
}
