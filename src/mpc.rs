use async_trait::async_trait;
use log::info;
use rand::{rngs::OsRng, RngCore};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};
use hex::encode as hex_encode;
use std::collections::HashMap;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Clone)]
pub enum MockedKey {
    Ecdsa(SecretKey),
    PqcSphincs(Vec<u8>), // Mocking a 64-byte PQC seed/key structure
}

#[async_trait]
pub trait MpcProvider: Send + Sync {
    /// Calls the centralized/decentralized network to provision a new key.
    /// Returns: (Public Address, Unique Network Key ID payload)
    async fn provision_key(&self, chain_id: &str, use_pqc: bool, user_auth_material: &str) -> Result<(String, String), String>;

    /// Distributes a signing payload to the network nodes.
    async fn sign_payload(
        &self, 
        network_key_id: &str, 
        payload_hash: &[u8], 
        user_auth_material: &str
    ) -> Result<String, String>;
}

pub struct MockLitTurnkeyApi {
    external_vault: Mutex<HashMap<String, MockedKey>>,
}

impl MockLitTurnkeyApi {
    pub fn new() -> Self {
        Self {
            external_vault: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl MpcProvider for MockLitTurnkeyApi {
    async fn provision_key(&self, _chain_id: &str, use_pqc: bool, user_auth_material: &str) -> Result<(String, String), String> {
        info!(">>> [Network Request] Calling MPC Provider to generated distributed key (PQC: {})...", use_pqc);
        
        if user_auth_material.is_empty() {
            return Err("Missing FIDO Auth Material".to_string());
        }

        let address;
        let mocked_key;

        if use_pqc {
            info!("MINTING TRACK B: Post-Quantum Hash-Based Signature Keys (Mocked SPHINCS+)");
            // Mocking a PQC Key Generation (Sphincs+ / Dilithium)
            let mut pqc_seed = vec![0u8; 64];
            OsRng.fill_bytes(&mut pqc_seed);
            
            // Simulating a larger PQC public key abstraction hashed down to an address representation
            let mut hasher = Keccak256::new();
            hasher.update(b"PQC_PUBLIC_ABSTRACTION:");
            hasher.update(&pqc_seed);
            
            address = format!("0x{}", hex_encode(&hasher.finalize()[12..]));
            mocked_key = MockedKey::PqcSphincs(pqc_seed);
        } else {
            info!("MINTING TRACK A: Standard ECDSA Keys");
            let secp = Secp256k1::new();
            let mut priv_key = [0u8; 32];
            OsRng.fill_bytes(&mut priv_key);

            let secret_key = SecretKey::from_slice(&priv_key).map_err(|_| "Crypto Error")?;
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let public_key_bytes = public_key.serialize_uncompressed();
            
            address = format!("0x{}", hex_encode(&Keccak256::digest(&public_key_bytes[1..])[12..]));
            mocked_key = MockedKey::Ecdsa(secret_key);
        }

        let network_key_id = Uuid::new_v4().to_string();

        let mut vault = self.external_vault.lock().await;
        vault.insert(network_key_id.clone(), mocked_key);

        info!("<<< [Network Response] Key Provisioned! Address: {}", address);
        Ok((address, network_key_id))
    }

    async fn sign_payload(
        &self, 
        network_key_id: &str, 
        payload_hash: &[u8], 
        user_auth_material: &str
    ) -> Result<String, String> {
        info!(">>> [Network Request] Requesting Distributed Network Signature...");
        
        if user_auth_material.is_empty() {
            return Err("Missing FIDO Auth Material".to_string());
        }

        let vault = self.external_vault.lock().await;
        let mocked_key = vault.get(network_key_id).ok_or("Key not found in external network")?;

        let signature_hex = match mocked_key {
            MockedKey::Ecdsa(secret_key) => {
                let secp = Secp256k1::new();
                let message = Message::from_digest_slice(payload_hash).map_err(|_| "Invalid Hash")?;

                let signature = secp.sign_ecdsa(&message, secret_key);
                format!("0x{}", hex_encode(signature.serialize_der()))
            }
            MockedKey::PqcSphincs(seed) => {
                info!("Executing PQC Hash-Based Signature Routine over payload...");
                // Mocking a massive output block that SPHINCS+ would generate (using keccak for a deterministic mock)
                let mut hasher = Keccak256::new();
                hasher.update(b"PQC_SIGNATURE_MOCK");
                hasher.update(seed);
                hasher.update(payload_hash);
                
                let simulated_pqc_block = hasher.finalize();
                // A real PQC signature would be massive (e.g. 40KB for SPHINCS+). We just return a prefixed mock hex.
                format!("0xPQC_MOCK_{}", hex_encode(simulated_pqc_block))
            }
        };

        info!("<<< [Network Response] Network computed signature securely!");
        Ok(signature_hex)
    }
}
