use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct MetaAccount {
    pub id: i64,
    pub canonical_identifier: String,
    pub auth_methods_json: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphemeralAddress {
    pub id: i64,
    pub meta_account_id: i64,
    pub chain_id: String,
    pub public_address: String,
    pub encrypted_key_shard: Vec<u8>,
    pub pqc_signature_capable: bool,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: i64, // Meta Account ID
    pub exp: i64,
}
