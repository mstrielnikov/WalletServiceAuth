use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{CreationChallengeResponse, PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse};
use uuid::Uuid;

// ----------------------------------------------------
// Registration DTOs
// ----------------------------------------------------

#[derive(Deserialize)]
pub struct RegisterStartReq {
    pub canonical_identifier: String,
}

#[derive(Serialize)]
pub struct RegisterStartRes {
    pub session_id: Uuid,
    pub challenge: CreationChallengeResponse,
}

#[derive(Deserialize)]
pub struct RegisterFinishReq {
    pub session_id: Uuid,
    pub canonical_identifier: String,
    pub credential: RegisterPublicKeyCredential,
}

#[derive(Serialize)]
pub struct RegisterFinishRes {
    pub meta_account_id: i64,
}

// ----------------------------------------------------
// Authentication / Login DTOs
// ----------------------------------------------------

#[derive(Deserialize)]
pub struct LoginStartReq {
    pub canonical_identifier: String,
}

#[derive(Serialize)]
pub struct LoginStartRes {
    pub session_id: Uuid,
    pub challenge: RequestChallengeResponse,
}

#[derive(Deserialize)]
pub struct LoginFinishReq {
    pub session_id: Uuid,
    pub canonical_identifier: String,
    pub credential: PublicKeyCredential,
}

#[derive(Serialize)]
pub struct LoginFinishRes {
    pub token: String, // The generated JWT
}

// ----------------------------------------------------
// Ephemeral Wallet DTOs
// ----------------------------------------------------

#[derive(Deserialize)]
pub struct GenerateEphemeralReq {
    pub meta_account_id: i64,
    pub chain_id: String,
    pub use_pqc: bool, 
    pub auth_assertion: String,
}

#[derive(Serialize)]
pub struct GenerateEphemeralRes {
    pub ephemeral_address_id: i64,
    pub public_address: String,
}

#[derive(Deserialize)]
pub struct ListEphemeralReq {
    pub meta_account_id: i64,
}

#[derive(Deserialize)]
pub struct SignEphemeralReq {
    pub ephemeral_address_id: i64,
    pub payload_hash_hex: String,
    pub auth_assertion: String,
}

#[derive(Serialize)]
pub struct SignEphemeralRes {
    pub signature: String,
}

// ----------------------------------------------------
// Paymaster Intent DTOs
// ----------------------------------------------------

#[derive(Deserialize)]
pub struct SubmitSwapIntentReq {
    pub meta_account_id: i64,
    pub destination_chain: String,
    pub destination_asset: String,
    pub amount_required: f64,
    pub collateral_chain: String,
    pub collateral_asset: String,
    pub user_auth_assertion: String,
}

#[derive(Serialize)]
pub struct SubmitSwapIntentRes {
    pub intent_id: String,
    pub status: String,
    pub assigned_proxy_ephemeral_address: String,
    pub expected_network_fee: f64,
}
