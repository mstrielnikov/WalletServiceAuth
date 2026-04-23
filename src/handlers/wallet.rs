use crate::models::dto::{
    GenerateEphemeralReq, GenerateEphemeralRes,
    ListEphemeralReq,
    SignEphemeralReq, SignEphemeralRes,
};
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use log::{error, info};
use std::sync::Arc;

pub async fn generate_ephemeral(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<GenerateEphemeralReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!(
        "generate_ephemeral via MPC (pqc={}) for meta-account {}",
        payload.use_pqc, payload.meta_account_id
    );

    let (public_address, network_key_id) = state
        .mpc
        .provision_key(&payload.chain_id, payload.use_pqc, &payload.auth_assertion)
        .await
        .map_err(|e| {
            error!("MPC provision_key: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to provision distributed key".to_string())
        })?;

    let ephemeral_id = state
        .db
        .create_ephemeral_address(
            payload.meta_account_id,
            &payload.chain_id,
            &public_address,
            network_key_id.into_bytes(),
            payload.use_pqc,
        )
        .await
        .map_err(|e| {
            error!("create_ephemeral_address: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "DB error".to_string())
        })?;

    Ok(Json(GenerateEphemeralRes {
        ephemeral_address_id: ephemeral_id,
        public_address,
    }))
}

pub async fn sign_ephemeral(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SignEphemeralReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("sign_ephemeral for address id {}", payload.ephemeral_address_id);

    // TODO: query DB for the ephemeral address to fetch its `network_key_id`
    // Tracked in: https://github.com/…/issues/XXX
    // For now we return an unimplemented stub so the endpoint compiles and routes.
    let network_key_id = String::new(); // placeholder – add `get_ephemeral_by_id` to DbClient

    let payload_bytes = hex::decode(payload.payload_hash_hex.trim_start_matches("0x"))
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex payload".to_string()))?;

    let signature = state
        .mpc
        .sign_payload(&network_key_id, &payload_bytes, &payload.auth_assertion)
        .await
        .map_err(|e| {
            error!("MPC sign_payload: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Signature failed".to_string())
        })?;

    Ok(Json(SignEphemeralRes { signature }))
}

pub async fn list_ephemeral(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<ListEphemeralReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("list_ephemeral for meta-account {}", payload.meta_account_id);

    let addresses = state
        .db
        .get_ephemeral_addresses_for_account(payload.meta_account_id)
        .await
        .map_err(|e| {
            error!("get_ephemeral_addresses_for_account: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "DB error".to_string())
        })?;

    Ok(Json(addresses))
}

