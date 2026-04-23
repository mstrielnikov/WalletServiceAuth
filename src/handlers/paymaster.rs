use crate::models::dto::{SubmitSwapIntentReq, SubmitSwapIntentRes};
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use log::{error, info};
use std::sync::Arc;
use uuid::Uuid;

/// `POST /paymaster/swap_intent`
///
/// Accepts a chain-agnostic swap intent, provisions a one-time proxy address on
/// the destination chain via the MPC network, links it to the caller's
/// Meta-Account, and returns the execution queue ticket.
pub async fn submit_swap_intent(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<SubmitSwapIntentReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!(
        "swap_intent account={} {} {} → {} {}",
        payload.meta_account_id,
        payload.collateral_chain,
        payload.collateral_asset,
        payload.destination_chain,
        payload.destination_asset,
    );

    if payload.user_auth_assertion.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "Missing FIDO assertion".to_string()));
    }

    // Provision a one-time execution proxy on the destination chain.
    let (proxy_address, network_key) = state
        .mpc
        .provision_key(
            &payload.destination_chain,
            false, // paymaster uses ECDSA for cross-chain compat; PQC bridging is out-of-scope
            &payload.user_auth_assertion,
        )
        .await
        .map_err(|e| {
            error!("MPC provision_key for swap: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Paymaster proxy failed".to_string())
        })?;

    state
        .db
        .create_ephemeral_address(
            payload.meta_account_id,
            &payload.destination_chain,
            &proxy_address,
            network_key.into_bytes(),
            false,
        )
        .await
        .map_err(|e| {
            error!("create_ephemeral_address for swap proxy: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "DB error".to_string())
        })?;

    Ok(Json(SubmitSwapIntentRes {
        intent_id: Uuid::new_v4().to_string(),
        status: "queued".to_string(),
        assigned_proxy_ephemeral_address: proxy_address,
        expected_network_fee: payload.amount_required * 0.003, // 0.3 % mock slippage
    }))
}
