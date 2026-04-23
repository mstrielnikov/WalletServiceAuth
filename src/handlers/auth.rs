use crate::models::domain::Claims;
use crate::models::dto::{LoginFinishReq, LoginStartReq, LoginStartRes, LoginFinishRes,
                         RegisterFinishReq, RegisterStartReq, RegisterStartRes, RegisterFinishRes};
use crate::state::AppState;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use jsonwebtoken::{encode, EncodingKey, Header};
use log::{error, info};
use std::sync::Arc;
use uuid::Uuid;
use webauthn_rs::prelude::Passkey;

// ── Registration ─────────────────────────────────────────────────────────────

pub async fn register_start(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterStartReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("WebAuthn register_start for '{}'", payload.canonical_identifier);

    let user_id = Uuid::new_v4();
    let (challenge, passkey_registration) = state
        .webauthn
        .start_passkey_registration(
            user_id,
            &payload.canonical_identifier,
            &payload.canonical_identifier,
            None,
        )
        .map_err(|e| {
            error!("start_passkey_registration: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn Error".to_string())
        })?;

    state.auth_reg_sessions.insert(user_id, passkey_registration).await;

    Ok(Json(RegisterStartRes { session_id: user_id, challenge }))
}

pub async fn register_finish(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<RegisterFinishReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("WebAuthn register_finish for session {}", payload.session_id);

    let reg_state = state
        .auth_reg_sessions
        .get(&payload.session_id)
        .await
        .ok_or((StatusCode::BAD_REQUEST, "Invalid or expired session".to_string()))?;
    state.auth_reg_sessions.remove(&payload.session_id).await;

    let passkey = state
        .webauthn
        .finish_passkey_registration(&payload.credential, &reg_state)
        .map_err(|e| {
            error!("finish_passkey_registration: {:?}", e);
            (StatusCode::UNAUTHORIZED, "Invalid Passkey Signature".to_string())
        })?;

    let auth_methods_json = serde_json::to_string(&passkey).map_err(|e| {
        error!("Passkey serialisation: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Encoding error".to_string())
    })?;

    let meta_id = state
        .db
        .create_meta_account(&payload.canonical_identifier, &auth_methods_json)
        .await
        .map_err(|e| {
            error!("create_meta_account: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "DB error".to_string())
        })?;

    info!("MetaAccount {} created (WebAuthn passkey)", meta_id);
    Ok(Json(RegisterFinishRes { meta_account_id: meta_id }))
}

// ── Login ─────────────────────────────────────────────────────────────────────

pub async fn login_start(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginStartReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("WebAuthn login_start for '{}'", payload.canonical_identifier);

    let account = state
        .db
        .get_meta_account_by_identifier(&payload.canonical_identifier)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error".to_string()))?
        .ok_or((StatusCode::UNAUTHORIZED, "User not found".to_string()))?;

    let passkey: Passkey = serde_json::from_str(&account.auth_methods_json).map_err(|e| {
        error!("Corrupt passkey data: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Config error".to_string())
    })?;

    let (challenge, passkey_auth) = state
        .webauthn
        .start_passkey_authentication(&[passkey])
        .map_err(|e| {
            error!("start_passkey_authentication: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "WebAuthn error".to_string())
        })?;

    let session_id = Uuid::new_v4();
    state.auth_login_sessions.insert(session_id, passkey_auth).await;

    Ok(Json(LoginStartRes { session_id, challenge }))
}

pub async fn login_finish(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<LoginFinishReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("WebAuthn login_finish for session {}", payload.session_id);

    let auth_state = state
        .auth_login_sessions
        .get(&payload.session_id)
        .await
        .ok_or((StatusCode::BAD_REQUEST, "Invalid or expired session".to_string()))?;
    state.auth_login_sessions.remove(&payload.session_id).await;

    state
        .webauthn
        .finish_passkey_authentication(&payload.credential, &auth_state)
        .map_err(|e| {
            error!("finish_passkey_authentication: {:?}", e);
            (StatusCode::UNAUTHORIZED, "Invalid Passkey Signature".to_string())
        })?;

    let account = state
        .db
        .get_meta_account_by_identifier(&payload.canonical_identifier)
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "DB error".to_string()))?
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Account missing".to_string()))?;

    let claims = Claims {
        sub: account.id,
        exp: (chrono::Utc::now() + chrono::Duration::hours(1)).timestamp(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&state.jwt_secret),
    )
    .map_err(|e| {
        error!("JWT encode: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Token error".to_string())
    })?;

    Ok(Json(LoginFinishRes { token }))
}

