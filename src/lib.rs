pub mod crypto;
pub mod db;
pub mod handlers;
pub mod models;
pub mod mpc;
pub mod state;

use axum::{
    routing::{get, post},
    Router,
};
use state::AppState;
use std::sync::Arc;

/// Construct the full application router with all routes wired up.
///
/// Extracted from `main()` so integration tests can exercise the
/// real handler stack in-process via `tower::ServiceExt::oneshot`.
pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/health", get(|| async { "OK" }))
        // Identity management (WebAuthn registration)
        .route("/meta_account/register_start",  post(handlers::auth::register_start))
        .route("/meta_account/register_finish", post(handlers::auth::register_finish))
        // Authentication (WebAuthn login → JWT)
        .route("/auth/login_start",  post(handlers::auth::login_start))
        .route("/auth/login_finish", post(handlers::auth::login_finish))
        // Ephemeral wallet management
        .route("/wallet/ephemeral/generate", post(handlers::wallet::generate_ephemeral))
        .route("/wallet/ephemeral/sign",     post(handlers::wallet::sign_ephemeral))
        .route("/wallet/ephemeral/list",     post(handlers::wallet::list_ephemeral))
        // Cross-chain paymaster
        .route("/paymaster/swap_intent", post(handlers::paymaster::submit_swap_intent))
        .with_state(state)
}
