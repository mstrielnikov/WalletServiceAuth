mod db;
mod handlers;
mod models;
mod mpc;
mod state;

use axum::{
    routing::{get, post},
    Router,
};
use env_logger::Env;
use log::info;
use state::AppState;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Starting WalletServiceAuth WaaS Platform…");

    let state = Arc::new(AppState::build().await?);

    let app = Router::new()
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
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}
