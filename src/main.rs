use env_logger::Env;
use log::info;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Starting WalletServiceAuth WaaS Platform…");

    let state = Arc::new(wallet_service_auth::state::AppState::build().await?);
    let app = wallet_service_auth::build_router(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    info!("Listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await?;

    Ok(())
}
