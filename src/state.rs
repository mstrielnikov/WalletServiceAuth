use crate::db::DbClient;
use crate::mpc::MpcProvider;
use moka::future::Cache;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Shared application state injected into every Axum handler via `State<Arc<AppState>>`.
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<DbClient>,
    pub webauthn: Arc<Webauthn>,
    pub mpc: Arc<dyn MpcProvider>,
    /// Short-lived WebAuthn registration sessions keyed by a random UUID.
    /// TTL: 5 minutes – stale challenges are evicted automatically by moka.
    pub auth_reg_sessions: Cache<Uuid, PasskeyRegistration>,
    /// Short-lived WebAuthn login sessions keyed by a random UUID.
    pub auth_login_sessions: Cache<Uuid, PasskeyAuthentication>,
    pub jwt_secret: Vec<u8>,
}

impl AppState {
    pub async fn build() -> Result<Self, Box<dyn std::error::Error>> {
        // ── Database ──────────────────────────────────────────────────────────
        let db = Arc::new(DbClient::new().await?);

        // ── WebAuthn ──────────────────────────────────────────────────────────
        let rp_id = std::env::var("WEBAUTHN_RP_ID")
            .unwrap_or_else(|_| "localhost".to_string());
        let rp_origin_str = std::env::var("WEBAUTHN_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:3000".to_string());
        let rp_origin = Url::parse(&rp_origin_str)?;
        let webauthn = Arc::new(
            WebauthnBuilder::new(&rp_id, &rp_origin)?.build()?,
        );

        // ── MPC Provider (swappable – currently mocked) ───────────────────────
        let mpc: Arc<dyn MpcProvider> =
            Arc::new(crate::mpc::MockLitTurnkeyApi::new());

        // ── Session caches ────────────────────────────────────────────────────
        let session_ttl = Duration::from_secs(300);
        let auth_reg_sessions = Cache::builder()
            .time_to_live(session_ttl)
            .build();
        let auth_login_sessions = Cache::builder()
            .time_to_live(session_ttl)
            .build();

        // ── JWT secret ────────────────────────────────────────────────────────
        let jwt_secret = std::env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set in production")
            .into_bytes();

        Ok(Self {
            db,
            webauthn,
            mpc,
            auth_reg_sessions,
            auth_login_sessions,
            jwt_secret,
        })
    }
}
