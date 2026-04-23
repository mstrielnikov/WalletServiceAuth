//! Shared test harness for in-process Axum integration tests.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::OnceCell;

static TEST_STATE: OnceCell<Arc<wallet_service_auth::state::AppState>> = OnceCell::const_new();

pub async fn shared_state() -> Arc<wallet_service_auth::state::AppState> {
    TEST_STATE
        .get_or_init(|| async {
            unsafe {
                std::env::set_var("JWT_SECRET", "test-jwt-secret-do-not-use-in-prod");
            }
            Arc::new(
                wallet_service_auth::state::AppState::build()
                    .await
                    .expect("Failed to build test AppState"),
            )
        })
        .await
        .clone()
}

pub async fn app() -> axum::Router {
    wallet_service_auth::build_router(shared_state().await)
}

/// POST JSON and return (status, parsed body).
pub async fn post_json(uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();

    let resp = tower::ServiceExt::oneshot(app().await, req)
        .await
        .unwrap();

    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
        Value::String(String::from_utf8_lossy(&bytes).into_owned())
    });
    (status, json)
}

/// Send a bare request (no body) and return (status, body text).
pub async fn send(method: Method, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap();

    let resp = tower::ServiceExt::oneshot(app().await, req)
        .await
        .unwrap();

    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Seed a meta account directly in the DB, returning its ID.
/// Appends a UUID to the canonical_id to avoid UNIQUE collisions
/// across repeated test runs against a persistent `wallet.db`.
pub async fn seed_meta_account(canonical_id: &str) -> i64 {
    let unique_id = format!("{}_{}", canonical_id, uuid::Uuid::new_v4());
    let state = shared_state().await;
    state
        .db
        .create_meta_account(&unique_id, "{}")
        .await
        .expect("seed_meta_account failed")
}
