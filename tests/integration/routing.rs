//! Cross-cutting integration tests (routing, health, shape validation).
//!
//! Handler-specific tests live co-located in their modules:
//!   src/handlers/auth.rs      — registration & login
//!   src/handlers/wallet.rs    — ephemeral address CRUD
//!   src/handlers/paymaster.rs — swap intents
//!
//! Run all tests:
//!   JWT_SECRET=test cargo test -- --nocapture

use super::common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};

// ═══════════════════════════════════════════════════════════════════════════════
// Health & routing
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn health_returns_ok() {
    let (status, body) = common::send(Method::GET, "/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "OK");
}

#[tokio::test]
async fn unknown_route_returns_404() {
    let (status, _) = common::send(Method::GET, "/nonexistent").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

// ═══════════════════════════════════════════════════════════════════════════════
// All POST endpoints reject empty JSON body
// ═══════════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn all_post_endpoints_reject_empty_body() {
    let endpoints = [
        "/meta_account/register_start",
        "/meta_account/register_finish",
        "/auth/login_start",
        "/auth/login_finish",
        "/wallet/ephemeral/generate",
        "/wallet/ephemeral/sign",
        "/wallet/ephemeral/list",
        "/paymaster/swap_intent",
    ];

    for uri in endpoints {
        let req = Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();

        let resp = tower::ServiceExt::oneshot(common::app().await, req).await.unwrap();
        let status = resp.status();
        assert!(
            status == StatusCode::UNPROCESSABLE_ENTITY || status == StatusCode::BAD_REQUEST,
            "{uri} accepted empty body — expected 422 or 400, got {status}"
        );
    }
}
