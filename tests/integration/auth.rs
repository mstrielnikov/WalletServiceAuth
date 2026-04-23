use super::common;

use axum::http::StatusCode;
use serde_json::json;

// ── Registration ────────────────────────────────────────────────────────────

#[tokio::test]
async fn register_start_returns_challenge_and_session() {
    let (status, body) = common::post_json(
        "/meta_account/register_start",
        json!({ "canonical_identifier": "alice@auth-test.local" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.get("session_id").is_some(), "missing session_id");
    assert!(body.get("challenge").is_some(), "missing challenge");

    let sid = body["session_id"].as_str().unwrap();
    assert_eq!(sid.len(), 36, "session_id not UUID-shaped: {sid}");

    let pk = &body["challenge"]["publicKey"];
    assert!(pk.is_object(), "challenge.publicKey must be an object");
    assert!(pk.get("rp").is_some(), "missing rp");
    assert!(pk.get("challenge").is_some(), "missing challenge nonce");
    assert!(pk.get("user").is_some(), "missing user");
}

#[tokio::test]
async fn register_start_rejects_malformed_body() {
    let (status, _) = common::post_json(
        "/meta_account/register_start",
        json!({ "wrong_field": 123 }),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

// ── Login ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn login_start_rejects_unknown_user() {
    let (status, _) = common::post_json(
        "/auth/login_start",
        json!({ "canonical_identifier": "nobody@does-not-exist.local" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_start_rejects_malformed_body() {
    let (status, _) = common::post_json("/auth/login_start", json!({})).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
