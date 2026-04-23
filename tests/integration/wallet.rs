use super::common;

use axum::http::StatusCode;
use serde_json::json;

// ── Generate ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn generate_rejects_empty_auth() {
    let (status, _) = common::post_json(
        "/wallet/ephemeral/generate",
        json!({
            "meta_account_id": 1,
            "chain_id": "evm:1",
            "use_pqc": false,
            "auth_assertion": ""
        }),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn generate_ecdsa_returns_address() {
    let meta_id = common::seed_meta_account("wallet-ecdsa@test.local").await;

    let (status, body) = common::post_json(
        "/wallet/ephemeral/generate",
        json!({
            "meta_account_id": meta_id,
            "chain_id": "evm:1",
            "use_pqc": false,
            "auth_assertion": "valid-test-assertion"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["ephemeral_address_id"].is_number(), "missing ephemeral_address_id");
    assert!(body["public_address"].as_str().unwrap().starts_with("0x"), "address must be 0x-prefixed");
}

#[tokio::test]
async fn generate_pqc_returns_address() {
    let meta_id = common::seed_meta_account("wallet-pqc@test.local").await;

    let (status, body) = common::post_json(
        "/wallet/ephemeral/generate",
        json!({
            "meta_account_id": meta_id,
            "chain_id": "evm:137",
            "use_pqc": true,
            "auth_assertion": "valid-test-assertion"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body["public_address"].as_str().unwrap().starts_with("0x"), "PQC address must be 0x-prefixed");
}

// ── List ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_returns_array_for_nonexistent() {
    let (status, body) = common::post_json(
        "/wallet/ephemeral/list",
        json!({ "meta_account_id": 999999 }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert!(body.is_array(), "expected JSON array, got: {body}");
}

// ── Sign ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sign_rejects_invalid_hex() {
    let (status, _) = common::post_json(
        "/wallet/ephemeral/sign",
        json!({
            "ephemeral_address_id": 1,
            "payload_hash_hex": "not-valid-hex",
            "auth_assertion": "valid"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sign_rejects_empty_auth() {
    let (status, _) = common::post_json(
        "/wallet/ephemeral/sign",
        json!({
            "ephemeral_address_id": 1,
            "payload_hash_hex": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "auth_assertion": ""
        }),
    )
    .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}
