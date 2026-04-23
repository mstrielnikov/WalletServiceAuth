use super::common;

use axum::http::StatusCode;
use serde_json::json;

#[tokio::test]
async fn rejects_empty_auth() {
    let (status, _) = common::post_json(
        "/paymaster/swap_intent",
        json!({
            "meta_account_id": 1,
            "destination_chain": "evm:42161",
            "destination_asset": "USDC",
            "amount_required": 100.0,
            "collateral_chain": "evm:1",
            "collateral_asset": "ETH",
            "user_auth_assertion": ""
        }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn returns_queued_intent() {
    let meta_id = common::seed_meta_account("paymaster@test.local").await;

    let (status, body) = common::post_json(
        "/paymaster/swap_intent",
        json!({
            "meta_account_id": meta_id,
            "destination_chain": "evm:42161",
            "destination_asset": "USDC",
            "amount_required": 100.0,
            "collateral_chain": "evm:1",
            "collateral_asset": "ETH",
            "user_auth_assertion": "valid-fido-assertion"
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK, "body: {body}");
    assert_eq!(body["status"].as_str().unwrap(), "queued");
    assert!(body["intent_id"].as_str().is_some(), "missing intent_id");
    assert!(
        body["assigned_proxy_ephemeral_address"].as_str().unwrap().starts_with("0x"),
        "proxy address must be 0x-prefixed"
    );
    let fee = body["expected_network_fee"].as_f64().unwrap();
    assert!((fee - 0.3).abs() < 0.001, "expected fee ~0.3, got {fee}");
}
