use std::net::SocketAddr;
use std::sync::Arc;
use std::env;

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use argon2::{self, Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    body::Body,
    extract::{Extension, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::Utc;
use hex::encode as hex_encode;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand::{RngCore, thread_rng};
use scrypt::{scrypt, Params};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use sqlx::{SqlitePool, Row, Error as SqlxError};
use totp_rs::{Algorithm, TOTP};
use base32;
use log::{info, error};

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    jwt_secret: Vec<u8>,
}

#[derive(Deserialize)]
struct Register {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    totp_url: String,
}

#[derive(Deserialize)]
struct Login {
    username: String,
    password: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct GenerateKey {
    totp_code: String,
}

#[derive(Deserialize)]
struct SignMessage {
    message: String,
    totp_code: String,
}

async fn init_db(pool: &SqlitePool) -> Result<(), SqlxError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS wallets (
            user_id INTEGER PRIMARY KEY,
            encrypted_privkey BLOB NOT NULL,
            salt BLOB NOT NULL,
            address TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS totp_secrets (
            user_id INTEGER PRIMARY KEY,
            totp_secret TEXT NOT NULL
        );
        "#,
    )
        .execute(pool)
        .await?;
    Ok(())
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Register>,
) -> Result<impl IntoResponse, StatusCode> {
    let argon2 = Argon2::default();
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    let salt_string = SaltString::encode_b64(&salt).unwrap();
    let hash = argon2
        .hash_password(body.password.as_bytes(), &salt_string)
        .map_err(|e| {
            error!("Failed to hash password: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .to_string();

    let exists = sqlx::query("SELECT COUNT(*) FROM users WHERE username = ?")
        .bind(&body.username)
        .fetch_one(&state.db)
        .await
        .map(|row| row.get::<i64, _>(0) > 0)
        .map_err(|e| {
            error!("Failed to check username existence: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    if exists {
        return Ok((StatusCode::CONFLICT, "Username already exists").into_response());
    }

    let mut totp_secret_bytes = [0u8; 20];
    thread_rng().fill_bytes(&mut totp_secret_bytes);
    let totp_secret_b64 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &totp_secret_bytes);

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        totp_secret_bytes.to_vec(),
    ).unwrap();
    let test_code = totp.generate_current().unwrap();
    info!("Generated TOTP for {}: code={}", body.username, test_code);

    let totp_url = format!(
        "otpauth://totp/WalletServiceAuth:{}?secret={}&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30",
        body.username, totp_secret_b64
    );

    let mut tx = state.db.begin().await.map_err(|e| {
        error!("Failed to start transaction: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let result = sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(&body.username)
        .bind(&hash)
        .execute(&mut *tx)
        .await;

    match result {
        Ok(_insert) => {
            let user_id: i64 = sqlx::query("SELECT last_insert_rowid()")
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| {
                    error!("Failed to get user_id: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?
                .get(0);

            sqlx::query("INSERT INTO totp_secrets (user_id, totp_secret) VALUES (?, ?)")
                .bind(user_id)
                .bind(&totp_secret_b64)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!("Failed to store TOTP secret: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;

            tx.commit().await.map_err(|e| {
                error!("Failed to commit transaction: {}", e);
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

            Ok(Json(RegisterResponse { totp_url }).into_response())
        }
        Err(e) if e.to_string().contains("UNIQUE constraint failed") => {
            Ok((StatusCode::CONFLICT, "Username already exists").into_response())
        }
        Err(e) => {
            error!("Failed to insert user: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Login>,
) -> Result<impl IntoResponse, StatusCode> {
    let user_row = sqlx::query("SELECT id, password_hash FROM users WHERE username = ?")
        .bind(&body.username)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            error!("Failed to query user: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if let Some(u) = user_row {
        let password_hash: String = u.get("password_hash");
        let id: i64 = u.get("id");

        let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| {
            error!("Failed to parse password hash: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        let argon2 = Argon2::default();
        if argon2.verify_password(body.password.as_bytes(), &parsed_hash).is_ok() {
            let now = Utc::now().timestamp();
            let claims = Claims {
                sub: id,
                exp: now + 3600,
            };
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(&state.jwt_secret))
                .map_err(|e| {
                    error!("Failed to encode JWT: {}", e);
                    StatusCode::INTERNAL_SERVER_ERROR
                })?;
            Ok(Json(serde_json::json!({"token": token})).into_response())
        } else {
            Ok(StatusCode::UNAUTHORIZED.into_response())
        }
    } else {
        Ok(StatusCode::UNAUTHORIZED.into_response())
    }
}

async fn verify_totp(db: &SqlitePool, user_id: i64, totp_code: &str) -> bool {
    let totp_row = match sqlx::query("SELECT totp_secret FROM totp_secrets WHERE user_id = ?")
        .bind(user_id)
        .fetch_optional(db)
        .await
    {
        Ok(row) => row,
        Err(e) => {
            error!("Failed to query TOTP secret for user_id {}: {}", user_id, e);
            return false;
        }
    };

    match totp_row {
        Some(row) => {
            let totp_secret_b64: String = row.get("totp_secret");
            let totp_secret_bytes = match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &totp_secret_b64) {
                Some(bytes) => bytes,
                None => {
                    error!("Invalid Base32 TOTP secret for user_id {}", user_id);
                    return false;
                }
            };

            let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, totp_secret_bytes).unwrap();
            let now = Utc::now().timestamp();
            let current_time_step = now as u64;
            let prev_time_step = (now - 30) as u64;

            totp.check(totp_code, current_time_step) || totp.check(totp_code, prev_time_step)
        }
        None => {
            error!("No TOTP secret found for user_id {}", user_id);
            false
        }
    }
}

async fn generate_key(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GenerateKey>,
) -> Result<impl IntoResponse, StatusCode> {
    if !verify_totp(&state.db, claims.sub, &body.totp_code).await {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    let exists = sqlx::query("SELECT user_id FROM wallets WHERE user_id = ?")
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map(|row| row.is_some())
        .map_err(|e| {
            error!("Failed to check wallet existence for user_id {}: {}", claims.sub, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if exists {
        return Ok((StatusCode::BAD_REQUEST, "Wallet already exists").into_response());
    }

    let mut privkey = [0u8; 32];
    OsRng.fill_bytes(&mut privkey);
    let secret_key = SecretKey::from_slice(&privkey).map_err(|e| {
        error!("Failed to create secret key: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, &secret_key);
    let pubkey_bytes = pubkey.serialize_uncompressed();
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]);
    let hash = hasher.finalize();
    let address = format!("0x{}", hex_encode(&hash[12..]));

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let params = Params::new(14, 8, 1, 32).unwrap();
    let mut dk = [0u8; 32];
    scrypt(claims.sub.to_le_bytes().as_ref(), &salt, &params, &mut dk).unwrap();

    let cipher = Aes256Gcm::new_from_slice(&dk).unwrap();
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), privkey.as_ref()).map_err(|e| {
        error!("Failed to encrypt private key: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let mut encrypted = nonce.to_vec();
    encrypted.extend_from_slice(&ciphertext);

    sqlx::query("INSERT INTO wallets (user_id, encrypted_privkey, salt, address) VALUES (?, ?, ?, ?)")
        .bind(claims.sub)
        .bind(encrypted)
        .bind(salt.to_vec())
        .bind(&address)
        .execute(&state.db)
        .await
        .map_err(|e| {
            error!("Failed to store wallet for user_id {}: {}", claims.sub, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(serde_json::json!({"address": address})).into_response())
}

async fn sign(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<SignMessage>,
) -> Result<impl IntoResponse, StatusCode> {
    if !verify_totp(&state.db, claims.sub, &body.totp_code).await {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    let wallet_row = sqlx::query("SELECT encrypted_privkey, salt FROM wallets WHERE user_id = ?")
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            error!("Failed to query wallet for user_id {}: {}", claims.sub, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    if let Some(w) = wallet_row {
        let encrypted_privkey: Vec<u8> = w.get("encrypted_privkey");
        let salt: Vec<u8> = w.get("salt");

        let params = Params::new(14, 8, 1, 32).unwrap();
        let mut dk = [0u8; 32];
        scrypt(claims.sub.to_le_bytes().as_ref(), &salt, &params, &mut dk).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&dk).unwrap();
        let nonce_slice = &encrypted_privkey[0..12];
        let ciphertext_slice = &encrypted_privkey[12..];
        let privkey_bytes: Vec<u8> = cipher.decrypt(Nonce::from_slice(nonce_slice), ciphertext_slice).map_err(|e| {
            error!("Failed to decrypt private key for user_id {}: {}", claims.sub, e);
            StatusCode::BAD_REQUEST
        })?;
        let secret_key = SecretKey::from_slice(&privkey_bytes).map_err(|e| {
            error!("Invalid private key for user_id {}: {}", claims.sub, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let prefixed_msg = format!(
            "\x19Ethereum Signed Message:\n{}{}",
            body.message.len(),
            body.message
        );
        let mut hasher = Keccak256::new();
        hasher.update(prefixed_msg.as_bytes());
        let msg_hash = hasher.finalize();
        let message = Message::from_digest_slice(&msg_hash).map_err(|e| {
            error!("Failed to create message hash: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

        let secp = Secp256k1::new();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (rec_id, compact) = recoverable_sig.serialize_compact();
        let v = rec_id.to_i32() + 27;
        let r = hex_encode(&compact[0..32]);
        let s = hex_encode(&compact[32..64]);
        let signature = format!("0x{}{}{:02x}", r, s, v);

        Ok(Json(serde_json::json!({"signature": signature})).into_response())
    } else {
        Ok(StatusCode::NOT_FOUND.into_response())
    }
}

async fn forget(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GenerateKey>,
) -> Result<impl IntoResponse, StatusCode> {
    if !verify_totp(&state.db, claims.sub, &body.totp_code).await {
        return Ok(StatusCode::UNAUTHORIZED.into_response());
    }

    sqlx::query("DELETE FROM totp_secrets WHERE user_id = ?")
        .bind(claims.sub)
        .execute(&state.db)
        .await
        .map_err(|e| {
            error!("Failed to delete TOTP secret for user_id {}: {}", claims.sub, e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(StatusCode::OK.into_response())
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(axum::http::header::AUTHORIZATION);
    let token = match auth_header {
        Some(header_value) => match header_value.to_str() {
            Ok(header_str) if header_str.starts_with("Bearer ") => &header_str[7..],
            _ => return Err(StatusCode::UNAUTHORIZED),
        },
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    let validation = Validation::default();
    match decode::<Claims>(token, &DecodingKey::from_secret(&state.jwt_secret), &validation) {
        Ok(decoded) => {
            req.extensions_mut().insert(decoded.claims);
            Ok(next.run(req).await)
        }
        Err(e) => {
            error!("JWT validation failed: {}", e);
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();

    let database_url = "sqlite://./data/wallet.db";
    let db = match SqlitePool::connect(database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Failed to connect to database at {}: {}", database_url, e);
            std::process::exit(1);
        }
    };

    if let Err(e) = init_db(&db).await {
        eprintln!("Failed to initialize database at {}: {}", database_url, e);
        std::process::exit(1);
    }

    let jwt_secret = match env::var("JWT_SECRET") {
        Ok(secret) => secret.into_bytes(),
        Err(_) => {
            eprintln!("JWT_SECRET environment variable not set");
            std::process::exit(1);
        }
    };

    let state = Arc::new(AppState { db, jwt_secret });

    let protected_routes = Router::new()
        .route("/generate_key", post(generate_key))
        .route("/sign", post(sign))
        .route("/forget", post(forget))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ));

    let app = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .nest("/api", protected_routes)
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Server running on http://{}", addr);

    if let Err(e) = axum::serve(
        tokio::net::TcpListener::bind(&addr).await.unwrap(),
        app.into_make_service(),
    )
        .await
    {
        eprintln!("Server error: {}", e);
        std::process::exit(1);
    }
}
