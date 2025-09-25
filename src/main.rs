use std::net::SocketAddr;
use std::sync::Arc;
use std::env;
use std::path::Path;
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
use sqlx::{SqlitePool, Row, Error as SqlxError, sqlite::SqliteConnectOptions};
use totp_rs::{Algorithm, TOTP};
use base64::Engine;

#[derive(Clone)]
struct AppState {
    db: SqlitePool, // Persistent database for wallet data
    totp_db: SqlitePool, // In-memory database for TOTP secrets
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
        "#,
    )
        .execute(pool)
        .await?;
    Ok(())
}

async fn init_totp_db(totp_db: &SqlitePool) -> Result<(), SqlxError> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS totp_secrets (
            user_id INTEGER PRIMARY KEY,
            totp_secret TEXT NOT NULL
        );
        "#,
    )
        .execute(totp_db)
        .await?;
    Ok(())
}

async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Register>,
) -> impl IntoResponse {
    let argon2 = Argon2::default();
    let mut salt = [0u8; 16];
    thread_rng().fill_bytes(&mut salt);
    let salt_string = SaltString::encode_b64(&salt).unwrap();
    let hash = argon2
        .hash_password(body.password.as_bytes(), &salt_string)
        .unwrap()
        .to_string();

    // Derive TOTP secret from password hash using Scrypt
    let mut totp_secret_bytes = [0u8; 32];
    let params = Params::new(14, 8, 1, 32).unwrap();
    scrypt(hash.as_bytes(), b"totp_salt", &params, &mut totp_secret_bytes).unwrap();

    let _totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        totp_secret_bytes.to_vec(),
    ).unwrap();
    let totp_secret_b64 = base64::engine::general_purpose::STANDARD.encode(&totp_secret_bytes);
    // Manually construct TOTP URL
    let totp_url = format!(
        "otpauth://totp/WalletServiceAuth:{}?secret={}&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30",
        body.username, totp_secret_b64
    );

    let result = sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    )
        .bind(&body.username)
        .bind(&hash)
        .execute(&state.db)
        .await;

    match result {
        Ok(_insert) => {
            let user_id: i64 = sqlx::query("SELECT last_insert_rowid()")
                .fetch_one(&state.db)
                .await
                .unwrap()
                .get(0);

            // Store TOTP secret in in-memory database
            if let Err(e) = sqlx::query(
                "INSERT INTO totp_secrets (user_id, totp_secret) VALUES (?, ?)",
            )
                .bind(user_id)
                .bind(&totp_secret_b64)
                .execute(&state.totp_db)
                .await
            {
                eprintln!("Failed to store TOTP secret: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            Json(RegisterResponse { totp_url }).into_response()
        }
        Err(_) => StatusCode::CONFLICT.into_response(), // Username taken
    }
}

async fn login(State(state): State<Arc<AppState>>, Json(body): Json<Login>) -> impl IntoResponse {
    let user_row = sqlx::query(
        "SELECT id, password_hash FROM users WHERE username = ?",
    )
        .bind(body.username)
        .fetch_optional(&state.db)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Database error in login: {}", e);
            None
        });

    if let Some(u) = user_row {
        let password_hash: String = u.get("password_hash");
        let id: i64 = u.get("id");

        if let Ok(parsed_hash) = PasswordHash::new(&password_hash) {
            let argon2 = Argon2::default();
            if argon2.verify_password(body.password.as_bytes(), &parsed_hash).is_ok() {
                let now = Utc::now().timestamp();
                let claims = Claims {
                    sub: id,
                    exp: now + 3600, // 1 hour
                };
                let token = encode(
                    &Header::default(),
                    &claims,
                    &EncodingKey::from_secret(&state.jwt_secret),
                )
                    .unwrap();
                return Json(serde_json::json!({"token": token})).into_response();
            }
        }
    }
    StatusCode::UNAUTHORIZED.into_response()
}

async fn verify_totp(totp_db: &SqlitePool, user_id: i64, totp_code: &str) -> bool {
    let totp_row = sqlx::query(
        "SELECT totp_secret FROM totp_secrets WHERE user_id = ?",
    )
        .bind(user_id)
        .fetch_optional(totp_db)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Database error in verify_totp: {}", e);
            None
        });

    match totp_row {
        Some(row) => {
            let totp_secret_b64: String = row.get("totp_secret");
            let totp_secret_bytes = match base64::engine::general_purpose::STANDARD.decode(&totp_secret_b64) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("Failed to decode TOTP secret: {}", e);
                    return false;
                }
            };

            let totp = TOTP::new(
                Algorithm::SHA1,
                6,
                1,
                30,
                totp_secret_bytes,
            ).unwrap();

            totp.check_current(totp_code).unwrap_or(false)
        }
        None => false,
    }
}

async fn generate_key(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GenerateKey>,
) -> impl IntoResponse {
    // Verify TOTP code
    if !verify_totp(&state.totp_db, claims.sub, &body.totp_code).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let existing = sqlx::query(
        "SELECT user_id FROM wallets WHERE user_id = ?",
    )
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Database error in generate_key: {}", e);
            None
        });

    if existing.is_some() {
        return (StatusCode::BAD_REQUEST, "Wallet already exists").into_response();
    }

    // Generate private key
    let mut privkey = [0u8; 32];
    OsRng.fill_bytes(&mut privkey);
    let secret_key = SecretKey::from_slice(&privkey).unwrap();

    // Generate public key and address
    let secp = Secp256k1::new();
    let pubkey = PublicKey::from_secret_key(&secp, &secret_key);
    let pubkey_bytes = pubkey.serialize_uncompressed();
    let mut hasher = Keccak256::new();
    hasher.update(&pubkey_bytes[1..]);
    let hash = hasher.finalize();
    let address = format!("0x{}", hex_encode(&hash[12..]));

    // Derive encryption key with Scrypt (using user_id as salt for simplicity)
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let params = Params::new(14, 8, 1, 32).unwrap();
    let mut dk = [0u8; 32];
    scrypt(claims.sub.to_le_bytes().as_ref(), &salt, &params, &mut dk).unwrap();

    // Encrypt private key
    let cipher = Aes256Gcm::new_from_slice(&dk).unwrap();
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), privkey.as_ref())
        .unwrap();
    let mut encrypted = nonce.to_vec();
    encrypted.extend_from_slice(&ciphertext);

    // Store
    if let Err(e) = sqlx::query(
        "INSERT INTO wallets (user_id, encrypted_privkey, salt, address) VALUES (?, ?, ?, ?)",
    )
        .bind(claims.sub)
        .bind(encrypted)
        .bind(salt.to_vec())
        .bind(address.clone())
        .execute(&state.db)
        .await
    {
        eprintln!("Database error in generate_key store: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    Json(serde_json::json!({"address": address})).into_response()
}

async fn sign(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<SignMessage>,
) -> impl IntoResponse {
    // Verify TOTP code
    if !verify_totp(&state.totp_db, claims.sub, &body.totp_code).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let wallet_row = sqlx::query(
        "SELECT encrypted_privkey, salt FROM wallets WHERE user_id = ?",
    )
        .bind(claims.sub)
        .fetch_optional(&state.db)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Database error in sign: {}", e);
            None
        });

    if let Some(w) = wallet_row {
        let encrypted_privkey: Vec<u8> = w.get("encrypted_privkey");
        let salt: Vec<u8> = w.get("salt");

        // Derive key (using user_id as input for Scrypt)
        let params = Params::new(14, 8, 1, 32).unwrap();
        let mut dk = [0u8; 32];
        scrypt(claims.sub.to_le_bytes().as_ref(), &salt, &params, &mut dk).unwrap();

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&dk).unwrap();
        let nonce_slice = &encrypted_privkey[0..12];
        let ciphertext_slice = &encrypted_privkey[12..];
        let privkey_bytes: Vec<u8> = match cipher.decrypt(Nonce::from_slice(nonce_slice), ciphertext_slice) {
            Ok(p) => p,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(), // Invalid key
        };
        let secret_key = SecretKey::from_slice(&privkey_bytes).unwrap();

        // Prepare message hash (EIP-191)
        let prefixed_msg = format!(
            "\x19Ethereum Signed Message:\n{}{}",
            body.message.len(),
            body.message
        );
        let mut hasher = Keccak256::new();
        hasher.update(prefixed_msg.as_bytes());
        let msg_hash = hasher.finalize();
        let message = Message::from_digest_slice(&msg_hash).unwrap();

        // Sign recoverable
        let secp = Secp256k1::new();
        let recoverable_sig = secp.sign_ecdsa_recoverable(&message, &secret_key);
        let (rec_id, compact) = recoverable_sig.serialize_compact();
        let v = rec_id.to_i32() + 27;
        let r = hex_encode(&compact[0..32]);
        let s = hex_encode(&compact[32..64]);
        let signature = format!("0x{}{}{:02x}", r, s, v);

        Json(serde_json::json!({"signature": signature})).into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

async fn forget(
    Extension(claims): Extension<Claims>,
    State(state): State<Arc<AppState>>,
    Json(body): Json<GenerateKey>,
) -> impl IntoResponse {
    // Verify TOTP code
    if !verify_totp(&state.totp_db, claims.sub, &body.totp_code).await {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    // Only delete TOTP secret
    if let Err(e) = sqlx::query("DELETE FROM totp_secrets WHERE user_id = ?")
        .bind(claims.sub)
        .execute(&state.totp_db)
        .await
    {
        eprintln!("Database error in forget TOTP secret: {}", e);
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    StatusCode::OK.into_response()
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = req.headers().get(axum::http::header::AUTHORIZATION);
    if let Some(header_value) = auth_header {
        if let Ok(header_str) = header_value.to_str() {
            if header_str.starts_with("Bearer ") {
                let token = &header_str[7..];
                let validation = Validation::default();
                if let Ok(decoded) = decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(&state.jwt_secret),
                    &validation,
                ) {
                    req.extensions_mut().insert(decoded.claims);
                    return Ok(next.run(req).await);
                }
            }
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

#[tokio::main]
async fn main() {
    let db_path = Path::new("./data").join("wallet.db");
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!("Failed to create directory {}: {}", parent.display(), e);
            std::process::exit(1);
        });
    }

    let database_url = format!("sqlite://{}", db_path.display());
    println!("Connecting to database: {}", database_url);

    let db = match SqlitePool::connect(&database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("Failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };

    if let Err(e) = init_db(&db).await {
        eprintln!("Failed to initialize database: {}", e);
        std::process::exit(1);
    }

    if let Err(e) = init_db(&db).await {
        eprintln!("Failed to initialize database at {}: {}", db_path.display(), e);
        std::process::exit(1);
    }

    // Initialize in-memory TOTP database
    let totp_db = SqlitePool::connect_with(
        SqliteConnectOptions::new()
            .filename(":memory:")
            .create_if_missing(true),
    )
        .await
        .unwrap_or_else(|e| {
            eprintln!("Failed to initialize in-memory TOTP database: {}", e);
            std::process::exit(1);
        });

    if let Err(e) = init_totp_db(&totp_db).await {
        eprintln!("Failed to initialize TOTP database: {}", e);
        std::process::exit(1);
    }

    println!("Database initialized successfully at: {}", db_path.display());
    println!("TOTP database initialized in memory");

    let jwt_secret = env::var("JWT_SECRET")
        .unwrap_or_else(|_| "supersecretkey".to_string())
        .into_bytes();

    let state = Arc::new(AppState { db, totp_db, jwt_secret });

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
