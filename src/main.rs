use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    extract::{State, Json},
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::post,
    Router,
    Extension,
};
use base32;
use chrono::Utc;
use env_logger::Env;
use hex::encode as hex_encode;
use log::{debug, info, error};
use rand::{rngs::OsRng, RngCore};
use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use totp_rs::{Algorithm, TOTP};
use jsonwebtoken::{encode, Header, EncodingKey, decode, DecodingKey, Validation};
use jsonwebtoken::Algorithm as JwtAlgorithm;
use argon2::password_hash::SaltString;

// App state
#[derive(Clone)]
struct AppState {
    db: PgPool,
    jwt_secret: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct Register {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterResponse {
    totp_url: String,
}

#[derive(Deserialize, Debug)]
struct Login {
    username: String,
    password: String,
    totp_code: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
}

#[derive(Deserialize, Debug)]
struct GenerateKey {
    password: String,
    totp_code: String,
}

#[derive(Serialize)]
struct GenerateKeyResponse {
    address: String,
}

#[derive(Deserialize, Debug)]
struct SignMessage {
    message: String,
    password: String,
    totp_code: String,
}

#[derive(Serialize)]
struct SignResponse {
    signature: String,
}

#[derive(Deserialize, Debug)]
struct Forget {
    password: String,
    totp_code: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Claims {
    sub: i32, // Changed from i64 to i32
    exp: i64,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    info!("Starting WalletServiceAuth server...");

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    info!("Connecting to database: {}", db_url);
    let db = match PgPool::connect(&db_url).await {
        Ok(db) => {
            info!("Successfully connected to database");
            db
        }
        Err(e) => {
            error!("Failed to connect to database: {}", e);
            panic!("Database connection failed: {}", e);
        }
    };

    if let Err(e) = sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            encrypted_totp_secret BYTEA NOT NULL,
            salt BYTEA NOT NULL
         )"
    )
        .execute(&db)
        .await
    {
        error!("Failed to create users table: {}", e);
        panic!("Database initialization failed: {}", e);
    }

    if let Err(e) = sqlx::query(
        "CREATE TABLE IF NOT EXISTS wallets (
            user_id BIGINT PRIMARY KEY REFERENCES users(id),
            encrypted_privkey BYTEA NOT NULL,
            salt BYTEA NOT NULL
         )"
    )
        .execute(&db)
        .await
    {
        error!("Failed to create wallets table: {}", e);
        panic!("Database initialization failed: {}", e);
    }
    info!("Database initialized successfully");

    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET must be set")
        .into_bytes();
    let state = Arc::new(AppState { db, jwt_secret });

    let public_routes = Router::new()
        .route("/register", post(register))
        .route("/login", post(login))
        .with_state(state.clone());

    let protected_routes = Router::new()
        .route("/generate_key", post(generate_key))
        .route("/sign", post(sign))
        .route("/forget", post(forget))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state.clone());

    let app = Router::new()
        .nest("/api", protected_routes)
        .merge(public_routes)
        .with_state(state);

    info!("Server running on http://0.0.0.0:3000");
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[axum::debug_handler]
async fn register(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Register>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    debug!("Received register request for username: {}", body.username);

    let mut salt_bytes = [0u8; 16];
    OsRng.fill_bytes(&mut salt_bytes);
    let salt = SaltString::encode_b64(&salt_bytes).unwrap();
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            error!("Password hashing failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })?
        .to_string();

    let mut totp_secret_bytes = [0u8; 20];
    OsRng.fill_bytes(&mut totp_secret_bytes);
    let totp_secret_b64 = base32::encode(base32::Alphabet::RFC4648 { padding: false }, &totp_secret_bytes);

    let encryption_key: [u8; 32] = argon2
        .hash_password(body.password.as_bytes(), &salt)
        .map_err(|e| {
            error!("Encryption key derivation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })?
        .hash
        .unwrap()
        .as_bytes()[0..32]
        .try_into()
        .unwrap();
    let cipher = Aes256Gcm::new(&encryption_key.into());
    let nonce = Nonce::from_slice(&salt_bytes[..12]);
    let encrypted_totp_secret = cipher
        .encrypt(nonce, totp_secret_bytes.as_ref())
        .map_err(|e| {
            error!("TOTP secret encryption failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })?;

    sqlx::query(
        "INSERT INTO users (username, password_hash, encrypted_totp_secret, salt) VALUES ($1, $2, $3, $4) RETURNING id",
    )
        .bind(&body.username)
        .bind(&password_hash)
        .bind(&encrypted_totp_secret)
        .bind(&salt_bytes.to_vec())
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            if e.as_database_error()
                .map_or(false, |db_err| db_err.message().contains("unique constraint"))
            {
                (StatusCode::CONFLICT, "Username already exists")
            } else {
                error!("Database insertion error: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
            }
        })?;

    let totp_url = format!(
        "otpauth://totp/WalletServiceAuth:{}?secret={}&issuer=WalletServiceAuth&algorithm=SHA1&digits=6&period=30",
        body.username, totp_secret_b64
    );

    Ok(Json(RegisterResponse { totp_url }))
}

#[axum::debug_handler]
async fn login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Login>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    debug!("Received login request for username: {}", body.username);

    let user = match sqlx::query("SELECT id, password_hash, encrypted_totp_secret, salt FROM users WHERE username = $1")
        .bind(&body.username)
        .fetch_optional(&state.db)
        .await
    {
        Ok(Some(row)) => row,
        Ok(None) => return Err((StatusCode::UNAUTHORIZED, "Unauthorized")),
        Err(e) => {
            error!("Database query error: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"));
        }
    };

    let user_id = user.get::<i32, _>("id"); // Changed from i64 to i32
    let password_hash = user.get::<String, _>("password_hash");
    let encrypted_totp_secret = user.get::<Vec<u8>, _>("encrypted_totp_secret");
    let salt = user.get::<Vec<u8>, _>("salt");

    let parsed_hash = PasswordHash::new(&password_hash).map_err(|e| {
        error!("Password hash parsing failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    })?;
    Argon2::default()
        .verify_password(body.password.as_bytes(), &parsed_hash)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Unauthorized"))?;

    let salt_str = SaltString::encode_b64(&salt).unwrap();
    let encryption_key: [u8; 32] = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt_str)
        .map_err(|e| {
            error!("Encryption key derivation failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })?
        .hash
        .unwrap()
        .as_bytes()[0..32]
        .try_into()
        .unwrap();
    let cipher = Aes256Gcm::new(&encryption_key.into());
    let nonce = Nonce::from_slice(&salt[..12]);
    let totp_secret_bytes = cipher
        .decrypt(nonce, encrypted_totp_secret.as_ref())
        .map_err(|e| {
            error!("TOTP secret decryption failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })?;

    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, totp_secret_bytes) {
        Ok(totp) => totp,
        Err(e) => {
            error!("TOTP creation failed: {}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error"));
        }
    };
    if !totp.check_current(&body.totp_code).map_err(|e| {
        error!("TOTP verification failed: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
    })? {
        return Err((StatusCode::UNAUTHORIZED, "Unauthorized"));
    }

    let claims = Claims {
        sub: user_id,
        exp: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
    };
    let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(&state.jwt_secret))
        .map_err(|e| {
            error!("JWT encoding failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error")
        })?;

    Ok(Json(LoginResponse { token }))
}

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut req: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok())
        .and_then(|header| header.strip_prefix("Bearer ").map(|s| s.to_string()))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let decoded = decode::<Claims>(
        &auth_header,
        &DecodingKey::from_secret(&state.jwt_secret),
        &Validation::new(JwtAlgorithm::HS256),
    )
        .map_err(|e| {
            error!("JWT validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    req.extensions_mut().insert(decoded.claims);
    Ok(next.run(req).await)
}

#[axum::debug_handler]
async fn generate_key(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<GenerateKey>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = sqlx::query("SELECT encrypted_totp_secret, salt FROM users WHERE id = $1")
        .bind(claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            error!("User query failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let encrypted_totp_secret = user.get::<Vec<u8>, _>("encrypted_totp_secret");
    let salt = user.get::<Vec<u8>, _>("salt");

    let salt_str = SaltString::encode_b64(&salt).unwrap();
    let encryption_key: [u8; 32] = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt_str)
        .map_err(|e| {
            error!("Encryption key derivation failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .hash
        .unwrap()
        .as_bytes()[0..32]
        .try_into()
        .unwrap();
    let cipher = Aes256Gcm::new(&encryption_key.into());
    let nonce = Nonce::from_slice(&salt[..12]);
    let totp_secret_bytes = cipher
        .decrypt(nonce, encrypted_totp_secret.as_ref())
        .map_err(|e| {
            error!("TOTP secret decryption failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, totp_secret_bytes) {
        Ok(totp) => totp,
        Err(e) => {
            error!("TOTP creation failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if !totp.check_current(&body.totp_code).map_err(|e| {
        error!("TOTP verification failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let secp = Secp256k1::new();
    let mut priv_key = [0u8; 32];
    OsRng.fill_bytes(&mut priv_key);
    let secret_key = SecretKey::from_slice(&priv_key).map_err(|e| {
        error!("Secret key creation failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    let public_key_bytes = public_key.serialize_uncompressed();
    let address = hex_encode(&Keccak256::digest(&public_key_bytes[1..])[12..]);

    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let cipher = Aes256Gcm::new(&encryption_key.into());
    let nonce = Nonce::from_slice(&salt[..12]);
    let encrypted_privkey = cipher.encrypt(nonce, priv_key.as_ref()).map_err(|e| {
        error!("Private key encryption failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query("INSERT INTO wallets (user_id, encrypted_privkey, salt) VALUES ($1, $2, $3)")
        .bind(claims.sub)
        .bind(encrypted_privkey)
        .bind(salt.to_vec())
        .execute(&state.db)
        .await
        .map_err(|e| {
            error!("Wallet insertion failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(Json(GenerateKeyResponse {
        address: format!("0x{}", address),
    }))
}

#[axum::debug_handler]
async fn sign(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<SignMessage>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = sqlx::query("SELECT encrypted_totp_secret, salt FROM users WHERE id = $1")
        .bind(claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            error!("User query failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let encrypted_totp_secret = user.get::<Vec<u8>, _>("encrypted_totp_secret");
    let salt = user.get::<Vec<u8>, _>("salt");

    let salt_str = SaltString::encode_b64(&salt).unwrap();
    let encryption_key: [u8; 32] = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt_str)
        .map_err(|e| {
            error!("Encryption key derivation failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .hash
        .unwrap()
        .as_bytes()[0..32]
        .try_into()
        .unwrap();
    let cipher = Aes256Gcm::new(&encryption_key.into());
    let nonce = Nonce::from_slice(&salt[..12]);
    let totp_secret_bytes = cipher
        .decrypt(nonce, encrypted_totp_secret.as_ref())
        .map_err(|e| {
            error!("TOTP secret decryption failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, totp_secret_bytes) {
        Ok(totp) => totp,
        Err(e) => {
            error!("TOTP creation failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if !totp.check_current(&body.totp_code).map_err(|e| {
        error!("TOTP verification failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let wallet = sqlx::query("SELECT encrypted_privkey, salt FROM wallets WHERE user_id = $1")
        .bind(claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            error!("Wallet query failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let encrypted_privkey = wallet.get::<Vec<u8>, _>("encrypted_privkey");
    let wallet_salt = wallet.get::<Vec<u8>, _>("salt");
    let nonce = Nonce::from_slice(&wallet_salt[..12]);
    let priv_key = cipher.decrypt(nonce, encrypted_privkey.as_ref()).map_err(|e| {
        error!("Private key decryption failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(&priv_key).map_err(|e| {
        error!("Secret key creation failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let message_hash = Keccak256::digest(body.message.as_bytes());
    let message = Message::from_digest_slice(&message_hash).map_err(|e| {
        error!("Message creation failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    let signature = secp.sign_ecdsa(&message, &secret_key);
    let signature_bytes = signature.serialize_der();
    let signature_hex = hex_encode(signature_bytes);

    Ok(Json(SignResponse {
        signature: format!("0x{}", signature_hex),
    }))
}

#[axum::debug_handler]
async fn forget(
    State(state): State<Arc<AppState>>,
    Extension(claims): Extension<Claims>,
    Json(body): Json<Forget>,
) -> Result<impl IntoResponse, StatusCode> {
    let user = sqlx::query("SELECT encrypted_totp_secret, salt FROM users WHERE id = $1")
        .bind(claims.sub)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            error!("User query failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    let encrypted_totp_secret = user.get::<Vec<u8>, _>("encrypted_totp_secret");
    let salt = user.get::<Vec<u8>, _>("salt");

    let salt_str = SaltString::encode_b64(&salt).unwrap();
    let encryption_key: [u8; 32] = Argon2::default()
        .hash_password(body.password.as_bytes(), &salt_str)
        .map_err(|e| {
            error!("Encryption key derivation failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .hash
        .unwrap()
        .as_bytes()[0..32]
        .try_into()
        .unwrap();
    let cipher = Aes256Gcm::new(&encryption_key.into());
    let nonce = Nonce::from_slice(&salt[..12]);
    let totp_secret_bytes = cipher
        .decrypt(nonce, encrypted_totp_secret.as_ref())
        .map_err(|e| {
            error!("TOTP secret decryption failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let totp = match TOTP::new(Algorithm::SHA1, 6, 1, 30, totp_secret_bytes) {
        Ok(totp) => totp,
        Err(e) => {
            error!("TOTP creation failed: {}", e);
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    };
    if !totp.check_current(&body.totp_code).map_err(|e| {
        error!("TOTP verification failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })? {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let mut tx = state.db.begin().await.map_err(|e| {
        error!("Transaction start failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    sqlx::query("DELETE FROM wallets WHERE user_id = $1")
        .bind(claims.sub)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Wallet deletion failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(claims.sub)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("User deletion failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    tx.commit().await.map_err(|e| {
        error!("Transaction commit failed: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(StatusCode::OK)
}
