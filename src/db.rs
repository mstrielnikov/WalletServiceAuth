use crate::models::domain::{EphemeralAddress, MetaAccount};
use libsql::{Builder, Connection, Database};
use log::{error, info};

pub struct DbClient {
    pub conn: Connection,
    // Database instance must be kept alive alongside the connection in libsql
    _db: Database,
}

impl DbClient {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Here we attempt to use Turso Remote with local replica,
        // but fallback to purely local SQLite if ENV variables are missing.
        let url = std::env::var("TURSO_DATABASE_URL").unwrap_or_else(|_| "wallet.db".to_string());
        
        info!("Connecting to Turso / libSQL at: {}", url);
        
        let db = if url == "wallet.db" || url.starts_with("file:") {
            Builder::new_local(&url).build().await?
        } else {
            let token = std::env::var("TURSO_AUTH_TOKEN").unwrap_or_default();
            let local_db = std::env::var("TURSO_LOCAL_URL").unwrap_or_else(|_| "local_sync.db".to_string());
            Builder::new_remote_replica(&local_db, url, token).build().await?
        };

        let conn = db.connect()?;
        
        let client = Self {
            conn,
            _db: db,
        };

        client.init_schema().await?;

        Ok(client)
    }

    async fn init_schema(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Initializing database schema...");

        // Note: Switching to the Hedera-inspired Meta-Account architecture.
        // We no longer have tight coupling. The Meta-Account is the canonical identity.
        let create_meta_accounts = "
            CREATE TABLE IF NOT EXISTS meta_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                canonical_identifier TEXT NOT NULL UNIQUE,  -- E.g. User abstract ID
                auth_methods_json TEXT NOT NULL,            -- Stores serialized MFA/WebAuthn configs
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ";
        
        self.conn.execute(create_meta_accounts, ()).await.map_err(|e| {
            error!("Failed to create meta_accounts table: {}", e);
            e
        })?;

        // Ephemeral addresses are spawned from the Meta-Account
        // They hold encrypted shards (Track A SDK keys or Track B PQC keys)
        let create_ephemeral_addresses = "
            CREATE TABLE IF NOT EXISTS ephemeral_addresses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                meta_account_id INTEGER NOT NULL,
                chain_id TEXT NOT NULL,                     -- e.g. 'ethereum', 'solana', 'starknet'
                public_address TEXT NOT NULL UNIQUE,        -- The 0x... or Base58 address
                encrypted_key_shard BLOB NOT NULL,          -- AES/ChaCha encrypted key fragment
                pqc_signature_capable BOOLEAN DEFAULT 0,    -- Flag for Track B (PQC) integration
                status TEXT DEFAULT 'active',               -- 'active', 'used', 'revoked'
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (meta_account_id) REFERENCES meta_accounts(id)
            )
        ";

        self.conn.execute(create_ephemeral_addresses, ()).await.map_err(|e| {
            error!("Failed to create ephemeral_addresses table: {}", e);
            e
        })?;

        info!("Database schema initialized successfully!");
        Ok(())
    }

    /// Creates a new Meta-Account (canonical identity)
    pub async fn create_meta_account(
        &self,
        canonical_identifier: &str,
        auth_methods_json: &str,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        self.conn
            .execute(
                "INSERT INTO meta_accounts (canonical_identifier, auth_methods_json) VALUES (?1, ?2)",
                (canonical_identifier, auth_methods_json),
            )
            .await?;
        let id = self.conn.last_insert_rowid();
        Ok(id)
    }

    /// Spawns a new Ephemeral Address tied to a Meta-Account
    pub async fn create_ephemeral_address(
        &self,
        meta_account_id: i64,
        chain_id: &str,
        public_address: &str,
        encrypted_key_shard: Vec<u8>,
        pqc_signature_capable: bool,
    ) -> Result<i64, Box<dyn std::error::Error>> {
        self.conn
            .execute(
                "INSERT INTO ephemeral_addresses (meta_account_id, chain_id, public_address, encrypted_key_shard, pqc_signature_capable) VALUES (?1, ?2, ?3, ?4, ?5)",
                (
                    meta_account_id,
                    chain_id,
                    public_address,
                    encrypted_key_shard,
                    pqc_signature_capable,
                ),
            )
            .await?;
        let id = self.conn.last_insert_rowid();
        Ok(id)
    }

    /// Fetches all active ephemeral addresses for a Meta-Account
    pub async fn get_ephemeral_addresses_for_account(
        &self,
        meta_account_id: i64,
    ) -> Result<Vec<EphemeralAddress>, Box<dyn std::error::Error>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, meta_account_id, chain_id, public_address, encrypted_key_shard, pqc_signature_capable, status, created_at FROM ephemeral_addresses WHERE meta_account_id = ?1 AND status = 'active'",
                [meta_account_id],
            )
            .await?;

        let mut addresses = Vec::new();
        while let Some(row) = rows.next().await? {
            addresses.push(EphemeralAddress {
                id: row.get(0)?,
                meta_account_id: row.get(1)?,
                chain_id: row.get(2)?,
                public_address: row.get(3)?,
                encrypted_key_shard: row.get(4)?,
                pqc_signature_capable: row.get(5)?,
                status: row.get(6)?,
                created_at: row.get(7)?,
            });
        }
        Ok(addresses)
    }


    /// Fetches a Meta-Account by its canonical identifier
    pub async fn get_meta_account_by_identifier(
        &self,
        canonical_identifier: &str,
    ) -> Result<Option<MetaAccount>, Box<dyn std::error::Error>> {
        let mut rows = self
            .conn
            .query(
                "SELECT id, canonical_identifier, auth_methods_json, created_at FROM meta_accounts WHERE canonical_identifier = ?1",
                [canonical_identifier],
            )
            .await?;

        if let Some(row) = rows.next().await? {
            Ok(Some(MetaAccount {
                id: row.get(0)?,
                canonical_identifier: row.get(1)?,
                auth_methods_json: row.get(2)?,
                created_at: row.get(3)?,
            }))
        } else {
            Ok(None)
        }
    }
}

// Domain types are imported at the top of this file from `crate::models::domain`.
// Additional callers can import them via `crate::models::domain` directly.
