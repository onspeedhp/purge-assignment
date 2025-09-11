//! Database module for MPC key shares storage

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{sqlite::SqlitePool, Row};
use std::collections::HashMap;
use uuid::Uuid;

use crate::error::Error as AppError;

/// Key share record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyShare {
    pub id: String,
    pub user_id: String,
    pub public_key: String,
    pub private_key: String, // Encrypted in production
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Database manager for MPC operations
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Create new database instance
    pub async fn new(database_url: &str) -> Result<Self, AppError> {
        let pool = SqlitePool::connect(database_url).await.map_err(|e| {
            AppError::DatabaseError(format!("Failed to connect to database: {}", e))
        })?;

        let db = Database { pool };
        db.init_schema().await?;
        Ok(db)
    }

    /// Initialize database schema
    async fn init_schema(&self) -> Result<(), AppError> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS keyshares (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL,
                created_at DATETIME NOT NULL,
                updated_at DATETIME NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to create schema: {}", e)))?;

        // Create index for faster lookups
        sqlx::query("CREATE INDEX IF NOT EXISTS idx_keyshares_user_id ON keyshares(user_id)")
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to create index: {}", e)))?;

        Ok(())
    }

    /// Store a new key share
    pub async fn store_key_share(
        &self,
        user_id: &str,
        public_key: &str,
        private_key: &str,
    ) -> Result<KeyShare, AppError> {
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query(
            r#"
            INSERT INTO keyshares (id, user_id, public_key, private_key, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(user_id)
        .bind(public_key)
        .bind(private_key)
        .bind(now)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to store key share: {}", e)))?;

        Ok(KeyShare {
            id,
            user_id: user_id.to_string(),
            public_key: public_key.to_string(),
            private_key: private_key.to_string(),
            created_at: now,
            updated_at: now,
        })
    }

    /// Get key share by user ID
    pub async fn get_key_share_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<KeyShare>, AppError> {
        let row = sqlx::query(
            "SELECT id, user_id, public_key, private_key, created_at, updated_at FROM keyshares WHERE user_id = ?"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get key share: {}", e)))?;

        if let Some(row) = row {
            Ok(Some(KeyShare {
                id: row.get("id"),
                user_id: row.get("user_id"),
                public_key: row.get("public_key"),
                private_key: row.get("private_key"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        } else {
            Ok(None)
        }
    }

    /// Get key share by public key
    pub async fn get_key_share_by_public_key(
        &self,
        public_key: &str,
    ) -> Result<Option<KeyShare>, AppError> {
        let row = sqlx::query(
            "SELECT id, user_id, public_key, private_key, created_at, updated_at FROM keyshares WHERE public_key = ?"
        )
        .bind(public_key)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to get key share: {}", e)))?;

        if let Some(row) = row {
            Ok(Some(KeyShare {
                id: row.get("id"),
                user_id: row.get("user_id"),
                public_key: row.get("public_key"),
                private_key: row.get("private_key"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            }))
        } else {
            Ok(None)
        }
    }

    /// Get all key shares for multiple user IDs (for TSS operations)
    pub async fn get_key_shares_by_user_ids(
        &self,
        user_ids: &[String],
    ) -> Result<HashMap<String, KeyShare>, AppError> {
        let mut key_shares = HashMap::new();

        for user_id in user_ids {
            if let Some(key_share) = self.get_key_share_by_user_id(user_id).await? {
                key_shares.insert(user_id.clone(), key_share);
            }
        }

        Ok(key_shares)
    }

    /// Update key share
    pub async fn update_key_share(
        &self,
        user_id: &str,
        public_key: &str,
        private_key: &str,
    ) -> Result<KeyShare, AppError> {
        let now = Utc::now();

        sqlx::query(
            r#"
            UPDATE keyshares 
            SET public_key = ?, private_key = ?, updated_at = ?
            WHERE user_id = ?
            "#,
        )
        .bind(public_key)
        .bind(private_key)
        .bind(now)
        .bind(user_id)
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to update key share: {}", e)))?;

        // Return updated key share
        self.get_key_share_by_user_id(user_id)
            .await?
            .ok_or_else(|| AppError::DatabaseError("Key share not found after update".to_string()))
    }

    /// Delete key share by user ID
    pub async fn delete_key_share(&self, user_id: &str) -> Result<(), AppError> {
        sqlx::query("DELETE FROM keyshares WHERE user_id = ?")
            .bind(user_id)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::DatabaseError(format!("Failed to delete key share: {}", e)))?;

        Ok(())
    }

    /// List all key shares (for debugging)
    pub async fn list_key_shares(&self) -> Result<Vec<KeyShare>, AppError> {
        let rows = sqlx::query(
            "SELECT id, user_id, public_key, private_key, created_at, updated_at FROM keyshares ORDER BY created_at DESC"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::DatabaseError(format!("Failed to list key shares: {}", e)))?;

        let key_shares = rows
            .into_iter()
            .map(|row| KeyShare {
                id: row.get("id"),
                user_id: row.get("user_id"),
                public_key: row.get("public_key"),
                private_key: row.get("private_key"),
                created_at: row.get("created_at"),
                updated_at: row.get("updated_at"),
            })
            .collect();

        Ok(key_shares)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_database_operations() {
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test.db");
        let database_url = format!("sqlite:{}", db_path.display());

        let db = Database::new(&database_url).await.unwrap();

        // Test storing key share
        let key_share = db
            .store_key_share("user1", "pubkey1", "privkey1")
            .await
            .unwrap();
        assert_eq!(key_share.user_id, "user1");
        assert_eq!(key_share.public_key, "pubkey1");

        // Test retrieving key share
        let retrieved = db.get_key_share_by_user_id("user1").await.unwrap().unwrap();
        assert_eq!(retrieved.user_id, "user1");

        // Test updating key share
        let updated = db
            .update_key_share("user1", "pubkey1_updated", "privkey1_updated")
            .await
            .unwrap();
        assert_eq!(updated.public_key, "pubkey1_updated");

        // Test deleting key share
        db.delete_key_share("user1").await.unwrap();
        let deleted = db.get_key_share_by_user_id("user1").await.unwrap();
        assert!(deleted.is_none());
    }
}
