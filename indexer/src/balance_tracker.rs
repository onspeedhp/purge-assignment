use sqlx::PgPool;
use serde::{Deserialize, Serialize};
use tracing::{info, warn, error, debug};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    pub mint_address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: i32,
    pub logo_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UserToken {
    pub user_id: String,
    pub wallet_address: String,
    pub token_mint: String,
}

pub struct BalanceTracker {
    pool: PgPool,
}

impl BalanceTracker {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Track a new token for a user's wallet
    pub async fn track_user_token(&self, user_id: &str, wallet_address: &str, token_mint: &str) -> Result<(), sqlx::Error> {
        debug!("Tracking token {} for user {} wallet {}", token_mint, user_id, wallet_address);
        
        sqlx::query!(
            r#"
            INSERT INTO user_tokens (user_id, wallet_address, token_mint, first_seen_at, last_seen_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            ON CONFLICT (user_id, token_mint) 
            DO UPDATE SET 
                last_seen_at = NOW(),
                wallet_address = EXCLUDED.wallet_address
            "#,
            user_id,
            wallet_address,
            token_mint
        )
        .execute(&self.pool)
        .await?;

        info!("Successfully tracked token {} for user {}", token_mint, user_id);
        Ok(())
    }

    /// Get all token mints that a user has ever held
    pub async fn get_user_token_mints(&self, user_id: &str) -> Result<Vec<String>, sqlx::Error> {
        let rows = sqlx::query!(
            "SELECT token_mint FROM user_tokens WHERE user_id = $1",
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|row| row.token_mint).collect())
    }

    /// Get token metadata for a given mint address
    pub async fn get_token_metadata(&self, mint_address: &str) -> Result<Option<TokenMetadata>, sqlx::Error> {
        let row = sqlx::query!(
            r#"
            SELECT mint_address, symbol, name, decimals, logo_url
            FROM token_metadata 
            WHERE mint_address = $1
            "#,
            mint_address
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| TokenMetadata {
            mint_address: r.mint_address,
            symbol: r.symbol,
            name: r.name,
            decimals: r.decimals,
            logo_url: r.logo_url,
        }))
    }

    /// Update or insert token metadata
    pub async fn upsert_token_metadata(&self, metadata: &TokenMetadata) -> Result<(), sqlx::Error> {
        sqlx::query!(
            r#"
            INSERT INTO token_metadata (mint_address, symbol, name, decimals, logo_url, last_updated)
            VALUES ($1, $2, $3, $4, $5, NOW())
            ON CONFLICT (mint_address) 
            DO UPDATE SET 
                symbol = EXCLUDED.symbol,
                name = EXCLUDED.name,
                decimals = EXCLUDED.decimals,
                logo_url = EXCLUDED.logo_url,
                last_updated = NOW()
            "#,
            metadata.mint_address,
            metadata.symbol,
            metadata.name,
            metadata.decimals,
            metadata.logo_url
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Process a transaction and extract token interactions
    pub async fn process_transaction(&self, transaction: &TransactionData) -> Result<(), Box<dyn std::error::Error>> {
        // Extract token transfers from transaction
        let token_transfers = self.extract_token_transfers(transaction)?;
        
        for transfer in token_transfers {
            // Track the token for the user
            if let Some(user_id) = self.get_user_id_for_wallet(&transfer.from_wallet).await? {
                self.track_user_token(&user_id, &transfer.from_wallet, &transfer.token_mint).await?;
            }
            
            if let Some(user_id) = self.get_user_id_for_wallet(&transfer.to_wallet).await? {
                self.track_user_token(&user_id, &transfer.to_wallet, &transfer.token_mint).await?;
            }
        }

        Ok(())
    }

    /// Extract token transfers from transaction data
    fn extract_token_transfers(&self, _transaction: &TransactionData) -> Result<Vec<TokenTransfer>, Box<dyn std::error::Error>> {
        // TODO: Implement actual transaction parsing
        // This would parse the transaction and extract SPL token transfers
        // For now, return empty vector
        Ok(vec![])
    }

    /// Get user ID for a wallet address
    async fn get_user_id_for_wallet(&self, _wallet_address: &str) -> Result<Option<String>, sqlx::Error> {
        // TODO: Implement wallet to user mapping
        // This would query a table that maps wallet addresses to user IDs
        // For now, return None
        Ok(None)
    }
}

#[derive(Debug, Clone)]
pub struct TransactionData {
    pub signature: String,
    pub slot: u64,
    pub block_time: Option<i64>,
    pub accounts: Vec<String>,
    pub instructions: Vec<InstructionData>,
}

#[derive(Debug, Clone)]
pub struct InstructionData {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct TokenTransfer {
    pub from_wallet: String,
    pub to_wallet: String,
    pub token_mint: String,
    pub amount: u64,
}
