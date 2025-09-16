use sqlx::PgPool;
use anyhow::Result;
use uuid::Uuid;
use chrono::Utc;

use crate::models::{Asset, UserAsset, AccountSubscription, TokenBalance};

pub struct AssetDatabase {
    pool: PgPool,
}

impl AssetDatabase {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn ensure_user_exists(&self, user_id: &str) -> Result<()> {
        // Try to insert user, ignore if already exists
        let _ = sqlx::query!(
            "INSERT INTO users (id, email, password_hash) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
            user_id,
            format!("test-{}@example.com", user_id),
            "dummy-hash" // In production, this would be a real password hash
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Asset operations
    pub async fn get_or_create_asset(
        &self,
        mint_address: &str,
        symbol: &str,
        name: &str,
        decimals: i32,
        logo_url: Option<&str>,
        is_native: bool,
    ) -> Result<Asset> {
        // Try to get existing asset first
        if let Ok(asset) = sqlx::query!(
            "SELECT id, mint_address, symbol, name, decimals, logo_url, is_native, created_at, updated_at 
             FROM assets WHERE mint_address = $1",
            mint_address
        )
        .fetch_one(&self.pool)
        .await
        {
            return Ok(Asset {
                id: asset.id,
                mint_address: asset.mint_address,
                symbol: asset.symbol,
                name: asset.name,
                decimals: asset.decimals,
                logo_url: asset.logo_url,
                is_native: asset.is_native.unwrap_or(false),
                created_at: asset.created_at,
                updated_at: asset.updated_at,
            });
        }

        // Create new asset if not found
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();

        sqlx::query!(
            "INSERT INTO assets (id, mint_address, symbol, name, decimals, logo_url, is_native, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            id,
            mint_address,
            symbol,
            name,
            decimals,
            logo_url,
            is_native,
            now,
            now
        )
        .execute(&self.pool)
        .await?;

        Ok(Asset {
            id,
            mint_address: mint_address.to_string(),
            symbol: symbol.to_string(),
            name: name.to_string(),
            decimals,
            logo_url: logo_url.map(|s| s.to_string()),
            is_native,
            created_at: now,
            updated_at: now,
        })
    }

    // User asset operations
    pub async fn update_user_asset_balance(
        &self,
        user_id: &str,
        asset_id: &str,
        wallet_address: &str,
        balance: i64,
    ) -> Result<()> {
        let now = Utc::now();

        sqlx::query!(
            "INSERT INTO user_assets (id, user_id, asset_id, wallet_address, balance, first_seen_at, last_updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             ON CONFLICT (user_id, asset_id) 
             DO UPDATE SET 
                balance = EXCLUDED.balance,
                last_updated_at = EXCLUDED.last_updated_at",
            Uuid::new_v4().to_string(),
            user_id,
            asset_id,
            wallet_address,
            balance,
            now,
            now
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_token_balances(&self, user_id: &str) -> Result<Vec<TokenBalance>> {
        let balances = sqlx::query!(
            "SELECT ua.balance, a.mint_address as token_mint, a.symbol, a.decimals
             FROM user_assets ua
             JOIN assets a ON ua.asset_id = a.id
             WHERE ua.user_id = $1 AND ua.balance > 0
             ORDER BY a.symbol",
            user_id
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(balances
            .into_iter()
            .map(|row| TokenBalance {
                balance: row.balance,
                token_mint: row.token_mint,
                symbol: row.symbol,
                decimals: row.decimals,
            })
            .collect())
    }

    // Account subscription operations
    pub async fn subscribe_to_account(
        &self,
        user_id: &str,
        wallet_address: &str,
    ) -> Result<()> {
        let now = Utc::now();

        sqlx::query!(
            "INSERT INTO account_subscriptions (id, user_id, wallet_address, is_active, subscribed_at, last_processed_slot)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (user_id, wallet_address) 
             DO UPDATE SET 
                is_active = EXCLUDED.is_active,
                subscribed_at = EXCLUDED.subscribed_at",
            Uuid::new_v4().to_string(),
            user_id,
            wallet_address,
            true,
            now,
            0
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn unsubscribe_from_account(
        &self,
        user_id: &str,
        wallet_address: &str,
    ) -> Result<()> {
        sqlx::query!(
            "UPDATE account_subscriptions 
             SET is_active = false 
             WHERE user_id = $1 AND wallet_address = $2",
            user_id,
            wallet_address
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_active_subscriptions(&self) -> Result<Vec<AccountSubscription>> {
        let subscriptions = sqlx::query!(
            "SELECT id, user_id, wallet_address, is_active, subscribed_at, last_processed_slot
             FROM account_subscriptions 
             WHERE is_active = true
             ORDER BY subscribed_at"
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(subscriptions
            .into_iter()
            .map(|row| AccountSubscription {
                id: row.id,
                user_id: row.user_id,
                wallet_address: row.wallet_address,
                is_active: row.is_active.unwrap_or(false),
                subscribed_at: row.subscribed_at,
                last_processed_slot: row.last_processed_slot.unwrap_or(0),
            })
            .collect())
    }

    pub async fn update_last_processed_slot(
        &self,
        subscription_id: &str,
        slot: i64,
    ) -> Result<()> {
        sqlx::query!(
            "UPDATE account_subscriptions 
             SET last_processed_slot = $1 
             WHERE id = $2",
            slot,
            subscription_id
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}
