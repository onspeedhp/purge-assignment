use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Asset {
    pub id: String,
    pub mint_address: String,
    pub symbol: String,
    pub name: String,
    pub decimals: i32,
    pub logo_url: Option<String>,
    pub is_native: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct UserAsset {
    pub id: String,
    pub user_id: String,
    pub asset_id: String,
    pub wallet_address: String,
    pub balance: i64,
    pub first_seen_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AccountSubscription {
    pub id: String,
    pub user_id: String,
    pub wallet_address: String,
    pub is_active: bool,
    pub subscribed_at: DateTime<Utc>,
    pub last_processed_slot: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub balance: i64,
    pub token_mint: String,
    pub symbol: String,
    pub decimals: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscribeRequest {
    pub user_id: String,
    pub wallet_address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsubscribeRequest {
    pub user_id: String,
    pub wallet_address: String,
}

#[derive(Debug, Clone)]
pub struct TokenMetadata {
    pub symbol: String,
    pub name: String,
    pub decimals: i32,
    pub logo_url: Option<String>,
}
