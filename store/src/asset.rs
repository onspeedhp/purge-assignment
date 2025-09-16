use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::prelude::{FromRow};

use crate::Store;

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

#[derive(Debug)]
pub enum AssetError {
  DatabaseError(String),
}

impl std::fmt::Display for AssetError {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      AssetError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
    }
  }
}

impl Store {
  pub async fn get_all_assets_not_native(&self) -> Result<Vec<Asset>, AssetError> {
    let assets = sqlx::query_as::<_, Asset>(
      "SELECT * FROM assets WHERE is_native = FALSE"
    )
    .fetch_all(&self.pool)
    .await
    .map_err(|e| AssetError::DatabaseError(e.to_string()))?;

    Ok(assets)
  }
}