use redis::{Client as RedisClient, AsyncCommands};
use serde::{Deserialize, Serialize};
use tracing::{info, error};

#[derive(Clone)]
pub struct RedisStore {
    pub client: RedisClient,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JupiterQuoteResponse {
    #[serde(rename = "inputMint")]
    pub input_mint: String,
    #[serde(rename = "inAmount")]
    pub in_amount: String,
    #[serde(rename = "outputMint")]
    pub output_mint: String,
    #[serde(rename = "outAmount")]
    pub out_amount: String,
    #[serde(rename = "otherAmountThreshold")]
    pub other_amount_threshold: String,
    #[serde(rename = "swapMode")]
    pub swap_mode: String,
    #[serde(rename = "slippageBps")]
    pub slippage_bps: u64,
    #[serde(rename = "platformFee")]
    pub platform_fee: Option<String>,
    #[serde(rename = "priceImpactPct")]
    pub price_impact_pct: String,
    #[serde(rename = "routePlan")]
    pub route_plan: Vec<RoutePlan>,
    #[serde(rename = "contextSlot")]
    pub context_slot: u64,
    #[serde(rename = "timeTaken")]
    pub time_taken: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RoutePlan {
    #[serde(rename = "swapInfo")]
    pub swap_info: SwapInfo,
    pub percent: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SwapInfo {
    #[serde(rename = "ammKey")]
    pub amm_key: String,
    pub label: String,
    #[serde(rename = "inputMint")]
    pub input_mint: String,
    #[serde(rename = "outputMint")]
    pub output_mint: String,
    #[serde(rename = "inAmount")]
    pub in_amount: String,
    #[serde(rename = "outAmount")]
    pub out_amount: String,
    #[serde(rename = "feeAmount")]
    pub fee_amount: String,
    #[serde(rename = "feeMint")]
    pub fee_mint: String,
}

impl RedisStore {
    pub fn new(client: RedisClient) -> Self {
        Self { client }
    }

    pub async fn store_quote(
        &self,
        quote_id: &str,
        quote_data: &JupiterQuoteResponse,
        ttl_seconds: u64,
    ) -> redis::RedisResult<()> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        
        let quote_json = serde_json::to_string(quote_data)
            .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Serialization failed", e.to_string())))?;
        
        let key = format!("quote:{}", quote_id);
        
        // Using the new API with set and expire
        let _: () = conn.set(&key, &quote_json).await?;
        let _: () = conn.expire(&key, ttl_seconds as i64).await?;
        
        info!("Stored quote {} in Redis with TTL {} seconds", quote_id, ttl_seconds);
        Ok(())
    }

    pub async fn get_quote(
        &self,
        quote_id: &str,
    ) -> redis::RedisResult<Option<JupiterQuoteResponse>> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("quote:{}", quote_id);
        
        let quote_json: Option<String> = conn.get(&key).await?;
        
        match quote_json {
            Some(json) => {
                let quote_data: JupiterQuoteResponse = serde_json::from_str(&json)
                    .map_err(|e| redis::RedisError::from((redis::ErrorKind::TypeError, "Deserialization failed", e.to_string())))?;
                info!("Retrieved quote {} from Redis", quote_id);
                Ok(Some(quote_data))
            }
            None => {
                info!("Quote {} not found in Redis", quote_id);
                Ok(None)
            }
        }
    }

    pub async fn delete_quote(&self, quote_id: &str) -> redis::RedisResult<bool> {
        let mut conn = self.client.get_multiplexed_async_connection().await?;
        let key = format!("quote:{}", quote_id);
        
        let deleted: i32 = conn.del(&key).await?;
        Ok(deleted > 0)
    }
}
