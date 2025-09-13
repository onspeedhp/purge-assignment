use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use uuid::Uuid;
use store::redis::{RedisStore, JupiterQuoteResponse};
use crate::auth::get_user_id_from_request;
use crate::solana_client::SolanaRpcClient;
use frost_mpc::distributed_mpc::MPCServerClient;
use frost_mpc::distributed_mpc::MPCServerConfig;
use solana_sdk::pubkey::Pubkey;
use hex;

/// Helper function để get wallet address từ MPC
async fn get_user_wallet_address(user_id: &str) -> Option<String> {
    let mpc_client = MPCServerClient::new(MPCServerConfig {
        id: 1,
        host: "127.0.0.1".to_string(),
        port: 8081,
    });

    let server_user_id = format!("{}_mpc_server_1", user_id);

    match mpc_client.get_key_share_by_user_id(&server_user_id).await {
        Ok(key_share) => {
            let public_key_hex = key_share.public_key;
            match Pubkey::try_from(hex::decode(&public_key_hex).unwrap().as_slice()) {
                Ok(pubkey) => Some(pubkey.to_string()),
                Err(_) => None,
            }
        }
        Err(_) => None,
    }
}

#[derive(Deserialize, Debug)]
pub struct QuoteRequest {
    #[serde(rename = "inputMint")]
    pub input_mint: String,
    #[serde(rename = "outputMint")]
    pub output_mint: String,
    #[serde(rename = "inAmount")]
    pub in_amount: u64,
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

#[derive(Serialize, Deserialize, Debug)]
pub struct QuoteResponse {
    #[serde(rename = "outAmount")]
    pub out_amount: String,
    pub id: String,
}

#[derive(Deserialize)]
pub struct SwapRequest {
    pub id: String,
}

#[derive(Serialize)]
pub struct SwapResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct BalanceResponse {
    pub wallet_address: String,
    pub sol_balance: u64,
    pub sol_balance_sol: f64,
}

#[derive(Serialize)]
pub struct TokenBalanceResponse {
    // Add fields when implementing
}

#[actix_web::post("/api/v1/quote")]
pub async fn quote(
    req: web::Json<QuoteRequest>, 
    http_req: HttpRequest,
    redis_store: web::Data<RedisStore>,
) -> Result<HttpResponse> {    
    let _user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Quote request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };

    // TODO: handle check balance user
    // 1. Call API from MPC to get user wallet
    // 2. Check current balance of user wallet with input token. 
    // 3. If current balance < inputAmount - return error
    
    let slippage_bps = 50;
    
    let jupiter_url = format!(
        "https://lite-api.jup.ag/swap/v1/quote?inputMint={}&outputMint={}&amount={}&slippageBps={}&restrictIntermediateTokens=true",
        req.input_mint,
        req.output_mint,
        req.in_amount,
        slippage_bps
    );
        
    let client = reqwest::Client::new();
    let jupiter_response = match client.get(&jupiter_url).send().await {
        Ok(response) => {
            if response.status().is_success() {
                match response.json::<JupiterQuoteResponse>().await {
                    Ok(quote_data) => {
                        quote_data
                    }
                    Err(e) => {
                        error!("Failed to parse Jupiter response: {}", e);
                        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Failed to parse quote response"
                        })));
                    }
                }
            } else {
                error!("Jupiter API returned error status: {}", response.status());
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid quote request"
                })));
            }
        }
        Err(e) => {
            error!("Failed to call Jupiter API: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get quote"
            })));
        }
    };
    
    let quote_id = Uuid::new_v4().to_string();
    
    // Store quote in Redis with 5 minutes TTL
    if let Err(e) = redis_store.store_quote(&quote_id, &jupiter_response, 300).await {
        error!("Failed to store quote in Redis: {}", e);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to cache quote"
        })));
    }
    
    let response = QuoteResponse {
        out_amount: jupiter_response.other_amount_threshold, // This is the worst price with slippage
        id: quote_id,
    };
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/api/v1/swap")]
pub async fn swap(
    req: web::Json<SwapRequest>, 
    http_req: HttpRequest,
    redis_store: web::Data<RedisStore>,
) -> Result<HttpResponse> {
    // Get authenticated user ID
    let _user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Swap request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };
    
    // Check if quote exists in Redis
    let _quote_data = match redis_store.get_quote(&req.id).await {
        Ok(Some(quote_data)) => quote_data,
        Ok(None) => {
            error!("Quote {} not found in Redis", req.id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Quote not found or expired. Please request a new quote."
            })));
        }
        Err(e) => {
            error!("Failed to retrieve quote from Redis: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve quote"
            })));
        }
    };
    
    info!("Found quote {} in Redis, proceeding with swap for user {}", req.id, _user_id);
    
    // TODO: Implement actual swap logic using the cached quote data
    // For now, just return success
    let response = SwapResponse {
        success: true,
        message: format!("Swap initiated for quote {}", req.id),
    };
    
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::get("/api/v1/balance/sol")]
pub async fn sol_balance(http_req: HttpRequest) -> Result<HttpResponse> {
    // Get authenticated user ID
    let user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("SOL balance request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };
    
    // Get user's wallet address from MPC
    let wallet_address = match get_user_wallet_address(&user_id).await {
        Some(address) => {
            info!("Found wallet address for user {}: {}", user_id, address);
            address
        }
        None => {
            error!("No wallet found for user {}", user_id);
            return Ok(HttpResponse::NotFound().json(serde_json::json!({
                "error": "Wallet not found for user"
            })));
        }
    };

    // Get SOL balance using existing SolanaRpcClient
    let rpc_url = "https://api.mainnet-beta.solana.com".to_string();
    let solana_client = SolanaRpcClient::new(rpc_url);
    
    match solana_client.get_sol_balance(&wallet_address).await {
        Ok(balance_lamports) => {
            let balance_sol = balance_lamports as f64 / 1_000_000_000.0;
            
            let response = BalanceResponse {
                wallet_address,
                sol_balance: balance_lamports,
                sol_balance_sol: balance_sol,
            };
            
            info!("SOL balance for user {}: {} lamports ({} SOL)", user_id, balance_lamports, balance_sol);
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            error!("Failed to get SOL balance for wallet {}: {}", wallet_address, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to retrieve SOL balance"
            })))
        }
    }
}

#[actix_web::get("/api/v1/balance/tokens")]
pub async fn token_balance(http_req: HttpRequest) -> Result<HttpResponse> {
    // Get authenticated user ID
    let _user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Token balance request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };
    
    // TODO: Implement token balance logic using user_id
    let response = TokenBalanceResponse {
        // Add fields when implementing
    };
    
    Ok(HttpResponse::Ok().json(response))
}
