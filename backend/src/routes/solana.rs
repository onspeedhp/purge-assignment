use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use uuid::Uuid;
use store::{Store, redis::{RedisStore, JupiterQuoteResponse}};
use crate::auth::get_user_id_from_request;
use frost_mpc::solana::SolanaMPCClient;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, system_instruction, transaction::Transaction};
use std::str::FromStr;

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

#[derive(Deserialize, Debug)]
pub struct SendRequest {
    pub to: String,
    pub amount: u64,
    #[serde(rename = "mint")]
    pub mint: Option<String>,
}

#[derive(Serialize)]
pub struct SwapResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Serialize)]
pub struct BalanceResponse {
    pub balance: u64, // lamports
}

#[derive(Serialize)]
pub struct TokenBalance {
    pub balance: u64,
    #[serde(rename = "tokenMint")]
    pub token_mint: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Serialize)]
pub struct SendResponse {
    pub success: bool,
    pub signature: String,
    pub message: String,
}

#[actix_web::post("/api/v1/quote")]
pub async fn quote(
    req: web::Json<QuoteRequest>, 
    http_req: HttpRequest,
    redis_store: web::Data<RedisStore>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {    
    let user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Quote request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };

    // Get user and MPC wallet
    let user = match store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            error!("User not found: {}", user_id);
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            error!("Database error getting user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    let wallet_pubkey = match user.mpc_wallet_pubkey {
        Some(pubkey) => pubkey,
        None => {
            error!("User {} has no MPC wallet", user_id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No MPC wallet found. Please contact support."
            })));
        }
    };

    // Check balance logic here
    let wallet_address = match Pubkey::from_str(&wallet_pubkey) {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid wallet pubkey {}: {}", wallet_pubkey, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Invalid wallet address"
            })));
        }
    };

    // For SOL native token
    if req.input_mint == "So11111111111111111111111111111111111111112" {
        let balance_result = tokio::task::spawn_blocking({
            let wallet_address = wallet_address;
            move || {
                let rpc_client = RpcClient::new("http://localhost:8899".to_string());
                rpc_client.get_balance(&wallet_address)
            }
        }).await;

        match balance_result {
            Ok(Ok(balance)) => {
                if balance < req.in_amount {
                    return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                        "error": "Insufficient balance"
                    })));
                }
            }
            Ok(Err(e)) => {
                error!("Failed to get SOL balance: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to check balance"
                })));
            }
            Err(e) => {
                error!("Task join error: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Internal server error"
                })));
            }
        }
    }
    // For SPL tokens, you would need to check token account balance
    // This is simplified for now
    
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
pub async fn sol_balance(http_req: HttpRequest, store: web::Data<Store>) -> Result<HttpResponse> {
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
    
    // Get user and MPC wallet
    let user = match store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            error!("User not found: {}", user_id);
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            error!("Database error getting user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    let wallet_pubkey = match user.mpc_wallet_pubkey {
        Some(pubkey) => pubkey,
        None => {
            error!("User {} has no MPC wallet", user_id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No MPC wallet found. Please contact support."
            })));
        }
    };

    let wallet_address = match Pubkey::from_str(&wallet_pubkey) {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid wallet pubkey {}: {}", wallet_pubkey, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Invalid wallet address"
            })));
        }
    };

    let balance_result = tokio::task::spawn_blocking({
        let wallet_address = wallet_address;
        move || {
            let rpc_client = RpcClient::new("http://localhost:8899".to_string());
            rpc_client.get_balance(&wallet_address)
        }
    }).await;

    match balance_result {
        Ok(Ok(balance)) => {
            let response = BalanceResponse { balance };
            Ok(HttpResponse::Ok().json(response))
        }
        Ok(Err(e)) => {
            error!("Failed to get SOL balance for {}: {}", wallet_pubkey, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to get balance"
            })))
        }
        Err(e) => {
            error!("Task join error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })))
        }
    }
}

#[actix_web::get("/api/v1/balance/tokens")]
pub async fn token_balance(http_req: HttpRequest, store: web::Data<Store>) -> Result<HttpResponse> {
    // Get authenticated user ID
    let user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Token balance request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };
    
    // Get user and MPC wallet
    let user = match store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            error!("User not found: {}", user_id);
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            error!("Database error getting user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    let _wallet_pubkey = match user.mpc_wallet_pubkey {
        Some(pubkey) => pubkey,
        None => {
            error!("User {} has no MPC wallet", user_id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No MPC wallet found. Please contact support."
            })));
        }
    };

    // For now, return empty token list
    // In production, you would fetch token accounts from the wallet
    let response: Vec<TokenBalance> = vec![];
    
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::post("/api/v1/send")]
pub async fn send_transaction(
    req: web::Json<SendRequest>,
    http_req: HttpRequest,
    store: web::Data<Store>,
    _mpc_client: web::Data<SolanaMPCClient>,
) -> Result<HttpResponse> {
    let user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Send transaction request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };

    // Get user and MPC wallet
    let user = match store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            error!("User not found: {}", user_id);
            return Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "User not found"
            })));
        }
        Err(e) => {
            error!("Database error getting user: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    let wallet_pubkey = match user.mpc_wallet_pubkey {
        Some(pubkey) => pubkey,
        None => {
            error!("User {} has no MPC wallet", user_id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "No MPC wallet found. Please contact support."
            })));
        }
    };

    let from_pubkey = match Pubkey::from_str(&wallet_pubkey) {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid wallet pubkey {}: {}", wallet_pubkey, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Invalid wallet address"
            })));
        }
    };

    let to_pubkey = match Pubkey::from_str(&req.to) {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid recipient address {}: {}", req.to, e);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid recipient address"
            })));
        }
    };

    // Check if MPC servers are running
    let mut healthy_servers = 0;
    for port in [8081, 8082, 8083] {
        let client = reqwest::Client::new();
        if let Ok(resp) = client.get(&format!("http://localhost:{}/health", port)).send().await {
            if resp.status().is_success() {
                healthy_servers += 1;
            }
        }
    }

    if healthy_servers < 2 {
        error!("Not enough MPC servers running: {}/3", healthy_servers);
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "MPC service unavailable. Please try again later."
        })));
    }

    // Only handle SOL transfers for now
    if req.mint.is_some() {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": "SPL token transfers not implemented yet"
        })));
    }

    // Check balance and get recent blockhash using spawn_blocking
    let balance_and_hash_result = tokio::task::spawn_blocking({
        let from_pubkey = from_pubkey;
        move || {
            let rpc_client = RpcClient::new("http://localhost:8899".to_string());
            let balance = rpc_client.get_balance(&from_pubkey)?;
            let blockhash = rpc_client.get_latest_blockhash()?;
            Ok::<(u64, solana_sdk::hash::Hash), Box<dyn std::error::Error + Send + Sync>>((balance, blockhash))
        }
    }).await;

    let (balance, recent_blockhash) = match balance_and_hash_result {
        Ok(Ok((bal, hash))) => (bal, hash),
        Ok(Err(e)) => {
            error!("RPC error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Solana network. Please ensure local validator is running."
            })));
        }
        Err(e) => {
            error!("Task join error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    // Check sufficient balance
    if balance < req.amount {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Insufficient balance. Available: {} lamports, Required: {} lamports", balance, req.amount)
        })));
    }

    info!("Creating transfer transaction from {} to {} for {} lamports", from_pubkey, to_pubkey, req.amount);
    info!("Recent blockhash: {}", recent_blockhash);

    // Create transfer instruction (like in test.rs line 199-203)
    let transfer_instruction = system_instruction::transfer(
        &from_pubkey,
        &to_pubkey,
        req.amount,
    );

    // Create transaction (like in test.rs line 206-208)
    let mut transaction = Transaction::new_with_payer(&[transfer_instruction], Some(&from_pubkey));
    transaction.message.recent_blockhash = recent_blockhash;

    info!("Transaction created, signing with FROST MPC...");

    // Sign transaction with FROST MPC (like in test.rs line 213-216)
    let session_id = format!("transaction_{}", Uuid::new_v4());
    let mut solana_mpc = SolanaMPCClient::new();
    
    let signing_result = match solana_mpc.sign_solana_transaction(&user_id, &transaction, &session_id).await {
        Ok(result) => result,
        Err(e) => {
            error!("MPC signing failed for user {}: {}", user_id, e);
            
            // Check if it's the "No threshold available" error
            if e.to_string().contains("No threshold available") {
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "MPC wallet not properly initialized. Please contact support to regenerate your wallet."
                })));
            }
            
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Transaction signing failed: {}", e)
            })));
        }
    };

    info!("✅ FROST MPC signing successful!");
    info!("Transaction signature: {}", signing_result.signature);
    info!("Signature valid: {}", signing_result.is_valid);

    if !signing_result.is_valid {
        error!("FROST signature verification failed");
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Transaction signing failed - signature verification failed"
        })));
    }

    // Send transaction to network (like in test.rs line 233)
    info!("Sending transaction to Solana network...");
    
    let send_result = tokio::task::spawn_blocking({
        let signed_transaction = signing_result.transaction.clone();
        move || {
            let rpc_client = RpcClient::new("http://localhost:8899".to_string());
            rpc_client.send_and_confirm_transaction(&signed_transaction)
        }
    }).await;

    match send_result {
        Ok(Ok(signature)) => {
            info!("✅ Transaction sent successfully!");
            info!("Transaction signature: {}", signature);
            
            let response = SendResponse {
                success: true,
                signature: signature.to_string(),
                message: "Transaction sent successfully".to_string(),
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Ok(Err(e)) => {
            error!("❌ Transaction failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to send transaction: {}", e)
            })))
        }
        Err(e) => {
            error!("Task join error: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })))
        }
    }
}

#[actix_web::get("/api/v1/mpc/health")]
pub async fn mpc_health() -> Result<HttpResponse> {
    info!("MPC health check requested");
    
    let mut servers_status = Vec::new();
    
    for port in [8081, 8082, 8083] {
        let client = reqwest::Client::new();
        let status = match client.get(&format!("http://localhost:{}/health", port)).send().await {
            Ok(resp) if resp.status().is_success() => {
                match resp.json::<serde_json::Value>().await {
                    Ok(data) => {
                        info!("MPC server {} is healthy", port);
                        serde_json::json!({
                            "port": port,
                            "status": "healthy",
                            "details": data
                        })
                    }
                    Err(_) => {
                        serde_json::json!({
                            "port": port,
                            "status": "unhealthy",
                            "error": "Invalid response format"
                        })
                    }
                }
            }
            Ok(resp) => {
                error!("MPC server {} returned error status: {}", port, resp.status());
                serde_json::json!({
                    "port": port,
                    "status": "unhealthy",
                    "error": format!("HTTP {}", resp.status())
                })
            }
            Err(e) => {
                error!("Failed to connect to MPC server {}: {}", port, e);
                serde_json::json!({
                    "port": port,
                    "status": "unreachable",
                    "error": e.to_string()
                })
            }
        };
        servers_status.push(status);
    }
    
    let healthy_count = servers_status.iter()
        .filter(|s| s["status"] == "healthy")
        .count();
    
    let overall_status = if healthy_count >= 2 {
        "operational" // Threshold met for MPC operations
    } else if healthy_count > 0 {
        "degraded" // Some servers available but below threshold
    } else {
        "down" // No servers available
    };
    
    let response = serde_json::json!({
        "overall_status": overall_status,
        "healthy_servers": healthy_count,
        "total_servers": 3,
        "threshold_required": 2,
        "servers": servers_status,
        "timestamp": chrono::Utc::now().to_rfc3339()
    });
    
    Ok(HttpResponse::Ok().json(response))
}
