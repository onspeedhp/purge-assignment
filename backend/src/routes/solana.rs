use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use uuid::Uuid;
use store::{Store, redis::{RedisStore, JupiterQuoteResponse}};
use crate::auth::get_user_id_from_request;
use frost_mpc::solana::SolanaMPCClient;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, system_instruction, transaction::Transaction, signature::Signer};
use spl_token::{instruction as token_instruction, state::Mint};
use spl_associated_token_account::{instruction as ata_instruction, get_associated_token_address};
use solana_program::program_pack::Pack;
use std::str::FromStr;
use solana_account_decoder::UiAccountData;
use base64::{Engine as _, engine::general_purpose};

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

    // Get token accounts for the wallet using RPC
    let token_accounts_result = tokio::task::spawn_blocking({
        let wallet_address = wallet_address;
        move || {
            let rpc_client = RpcClient::new("http://localhost:8899".to_string());
            rpc_client.get_token_accounts_by_owner(
                &wallet_address,
                solana_client::rpc_request::TokenAccountsFilter::ProgramId(spl_token::id()),
            )
        }
    }).await;

    let token_accounts = match token_accounts_result {
        Ok(Ok(accounts)) => accounts,
        Ok(Err(e)) => {
            error!("Failed to get token accounts for {}: {}", wallet_pubkey, e);
            // Return empty list instead of error for better UX
            let response: Vec<TokenBalance> = vec![];
            return Ok(HttpResponse::Ok().json(response));
        }
        Err(e) => {
            error!("Task join error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    let mut token_balances = Vec::new();

    for account in token_accounts {
        // Parse token account data using Pack trait
        let token_account_data = match &account.account.data {
            UiAccountData::Binary(data, _) => {
                match general_purpose::STANDARD.decode(data) {
                    Ok(bytes) => match spl_token::state::Account::unpack(&bytes) {
                        Ok(data) => data,
                        Err(e) => {
                            error!("Failed to parse token account data: {}", e);
                            continue;
                        }
                    },
                    Err(e) => {
                        error!("Failed to decode base64 data: {}", e);
                        continue;
                    }
                }
            },
            _ => {
                error!("Unexpected account data format");
                continue;
            }
        };

        // Skip accounts with zero balance
        if token_account_data.amount == 0 {
            continue;
        }

        // Get mint info to determine decimals
        let mint_info_result = tokio::task::spawn_blocking({
            let mint = token_account_data.mint;
            move || {
                let rpc_client = RpcClient::new("http://localhost:8899".to_string());
                rpc_client.get_account(&mint)
            }
        }).await;

        let decimals = match mint_info_result {
            Ok(rpc_result) => match rpc_result {
                Ok(mint_account) => {
                    match Mint::unpack(&mint_account.data) {
                        Ok(mint_info) => mint_info.decimals,
                        Err(_) => {
                            error!("Failed to unpack mint data for {}", token_account_data.mint);
                            6 // Default to 6 if can't parse
                        }
                    }
                }
                Err(e) => {
                    error!("RPC error getting mint account for {}: {}", token_account_data.mint, e);
                    6 // Default on RPC error
                }
            },
            Err(e) => {
                error!("Task join error: {}", e);
                6 // Default on task error
            }
        };

        token_balances.push(TokenBalance {
            balance: token_account_data.amount,
            token_mint: token_account_data.mint.to_string(),
            symbol: format!("TOKEN-{}", &token_account_data.mint.to_string()[..8]), // Short name
            decimals,
        });
    }

    info!("Found {} token accounts with non-zero balances", token_balances.len());
    Ok(HttpResponse::Ok().json(token_balances))
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

    // Get user and MPC wallet metadata
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

    let (wallet_pubkey, mpc_threshold, mpc_pubkey_package) = match (
        user.mpc_wallet_pubkey,
        user.mpc_threshold,
        user.mpc_pubkey_package,
    ) {
        (Some(pubkey), Some(threshold), Some(package)) => (pubkey, threshold, package),
        _ => {
            error!("User {} has incomplete MPC wallet data", user_id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "MPC wallet not properly initialized. Please contact support to regenerate your wallet."
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

    // Handle both SOL and SPL token transfers
    let is_spl_token = req.mint.is_some();
    let mint_pubkey = if let Some(mint) = &req.mint {
        let mint_addr = match Pubkey::from_str(mint) {
            Ok(addr) => addr,
            Err(e) => {
                error!("Invalid mint address {}: {}", mint, e);
                return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                    "error": "Invalid mint address"
                })));
            }
        };
        
        // Check if this is actually a SPL token mint (not System Program or other common programs)
        if mint_addr == solana_sdk::system_program::ID {
            error!("Mint address {} is System Program ID, not a valid SPL token", mint);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid SPL token mint address. System Program ID is not a token mint."
            })));
        }
        
        Some(mint_addr)
    } else {
        None
    };

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

    // For SOL transfers, check balance against amount
    if !is_spl_token && balance < req.amount {
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "error": format!("Insufficient balance. Available: {} lamports, Required: {} lamports", balance, req.amount)
        })));
    }

    info!("Creating {} transfer transaction from {} to {} for {} {}", 
        if is_spl_token { "SPL token" } else { "SOL" }, 
        from_pubkey, to_pubkey, req.amount,
        if is_spl_token { "tokens" } else { "lamports" }
    );
    info!("Recent blockhash: {}", recent_blockhash);

    // Create transfer instruction based on type (SOL or SPL token)
    let instructions = if is_spl_token {
        let mint_pubkey = mint_pubkey.unwrap(); // Safe because we checked is_spl_token
        
        // Get associated token accounts
        let from_ata = get_associated_token_address(&from_pubkey, &mint_pubkey);
        let to_ata = get_associated_token_address(&to_pubkey, &mint_pubkey);
        
        info!("From ATA: {}, To ATA: {}", from_ata, to_ata);
        
        let mut instructions = Vec::new();
        
        // Check if recipient ATA exists and create it if needed
        // Note: We check if the account exists first to avoid unnecessary instruction
        let ata_exists = tokio::task::spawn_blocking({
            let to_ata = to_ata;
            move || {
                let rpc_client = RpcClient::new("http://localhost:8899".to_string());
                rpc_client.get_account(&to_ata).is_ok()
            }
        }).await;
        
        match ata_exists {
            Ok(false) => {
                // ATA doesn't exist, create it
                let create_ata_instruction = ata_instruction::create_associated_token_account(
                    &from_pubkey, // payer
                    &to_pubkey,   // wallet owner - FIXED: This should be the owner of the ATA
                    &mint_pubkey, // mint
                    &spl_token::id(),
                );
                instructions.push(create_ata_instruction);
                info!("Added instruction to create ATA for recipient");
            }
            Ok(true) => {
                info!("Recipient ATA already exists");
            }
            Err(e) => {
                error!("Failed to check if ATA exists: {}", e);
                // Continue anyway, instruction will fail gracefully if ATA already exists
                let create_ata_instruction = ata_instruction::create_associated_token_account(
                    &from_pubkey, // payer
                    &to_pubkey,   // wallet owner
                    &mint_pubkey, // mint
                    &spl_token::id(),
                );
                instructions.push(create_ata_instruction);
            }
        }
        
        // Create SPL token transfer instruction
        let transfer_instruction = token_instruction::transfer(
            &spl_token::id(),
            &from_ata,      // source token account
            &to_ata,        // destination token account  
            &from_pubkey,   // authority
            &[],            // signers
            req.amount,     // amount
        ).map_err(|e| {
            error!("Failed to create SPL token transfer instruction: {}", e);
            actix_web::error::ErrorInternalServerError("Failed to create transfer instruction")
        })?;
        instructions.push(transfer_instruction);
        
        instructions
    } else {
        // SOL transfer (existing logic)
        vec![system_instruction::transfer(
            &from_pubkey,
            &to_pubkey,
            req.amount,
        )]
    };

    // Create transaction with the appropriate instructions
    let mut transaction = Transaction::new_with_payer(&instructions, Some(&from_pubkey));
    transaction.message.recent_blockhash = recent_blockhash;

    info!("Transaction created, signing with FROST MPC...");

    // Create MPC client with existing wallet metadata
    let solana_mpc = match SolanaMPCClient::with_existing_wallet(
        mpc_threshold as u16,
        &mpc_pubkey_package,
    ) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create MPC client with existing wallet: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to initialize MPC client"
            })));
        }
    };

    // Sign transaction with FROST MPC (like in test.rs line 213-216)
    let session_id = format!("transaction_{}", Uuid::new_v4());
    
    let signing_result = match solana_mpc.sign_solana_transaction(&user_id, &transaction, &session_id).await {
        Ok(result) => result,
        Err(e) => {
            error!("MPC signing failed for user {}: {}", user_id, e);
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

#[actix_web::post("/api/v1/create-test-token")]
pub async fn create_test_token(
    http_req: HttpRequest,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    let user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Create test token request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };

    // Get user and MPC wallet metadata
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

    let (wallet_pubkey, mpc_threshold, mpc_pubkey_package) = match (
        user.mpc_wallet_pubkey,
        user.mpc_threshold,
        user.mpc_pubkey_package,
    ) {
        (Some(pubkey), Some(threshold), Some(package)) => (pubkey, threshold, package),
        _ => {
            error!("User {} has incomplete MPC wallet data", user_id);
            return Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": "MPC wallet not properly initialized. Please contact support to regenerate your wallet."
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

    // Create a real test token mint and mint 1 million tokens to user
    info!("Creating real test token for user {}", user_id);
    
    // Generate new keypair for the mint
    let mint_keypair = solana_sdk::signature::Keypair::new();
    let mint_pubkey = mint_keypair.pubkey();
    
    // Get user's Associated Token Account
    let user_ata = get_associated_token_address(&from_pubkey, &mint_pubkey);
    
    info!("Creating token mint: {}", mint_pubkey);
    info!("User ATA will be: {}", user_ata);
    
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

    // Get recent blockhash and mint rent in parallel
    let (recent_blockhash_result, mint_rent_result) = tokio::join!(
        tokio::task::spawn_blocking({
            move || {
                let rpc_client = RpcClient::new("http://localhost:8899".to_string());
                rpc_client.get_latest_blockhash()
            }
        }),
        tokio::task::spawn_blocking({
            move || {
                let rpc_client = RpcClient::new("http://localhost:8899".to_string());
                rpc_client.get_minimum_balance_for_rent_exemption(Mint::LEN)
            }
        })
    );
    
    let recent_blockhash = match recent_blockhash_result {
        Ok(Ok(hash)) => hash,
        Ok(Err(e)) => {
            error!("RPC error getting blockhash: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to connect to Solana network"
            })));
        }
        Err(e) => {
            error!("Task join error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };

    let mint_rent = match mint_rent_result {
        Ok(Ok(rent)) => rent,
        Ok(Err(e)) => {
            error!("Failed to get mint rent: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to calculate rent"
            })));
        }
        Err(e) => {
            error!("Task join error: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })));
        }
    };
    
    // Create MPC client with existing wallet metadata
    let solana_mpc = match SolanaMPCClient::with_existing_wallet(
        mpc_threshold as u16,
        &mpc_pubkey_package,
    ) {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to create MPC client with existing wallet: {}", e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to initialize MPC client"
            })));
        }
    };
    
    // Build instructions for token creation
    let mut instructions = Vec::new();
    
    // 1. Create mint account
    let create_mint_account_ix = solana_sdk::system_instruction::create_account(
        &from_pubkey,
        &mint_pubkey,
        mint_rent,
        Mint::LEN as u64,
        &spl_token::id(),
    );
    instructions.push(create_mint_account_ix);
    
    // 2. Initialize mint - FIX: Use correct function signature for SDK 2.0
    let init_mint_ix = token_instruction::initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &from_pubkey, // mint authority
        Some(&from_pubkey), // freeze authority
        6, // decimals
    ).map_err(|e| {
        error!("Failed to create initialize mint instruction: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create mint instruction")
    })?;
    instructions.push(init_mint_ix);
    
    // 3. Create associated token account for user
    let create_ata_ix = ata_instruction::create_associated_token_account(
        &from_pubkey, // payer
        &from_pubkey, // wallet owner
        &mint_pubkey, // mint
        &spl_token::id(),
    );
    instructions.push(create_ata_ix);
    
    // 4. Mint 1 million tokens to user (with 6 decimals = 1,000,000 * 10^6)
    let mint_to_ix = token_instruction::mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &user_ata,
        &from_pubkey,
        &[],
        1_000_000_000_000, // 1 million tokens with 6 decimals
    ).map_err(|e| {
        error!("Failed to create mint_to instruction: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create mint instruction")
    })?;
    instructions.push(mint_to_ix);
    
    // Create transaction with all instructions
    let mut transaction = Transaction::new_with_payer(&instructions, Some(&from_pubkey));
    transaction.message.recent_blockhash = recent_blockhash;
    
    // Sign transaction with FROST MPC
    info!("Signing token creation transaction with FROST MPC...");
    
    let session_id = format!("create_token_{}", Uuid::new_v4());
    let signing_result = match solana_mpc.sign_solana_transaction(&user_id, &transaction, &session_id).await {
        Ok(result) => result,
        Err(e) => {
            error!("MPC signing failed for user {}: {}", user_id, e);
            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Transaction signing failed: {}", e)
            })));
        }
    };
    
    if !signing_result.is_valid {
        error!("FROST signature verification failed");
        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Transaction signing failed - signature verification failed"
        })));
    }
    
    // Get the signed transaction and add mint keypair signature
    let mut final_transaction = signing_result.transaction;
    
    // Sign with mint keypair (for create account instruction)
    final_transaction.partial_sign(&[&mint_keypair], recent_blockhash);
    
    // Send transaction to network
    info!("Sending token creation transaction to Solana network...");
    
    let send_result = tokio::task::spawn_blocking({
        let final_transaction = final_transaction.clone();
        move || {
            let rpc_client = RpcClient::new("http://localhost:8899".to_string());
            rpc_client.send_and_confirm_transaction(&final_transaction)
        }
    }).await;
    
    match send_result {
        Ok(Ok(signature)) => {
            info!("✅ Token creation transaction sent successfully!");
            info!("Transaction signature: {}", signature);
            
            let response = serde_json::json!({
                "success": true,
                "message": "Test token created successfully!",
                "token_mint": mint_pubkey.to_string(),
                "user_token_account": user_ata.to_string(),
                "amount_minted": "1,000,000",
                "decimals": 6,
                "transaction_signature": signature.to_string(),
                "your_wallet": wallet_pubkey,
                "instructions": [
                    "You now have 1 million test tokens!",
                    "Use the token_mint address to transfer these tokens",
                    "Your tokens are in the user_token_account address"
                ]
            });
            
            Ok(HttpResponse::Ok().json(response))
        }
        Ok(Err(e)) => {
            error!("❌ Token creation transaction failed: {}", e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to create token: {}", e)
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
