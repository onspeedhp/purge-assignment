use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde::{Deserialize, Serialize};
use tracing::{info, error};
use frost_mpc::distributed_mpc::DistributedMPC;
use crate::auth::get_user_id_from_request;

#[derive(Deserialize, Debug)]
pub struct CreateWalletRequest {
    #[serde(default = "default_threshold")]
    pub threshold: u16,
}

fn default_threshold() -> u16 {
    2 // Default 2-of-3 threshold
}

#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub success: bool,
    pub message: String,
    pub wallet_address: String,
    pub public_key: String,
}

#[derive(Serialize)]
pub struct GetWalletResponse {
    pub wallet_address: String,
    pub public_key: String,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

/// Create a new wallet for the authenticated user using MPC
#[actix_web::post("/api/v1/wallet/create")]
pub async fn create_wallet(
    req: web::Json<CreateWalletRequest>,
    http_req: HttpRequest,
) -> Result<HttpResponse> {
    // Get authenticated user ID
    let user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Create wallet request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };

    info!("Creating MPC wallet for user: {} with threshold: {}", user_id, req.threshold);

    // Initialize MPC coordinator
    let mut mpc = DistributedMPC::new();

    // Generate key shares using MPC
    match mpc.generate_key_shares(&user_id, req.threshold).await {
        Ok(keygen_result) => {
            let public_key_hex = hex::encode(&keygen_result.group_public_key);
            
            // Convert to Solana address format
            let wallet_address = match solana_sdk::pubkey::Pubkey::try_from(keygen_result.group_public_key.as_slice()) {
                Ok(pubkey) => pubkey.to_string(),
                Err(e) => {
                    error!("Failed to convert public key to Solana address: {}", e);
                    return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to generate wallet address".to_string(),
                    }));
                }
            };

            info!("✅ MPC wallet created successfully for user: {}", user_id);
            info!("   Public Key: {}", public_key_hex);
            info!("   Wallet Address: {}", wallet_address);
            info!("   Participants: {:?}", keygen_result.participants);

            Ok(HttpResponse::Ok().json(CreateWalletResponse {
                success: true,
                message: "Wallet created successfully using MPC".to_string(),
                wallet_address,
                public_key: public_key_hex,
            }))
        }
        Err(e) => {
            error!("Failed to create MPC wallet for user {}: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                error: format!("Failed to create wallet: {}", e),
            }))
        }
    }
}

/// Get wallet information for the authenticated user
#[actix_web::get("/api/v1/wallet")]
pub async fn get_wallet(http_req: HttpRequest) -> Result<HttpResponse> {
    // Get authenticated user ID
    let user_id = match get_user_id_from_request(&http_req) {
        Ok(id) => {
            info!("Get wallet request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };

    info!("Getting wallet information for user: {}", user_id);

    // Try to get key share from MPC servers
    let mpc_client = frost_mpc::distributed_mpc::MPCServerClient::new(
        frost_mpc::distributed_mpc::MPCServerConfig {
            id: 1,
            host: "127.0.0.1".to_string(),
            port: 8081,
        }
    );

    let server_user_id = format!("{}_mpc_server_1", user_id);
    
    match mpc_client.get_key_share_by_user_id(&server_user_id).await {
        Ok(key_share) => {
            // Convert public key to Solana address
            let public_key_bytes = match hex::decode(&key_share.public_key) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to decode public key hex: {}", e);
                    return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Invalid public key format".to_string(),
                    }));
                }
            };

            let wallet_address = match solana_sdk::pubkey::Pubkey::try_from(public_key_bytes.as_slice()) {
                Ok(pubkey) => pubkey.to_string(),
                Err(e) => {
                    error!("Failed to convert public key to Solana address: {}", e);
                    return Ok(HttpResponse::InternalServerError().json(ErrorResponse {
                        error: "Failed to convert to wallet address".to_string(),
                    }));
                }
            };

            Ok(HttpResponse::Ok().json(GetWalletResponse {
                wallet_address,
                public_key: key_share.public_key,
                created_at: key_share.created_at.to_rfc3339(),
            }))
        }
        Err(e) => {
            info!("No wallet found for user {}: {}", user_id, e);
            Ok(HttpResponse::NotFound().json(ErrorResponse {
                error: "Wallet not found. Please create a wallet first.".to_string(),
            }))
        }
    }
}

/// Health check for MPC servers
#[actix_web::get("/api/v1/wallet/health")]
pub async fn wallet_health() -> Result<HttpResponse> {
    let mut server_status = Vec::new();
    
    for port in [8081, 8082, 8083] {
        let client = reqwest::Client::new();
        let url = format!("http://localhost:{}/health", port);
        
        match client.get(&url).send().await {
            Ok(response) if response.status().is_success() => {
                server_status.push(serde_json::json!({
                    "port": port,
                    "status": "healthy"
                }));
            }
            _ => {
                server_status.push(serde_json::json!({
                    "port": port,
                    "status": "unhealthy"
                }));
            }
        }
    }
    
    let healthy_count = server_status.iter()
        .filter(|s| s["status"] == "healthy")
        .count();
    
    let overall_status = if healthy_count >= 2 {
        "healthy" // Need at least 2 servers for 2-of-3 threshold
    } else {
        "unhealthy"
    };
    
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "overall_status": overall_status,
        "healthy_servers": healthy_count,
        "total_servers": 3,
        "servers": server_status
    })))
}
