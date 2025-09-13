use actix_web::{HttpRequest, HttpResponse, Result, web};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::env;
use store::{Store, user::CreateUserRequest};
use tracing::{error, info, warn};
use crate::auth::get_user_id_from_request;
use frost_mpc::distributed_mpc::{DistributedMPC, MPCServerClient, MPCServerConfig};

/// Helper function to get wallet info from MPC
async fn get_wallet_info(user_id: &str) -> Option<(String, String)> {
    let mpc_client = MPCServerClient::new(MPCServerConfig {
        id: 1,
        host: "127.0.0.1".to_string(),
        port: 8081,
    });

    let server_user_id = format!("{}_mpc_server_1", user_id);
    
    match mpc_client.get_key_share_by_user_id(&server_user_id).await {
        Ok(key_share) => {
            // Convert public key to Solana address
            if let Ok(public_key_bytes) = hex::decode(&key_share.public_key) {
                if let Ok(pubkey) = solana_sdk::pubkey::Pubkey::try_from(public_key_bytes.as_slice()) {
                    return Some((pubkey.to_string(), key_share.public_key));
                }
            }
            None
        }
        Err(_) => None,
    }
}

#[derive(Deserialize, Debug)]
pub struct SignUpRequest {
    pub username: String, // Changed from email to username as per spec
    pub password: String,
}

#[derive(Deserialize, Debug)]
pub struct SignInRequest {
    pub username: String, // Changed from email to username as per spec
    pub password: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub email: String,
    pub wallet_address: Option<String>,
    pub public_key: Option<String>,
    pub wallet_created_at: Option<String>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserInfo,
}

#[derive(Serialize)]
pub struct UserInfo {
    pub email: String,
    pub wallet_address: Option<String>,
    pub public_key: Option<String>,
    pub wallet_created_at: Option<String>,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
    pub user: UserInfo,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // user id
    exp: usize,
}

#[actix_web::post("/api/v1/signup")]
pub async fn sign_up(
    req: web::Json<SignUpRequest>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    let create_user_req = CreateUserRequest {
        email: req.username.clone(), // Using username as email for now
        password: req.password.clone(),
    };

    match store.create_user(create_user_req).await {
        Ok(user) => {
            info!("User created successfully: {}", user.email);
            
            // Tạo MPC wallet cho user mới
            info!("Creating MPC wallet for new user: {}", user.id);
            let mut mpc = DistributedMPC::new();
            
            match mpc.generate_key_shares(&user.id, 2).await { // 2-of-3 threshold
                Ok(keygen_result) => {
                    let public_key_hex = hex::encode(&keygen_result.group_public_key);
                    
                    // Convert to Solana address
                    let wallet_address = match solana_sdk::pubkey::Pubkey::try_from(keygen_result.group_public_key.as_slice()) {
                        Ok(pubkey) => pubkey.to_string(),
                        Err(e) => {
                            error!("Failed to convert public key to Solana address: {}", e);
                            return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                                "error": "Failed to generate wallet address"
                            })));
                        }
                    };

                    info!("✅ MPC wallet created for user {}", user.id);
                    info!("   Wallet Address: {}", wallet_address);
                    info!("   Public Key: {}", public_key_hex);

                    let response = SignupResponse {
                        message: "User created successfully with MPC wallet".to_string(),
                        user: UserInfo {
                            email: user.email,
                            wallet_address: Some(wallet_address),
                            public_key: Some(public_key_hex),
                            wallet_created_at: Some(chrono::Utc::now().to_rfc3339()),
                        },
                    };

                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    error!("Failed to create MPC wallet for user {}: {}", user.id, e);
                    // Vẫn trả về success cho user creation, nhưng báo lỗi wallet
                    let response = SignupResponse {
                        message: format!("User created successfully, but wallet creation failed: {}", e),
                        user: UserInfo {
                            email: user.email,
                            wallet_address: None,
                            public_key: None,
                            wallet_created_at: None,
                        },
                    };
                    Ok(HttpResponse::Ok().json(response))
                }
            }
        }
        Err(store::user::UserError::UserExists) => {
            warn!("Signup failed: User already exists - {}", req.username);
            Ok(HttpResponse::Conflict().json(serde_json::json!({
                "error": "User already exists"
            })))
        }
        Err(store::user::UserError::InvalidInput(msg)) => {
            warn!("Signup failed: Invalid input - {}", msg);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": msg
            })))
        }
        Err(store::user::UserError::DatabaseError(msg)) => {
            error!("Signup failed: Database error - {}", msg);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })))
        }
        _ => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal server error"
        }))),
    }
}

#[actix_web::post("/api/v1/signin")]
pub async fn sign_in(
    req: web::Json<SignInRequest>,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    match store.validate_password(&req.username, &req.password).await {
        Ok(Some(user)) => {
            info!("User login successful: {}", user.email);
            
            // Generate JWT token
            let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
            let now = Utc::now();
            let exp = (now + Duration::hours(24)).timestamp() as usize;

            let claims = Claims { sub: user.id.clone(), exp };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_ref()),
            )
            .map_err(|e| {
                error!("Failed to generate JWT token: {}", e);
                actix_web::error::ErrorInternalServerError(e)
            })?;

            // Get wallet info from MPC
            let (wallet_address, public_key, wallet_created_at) = match get_wallet_info(&user.id).await {
                Some((address, pubkey)) => {
                    info!("Found wallet for user {}: {}", user.id, address);
                    (Some(address), Some(pubkey), Some(chrono::Utc::now().to_rfc3339()))
                }
                None => {
                    info!("No wallet found for user {}", user.id);
                    (None, None, None)
                }
            };

            let response = AuthResponse { 
                token,
                user: UserInfo {
                    email: user.email,
                    wallet_address,
                    public_key,
                    wallet_created_at,
                },
            };

            Ok(HttpResponse::Ok().json(response))
        }
        Ok(None) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        }))),
        Err(store::user::UserError::InvalidInput(msg)) => {
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": msg
            })))
        }
        Err(store::user::UserError::UserNotFound) => {
            Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            })))
        }
        Err(store::user::UserError::InvalidPassword) => {
            Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            })))
        }
        _ => Ok(HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Internal server error"
        }))),
    }
}

#[actix_web::get("/api/v1/user")]
pub async fn get_user(req: HttpRequest, store: web::Data<Store>) -> Result<HttpResponse> {
    let user_id = match get_user_id_from_request(&req) {
        Ok(id) => {
            info!("Get user request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };
    
    match store.get_user_by_id(&user_id).await {
        Ok(Some(user)) => {
            // Get wallet info from MPC
            let (wallet_address, public_key, wallet_created_at) = match get_wallet_info(&user.id).await {
                Some((address, pubkey)) => {
                    info!("Found wallet for user {}: {}", user.id, address);
                    (Some(address), Some(pubkey), Some(chrono::Utc::now().to_rfc3339()))
                }
                None => {
                    info!("No wallet found for user {}", user.id);
                    (None, None, None)
                }
            };

            let response = UserResponse {
                email: user.email,
                wallet_address,
                public_key,
                wallet_created_at,
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Ok(None) => {
            error!("User not found for ID: {}", user_id);
            Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "User not found"
            })))
        }
        Err(store::user::UserError::InvalidInput(msg)) => {
            error!("Invalid input for user ID {}: {}", user_id, msg);
            Ok(HttpResponse::BadRequest().json(serde_json::json!({
                "error": msg
            })))
        }
        Err(store::user::UserError::UserNotFound) => {
            error!("User not found for ID: {}", user_id);
            Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "User not found"
            })))
        }
        Err(store::user::UserError::InvalidPassword) => {
            error!("Invalid password for user ID: {}", user_id);
            Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            })))
        }
        Err(store::user::UserError::DatabaseError(_)) => {
            error!("Database error for user ID: {}", user_id);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            })))
        }
        Err(store::user::UserError::UserExists) => {
            error!("User already exists for ID: {}", user_id);
            Ok(HttpResponse::Conflict().json(serde_json::json!({
                "error": "User already exists"
            })))
        }
    }
}
