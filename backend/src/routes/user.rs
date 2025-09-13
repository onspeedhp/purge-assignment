use actix_web::{HttpRequest, HttpResponse, Result, web};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::env;
use store::{Store, user::CreateUserRequest};
use tracing::{error, info, warn};
use crate::auth::get_user_id_from_request;
use frost_mpc::solana::SolanaMPCClient;

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpc_wallet_pubkey: Option<String>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
}

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
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
    _mpc_client: web::Data<SolanaMPCClient>,
) -> Result<HttpResponse> {
    let create_user_req = CreateUserRequest {
        email: req.username.clone(), // Using username as email for now
        password: req.password.clone(),
    };

    match store.create_user(create_user_req).await {
        Ok(user) => {
            let user_id = user.id.clone();
            
            // Create MPC wallet for the user
            info!("Creating MPC wallet for user: {}", user_id);
            let mut mpc_client_mut = SolanaMPCClient::new();
            
            match mpc_client_mut.generate_solana_keypair_with_metadata(&user_id, 2).await {
                Ok((keypair, pubkey_package_json)) => {
                    let mpc_wallet_pubkey = keypair.pubkey().to_string();
                    info!("MPC wallet created for user {}: {}", user_id, mpc_wallet_pubkey);
                    
                    // Update user with MPC wallet pubkey and metadata
                    if let Err(e) = store.update_user_mpc_wallet_with_metadata(
                        &user_id, 
                        &mpc_wallet_pubkey,
                        2, // threshold
                        &pubkey_package_json
                    ).await {
                        error!("Failed to update user MPC wallet metadata: {}", e);
                        return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                            "error": "Failed to save MPC wallet metadata"
                        })));
                    }
                    
                    let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
                    let now = Utc::now();
                    let exp = (now + Duration::hours(24)).timestamp() as usize;

                    let claims = Claims { sub: user.id, exp };
                    let _token = encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(secret.as_ref()),
                    )
                    .map_err(|e| {
                        error!("Failed to generate JWT token: {}", e);
                        actix_web::error::ErrorInternalServerError(e)
                    })?;

                    let response = SignupResponse {
                        message: "signed up successfully".to_string(),
                    };

                    Ok(HttpResponse::Ok().json(response))
                }
                Err(e) => {
                    error!("Failed to create MPC wallet for user {}: {}", user_id, e);
                    // For now, we'll still create the user but without MPC wallet
                    // In production, you might want to rollback user creation
                    let response = SignupResponse {
                        message: "signed up successfully".to_string(),
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
            // Generate JWT token
            let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
            let now = Utc::now();
            let exp = (now + Duration::hours(24)).timestamp() as usize;

            let claims = Claims { sub: user.id, exp };

            let token = encode(
                &Header::default(),
                &claims,
                &EncodingKey::from_secret(secret.as_ref()),
            )
            .map_err(|e| {
                error!("Failed to generate JWT token: {}", e);
                actix_web::error::ErrorInternalServerError(e)
            })?;

            let response = AuthResponse { token };

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
            let response = UserResponse {
                email: user.email,
                mpc_wallet_pubkey: user.mpc_wallet_pubkey,
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

/// Regenerate MPC wallet for a user
#[actix_web::post("/api/v1/user/regenerate-mpc-wallet")]
pub async fn regenerate_mpc_wallet(
    req: HttpRequest,
    store: web::Data<Store>,
) -> Result<HttpResponse> {
    let user_id = match get_user_id_from_request(&req) {
        Ok(id) => {
            info!("Regenerate MPC wallet request from authenticated user: {}", id);
            id
        }
        Err(response) => {
            return Ok(response);
        }
    };

    // Check if user exists
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

    // Generate new MPC wallet
    info!("Regenerating MPC wallet for user: {}", user_id);
    let mut mpc_client_mut = SolanaMPCClient::new();
    
    match mpc_client_mut.generate_solana_keypair_with_metadata(&user_id, 2).await {
        Ok((keypair, pubkey_package_json)) => {
            let mpc_wallet_pubkey = keypair.pubkey().to_string();
            info!("New MPC wallet created for user {}: {}", user_id, mpc_wallet_pubkey);
            
            // Update user with new MPC wallet pubkey and metadata
            if let Err(e) = store.update_user_mpc_wallet_with_metadata(
                &user_id, 
                &mpc_wallet_pubkey,
                2, // threshold
                &pubkey_package_json
            ).await {
                error!("Failed to update user MPC wallet metadata: {}", e);
                return Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Failed to save new MPC wallet metadata"
                })));
            }
            
            Ok(HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "message": "MPC wallet regenerated successfully",
                "new_wallet_pubkey": mpc_wallet_pubkey
            })))
        }
        Err(e) => {
            error!("Failed to regenerate MPC wallet for user {}: {}", user_id, e);
            Ok(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": format!("Failed to regenerate MPC wallet: {}", e)
            })))
        }
    }
}
