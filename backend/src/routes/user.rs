use actix_web::{HttpRequest, HttpResponse, Result, web};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::env;
use store::{Store, user::CreateUserRequest};
use tracing::{debug, error, info, warn};
use crate::auth::get_user_id_from_request;

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
) -> Result<HttpResponse> {
    let create_user_req = CreateUserRequest {
        email: req.username.clone(), // Using username as email for now
        password: req.password.clone(),
    };

    match store.create_user(create_user_req).await {
        Ok(user) => {
            let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
            let now = Utc::now();
            let exp = (now + Duration::hours(24)).timestamp() as usize;

            let user_id = user.id.clone();

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
