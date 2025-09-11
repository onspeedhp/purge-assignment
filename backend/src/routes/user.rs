use actix_web::{HttpRequest, HttpResponse, Result, web};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use store::{Store, user::CreateUserRequest};
use tracing::{debug, error, info, warn};

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

    info!("Creating user in database...");
    match store.create_user(create_user_req).await {
        Ok(user) => {
            info!("User created successfully with ID: {}", user.id);

            // Generate JWT token
            let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());
            let now = Utc::now();
            let exp = (now + Duration::hours(24)).timestamp() as usize;

            let user_id = user.id.clone();
            debug!("Generating JWT token for user: {}", user_id);

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

            info!("Signup completed successfully for user: {}", user_id);
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
    if let Some(auth_header) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..]; // Extract the token after "Bearer "
                let secret = env::var("JWT_SECRET").unwrap_or_else(|_| "your-secret-key".to_string());

                match decode::<Claims>(
                    token,
                    &DecodingKey::from_secret(secret.as_ref()),
                    &Validation::default(),
                ) {
                    Ok(claims) => {
                        let user_id = (claims.claims as Claims).sub;
                        
                        match store.get_user_by_id(&user_id).await {
                            Ok(Some(user)) => {
                                let response = UserResponse {
                                    email: user.email,
                                };
                                Ok(HttpResponse::Ok().json(response))
                            }
                            Ok(None) => {
                                Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                                    "error": "Invalid token"
                                })))
                            }
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
                    Err(_) => Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                        "error": "Invalid token"
                    })))
                }
            } else {
                Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                    "error": "Invalid authorization header"
                })))
            }
        } else {
            Ok(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid authorization header"
            })))
        }
    } else {
        Ok(HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Missing authorization header"
        })))
    }
}
