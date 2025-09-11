use actix_web::{HttpRequest, HttpResponse, Result};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use tracing::{info, warn, error};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
}

// Helper function to extract and validate JWT token from request
pub fn get_user_id_from_request(req: &HttpRequest) -> Result<String, HttpResponse> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|header| header.to_str().ok());

    let token = match auth_header {
        Some(header) if header.starts_with("Bearer ") => {
            let token = &header[7..]; // Remove "Bearer " prefix
            info!("Extracted token from Authorization header");
            Some(token)
        }
        Some(_) => {
            warn!("Invalid Authorization header format");
            None
        }
        None => {
            warn!("Missing Authorization header");
            None
        }
    };

    let token = match token {
        Some(t) => t,
        None => {
            return Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Missing or invalid authorization header"
            })));
        }
    };

    // Decode and validate JWT token
    let jwt_secret = match env::var("JWT_SECRET") {
        Ok(secret) => secret,
        Err(_) => {
            error!("JWT_SECRET environment variable not set");
            return Err(HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Server configuration error"
            })));
        }
    };

    let validation = Validation::default();
    let key = DecodingKey::from_secret(jwt_secret.as_ref());

    match decode::<Claims>(token, &key, &validation) {
        Ok(token_data) => {
            info!("JWT token validated successfully for user: {}", token_data.claims.sub);
            Ok(token_data.claims.sub)
        }
        Err(e) => {
            warn!("JWT token validation failed: {}", e);
            Err(HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid or expired token"
            })))
        }
    }
}
