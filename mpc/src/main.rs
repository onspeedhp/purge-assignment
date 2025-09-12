//! # FROST MPC Server
//!
//! A FROST-ed25519 MPC server that follows the README exactly,
//! designed to run on different ports for distributed signing.

use actix_web::{
    web::{post, Data, Json},
    App, Error, HttpResponse, HttpServer,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod database;
pub mod distributed_mpc;
pub mod error;
pub mod solana;

use crate::database::Database;
use crate::error::Error as AppError;
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    /// ephemeral storage: session_id -> (user_id -> nonces)
    pub nonces: Arc<
        Mutex<
            std::collections::HashMap<
                String,
                std::collections::HashMap<String, frost_ed25519::round1::SigningNonces>,
            >,
        >,
    >,
}

// ====== FROST MPC Handlers ======

async fn health_check() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "frost-mpc-server",
        "timestamp": chrono::Utc::now().to_rfc3339()
    })))
}

/// Get server status and information
async fn server_status(state: Data<AppState>) -> Result<HttpResponse, Error> {
    let participant_id = get_server_participant_id();
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    // Count stored key shares
    let key_shares = state
        .db
        .list_key_shares()
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "server_id": participant_id,
        "port": port,
        "status": "running",
        "service": "frost-mpc-server",
        "key_shares_count": key_shares.len(),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "endpoints": {
            "health": "/health",
            "status": "/status",
            "keygen": "/frost/keygen",
            "round1": "/frost/round1",
            "round2": "/frost/round2",
            "aggregate": "/frost/aggregate"
        }
    })))
}

/// FROST Round 1: Generate nonces and commitments (exactly like FROST-ed25519 README)
#[derive(Debug, Deserialize)]
pub struct FrostRound1Request {
    pub user_id: String,
    pub session_id: String,
}

#[derive(Debug, Serialize)]
pub struct FrostRound1Response {
    pub participant: u16,
    pub commitments: serde_json::Value,
}

async fn frost_round1(
    state: Data<AppState>,
    Json(payload): Json<FrostRound1Request>,
) -> Result<HttpResponse, Error> {
    // The user_id is already server-specific (e.g., "test_user_123_mpc_server_1")
    let server_user_id = &payload.user_id;
    println!("Round 1: Looking for user_id: {}", server_user_id);

    // Load participant KeyPackage from DB
    let key_share = state
        .db
        .get_key_share_by_user_id(server_user_id)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::InvalidInput("Key share not found for this server".into()))?;

    let key_pkg: frost_ed25519::keys::KeyPackage = serde_json::from_str(&key_share.private_key)
        .map_err(|e| AppError::InternalError(format!("Invalid stored key package: {}", e)))?;

    // Round1: Generate nonces and commitments (exactly like FROST-ed25519 README)
    let mut rng = OsRng;
    let (nonces, commitments) = frost_ed25519::round1::commit(&key_pkg.signing_share(), &mut rng);

    // Store nonces for Round 2
    let mut guard = state.nonces.lock().await;
    let entry = guard
        .entry(payload.session_id.clone())
        .or_insert_with(Default::default);
    entry.insert(server_user_id.to_string(), nonces);

    // Extract participant ID from the server-specific user ID
    let participant_id = get_server_participant_id();

    Ok(HttpResponse::Ok().json(FrostRound1Response {
        participant: participant_id,
        commitments: serde_json::to_value(&commitments).unwrap(),
    }))
}

/// FROST Round 2: Generate signature share (exactly like FROST-ed25519 README)
#[derive(Debug, Deserialize)]
pub struct FrostRound2Request {
    pub user_id: String,
    pub session_id: String,
    pub signing_package: serde_json::Value,
    pub message_hex: String,
}

#[derive(Debug, Serialize)]
pub struct FrostRound2Response {
    pub participant: u16,
    pub signature_share: serde_json::Value,
}

/// FROST Aggregate: Aggregate signature shares into final signature (exactly like FROST-ed25519 README)
#[derive(Debug, Deserialize)]
pub struct FrostAggregateRequest {
    pub user_id: String,
    pub session_id: String,
    pub signing_package: serde_json::Value,
    pub signature_shares: serde_json::Value,
    pub pubkey_package: serde_json::Value,
}

#[derive(Debug, Serialize)]
pub struct FrostAggregateResponse {
    pub signature: String, // hex encoded
    pub is_valid: bool,
    pub message: String, // hex encoded
}

async fn frost_round2(
    state: Data<AppState>,
    Json(payload): Json<FrostRound2Request>,
) -> Result<HttpResponse, Error> {
    // The user_id is already server-specific (e.g., "test_user_123_mpc_server_1")
    let server_user_id = &payload.user_id;

    // Load stored nonces
    let mut guard = state.nonces.lock().await;
    let Some(map) = guard.get_mut(&payload.session_id) else {
        return Err(AppError::InvalidInput("Unknown session_id".into()).into());
    };
    let Some(nonces) = map.remove(server_user_id) else {
        return Err(AppError::InvalidInput("Nonces not found for this server".into()).into());
    };

    // Load KeyPackage
    let key_share = state
        .db
        .get_key_share_by_user_id(&server_user_id)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::InvalidInput("Key share not found for this server".into()))?;
    let key_pkg: frost_ed25519::keys::KeyPackage = serde_json::from_str(&key_share.private_key)
        .map_err(|e| AppError::InternalError(format!("Invalid stored key package: {}", e)))?;

    // Parse signing package & message
    let signing_pkg: frost_ed25519::SigningPackage =
        serde_json::from_value(payload.signing_package.clone())
            .map_err(|e| AppError::InvalidInput(format!("Bad signing package: {}", e)))?;
    let _message = hex::decode(&payload.message_hex)
        .map_err(|e| AppError::InvalidInput(format!("Bad hex: {}", e)))?;

    // Round2: Generate signature share (exactly like FROST-ed25519 README)
    let share = frost_ed25519::round2::sign(&signing_pkg, &nonces, &key_pkg)
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    // Get participant ID for response
    let participant_id = get_server_participant_id();

    Ok(HttpResponse::Ok().json(FrostRound2Response {
        participant: participant_id,
        signature_share: serde_json::to_value(&share).unwrap(),
    }))
}

/// FROST Aggregate: Aggregate signature shares into final signature (exactly like FROST-ed25519 README)
async fn frost_aggregate(
    _state: Data<AppState>,
    Json(payload): Json<FrostAggregateRequest>,
) -> Result<HttpResponse, Error> {
    // Parse the signing package
    let signing_package: frost_ed25519::SigningPackage =
        serde_json::from_value(payload.signing_package.clone())
            .map_err(|e| AppError::InvalidInput(format!("Bad signing package: {}", e)))?;

    // Parse signature shares
    let signature_shares_map: std::collections::BTreeMap<
        frost_ed25519::Identifier,
        frost_ed25519::round2::SignatureShare,
    > = serde_json::from_value(payload.signature_shares.clone())
        .map_err(|e| AppError::InvalidInput(format!("Bad signature shares: {}", e)))?;

    // Parse pubkey package
    let pubkey_package: frost_ed25519::keys::PublicKeyPackage =
        serde_json::from_value(payload.pubkey_package.clone())
            .map_err(|e| AppError::InvalidInput(format!("Bad pubkey package: {}", e)))?;

    // Aggregate signature (exactly like FROST-ed25519 README)
    let group_signature =
        frost_ed25519::aggregate(&signing_package, &signature_shares_map, &pubkey_package)
            .map_err(|e| AppError::InternalError(e.to_string()))?;

    // Verify signature (exactly like FROST-ed25519 README)
    let message = signing_package.message();
    let is_signature_valid = pubkey_package
        .verifying_key()
        .verify(message, &group_signature)
        .is_ok();

    Ok(HttpResponse::Ok().json(FrostAggregateResponse {
        signature: hex::encode(group_signature.serialize().unwrap()),
        is_valid: is_signature_valid,
        message: hex::encode(message),
    }))
}

/// Get key share by user ID
async fn get_key_share(
    state: Data<AppState>,
    path: actix_web::web::Path<String>,
) -> Result<HttpResponse, Error> {
    let user_id = path.into_inner();

    let key_share = state
        .db
        .get_key_share_by_user_id(&user_id)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::InvalidInput("Key share not found".into()))?;

    Ok(HttpResponse::Ok().json(key_share))
}

/// FROST Key Generation: Generate and store key shares (exactly like FROST-ed25519 README)
#[derive(Debug, Deserialize)]
pub struct FrostKeygenRequest {
    pub user_id: String,
    pub threshold: u16,
    pub total_signers: u16,
}

/// FROST Key Generation with specific key package (for coordinated distribution)
#[derive(Debug, Deserialize)]
pub struct FrostKeygenWithPackageRequest {
    pub user_id: String,
    pub threshold: u16,
    pub total_signers: u16,
    pub key_package_json: String,
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct FrostKeygenResponse {
    pub participant: u16,
    pub public_key: String,
    pub success: bool,
    pub user_id: String,
}

async fn frost_keygen(
    _state: Data<AppState>,
    _payload: Json<FrostKeygenRequest>,
) -> Result<HttpResponse, Error> {
    // This endpoint is deprecated - use keygen-with-package instead
    // for coordinated key generation
    Err(AppError::InvalidInput(
        "Use /frost/keygen-with-package for coordinated key generation".into(),
    )
    .into())
}

/// Get this server's participant ID based on port or environment variable
fn get_server_participant_id() -> u16 {
    // Try to get from environment variable first
    if let Ok(participant_id) = std::env::var("PARTICIPANT_ID") {
        if let Ok(id) = participant_id.parse::<u16>() {
            return id;
        }
    }

    // Fallback: determine from port
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 2 && args[1] == "--port" {
        if let Ok(port) = args[2].parse::<u16>() {
            match port {
                8081 => return 1,
                8082 => return 2,
                8083 => return 3,
                _ => {}
            }
        }
    }

    // Default fallback
    1
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Check if we should run in client mode
    if args.len() > 1 && args[1] == "client" {
        return run_client().await;
    }

    // Server mode
    let port = if args.len() > 1 && args[1] == "--port" && args.len() > 2 {
        args[2].parse::<u16>().unwrap_or(8080)
    } else {
        std::env::var("PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse::<u16>()
            .unwrap_or(8080)
    };

    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| format!("sqlite:data/mpc{}.db", port));

    // Ensure data directory exists
    std::fs::create_dir_all("data").expect("Failed to create data directory");

    let db = Database::new(&database_url).await.expect("db init");

    let state = AppState {
        db: Arc::new(db),
        nonces: Arc::new(Mutex::new(std::collections::HashMap::new())),
    };

    println!("Starting FROST MPC server on port {}", port);

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(state.clone()))
            .route("/health", actix_web::web::get().to(health_check))
            .route("/status", actix_web::web::get().to(server_status))
            // FROST MPC endpoints
            .route("/frost/keygen", post().to(frost_keygen))
            .route("/frost/round1", post().to(frost_round1))
            .route("/frost/round2", post().to(frost_round2))
            .route("/frost/aggregate", post().to(frost_aggregate))
            .route(
                "/frost/key-share/{user_id}",
                actix_web::web::get().to(get_key_share),
            )
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}

/// Run the FROST MPC client that demonstrates the complete flow
async fn run_client() -> std::io::Result<()> {
    println!("=== FROST MPC Client Demo ===");
    println!("This demonstrates the complete FROST-ed25519 flow across 3 MPC servers");
    println!("Make sure to start the 3 MPC servers first:");
    println!("  Terminal 1: cargo run -- --port 8081");
    println!("  Terminal 2: cargo run -- --port 8082");
    println!("  Terminal 3: cargo run -- --port 8083");
    println!();

    // Wait a moment for servers to start
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // Run basic FROST example
    match crate::distributed_mpc::distributed_frost_example().await {
        Ok(_) => {
            println!("\n✅ FROST MPC demo completed successfully!");
        }
        Err(e) => {
            println!("\n❌ FROST MPC demo failed: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    // Run Solana MPC example
    println!("\n=== Solana FROST MPC Demo ===");
    match crate::solana::solana_mpc_example().await {
        Ok(_) => {
            println!("\n✅ Solana FROST MPC demo completed successfully!");
        }
        Err(e) => {
            println!("\n❌ Solana FROST MPC demo failed: {}", e);
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                e.to_string(),
            ));
        }
    }

    Ok(())
}
