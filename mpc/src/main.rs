//! # Solana MPC TSS Server
//!
//! A comprehensive server for Solana Multi-Party Computation (MPC) and
//! Threshold Signature Schemes (TSS) operations with database integration.

use actix_web::{
    web::{post, Data, Json},
    App, Error, HttpResponse, HttpServer,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Core modules
pub mod database;
pub mod error;
pub mod mpc;
pub mod solana;
pub mod tss;
pub mod utils;

use crate::{
    database::Database,
    error::Error as AppError,
    tss::{cli::TSSCli, types::SolanaNetwork, AggSignStepOneResult},
};

/// Application state containing database
#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
}

/// Request/Response types for API endpoints

#[derive(Debug, Deserialize)]
pub struct GenerateRequest {
    pub user_id: String,
    pub network: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GenerateResponse {
    pub user_id: String,
    pub public_key: String,
    pub secret_key: String,
    pub network: String,
}

#[derive(Debug, Deserialize)]
pub struct SendSingleRequest {
    pub user_id: String,
    pub to: String,
    pub amount: f64,
    pub memo: Option<String>,
    pub network: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SendSingleResponse {
    pub transaction_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AggregateKeysRequest {
    pub participant_keys: Vec<String>,
    pub threshold: Option<usize>,
    pub network: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AggregateKeysResponse {
    pub aggregated_public_key: String,
    pub participant_keys: Vec<String>,
    pub threshold: usize,
}

#[derive(Debug, Deserialize)]
pub struct AggSendStep1Request {
    pub user_id: String,
    pub to: String,
    pub amount: f64,
    pub memo: Option<String>,
    pub network: Option<String>,
    pub recent_blockhash: String,
}

#[derive(Debug, Serialize)]
pub struct AggSendStep1Response {
    pub secret_nonce: String,
    pub public_nonce: String,
    pub participant_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AggSendStep2Request {
    pub step1_data: AggSignStepOneResult,
    pub user_id: String,
    pub to: String,
    pub amount: f64,
    pub all_public_nonces: Vec<String>,
    pub memo: Option<String>,
    pub network: Option<String>,
    pub recent_blockhash: String,
}

#[derive(Debug, Serialize)]
pub struct AggSendStep2Response {
    pub partial_signature: String,
    pub public_nonce: String,
    pub participant_key: String,
}

#[derive(Debug, Deserialize)]
pub struct AggregateSignaturesBroadcastRequest {
    pub partial_signatures: Vec<crate::tss::cli::AggSignStepTwoResult>, // Vec of step2 responses
    pub transaction_details: crate::tss::cli::TransactionDetailsParams, // Transaction details struct
    pub aggregated_wallet: crate::tss::cli::AggregateWalletParams, // JSON string of aggregated wallet
    pub network: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AggregateSignaturesBroadcastResponse {
    pub transaction_id: String,
}

#[derive(Debug, Deserialize)]
pub struct GetBlockHashRequest {
    pub network: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GetBlockHashResponse {
    pub block_hash: String,
    pub network: String,
}

/// Generate keypair endpoint - equivalent to TSSCli.generate()
async fn generate(
    state: Data<AppState>,
    Json(payload): Json<GenerateRequest>,
) -> Result<HttpResponse, Error> {
    let network_str = payload.network.unwrap_or_else(|| "devnet".to_string());
    let network = match network_str.as_str() {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let result = cli
        .generate()
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    // Store key share in database
    state
        .db
        .store_key_share(&payload.user_id, &result.public_key, &result.secret_key)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(GenerateResponse {
        user_id: payload.user_id,
        public_key: result.public_key,
        secret_key: result.secret_key,
        network: network_str,
    }))
}

/// Send single transaction endpoint - equivalent to TSSCli.send_single()
async fn send_single(
    state: Data<AppState>,
    Json(payload): Json<SendSingleRequest>,
) -> Result<HttpResponse, Error> {
    // Get key share from database
    let key_share = state
        .db
        .get_key_share_by_user_id(&payload.user_id)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::InvalidInput("User not found".to_string()))?;

    let network_str = payload.network.unwrap_or_else(|| "devnet".to_string());
    let network = match network_str.as_str() {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let tx_id = cli
        .send_single(
            &key_share.private_key,
            &payload.to,
            payload.amount,
            payload.memo,
        )
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(SendSingleResponse {
        transaction_id: tx_id,
    }))
}

/// Aggregate keys endpoint - equivalent to TSSCli.aggregate_keys()
async fn aggregate_keys(Json(payload): Json<AggregateKeysRequest>) -> Result<HttpResponse, Error> {
    // Use participant keys directly from request
    let participant_keys = payload.participant_keys;

    let network_str = payload.network.unwrap_or_else(|| "devnet".to_string());
    let network = match network_str.as_str() {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let result = cli
        .aggregate_keys(&participant_keys, payload.threshold)
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(AggregateKeysResponse {
        aggregated_public_key: result.aggregated_public_key,
        participant_keys: result.participant_keys,
        threshold: result.threshold,
    }))
}

/// Aggregate send step 1 endpoint - equivalent to TSSCli.aggregate_sign_step_one()
async fn agg_send_step1(
    state: Data<AppState>,
    Json(payload): Json<AggSendStep1Request>,
) -> Result<HttpResponse, Error> {
    // Get key share from database
    let key_share = state
        .db
        .get_key_share_by_user_id(&payload.user_id)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::InvalidInput("User not found".to_string()))?;

    let network_str = payload.network.unwrap_or_else(|| "devnet".to_string());
    let network = match network_str.as_str() {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);

    let result = cli
        .aggregate_sign_step_one(
            &key_share.private_key,
            &payload.to,
            payload.amount,
            payload.memo,
            Some(payload.recent_blockhash),
        )
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(AggSendStep1Response {
        secret_nonce: result.secret_nonce,
        public_nonce: result.public_nonce,
        participant_key: result.participant_key,
    }))
}

/// Aggregate send step 2 endpoint - equivalent to TSSCli.aggregate_sign_step_two()
async fn agg_send_step2(
    state: Data<AppState>,
    Json(payload): Json<AggSendStep2Request>,
) -> Result<HttpResponse, Error> {
    // Get key share from database
    let key_share = state
        .db
        .get_key_share_by_user_id(&payload.user_id)
        .await
        .map_err(|e| AppError::DatabaseError(e.to_string()))?
        .ok_or_else(|| AppError::InvalidInput("User not found".to_string()))?;

    let network_str = payload.network.unwrap_or_else(|| "devnet".to_string());
    let network = match network_str.as_str() {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);

    let result = cli
        .aggregate_sign_step_two(
            &AggSignStepOneResult {
                secret_nonce: payload.step1_data.secret_nonce,
                public_nonce: payload.step1_data.public_nonce,
                participant_key: payload.step1_data.participant_key,
            },
            &key_share.private_key,
            &payload.to,
            payload.amount,
            &payload.all_public_nonces,
            payload.memo,
            Some(payload.recent_blockhash),
        )
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(AggSendStep2Response {
        partial_signature: result.partial_signature,
        public_nonce: result.public_nonce,
        participant_key: result.participant_key,
    }))
}

/// Aggregate signatures and broadcast endpoint - equivalent to TSSCli.aggregate_signatures_and_broadcast()
async fn aggregate_signatures_broadcast(
    Json(payload): Json<AggregateSignaturesBroadcastRequest>,
) -> Result<HttpResponse, Error> {
    let network_str = payload.network.unwrap_or_else(|| "devnet".to_string());
    let network = match network_str.as_str() {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let tx_id = cli
        .aggregate_signatures_and_broadcast(
            payload.partial_signatures,
            payload.transaction_details,
            payload.aggregated_wallet,
        )
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(
        HttpResponse::Ok().json(AggregateSignaturesBroadcastResponse {
            transaction_id: tx_id,
        }),
    )
}

/// Get recent block hash endpoint
async fn get_blockhash(Json(payload): Json<GetBlockHashRequest>) -> Result<HttpResponse, Error> {
    let network_str = payload.network.unwrap_or_else(|| "devnet".to_string());
    let network = match network_str.as_str() {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let block_hash = cli
        .recent_block_hash()
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(GetBlockHashResponse {
        block_hash,
        network: network_str,
    }))
}

/// Health check endpoint
async fn health_check() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "solana-mpc-tss",
        "version": "1.0.0"
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Solana MPC TSS Server...");

    // Initialize database
    let database_url =
        std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite:mpc.db".to_string());

    let db = Database::new(&database_url)
        .await
        .expect("Failed to initialize database");

    let app_state = AppState { db: Arc::new(db) };

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or(8080);

    println!("Server will be available at: http://127.0.0.1:{}", port);
    println!("Database: {}", database_url);

    HttpServer::new(move || {
        App::new()
            .app_data(Data::new(app_state.clone()))
            // Health check
            .route("/health", actix_web::web::get().to(health_check))
            // Get block hash endpoint
            .route("/get-blockhash", post().to(get_blockhash))
            // 6 main TSS endpoints as requested
            .route("/generate", post().to(generate))
            .route("/send-single", post().to(send_single))
            .route("/aggregate-keys", post().to(aggregate_keys))
            .route("/agg-send-step1", post().to(agg_send_step1))
            .route("/agg-send-step2", post().to(agg_send_step2))
            .route(
                "/aggregate-signatures-broadcast",
                post().to(aggregate_signatures_broadcast),
            )
    })
    .bind(format!("127.0.0.1:{}", port))?
    .run()
    .await
}
