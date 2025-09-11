//! # Solana MPC TSS Server
//!
//! A comprehensive server for Solana Multi-Party Computation (MPC) and
//! Threshold Signature Schemes (TSS) operations.

use actix_web::{
    web::{post, Json},
    App, Error, HttpResponse, HttpServer,
};

// Core modules
pub mod error;
pub mod mpc;
pub mod solana;
pub mod tss;
pub mod utils;

use crate::{
    error::Error as AppError,
    tss::{cli::TSSCli, types::SolanaNetwork, wallet::TSSWallet},
    utils::serialization::*,
};

/// Health check endpoint
async fn health_check() -> Result<HttpResponse, Error> {
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "solana-mpc-tss",
        "version": "1.0.0"
    })))
}

/// Create MPC keypair endpoint
async fn create_mpc_keypair() -> Result<HttpResponse, Error> {
    let mpc_keypair = mpc::MPCKeypair::new();

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "public_key": mpc_keypair.public_key.to_string(),
        "secret_key": bytes_to_hex(&mpc_keypair.secret_key)
    })))
}

/// Create TSS wallet endpoint
async fn create_tss_wallet(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let network_str = payload
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("devnet");

    let network = match network_str {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let wallet = TSSWallet::new(network);
    let keypair = wallet
        .generate_keypair()
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "public_key": keypair.public_key.to_string(),
        "secret_key": bytes_to_hex(&keypair.secret_key),
        "network": network_str
    })))
}

/// Aggregate keys endpoint
async fn aggregate_keys(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let participant_keys_str = payload
        .get("participant_keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::InvalidInput("Missing participant_keys".to_string()))?;

    let threshold = payload
        .get("threshold")
        .and_then(|v| v.as_u64())
        .unwrap_or(participant_keys_str.len() as u64) as usize;

    let mut participant_keys = Vec::new();
    for key_str in participant_keys_str {
        let key_str = key_str
            .as_str()
            .ok_or_else(|| AppError::InvalidPublicKey("Invalid key format".to_string()))?;
        let pubkey = key_str
            .parse()
            .map_err(|e| AppError::InvalidPublicKey(format!("Invalid public key: {}", e)))?;
        participant_keys.push(pubkey);
    }

    let wallet = TSSWallet::new(SolanaNetwork::Devnet);
    let aggregate_wallet = wallet.aggregate_keys(participant_keys, Some(threshold));

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "aggregated_public_key": aggregate_wallet.aggregated_public_key.to_string(),
        "participant_keys": aggregate_wallet.participant_keys.iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>(),
        "threshold": aggregate_wallet.threshold
    })))
}

/// Sign message endpoint
async fn sign_message(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let secret_key_hex = payload
        .get("secret_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing secret_key".to_string()))?;

    let message = payload
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing message".to_string()))?;

    let secret_key_bytes = hex_to_bytes(secret_key_hex)
        .map_err(|e| AppError::InvalidInput(format!("Invalid secret key: {}", e)))?;

    if secret_key_bytes.len() != 32 {
        return Err(AppError::InvalidInput("Secret key must be 32 bytes".to_string()).into());
    }

    let mut secret_key = [0u8; 32];
    secret_key.copy_from_slice(&secret_key_bytes);

    let mpc_keypair = mpc::MPCKeypair::from_secret_key(secret_key)
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    let signature = mpc_keypair.sign_message(message.as_bytes());

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "signature": signature.to_string(),
        "message": message
    })))
}

/// Verify signature endpoint
async fn verify_signature(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let public_key_str = payload
        .get("public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing public_key".to_string()))?;

    let signature_str = payload
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing signature".to_string()))?;

    let message = payload
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing message".to_string()))?;

    let public_key = public_key_str
        .parse()
        .map_err(|e| AppError::InvalidInput(format!("Invalid public key: {}", e)))?;

    let signature = signature_str
        .parse()
        .map_err(|e| AppError::InvalidInput(format!("Invalid signature: {}", e)))?;

    let mpc_keypair = mpc::MPCKeypair::from_public_key(public_key);
    let is_valid = mpc_keypair.verify(message.as_bytes(), &signature);

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "valid": is_valid,
        "public_key": public_key_str,
        "signature": signature_str,
        "message": message
    })))
}

/// CLI interface endpoint - equivalent to TSSCli functionality
async fn cli_generate(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let network_str = payload
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("devnet");

    let network = match network_str {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let result = cli
        .generate()
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "public_key": result.public_key,
        "secret_key": result.secret_key
    })))
}

/// CLI balance endpoint
async fn cli_balance(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let address = payload
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing address".to_string()))?;

    let network_str = payload
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("devnet");

    let network = match network_str {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let balance = cli
        .balance(address)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "balance": balance,
        "formatted_balance": TSSCli::format_balance(balance)
    })))
}

/// CLI airdrop endpoint
async fn cli_airdrop(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let address = payload
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing address".to_string()))?;

    let amount = payload
        .get("amount")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| AppError::InvalidInput("Missing amount".to_string()))?;

    let network_str = payload
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("devnet");

    let network = match network_str {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let tx_id = cli
        .airdrop(address, amount)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "transaction_id": tx_id
    })))
}

/// CLI send single endpoint
async fn cli_send_single(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let from_secret = payload
        .get("from_secret")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing from_secret".to_string()))?;

    let to = payload
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::InvalidInput("Missing to".to_string()))?;

    let amount = payload
        .get("amount")
        .and_then(|v| v.as_f64())
        .ok_or_else(|| AppError::InvalidInput("Missing amount".to_string()))?;

    let memo = payload
        .get("memo")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let network_str = payload
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("devnet");

    let network = match network_str {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let tx_id = cli
        .send_single(from_secret, to, amount, memo)
        .await
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "transaction_id": tx_id
    })))
}

/// CLI aggregate keys endpoint
async fn cli_aggregate_keys(Json(payload): Json<serde_json::Value>) -> Result<HttpResponse, Error> {
    let keys = payload
        .get("keys")
        .and_then(|v| v.as_array())
        .ok_or_else(|| AppError::InvalidInput("Missing keys".to_string()))?;

    let threshold = payload
        .get("threshold")
        .and_then(|v| v.as_u64())
        .map(|t| t as usize);

    let key_strings: Vec<String> = keys
        .iter()
        .filter_map(|v| v.as_str().map(|s| s.to_string()))
        .collect();

    let network_str = payload
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("devnet");

    let network = match network_str {
        "mainnet" => SolanaNetwork::MainnetBeta,
        "testnet" => SolanaNetwork::Testnet,
        _ => SolanaNetwork::Devnet,
    };

    let cli = TSSCli::new(network);
    let result = cli
        .aggregate_keys(&key_strings, threshold)
        .map_err(|e| AppError::InternalError(e.to_string()))?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "aggregated_public_key": result.aggregated_public_key,
        "participant_keys": result.participant_keys,
        "threshold": result.threshold
    })))
}

/// CLI help endpoint
async fn cli_help() -> Result<HttpResponse, Error> {
    let help_text = TSSCli::print_help();
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "help": help_text
    })))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting Solana MPC TSS Server...");
    println!("Server will be available at: http://localhost:8080");
    println!("CLI help available at: http://localhost:8080/cli/help");

    HttpServer::new(|| {
        App::new()
            // Health check
            .route("/health", actix_web::web::get().to(health_check))
            // MPC endpoints
            .route("/mpc/keypair", post().to(create_mpc_keypair))
            .route("/mpc/sign", post().to(sign_message))
            .route("/mpc/verify", post().to(verify_signature))
            // TSS endpoints
            .route("/tss/wallet", post().to(create_tss_wallet))
            .route("/tss/aggregate", post().to(aggregate_keys))
            // CLI endpoints (equivalent to TSSCli methods)
            .route("/cli/generate", post().to(cli_generate))
            .route("/cli/balance", post().to(cli_balance))
            .route("/cli/airdrop", post().to(cli_airdrop))
            .route("/cli/send-single", post().to(cli_send_single))
            .route("/cli/aggregate-keys", post().to(cli_aggregate_keys))
            .route("/cli/help", actix_web::web::get().to(cli_help))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
