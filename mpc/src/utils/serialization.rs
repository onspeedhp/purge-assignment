use crate::error::Error;
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;

/// Request/Response types for API endpoints

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeypairRequest {
    pub network: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenerateKeypairResponse {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendSingleRequest {
    pub from_secret_key: String,
    pub to: String,
    pub amount: f64,
    pub memo: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendSingleResponse {
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateKeysRequest {
    pub participant_keys: Vec<String>,
    pub threshold: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateKeysResponse {
    pub aggregated_public_key: String,
    pub participant_keys: Vec<String>,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepOneRequest {
    pub participant_secret_key: String,
    pub transaction_details: TSSTransactionDetailsRequest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepOneResponse {
    pub secret_nonce: String,
    pub public_nonce: String,
    pub participant_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepTwoRequest {
    pub step_one_data: AggSignStepOneResponse,
    pub participant_secret_key: String,
    pub transaction_details: TSSTransactionDetailsRequest,
    pub all_public_nonces: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepTwoResponse {
    pub partial_signature: String,
    pub public_nonce: String,
    pub participant_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSignaturesRequest {
    pub partial_signatures: Vec<AggSignStepTwoResponse>,
    pub transaction_details: TSSTransactionDetailsRequest,
    pub aggregate_wallet: AggregateKeysResponse,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateSignaturesResponse {
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TSSTransactionDetailsRequest {
    pub amount: f64,
    pub to: String,
    pub from: String,
    pub network: String,
    pub memo: Option<String>,
    pub recent_blockhash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceRequest {
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceResponse {
    pub balance: f64,
    pub formatted_balance: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirdropRequest {
    pub public_key: String,
    pub amount: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirdropResponse {
    pub transaction_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecentBlockhashResponse {
    pub recent_blockhash: String,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl From<Error> for ErrorResponse {
    fn from(err: Error) -> Self {
        Self {
            error: format!("{:?}", err),
            message: err.to_string(),
        }
    }
}

/// Helper functions for converting between string and byte representations

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, Error> {
    hex::decode(hex_str).map_err(|e| Error::SerializationError(e.to_string()))
}

pub fn pubkey_to_string(pubkey: &Pubkey) -> String {
    pubkey.to_string()
}

pub fn string_to_pubkey(s: &str) -> Result<Pubkey, Error> {
    s.parse()
        .map_err(|_| Error::InvalidPublicKey(s.to_string()))
}

pub fn bytes_to_base58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

pub fn base58_to_bytes(s: &str) -> Result<Vec<u8>, Error> {
    bs58::decode(s).into_vec().map_err(Error::from)
}
