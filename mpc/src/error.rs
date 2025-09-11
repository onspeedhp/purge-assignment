use std::fmt::{Display, Formatter};

use bs58::decode::Error as Bs58Error;
use ed25519_dalek::SignatureError;
use solana_client::client_error::ClientError;

#[derive(Debug)]
pub enum Error {
    WrongNetwork(String),
    BadBase58(Bs58Error),
    WrongKeyPair(SignatureError),
    AirdropFailed(ClientError),
    RecentHashFailed(ClientError),
    ConfirmingTransactionFailed(ClientError),
    BalaceFailed(ClientError),
    SendTransactionFailed(ClientError),
    MismatchMessages,
    InvalidSignature,
    KeyPairIsNotInKeys,
    InvalidPublicKey(String),
    InsufficientSignatures { provided: usize, required: usize },
    InvalidTransaction(String),
    NetworkError(String),
    SerializationError(String),
    InvalidInput(String),
    InternalError(String),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongNetwork(net) => write!(
                f,
                "Unrecognized network: {}, please select Mainnet/Testnet/Devnet",
                net
            ),
            Self::BadBase58(e) => write!(f, "Base58 Error: {}", e),
            Self::WrongKeyPair(e) => write!(f, "Failed deserializing keypair: {}", e),
            Self::AirdropFailed(e) => write!(f, "Failed asking for an airdrop: {}", e),
            Self::RecentHashFailed(e) => write!(f, "Failed receiving the latest hash: {}", e),
            Self::ConfirmingTransactionFailed(e) => {
                write!(f, "Failed confirming transaction: {}", e)
            }
            Self::BalaceFailed(e) => write!(f, "Failed checking balance: {}", e),
            Self::SendTransactionFailed(e) => write!(f, "Failed sending transaction: {}", e),
            Self::MismatchMessages => write!(
                f,
                "There is a mismatch between first_messages and second_messages"
            ),
            Self::InvalidSignature => {
                write!(f, "The resulting signature doesn't match the transaction")
            }
            Self::KeyPairIsNotInKeys => {
                write!(f, "The provided keypair is not in the list of pubkeys")
            }
            Self::InvalidPublicKey(key) => write!(f, "Invalid public key format: {}", key),
            Self::InsufficientSignatures { provided, required } => {
                write!(f, "Insufficient signatures: {}/{}", provided, required)
            }
            Self::InvalidTransaction(msg) => write!(f, "Invalid transaction: {}", msg),
            Self::NetworkError(msg) => write!(f, "Network error: {}", msg),
            Self::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            Self::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            Self::InternalError(msg) => write!(f, "Internal error: {}", msg),
        }
    }
}

impl From<Bs58Error> for Error {
    fn from(e: Bs58Error) -> Self {
        Self::BadBase58(e)
    }
}

impl From<SignatureError> for Error {
    fn from(e: SignatureError) -> Self {
        Self::WrongKeyPair(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(e: std::str::Utf8Error) -> Self {
        Self::SerializationError(e.to_string())
    }
}

impl std::error::Error for Error {}

impl From<Error> for actix_web::Error {
    fn from(err: Error) -> Self {
        actix_web::Error::from(Box::new(err) as Box<dyn std::error::Error>)
    }
}
