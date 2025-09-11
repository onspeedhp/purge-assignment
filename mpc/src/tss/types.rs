use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use solana_sdk::pubkey::Pubkey;

/// Network configuration for Solana TSS operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Copy)]
pub enum SolanaNetwork {
    #[serde(rename = "mainnet-beta")]
    MainnetBeta,
    #[serde(rename = "devnet")]
    Devnet,
    #[serde(rename = "testnet")]
    Testnet,
}

impl SolanaNetwork {
    /// Get the RPC URL for the network
    pub fn rpc_url(&self) -> &'static str {
        match self {
            SolanaNetwork::MainnetBeta => "https://api.mainnet-beta.solana.com",
            SolanaNetwork::Devnet => "https://api.devnet.solana.com",
            SolanaNetwork::Testnet => "https://api.testnet.solana.com",
        }
    }

    /// Get the WebSocket URL for the network
    pub fn ws_url(&self) -> &'static str {
        match self {
            SolanaNetwork::MainnetBeta => "wss://api.mainnet-beta.solana.com",
            SolanaNetwork::Devnet => "wss://api.devnet.solana.com",
            SolanaNetwork::Testnet => "wss://api.testnet.solana.com",
        }
    }
}

impl Default for SolanaNetwork {
    fn default() -> Self {
        SolanaNetwork::Devnet
    }
}

/// TSS Keypair structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TSSKeypair {
    pub public_key: Pubkey,
    pub secret_key: [u8; 32],
}

impl TSSKeypair {
    /// Create a new TSS keypair
    pub fn new() -> Self {
        use ed25519_dalek::SigningKey;

        let mut rng = OsRng;
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);
        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key = Pubkey::new_from_array(verifying_key.to_bytes());
        let secret_key = signing_key.to_bytes();

        Self {
            public_key,
            secret_key,
        }
    }

    /// Create a TSS keypair from existing secret key
    pub fn from_secret_key(secret_key: [u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        let public_key = Pubkey::new_from_array(verifying_key.to_bytes());

        Ok(Self {
            public_key,
            secret_key,
        })
    }
}

/// Partial signature for TSS aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialSignature {
    pub signer: Pubkey,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; 32],
}

/// TSS wallet aggregate data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateWallet {
    pub aggregated_public_key: Pubkey,
    pub participant_keys: Vec<Pubkey>,
    pub threshold: usize,
}

impl AggregateWallet {
    /// Create a new aggregate wallet
    pub fn new(participant_keys: Vec<Pubkey>, threshold: Option<usize>) -> Self {
        let threshold = threshold.unwrap_or(participant_keys.len());
        let aggregated_public_key = Self::combine_public_keys(&participant_keys);

        Self {
            aggregated_public_key,
            participant_keys,
            threshold,
        }
    }

    /// Combine multiple public keys into a single multisig address
    /// This is a simplified implementation - in production, this would use proper TSS key aggregation
    fn combine_public_keys(keys: &[Pubkey]) -> Pubkey {
        if keys.is_empty() {
            panic!("Cannot aggregate empty key list");
        }

        if keys.len() == 1 {
            return keys[0];
        }

        // Simple XOR aggregation for demo - replace with proper TSS aggregation
        let mut combined = [0u8; 32];
        for key in keys {
            let key_bytes = key.to_bytes();
            for i in 0..32 {
                combined[i] ^= key_bytes[i];
            }
        }

        Pubkey::new_from_array(combined)
    }
}

/// Step 1 data for aggregate signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepOneData {
    pub secret_nonce: [u8; 32],
    pub public_nonce: [u8; 32],
    pub participant_key: Pubkey,
}

/// Step 2 data for aggregate signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepTwoData {
    #[serde(with = "serde_bytes")]
    pub partial_signature: [u8; 64],
    #[serde(with = "serde_bytes")]
    pub public_nonce: [u8; 32],
    pub participant_key: Pubkey,
}

/// Transaction details for TSS signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TSSTransactionDetails {
    pub amount: f64, // in SOL
    pub to: Pubkey,
    pub from: Pubkey,
    pub network: SolanaNetwork,
    pub memo: Option<String>,
    pub recent_blockhash: String,
}

/// Complete TSS signature ready for broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteSignature {
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    pub public_key: Pubkey,
    pub transaction: Vec<u8>,
}

/// Enhanced TSS keypair with threshold capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedTSSKeypair {
    pub public_key: Pubkey,
    pub secret_key: [u8; 32],
    pub threshold: usize,
    pub key_hash: [u8; 32],
}

impl EnhancedTSSKeypair {
    /// Create a new enhanced TSS keypair
    pub fn new(threshold: usize) -> Self {
        let mut rng = OsRng;
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key = Pubkey::new_from_array(verifying_key.to_bytes());

        // Create a key hash for identification
        let mut hasher = sha2::Sha256::new();
        hasher.update(&public_key.to_bytes());
        hasher.update(&secret_key_bytes);
        let hash_result = hasher.finalize();
        let mut key_hash = [0u8; 32];
        key_hash.copy_from_slice(&hash_result);

        Self {
            public_key,
            secret_key: secret_key_bytes,
            threshold,
            key_hash,
        }
    }

    /// Create from existing secret key
    pub fn from_secret_key(
        secret_key: [u8; 32],
        threshold: usize,
    ) -> Result<Self, ed25519_dalek::SignatureError> {
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        let public_key = Pubkey::new_from_array(verifying_key.to_bytes());

        // Create a key hash for identification
        let mut hasher = sha2::Sha256::new();
        hasher.update(&public_key.to_bytes());
        hasher.update(&secret_key);
        let hash_result = hasher.finalize();
        let mut key_hash = [0u8; 32];
        key_hash.copy_from_slice(&hash_result);

        Ok(Self {
            public_key,
            secret_key,
            threshold,
            key_hash,
        })
    }
}

/// Multi-party threshold signature scheme configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TSSConfig {
    pub threshold: usize,
    pub total_participants: usize,
    pub master_public_key: Pubkey,
    pub participants: Vec<Pubkey>,
}

impl TSSConfig {
    /// Create a new TSS configuration
    pub fn new(participants: Vec<Pubkey>, threshold: usize) -> Self {
        // Simple key aggregation - XOR all participant keys
        let mut master_key_bytes = [0u8; 32];
        for participant in &participants {
            let key_bytes = participant.to_bytes();
            for i in 0..32 {
                master_key_bytes[i] ^= key_bytes[i];
            }
        }
        let master_public_key = Pubkey::new_from_array(master_key_bytes);

        Self {
            threshold,
            total_participants: participants.len(),
            master_public_key,
            participants,
        }
    }

    /// Get the master public key
    pub fn master_public_key(&self) -> Pubkey {
        self.master_public_key
    }

    /// Check if we have enough participants for threshold
    pub fn has_sufficient_participants(&self, count: usize) -> bool {
        count >= self.threshold
    }
}

/// Threshold signature share from a participant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdSignatureShare {
    pub participant_index: usize,
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    pub public_key: Pubkey,
}

/// Aggregated threshold signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedThresholdSignature {
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
    pub master_public_key: Pubkey,
    pub participant_count: usize,
    pub threshold: usize,
}

impl AggregatedThresholdSignature {
    /// Verify the aggregated signature
    pub fn verify(&self, message: &[u8]) -> bool {
        // Simple verification - in production, this would use proper threshold signature verification
        let verifying_key = match VerifyingKey::from_bytes(&self.master_public_key.to_bytes()) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&self.signature);

        verifying_key
            .verify_strict(message, &ed25519_signature)
            .is_ok()
    }
}

/// Multi-party computation session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCSession {
    pub session_id: String,
    pub participants: Vec<Pubkey>,
    pub threshold: usize,
    pub status: MPCSessionStatus,
    pub tss_config: TSSConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum MPCSessionStatus {
    Initializing,
    KeyGeneration,
    Ready,
    Signing,
    Completed,
    Failed,
}

impl MPCSession {
    /// Create a new MPC session
    pub fn new(session_id: String, participants: Vec<Pubkey>, threshold: usize) -> Self {
        let tss_config = TSSConfig::new(participants.clone(), threshold);

        Self {
            session_id,
            participants,
            threshold,
            status: MPCSessionStatus::Initializing,
            tss_config,
        }
    }

    /// Check if the session is ready for signing
    pub fn is_ready(&self) -> bool {
        self.status == MPCSessionStatus::Ready
    }

    /// Update session status
    pub fn update_status(&mut self, status: MPCSessionStatus) {
        self.status = status;
    }
}

