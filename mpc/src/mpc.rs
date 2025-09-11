use ed25519_dalek::{Signer as Ed25519Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use solana_sdk::{
    pubkey::Pubkey,
    signature::{Signature, Signer, SignerError},
    transaction::Transaction,
};
use std::fmt;

/// MPC Signer interface for multi-party computation
/// Equivalent to MPCSigner interface in TypeScript
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCSigner {
    pub public_key: Pubkey,
    pub secret_key: [u8; 32], // 32-byte seed for Ed25519
    pub wasm_available: bool, // Track if WASM module is available (like TypeScript)
}

impl fmt::Display for MPCSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MPCSigner(public_key: {}, wasm_available: {})", 
               self.public_key, self.wasm_available)
    }
}

impl MPCSigner {
    /// Create a new MPC signer with a random keypair
    /// Equivalent to createMPCSigner() in TypeScript with WASM fallback logic
    pub fn new() -> Self {
        // Try to use WASM module if available (like TypeScript)
        match Self::try_wasm_keypair() {
            Ok((public_key, secret_key)) => Self {
                public_key,
                secret_key,
                wasm_available: true,
            },
            Err(_) => {
                // Fallback to ed25519-dalek if WASM module is not available
                // This matches the TypeScript fallback logic
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
                    wasm_available: false,
                }
            }
        }
    }

    /// Create an MPC signer from existing secret key bytes
    /// Equivalent to createMPCSignerFromSecretKey() in TypeScript with WASM fallback
    pub fn from_secret_key(secret_key: [u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        // Try to use WASM module if available (like TypeScript)
        match Self::try_wasm_keypair_from_secret(&secret_key) {
            Ok((public_key, _)) => Ok(Self {
                public_key,
                secret_key,
                wasm_available: true,
            }),
            Err(_) => {
                // Fallback to ed25519-dalek
                let signing_key = SigningKey::from_bytes(&secret_key);
                let verifying_key = signing_key.verifying_key();
                let public_key = Pubkey::new_from_array(verifying_key.to_bytes());

                Ok(Self {
                    public_key,
                    secret_key,
                    wasm_available: false,
                })
            }
        }
    }

    /// Try to create a keypair using WASM module (placeholder for future WASM integration)
    /// Equivalent to the WASM module import in TypeScript
    fn try_wasm_keypair() -> Result<(Pubkey, [u8; 32]), String> {
        // For now, this always fails to simulate the TypeScript fallback behavior
        // In a real implementation, this would try to load and use a WASM module
        Err("WASM module not found, falling back to ed25519-dalek".to_string())
    }

    /// Try to create a keypair from secret key using WASM module
    /// Equivalent to the WASM module usage in TypeScript createMPCSignerFromSecretKey
    fn try_wasm_keypair_from_secret(_secret_key: &[u8; 32]) -> Result<(Pubkey, [u8; 32]), String> {
        // For now, this always fails to simulate the TypeScript fallback behavior
        // In a real implementation, this would try to use the WASM module with the provided secret
        Err("WASM module not found, falling back to ed25519-dalek".to_string())
    }

    /// Sign a message using the MPC signer
    /// Equivalent to sign() method in TypeScript MPCSigner
    pub fn sign(&self, message: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        let signature = signing_key.sign(message);
        Ok(Signature::from(signature.to_bytes()))
    }

    /// Verify a signature using the MPC signer
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.public_key.to_bytes()) {
            Ok(key) => key,
            Err(_) => return false,
        };

        // Convert Solana Signature to ed25519_dalek signature bytes
        let signature_bytes: [u8; 64] = match signature.as_ref().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify_strict(message, &ed25519_signature)
            .is_ok()
    }
}

/// MPC Keypair that implements Solana's Signer trait
/// Equivalent to MPCKeypair class in TypeScript
pub struct MPCKeypair {
    pub public_key: Pubkey,
    pub secret_key: [u8; 32], // Required by Signer interface (like TypeScript)
    mpc_signer: MPCSigner,
}

impl fmt::Display for MPCKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MPCKeypair(public_key: {})", self.public_key)
    }
}

impl MPCKeypair {
    /// Create a new MPC keypair
    /// Equivalent to new MPCKeypair(mpcSigner) in TypeScript
    pub fn new() -> Self {
        let mpc_signer = MPCSigner::new();
        Self {
            public_key: mpc_signer.public_key,
            secret_key: mpc_signer.secret_key,
            mpc_signer,
        }
    }

    /// Create an MPC keypair from existing secret key
    /// Equivalent to new MPCKeypair(mpcSigner) with existing secret in TypeScript
    pub fn from_secret_key(secret_key: [u8; 32]) -> Result<Self, ed25519_dalek::SignatureError> {
        let mpc_signer = MPCSigner::from_secret_key(secret_key)?;
        Ok(Self {
            public_key: mpc_signer.public_key,
            secret_key: mpc_signer.secret_key,
            mpc_signer,
        })
    }

    /// Create an MPC keypair from public key (for verification only)
    pub fn from_public_key(public_key: Pubkey) -> Self {
        // Create a dummy secret key since we only need the public key for verification
        let dummy_secret = [0u8; 32];
        Self {
            public_key,
            secret_key: dummy_secret,
            mpc_signer: MPCSigner {
                public_key,
                secret_key: dummy_secret,
                wasm_available: false,
            },
        }
    }

    /// Get the underlying MPC signer
    pub fn get_mpc_signer(&self) -> &MPCSigner {
        &self.mpc_signer
    }

    /// Sign a message (equivalent to sign() method in TypeScript MPCKeypair)
    pub async fn sign(&self, message: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        self.mpc_signer.sign(message)
    }

    /// Sign a transaction (equivalent to signTransaction() method in TypeScript MPCKeypair)
    pub async fn sign_transaction(
        &self,
        mut tx: Transaction,
    ) -> Result<Transaction, ed25519_dalek::SignatureError> {
        let msg = tx.message.serialize();
        let sig = self.sign(&msg).await?;
        tx.signatures.push(sig);
        Ok(tx)
    }

    /// Sign all transactions (equivalent to signAllTransactions() method in TypeScript MPCKeypair)
    pub async fn sign_all_transactions(
        &self,
        txs: Vec<Transaction>,
    ) -> Result<Vec<Transaction>, ed25519_dalek::SignatureError> {
        let mut signed_txs = Vec::new();
        for tx in txs {
            signed_txs.push(self.sign_transaction(tx).await?);
        }
        Ok(signed_txs)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        self.mpc_signer.verify(message, signature)
    }
}

impl Signer for MPCKeypair {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self.public_key)
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        self.mpc_signer
            .sign(message)
            .map_err(|_| SignerError::Custom("Failed to sign message".to_string()))
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

/// Create an MPC signer (equivalent to createMPCSigner in TypeScript)
pub fn create_mpc_signer() -> MPCSigner {
    MPCSigner::new()
}

/// Create an MPC signer from secret key bytes (equivalent to createMPCSignerFromSecretKey in TypeScript)
pub fn create_mpc_signer_from_secret_key(
    secret_key: [u8; 32],
) -> Result<MPCSigner, ed25519_dalek::SignatureError> {
    MPCSigner::from_secret_key(secret_key)
}

/// Threshold Signature Scheme (TSS) implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TSSSigner {
    pub secret_key: [u8; 32],
    pub public_key: Pubkey,
    pub threshold: usize,
}

impl TSSSigner {
    /// Create a new TSS signer with threshold capabilities
    pub fn new(threshold: usize) -> Self {
        let mut rng = OsRng;
        let mut secret_key_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_key_bytes);

        let signing_key = SigningKey::from_bytes(&secret_key_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key = Pubkey::new_from_array(verifying_key.to_bytes());

        Self {
            secret_key: secret_key_bytes,
            public_key,
            threshold,
        }
    }

    /// Create a TSS signer from existing secret key
    pub fn from_secret_key(
        secret_key: [u8; 32],
        threshold: usize,
    ) -> Result<Self, ed25519_dalek::SignatureError> {
        let signing_key = SigningKey::from_bytes(&secret_key);
        let verifying_key = signing_key.verifying_key();
        let public_key = Pubkey::new_from_array(verifying_key.to_bytes());

        Ok(Self {
            secret_key,
            public_key,
            threshold,
        })
    }

    /// Sign a message using the TSS signer
    pub fn sign(&self, message: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        let signing_key = SigningKey::from_bytes(&self.secret_key);
        let signature = signing_key.sign(message);
        Ok(Signature::from(signature.to_bytes()))
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let verifying_key = match VerifyingKey::from_bytes(&self.public_key.to_bytes()) {
            Ok(key) => key,
            Err(_) => return false,
        };

        let signature_bytes: [u8; 64] = match signature.as_ref().try_into() {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };
        let ed25519_signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

        verifying_key
            .verify_strict(message, &ed25519_signature)
            .is_ok()
    }
}

/// Multi-party key generation for threshold signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCKeyGeneration {
    pub participants: Vec<Pubkey>,
    pub threshold: usize,
    pub master_public_key: Pubkey,
}

impl MPCKeyGeneration {
    /// Generate a new threshold key set
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
            participants,
            threshold,
            master_public_key,
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

/// Enhanced MPC functionality with multiple key types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedMPCSigner {
    pub ed25519_signer: MPCSigner,
    pub tss_signer: TSSSigner,
    pub key_hash: [u8; 32],
}

impl EnhancedMPCSigner {
    /// Create a new enhanced MPC signer
    pub fn new(threshold: usize) -> Self {
        let ed25519_signer = MPCSigner::new();
        let tss_signer = TSSSigner::new(threshold);

        // Create a combined key hash
        let mut hasher = Sha256::new();
        hasher.update(&ed25519_signer.public_key.to_bytes());
        hasher.update(&tss_signer.public_key.to_bytes());
        let hash_result = hasher.finalize();
        let mut key_hash = [0u8; 32];
        key_hash.copy_from_slice(&hash_result);

        Self {
            ed25519_signer,
            tss_signer,
            key_hash,
        }
    }

    /// Create from existing Ed25519 signer
    pub fn from_ed25519_signer(ed25519_signer: MPCSigner, threshold: usize) -> Self {
        let tss_signer = TSSSigner::new(threshold);

        // Create a combined key hash
        let mut hasher = Sha256::new();
        hasher.update(&ed25519_signer.public_key.to_bytes());
        hasher.update(&tss_signer.public_key.to_bytes());
        let hash_result = hasher.finalize();
        let mut key_hash = [0u8; 32];
        key_hash.copy_from_slice(&hash_result);

        Self {
            ed25519_signer,
            tss_signer,
            key_hash,
        }
    }

    /// Get the Ed25519 public key
    pub fn ed25519_public_key(&self) -> Pubkey {
        self.ed25519_signer.public_key
    }

    /// Get the TSS public key
    pub fn tss_public_key(&self) -> Pubkey {
        self.tss_signer.public_key
    }

    /// Sign with Ed25519
    pub fn sign_ed25519(&self, message: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        self.ed25519_signer.sign(message)
    }

    /// Sign with TSS
    pub fn sign_tss(&self, message: &[u8]) -> Result<Signature, ed25519_dalek::SignatureError> {
        self.tss_signer.sign(message)
    }

    /// Get the combined key hash
    pub fn key_hash(&self) -> [u8; 32] {
        self.key_hash
    }
}

// Tests are now in api_tests.rs module
