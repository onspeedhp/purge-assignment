//! # Solana Integration for FROST MPC
//!
//! This module provides Solana-specific functionality for keypair generation
//! and transaction signing using FROST Ed25519 threshold signatures.

use frost_ed25519 as frost;
use solana_sdk::{
    hash::Hash, instruction::Instruction, message::Message, pubkey::Pubkey, signature::Signature,
    system_instruction, transaction::Transaction,
};
use std::collections::BTreeMap;

use crate::error::Error as AppError;

/// Solana keypair generated using FROST Ed25519
#[derive(Debug, Clone)]
pub struct SolanaFrostKeypair {
    pub pubkey: Pubkey,
    pub frost_pubkey_package: frost::keys::PublicKeyPackage,
    pub frost_key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
}

impl SolanaFrostKeypair {
    /// Create a new Solana keypair from FROST key generation result
    pub fn from_frost_result(
        frost_result: &crate::distributed_mpc::DistributedKeygenResult,
    ) -> Result<Self, AppError> {
        // Convert the FROST group public key to Solana Pubkey
        let pubkey = Pubkey::try_from(frost_result.group_public_key.as_slice())
            .map_err(|e| AppError::InternalError(format!("Invalid Solana pubkey: {}", e)))?;

        Ok(Self {
            pubkey,
            frost_pubkey_package: frost_result.pubkey_package.clone(),
            frost_key_packages: frost_result.key_packages.clone(),
        })
    }

    /// Get the Solana public key
    pub fn pubkey(&self) -> &Pubkey {
        &self.pubkey
    }

    /// Get the FROST public key package for signing
    pub fn frost_pubkey_package(&self) -> &frost::keys::PublicKeyPackage {
        &self.frost_pubkey_package
    }
}

/// Solana transaction signing result using FROST MPC
#[derive(Debug, Clone)]
pub struct SolanaFrostSigningResult {
    pub transaction: Transaction,
    pub signature: Signature,
    pub is_valid: bool,
}

/// Solana MPC client for transaction signing
pub struct SolanaMPCClient {
    pub distributed_mpc: crate::distributed_mpc::DistributedMPC,
}

impl SolanaMPCClient {
    /// Create a new Solana MPC client
    pub fn new() -> Self {
        Self {
            distributed_mpc: crate::distributed_mpc::DistributedMPC::new(),
        }
    }

    /// Generate a Solana keypair using FROST MPC
    pub async fn generate_solana_keypair(
        &mut self,
        user_id: &str,
        threshold: u16,
    ) -> Result<SolanaFrostKeypair, AppError> {
        println!(
            "Generating Solana keypair using FROST MPC for user '{}'...",
            user_id
        );

        // Generate FROST key shares
        let frost_result = self
            .distributed_mpc
            .generate_key_shares(user_id, threshold)
            .await?;

        // Convert to Solana keypair
        let solana_keypair = SolanaFrostKeypair::from_frost_result(&frost_result)?;

        println!(
            "✅ Solana keypair generated! Public key: {}",
            solana_keypair.pubkey()
        );

        Ok(solana_keypair)
    }

    /// Sign a Solana transaction using FROST MPC
    pub async fn sign_solana_transaction(
        &self,
        user_id: &str,
        _keypair: &SolanaFrostKeypair,
        transaction: &Transaction,
        session_id: &str,
    ) -> Result<SolanaFrostSigningResult, AppError> {
        println!(
            "Signing Solana transaction using FROST MPC for user '{}'...",
            user_id
        );

        // Serialize the transaction message for signing
        let message_bytes = bincode::serialize(&transaction.message).map_err(|e| {
            AppError::InternalError(format!("Failed to serialize transaction: {}", e))
        })?;

        // Sign using FROST MPC
        let frost_result = self
            .distributed_mpc
            .sign_message(user_id, &message_bytes, session_id)
            .await?;

        // Convert FROST signature to Solana signature
        let signature = Signature::try_from(frost_result.signature.as_slice())
            .map_err(|e| AppError::InternalError(format!("Invalid Solana signature: {}", e)))?;

        // Create a new transaction with the signature
        let mut signed_transaction = transaction.clone();
        signed_transaction.signatures = vec![signature];

        println!("✅ Solana transaction signed! Signature: {}", signature);

        Ok(SolanaFrostSigningResult {
            transaction: signed_transaction,
            signature,
            is_valid: frost_result.is_valid,
        })
    }

    /// Create a simple transfer transaction
    pub fn create_transfer_transaction(
        from_pubkey: &Pubkey,
        to_pubkey: &Pubkey,
        lamports: u64,
    ) -> Transaction {
        let instruction = system_instruction::transfer(from_pubkey, to_pubkey, lamports);
        let message = Message::new(&[instruction], Some(from_pubkey));
        Transaction {
            signatures: vec![],
            message,
        }
    }

    /// Create a simple instruction transaction
    pub fn create_instruction_transaction(
        payer: &Pubkey,
        instructions: Vec<Instruction>,
    ) -> Transaction {
        let message = Message::new(&instructions, Some(payer));
        Transaction {
            signatures: vec![],
            message,
        }
    }
}

/// Example usage for Solana MPC integration
pub async fn solana_mpc_example() -> Result<(), AppError> {
    println!("=== Solana FROST MPC Example ===");

    // Create Solana MPC client
    let mut solana_mpc = SolanaMPCClient::new();

    // User ID for this example
    let user_id = "solana_user_123";

    // Step 1: Generate Solana keypair using FROST MPC
    let keypair = solana_mpc
        .generate_solana_keypair(user_id, 2) // 2 out of 3 threshold
        .await?;

    println!("Generated Solana keypair: {}", keypair.pubkey());

    // Step 2: Create a simple transfer transaction
    let to_pubkey = Pubkey::new_unique();
    let _recent_blockhash = Hash::new_unique();
    let transaction = SolanaMPCClient::create_transfer_transaction(
        keypair.pubkey(),
        &to_pubkey,
        1_000_000, // 0.001 SOL
    );

    println!("Created transfer transaction to: {}", to_pubkey);

    // Step 3: Sign the transaction using FROST MPC
    let session_id = "solana_session_123";
    let signing_result = solana_mpc
        .sign_solana_transaction(user_id, &keypair, &transaction, session_id)
        .await?;

    println!("Transaction signed: {}", signing_result.signature);
    println!("Signature valid: {}", signing_result.is_valid);

    if signing_result.is_valid {
        println!("✅ Solana MPC transaction signing successful!");
    } else {
        println!("❌ Solana MPC transaction signing failed!");
    }

    Ok(())
}
