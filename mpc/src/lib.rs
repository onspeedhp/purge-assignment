//! # Solana MPC TSS Library
//!
//! A comprehensive Rust library for Solana Multi-Party Computation (MPC) and
//! Threshold Signature Schemes (TSS) - converted from TypeScript.
//!
//! ## Features
//! - Multi-Party Computation (MPC) key generation and signing
//! - Threshold Signature Schemes (TSS) for distributed signing
//! - Solana blockchain integration with real transaction support
//! - Local validator testing capabilities
//! - Comprehensive error handling and validation
//!
//! ## Quick Start
//!
//! ```rust
//! use solana_mpc_tss::{
//!     MPCKeypair, TSSWallet, TSSSigningService, SolanaNetwork
//! };
//!
//! // Create an MPC keypair
//! let mpc_keypair = MPCKeypair::new();
//!
//! // Create a TSS wallet
//! let wallet = TSSWallet::new(SolanaNetwork::Devnet);
//!
//! // Generate a keypair
//! let keypair = wallet.generate_keypair().unwrap();
//! ```

// Core modules
pub mod error;
pub mod mpc;
pub mod solana;
pub mod tss;
pub mod utils;

// MPC Core functionality - equivalent to TypeScript exports
pub use mpc::{
    create_mpc_signer, create_mpc_signer_from_secret_key, MPCKeypair, MPCSigner, TSSSigner,
};

// Solana utilities - equivalent to TypeScript exports
pub use solana::{
    client::AsyncRpcClient,
    transaction::{
        create_transaction_from_details, create_transfer_tx, create_transfer_tx_with_memo,
        format_balance, lamports_to_sol, sol_to_lamports, validate_public_key,
    },
};

// TSS functionality - equivalent to TypeScript exports
pub use tss::{
    cli::TSSCli,
    signing::TSSSigningService,
    types::{
        AggSignStepOneData, AggSignStepTwoData, AggregateWallet, AggregatedThresholdSignature,
        CompleteSignature, EnhancedTSSKeypair, MPCSession, MPCSessionStatus, PartialSignature,
        SolanaNetwork, TSSConfig, TSSKeypair, TSSTransactionDetails, ThresholdSignatureShare,
    },
    wallet::TSSWallet,
};

// Re-export commonly used types - equivalent to TypeScript re-exports
pub use solana_sdk::{pubkey::Pubkey, signature::Signature, transaction::Transaction};

// Utility functions
pub use utils::serialization::{
    base58_to_bytes, bytes_to_base58, bytes_to_hex, hex_to_bytes, pubkey_to_string,
    string_to_pubkey,
};
