//! # Solana Integration Module
//! 
//! This module contains all Solana blockchain integration functionality:
//! - Transaction creation and management
//! - RPC client operations
//! - Solana-specific utilities

pub mod transaction;
pub mod client;

// Re-export for convenience
pub use transaction::*;
pub use client::AsyncRpcClient;
