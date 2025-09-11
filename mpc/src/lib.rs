//! # FROST MPC Library
//!
//! A simple FROST-ed25519 Multi-Party Computation library that follows the README exactly,
//! designed for distributed threshold signing across multiple servers.
//!
//! ## Features
//! - FROST-ed25519 threshold signature scheme
//! - Multi-Party Computation (MPC) key generation and signing
//! - Distributed signing across 3 MPC servers
//! - Follows FROST-ed25519 README pattern exactly
//!
//! ## Quick Start
//!
//! ```rust
//! use frost_mpc::distributed_mpc::{DistributedMPC, distributed_frost_example};
//!
//! // Run the FROST example
//! distributed_frost_example().await?;
//! ```

// Core modules
pub mod database;
pub mod distributed_mpc;
pub mod error;
pub mod solana;

// Re-export commonly used types
pub use distributed_mpc::{distributed_frost_example, DistributedMPC};
pub use solana::{solana_mpc_example, SolanaFrostKeypair, SolanaMPCClient};
