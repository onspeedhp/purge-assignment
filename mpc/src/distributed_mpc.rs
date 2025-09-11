//! # Distributed MPC Operations
//!
//! This module handles distributed FROST operations across multiple MPC servers.
//! It provides the core logic for coordinating key generation and signing across
//! the 3 MPC servers, following the FROST-ed25519 README pattern exactly.

use frost_ed25519 as frost;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::Error as AppError;

/// Configuration for MPC servers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MPCServerConfig {
    pub id: u16,
    pub host: String,
    pub port: u16,
}

/// Client for communicating with individual MPC servers
pub struct MPCServerClient {
    pub config: MPCServerConfig,
    pub client: reqwest::Client,
}

impl MPCServerClient {
    pub fn new(config: MPCServerConfig) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    /// Send key generation request to MPC server
    pub async fn send_keygen_request(
        &self,
        user_id: &str,
        threshold: u16,
        total_signers: u16,
    ) -> Result<FrostKeygenResponse, AppError> {
        let url = format!(
            "http://{}:{}/frost/keygen",
            self.config.host, self.config.port
        );
        let request = FrostKeygenRequest {
            user_id: user_id.to_string(),
            threshold,
            total_signers,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?;

        if response.status().is_success() {
            let keygen_response: FrostKeygenResponse = response
                .json()
                .await
                .map_err(|e| AppError::InternalError(e.to_string()))?;
            Ok(keygen_response)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(AppError::InternalError(format!(
                "Server error: {}",
                error_text
            )))
        }
    }

    /// Send Round 1 request to MPC server
    pub async fn send_round1_request(
        &self,
        user_id: &str,
        session_id: &str,
    ) -> Result<FrostRound1Response, AppError> {
        let url = format!(
            "http://{}:{}/frost/round1",
            self.config.host, self.config.port
        );
        let request = FrostRound1Request {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?;

        if response.status().is_success() {
            let round1_response: FrostRound1Response = response
                .json()
                .await
                .map_err(|e| AppError::InternalError(e.to_string()))?;
            Ok(round1_response)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(AppError::InternalError(format!(
                "Server error: {}",
                error_text
            )))
        }
    }

    /// Send Round 2 request to MPC server
    pub async fn send_round2_request(
        &self,
        user_id: &str,
        session_id: &str,
        signing_package: &frost::SigningPackage,
        message_hex: &str,
    ) -> Result<FrostRound2Response, AppError> {
        let url = format!(
            "http://{}:{}/frost/round2",
            self.config.host, self.config.port
        );
        let request = FrostRound2Request {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            signing_package: serde_json::to_value(signing_package)
                .map_err(|e| AppError::InternalError(e.to_string()))?,
            message_hex: message_hex.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?;

        if response.status().is_success() {
            let round2_response: FrostRound2Response = response
                .json()
                .await
                .map_err(|e| AppError::InternalError(e.to_string()))?;
            Ok(round2_response)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(AppError::InternalError(format!(
                "Server error: {}",
                error_text
            )))
        }
    }

    /// Send key generation request with specific key package to MPC server
    pub async fn send_keygen_with_package_request(
        &self,
        user_id: &str,
        threshold: u16,
        total_signers: u16,
        key_package_json: &str,
        public_key: &str,
    ) -> Result<FrostKeygenResponse, AppError> {
        let url = format!(
            "http://{}:{}/frost/keygen-with-package",
            self.config.host, self.config.port
        );
        let request = FrostKeygenWithPackageRequest {
            user_id: user_id.to_string(),
            threshold,
            total_signers,
            key_package_json: key_package_json.to_string(),
            public_key: public_key.to_string(),
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?;

        if response.status().is_success() {
            let keygen_response: FrostKeygenResponse = response
                .json()
                .await
                .map_err(|e| AppError::InternalError(e.to_string()))?;
            Ok(keygen_response)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(AppError::InternalError(format!(
                "Server error: {}",
                error_text
            )))
        }
    }

    /// Get key share by user ID from MPC server
    pub async fn get_key_share_by_user_id(&self, user_id: &str) -> Result<crate::database::KeyShare, AppError> {
        let url = format!(
            "http://{}:{}/frost/key-share/{}",
            self.config.host, self.config.port, user_id
        );

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?;

        if response.status().is_success() {
            let key_share: crate::database::KeyShare = response
                .json()
                .await
                .map_err(|e| AppError::InternalError(e.to_string()))?;
            Ok(key_share)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(AppError::InternalError(format!(
                "Server error: {}",
                error_text
            )))
        }
    }

    /// Send aggregate request to MPC server
    pub async fn send_aggregate_request(
        &self,
        user_id: &str,
        session_id: &str,
        signing_package: &frost::SigningPackage,
        signature_shares: &BTreeMap<frost::Identifier, frost::round2::SignatureShare>,
        pubkey_package: &frost::keys::PublicKeyPackage,
    ) -> Result<FrostAggregateResponse, AppError> {
        let url = format!(
            "http://{}:{}/frost/aggregate",
            self.config.host, self.config.port
        );
        let request = FrostAggregateRequest {
            user_id: user_id.to_string(),
            session_id: session_id.to_string(),
            signing_package: serde_json::to_value(signing_package)
                .map_err(|e| AppError::InternalError(e.to_string()))?,
            signature_shares: serde_json::to_value(signature_shares)
                .map_err(|e| AppError::InternalError(e.to_string()))?,
            pubkey_package: serde_json::to_value(pubkey_package)
                .map_err(|e| AppError::InternalError(e.to_string()))?,
        };

        let response = self
            .client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::InternalError(e.to_string()))?;

        if response.status().is_success() {
            let aggregate_response: FrostAggregateResponse = response
                .json()
                .await
                .map_err(|e| AppError::InternalError(e.to_string()))?;
            Ok(aggregate_response)
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(AppError::InternalError(format!(
                "Server error: {}",
                error_text
            )))
        }
    }
}

/// Distributed MPC coordinator that manages 3 MPC servers
pub struct DistributedMPC {
    server_clients: Vec<MPCServerClient>,
    pubkey_package: Option<frost::keys::PublicKeyPackage>,
    threshold: Option<u16>,
}

impl DistributedMPC {
    /// Create a new distributed MPC coordinator
    pub fn new() -> Self {
        let server_configs = vec![
            MPCServerConfig {
                id: 1,
                host: "127.0.0.1".to_string(),
                port: 8081,
            },
            MPCServerConfig {
                id: 2,
                host: "127.0.0.1".to_string(),
                port: 8082,
            },
            MPCServerConfig {
                id: 3,
                host: "127.0.0.1".to_string(),
                port: 8083,
            },
        ];

        let server_clients: Vec<MPCServerClient> = server_configs
            .iter()
            .map(|config| MPCServerClient::new(config.clone()))
            .collect();

        Self {
            server_clients,
            pubkey_package: None,
            threshold: None,
        }
    }

    /// Generate FROST key shares using trusted dealer and distribute across MPC servers
    /// This follows the FROST-ed25519 README pattern exactly
    pub async fn generate_key_shares(
        &mut self,
        user_id: &str,
        threshold: u16,
    ) -> Result<DistributedKeygenResult, AppError> {
        println!(
            "Step 1: Generating key shares with trusted dealer for user '{}'...",
            user_id
        );
        println!("  This will create ONE coordinated key generation and distribute shares to 3 MPC servers");

        // Check if user already has key shares - if so, retrieve them
        let mut existing_key_packages = BTreeMap::new();
        let mut all_servers_have_keys = true;
        
        for (i, client) in self.server_clients.iter().enumerate() {
            let server_user_id = format!("{}_mpc_server_{}", user_id, i + 1);
            match client.get_key_share_by_user_id(&server_user_id).await {
                Ok(key_share) => {
                    println!("  Found existing key share for server {} (user: {})", i + 1, server_user_id);
                    // Parse the key package from the stored private key
                    let key_package: frost::keys::KeyPackage = serde_json::from_str(&key_share.private_key)
                        .map_err(|e| AppError::InternalError(format!("Failed to deserialize key package: {}", e)))?;
                    existing_key_packages.insert(*key_package.identifier(), key_package);
                }
                Err(_) => {
                    println!("  No existing key share found for server {} (user: {})", i + 1, server_user_id);
                    all_servers_have_keys = false;
                }
            }
        }

        if all_servers_have_keys && existing_key_packages.len() >= threshold as usize {
            println!("  ✅ User '{}' already has key shares on all servers, reusing them", user_id);
            // We need to reconstruct the pubkey_package from the first key package
            // since we can't create it from individual key packages
            let first_key_package = existing_key_packages.values().next().unwrap();
            let verifying_key = first_key_package.verifying_key();
            
            // Create verifying shares from key packages
            let mut verifying_shares = BTreeMap::new();
            for (identifier, key_package) in &existing_key_packages {
                verifying_shares.insert(*identifier, key_package.verifying_share().clone());
            }
            
            let pubkey_package = frost::keys::PublicKeyPackage::new(
                verifying_shares,
                verifying_key.clone(),
            );
            self.pubkey_package = Some(pubkey_package.clone());
            self.threshold = Some(threshold);
            return Ok(DistributedKeygenResult { 
                group_public_key: pubkey_package.verifying_key().serialize().unwrap().to_vec(),
                participants: existing_key_packages.keys().cloned().collect(),
                pubkey_package,
                key_packages: existing_key_packages,
            });
        }

        println!("  Generating new key shares...");
        // Generate key shares using FROST exactly as in the README
        let mut rng = OsRng;
        let (shares, pubkey_package) = frost::keys::generate_with_dealer(
            3, // total_signers
            threshold,
            frost::keys::IdentifierList::Default,
            &mut rng,
        )
        .map_err(|e| AppError::InternalError(e.to_string()))?;

        // Distribute key packages to each server
        let mut key_packages = BTreeMap::new();
        let mut participants = Vec::new();

        for (i, client) in self.server_clients.iter().enumerate() {
            let server_id = (i + 1) as u16;
            let identifier = server_id.try_into().expect("should be nonzero");

            if let Some(secret_share) = shares.get(&identifier) {
                let key_package = frost::keys::KeyPackage::try_from(secret_share.clone())
                    .map_err(|e| AppError::InternalError(e.to_string()))?;

                // Send the key package to this server
                let key_package_json = serde_json::to_string(&key_package)
                    .map_err(|e| AppError::InternalError(e.to_string()))?;
                let public_key = hex::encode(pubkey_package.verifying_key().serialize().unwrap());

                // Store the key package directly in the server's database
                let _response = client
                    .send_keygen_with_package_request(
                        user_id,
                        threshold,
                        3,
                        &key_package_json,
                        &public_key,
                    )
                    .await?;

                println!(
                    "  Server {}: Key package distributed for user '{}' (participant {})",
                    server_id,
                    user_id,
                    identifier.serialize()[0]
                );

                key_packages.insert(identifier, key_package);
                participants.push(identifier);
            }
        }

        println!(
            "  ✅ Key generation complete! Group public key: {}",
            hex::encode(pubkey_package.verifying_key().serialize().unwrap())
        );

        // Store the pubkey package and threshold for later use in signing
        self.pubkey_package = Some(pubkey_package.clone());
        self.threshold = Some(threshold);

        Ok(DistributedKeygenResult {
            group_public_key: pubkey_package.verifying_key().serialize().unwrap().to_vec(),
            participants,
            pubkey_package,
            key_packages,
        })
    }

    /// Execute FROST signing protocol across distributed MPC servers
    /// This follows the FROST-ed25519 README pattern exactly
    pub async fn sign_message(
        &self,
        user_id: &str,
        message: &[u8],
        session_id: &str,
    ) -> Result<DistributedSigningResult, AppError> {
        println!(
            "Step 2: Starting FROST signing protocol for user '{}'...",
            user_id
        );

        // Round 1: Generate nonces and commitments for each participant
        // Only use threshold number of participants (like frost-ed25519 README)
        println!("  Round 1: Generating nonces and commitments...");
        let mut round1_responses = Vec::new();
        let threshold = self.threshold.ok_or_else(|| {
            AppError::InternalError("No threshold available. Run key generation first.".to_string())
        })?;
        for (i, client) in self
            .server_clients
            .iter()
            .enumerate()
            .take(threshold as usize)
        {
            let server_user_id = format!("{}_mpc_server_{}", user_id, i + 1);
            let response = client.send_round1_request(&server_user_id, session_id).await?;
            round1_responses.push(response);
            println!("    Server {}: Generated commitments", i + 1);
        }

        // Collect commitments
        let mut commitments = BTreeMap::new();
        for response in &round1_responses {
            let identifier = response.participant.try_into().expect("should be nonzero");
            let commitments_data: frost::round1::SigningCommitments =
                serde_json::from_value(response.commitments.clone())
                    .map_err(|e| AppError::InternalError(e.to_string()))?;
            commitments.insert(identifier, commitments_data);
        }

        // Create signing package (exactly like FROST-ed25519 README)
        let commitments_count = commitments.len();
        let signing_package = frost::SigningPackage::new(commitments, message);
        println!(
            "  Signing package created with {} commitments",
            commitments_count
        );
        println!(
            "  Signing package message: {}",
            hex::encode(signing_package.message())
        );

        // Round 2: Generate signature shares
        // Only use threshold number of participants (like frost-ed25519 README)
        println!("  Round 2: Generating signature shares...");
        let mut round2_responses = Vec::new();
        let message_hex = hex::encode(message);

        for (i, client) in self
            .server_clients
            .iter()
            .enumerate()
            .take(threshold as usize)
        {
            let server_user_id = format!("{}_mpc_server_{}", user_id, i + 1);
            let response = client
                .send_round2_request(&server_user_id, session_id, &signing_package, &message_hex)
                .await?;
            round2_responses.push(response);
            println!("    Server {}: Generated signature share", i + 1);
        }

        // Collect signature shares
        let mut signature_shares = BTreeMap::new();
        for response in &round2_responses {
            let identifier: frost::Identifier = response.participant.try_into().expect("should be nonzero");
            let signature_share: frost::round2::SignatureShare =
                serde_json::from_value(response.signature_share.clone())
                    .map_err(|e| AppError::InternalError(e.to_string()))?;
            signature_shares.insert(identifier, signature_share);
            println!(
                "    Collected signature share from participant {}",
                identifier.serialize()[0]
            );
        }

        println!("  Collected {} signature shares", signature_shares.len());

        // Aggregate signature (exactly like FROST-ed25519 README)
        println!("  Aggregating signature shares...");
        let pubkey_package = self.pubkey_package.as_ref().ok_or_else(|| {
            AppError::InternalError(
                "No pubkey package available. Run key generation first.".to_string(),
            )
        })?;
        let group_signature = frost::aggregate(&signing_package, &signature_shares, pubkey_package)
            .map_err(|e| AppError::InternalError(e.to_string()))?;

        // Verify signature (exactly like FROST-ed25519 README)
        let is_signature_valid = pubkey_package
            .verifying_key()
            .verify(message, &group_signature)
            .is_ok();

        println!(
            "  Signature verification: {}",
            if is_signature_valid {
                "✅ Valid"
            } else {
                "❌ Invalid"
            }
        );

        Ok(DistributedSigningResult {
            signature: group_signature.serialize().unwrap().to_vec(),
            is_valid: is_signature_valid,
            message: message.to_vec(),
        })
    }
}

// Request/Response types for MPC server communication
#[derive(Debug, Serialize, Deserialize)]
pub struct FrostKeygenRequest {
    pub user_id: String,
    pub threshold: u16,
    pub total_signers: u16,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostKeygenWithPackageRequest {
    pub user_id: String,
    pub threshold: u16,
    pub total_signers: u16,
    pub key_package_json: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostKeygenResponse {
    pub participant: u16,
    pub public_key: String,
    pub success: bool,
    pub user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostRound1Request {
    pub user_id: String,
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostRound1Response {
    pub participant: u16,
    pub commitments: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostRound2Request {
    pub user_id: String,
    pub session_id: String,
    pub signing_package: serde_json::Value,
    pub message_hex: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostRound2Response {
    pub participant: u16,
    pub signature_share: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostAggregateRequest {
    pub user_id: String,
    pub session_id: String,
    pub signing_package: serde_json::Value,
    pub signature_shares: serde_json::Value,
    pub pubkey_package: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FrostAggregateResponse {
    pub signature: String, // hex encoded
    pub is_valid: bool,
    pub message: String, // hex encoded
}

/// Result of distributed FROST key generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedKeygenResult {
    pub group_public_key: Vec<u8>,
    pub participants: Vec<frost::Identifier>,
    pub pubkey_package: frost::keys::PublicKeyPackage,
    pub key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
}

/// Result of distributed FROST signing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedSigningResult {
    pub signature: Vec<u8>,
    pub is_valid: bool,
    pub message: Vec<u8>,
}

/// Example usage that follows the FROST-ed25519 README exactly
pub async fn distributed_frost_example() -> Result<(), AppError> {
    println!("=== Distributed FROST MPC Example (exactly like FROST-ed25519 README) ===");

    // Create distributed MPC coordinator
    let mut mpc = DistributedMPC::new();

    // User ID for this example
    let user_id = "alice_user_123";

    // Step 1: Generate key shares using trusted dealer (exactly like README)
    let keygen_result = mpc.generate_key_shares(user_id, 2).await?; // 2 out of 3 threshold

    println!(
        "Group public key: {}",
        hex::encode(&keygen_result.group_public_key)
    );
    println!("Participants: {:?}", keygen_result.participants);

    // Step 2: Sign a message (exactly like README)
    let message = b"message to sign";
    let session_id = "example_session_123";

    let signing_result = mpc.sign_message(user_id, message, session_id).await?;

    println!(
        "Message: {}",
        String::from_utf8_lossy(&signing_result.message)
    );
    println!("Signature: {}", hex::encode(&signing_result.signature));
    println!("Signature valid: {}", signing_result.is_valid);

    if signing_result.is_valid {
        println!("✅ Distributed FROST MPC signing successful!");
    } else {
        println!("❌ Distributed FROST MPC signing failed!");
    }

    Ok(())
}
