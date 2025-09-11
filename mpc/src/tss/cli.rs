use crate::{
    error::Error,
    tss::{
        signing::TSSSigningService,
        types::{
            AggSignStepOneData, AggSignStepTwoData, AggregateWallet, SolanaNetwork,
            TSSTransactionDetails,
        },
        wallet::TSSWallet,
    },
    utils::serialization::{bytes_to_hex, hex_to_bytes},
};
use serde::{Deserialize, Serialize};

/// CLI interface matching the original solana-tss functionality
/// Equivalent to TSSCli class in TypeScript
pub struct TSSCli {
    wallet: TSSWallet,
    signing_service: TSSSigningService,
}

impl TSSCli {
    /// Create a new TSS CLI instance
    /// Equivalent to new TSSCli(network) in TypeScript
    pub fn new(network: SolanaNetwork) -> Self {
        let wallet = TSSWallet::new(network);
        let signing_service = TSSSigningService::new_with_ref(wallet.get_connection());
        Self {
            wallet,
            signing_service,
        }
    }

    /// Generate a pair of keys
    /// Equivalent to: solana-tss generate
    pub async fn generate(&self) -> Result<GenerateResult, Error> {
        let keypair = self.wallet.generate_keypair()?;
        Ok(GenerateResult {
            public_key: keypair.public_key.to_string(),
            secret_key: bytes_to_hex(&keypair.secret_key),
        })
    }

    /// Check the balance of an address
    /// Equivalent to: solana-tss balance <address>
    pub async fn balance(&self, address: &str) -> Result<f64, Error> {
        let public_key = self.wallet.validate_public_key(address)?;
        self.wallet.get_balance(&public_key).await
    }

    /// Request an airdrop from a faucet
    /// Equivalent to: solana-tss airdrop <address> <amount>
    pub async fn airdrop(&self, address: &str, amount: f64) -> Result<String, Error> {
        let public_key = self.wallet.validate_public_key(address)?;
        self.wallet.request_airdrop(&public_key, amount).await
    }

    /// Send a transaction using a single private key
    /// Equivalent to: solana-tss send-single <from_secret> <to> <amount> [memo]
    pub async fn send_single(
        &self,
        from_secret_hex: &str,
        to: &str,
        amount: f64,
        memo: Option<String>,
    ) -> Result<String, Error> {
        let from_secret_bytes = hex_to_bytes(from_secret_hex)?;
        if from_secret_bytes.len() != 32 {
            return Err(Error::InvalidInput(
                "Secret key must be 32 bytes".to_string(),
            ));
        }
        let mut from_secret = [0u8; 32];
        from_secret.copy_from_slice(&from_secret_bytes);

        let to_public_key = self.wallet.validate_public_key(to)?;

        self.signing_service
            .send_single(from_secret, to_public_key, amount, memo)
            .await
    }

    /// Aggregate a list of addresses into a single address
    /// Equivalent to: solana-tss aggregate-keys <key1> <key2> ... <keyN>
    pub fn aggregate_keys(
        &self,
        key_strings: &[String],
        threshold: Option<usize>,
    ) -> Result<AggregateKeysResult, Error> {
        let keys = key_strings
            .iter()
            .map(|key_str| self.wallet.validate_public_key(key_str))
            .collect::<Result<Vec<_>, _>>()?;

        let aggregate_wallet = self.wallet.aggregate_keys(keys.clone(), threshold);

        Ok(AggregateKeysResult {
            aggregated_public_key: aggregate_wallet.aggregated_public_key.to_string(),
            participant_keys: aggregate_wallet
                .participant_keys
                .iter()
                .map(|k| k.to_string())
                .collect(),
            threshold: aggregate_wallet.threshold,
        })
    }

    /// Start aggregate signing
    /// Equivalent to: solana-tss agg-send-step-one <participant_secret> <to> <amount> <network> [memo] [recent_block_hash]
    pub async fn aggregate_sign_step_one(
        &self,
        participant_secret_hex: &str,
        to: &str,
        amount: f64,
        memo: Option<String>,
        recent_blockhash: Option<String>,
    ) -> Result<AggSignStepOneResult, Error> {
        let participant_secret_bytes = hex_to_bytes(participant_secret_hex)?;
        if participant_secret_bytes.len() != 32 {
            return Err(Error::InvalidInput(
                "Secret key must be 32 bytes".to_string(),
            ));
        }
        let mut participant_secret = [0u8; 32];
        participant_secret.copy_from_slice(&participant_secret_bytes);

        let to_public_key = self.wallet.validate_public_key(to)?;
        let from_public_key = to_public_key; // Will be derived from secret in real implementation (like TypeScript)

        let block_hash = recent_blockhash.unwrap_or_else(|| {
            // Use a default blockhash if not provided (like TypeScript)
            "11111111111111111111111111111111".to_string()
        });

        let transaction_details = TSSTransactionDetails {
            amount,
            to: to_public_key,
            from: from_public_key,
            network: self.wallet.get_current_network().clone(),
            memo,
            recent_blockhash: block_hash,
        };

        let step_one_data = self
            .signing_service
            .aggregate_sign_step_one(participant_secret, &transaction_details)?;

        Ok(AggSignStepOneResult {
            secret_nonce: bytes_to_hex(&step_one_data.secret_nonce),
            public_nonce: bytes_to_hex(&step_one_data.public_nonce),
            participant_key: step_one_data.participant_key.to_string(),
        })
    }

    /// Print the hash of a recent block
    /// Equivalent to: solana-tss recent-block-hash
    pub async fn recent_block_hash(&self) -> Result<String, Error> {
        self.wallet.get_recent_blockhash().await
    }

    /// Step 2 of aggregate signing
    /// Equivalent to: solana-tss agg-send-step-two <step_one_data> <participant_secret> <to> <amount> <network> <all_public_nonces> [memo] [recent_block_hash]
    pub async fn aggregate_sign_step_two(
        &self,
        step_one_data: &AggSignStepOneResult,
        participant_secret_hex: &str,
        to: &str,
        amount: f64,
        all_public_nonces_hex: &[String],
        memo: Option<String>,
        recent_blockhash: Option<String>,
    ) -> Result<AggSignStepTwoResult, Error> {
        // Convert hex strings to bytes and Pubkey
        let secret_nonce_bytes = hex_to_bytes(&step_one_data.secret_nonce)?;
        let public_nonce_bytes = hex_to_bytes(&step_one_data.public_nonce)?;
        let participant_key = step_one_data
            .participant_key
            .parse()
            .map_err(|e| Error::InvalidPublicKey(format!("Invalid participant key: {}", e)))?;

        if secret_nonce_bytes.len() != 32 || public_nonce_bytes.len() != 32 {
            return Err(Error::InvalidInput("Invalid nonce length".to_string()));
        }

        let mut secret_nonce = [0u8; 32];
        let mut public_nonce = [0u8; 32];
        secret_nonce.copy_from_slice(&secret_nonce_bytes);
        public_nonce.copy_from_slice(&public_nonce_bytes);

        let step_one_data = AggSignStepOneData {
            secret_nonce,
            public_nonce,
            participant_key,
        };

        let participant_secret_bytes = hex_to_bytes(participant_secret_hex)?;
        if participant_secret_bytes.len() != 32 {
            return Err(Error::InvalidInput(
                "Secret key must be 32 bytes".to_string(),
            ));
        }
        let mut participant_secret = [0u8; 32];
        participant_secret.copy_from_slice(&participant_secret_bytes);

        let to_public_key = self.wallet.validate_public_key(to)?;
        let from_public_key = step_one_data.participant_key;

        let block_hash = recent_blockhash.unwrap_or_else(|| {
            // Use a default blockhash if not provided (like TypeScript)
            "11111111111111111111111111111111".to_string()
        });

        let transaction_details = TSSTransactionDetails {
            amount,
            to: to_public_key,
            from: from_public_key,
            network: self.wallet.get_current_network().clone(),
            memo,
            recent_blockhash: block_hash,
        };

        let all_public_nonces = all_public_nonces_hex
            .iter()
            .map(|hex| {
                let bytes = hex_to_bytes(hex)?;
                if bytes.len() != 32 {
                    return Err(Error::InvalidInput("Nonce must be 32 bytes".to_string()));
                }
                let mut nonce = [0u8; 32];
                nonce.copy_from_slice(&bytes);
                Ok(nonce)
            })
            .collect::<Result<Vec<_>, _>>()?;

        let step_two_data = self
            .signing_service
            .aggregate_sign_step_two(
                &step_one_data,
                participant_secret,
                &transaction_details,
                &all_public_nonces,
            )
            .await?;

        Ok(AggSignStepTwoResult {
            partial_signature: bytes_to_hex(&step_two_data.partial_signature),
            public_nonce: bytes_to_hex(&step_two_data.public_nonce),
            participant_key: step_two_data.participant_key.to_string(),
        })
    }

    /// Aggregate all the partial signatures together and send transaction
    /// Equivalent to: solana-tss aggregate-signatures-and-broadcast <partial_signatures> <transaction_details> <aggregate_wallet>
    pub async fn aggregate_signatures_and_broadcast(
        &self,
        partial_signatures: Vec<AggSignStepTwoResult>,
        transaction_details_params: TransactionDetailsParams,
        aggregate_wallet_params: AggregateWalletParams,
    ) -> Result<String, Error> {
        // Convert Vec<AggSignStepTwoResult> to Vec<AggSignStepTwoData>
        let partial_signatures_data: Vec<AggSignStepTwoData> = partial_signatures
            .into_iter()
            .map(|result| {
                let partial_signature_bytes = hex_to_bytes(&result.partial_signature)?;
                let public_nonce_bytes = hex_to_bytes(&result.public_nonce)?;

                if partial_signature_bytes.len() != 64 {
                    return Err(Error::InvalidInput(
                        "Partial signature must be 64 bytes".to_string(),
                    ));
                }
                if public_nonce_bytes.len() != 32 {
                    return Err(Error::InvalidInput(
                        "Public nonce must be 32 bytes".to_string(),
                    ));
                }

                let mut partial_signature = [0u8; 64];
                let mut public_nonce = [0u8; 32];
                partial_signature.copy_from_slice(&partial_signature_bytes);
                public_nonce.copy_from_slice(&public_nonce_bytes);

                let participant_key = result.participant_key.parse().map_err(|e| {
                    Error::InvalidPublicKey(format!("Invalid participant key: {}", e))
                })?;

                Ok(AggSignStepTwoData {
                    partial_signature,
                    public_nonce,
                    participant_key,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Convert TransactionDetailsParams to TSSTransactionDetails

        let to_public_key = self
            .wallet
            .validate_public_key(&transaction_details_params.to)?;

        let from_public_key = self
            .wallet
            .validate_public_key(&transaction_details_params.from)?;

        let network = match transaction_details_params.network.as_str() {
            "mainnet" => SolanaNetwork::MainnetBeta,
            "testnet" => SolanaNetwork::Testnet,
            _ => SolanaNetwork::Devnet,
        };

        let memo = if transaction_details_params.memo.is_empty() {
            None
        } else {
            Some(transaction_details_params.memo)
        };

        let transaction_details = TSSTransactionDetails {
            amount: transaction_details_params.amount,
            to: to_public_key,
            from: from_public_key,
            network,
            memo,
            recent_blockhash: transaction_details_params.recent_blockhash,
        };

        // Convert AggregateWalletParams to AggregateWallet
        let participant_keys = aggregate_wallet_params
            .participant_keys
            .into_iter()
            .map(|key_str| self.wallet.validate_public_key(&key_str))
            .collect::<Result<Vec<_>, _>>()?;

        let aggregated_public_key = self
            .wallet
            .validate_public_key(&aggregate_wallet_params.aggregated_public_key)?;

        let aggregate_wallet = AggregateWallet {
            aggregated_public_key,
            participant_keys,
            threshold: aggregate_wallet_params.threshold,
        };

        self.signing_service
            .aggregate_signatures_and_broadcast(
                &partial_signatures_data,
                &transaction_details,
                &aggregate_wallet,
            )
            .await
    }

    /// Switch to a different network
    /// Equivalent to switchNetwork() in TypeScript
    pub fn switch_network(&mut self, network: SolanaNetwork) {
        self.wallet.switch_network(network);
        self.signing_service = TSSSigningService::new_with_ref(self.wallet.get_connection());
    }

    /// Get current network
    /// Equivalent to getCurrentNetwork() in TypeScript
    pub fn get_current_network(&self) -> &SolanaNetwork {
        self.wallet.get_current_network()
    }

    /// Format balance for display
    /// Equivalent to static formatBalance() in TypeScript
    pub fn format_balance(balance: f64) -> String {
        format!("{:.9} SOL", balance)
    }

    /// Helper to print help information
    /// Equivalent to static printHelp() in TypeScript
    pub fn print_help() -> String {
        r#"
Solana TSS Library v1.0.0
A Rust library for managing Solana TSS wallets

USAGE:
    Available methods in TSSCli struct:

METHODS:
    generate()
            Generate a pair of keys
    balance(address)
            Check the balance of an address
    airdrop(address, amount)
            Request an airdrop from a faucet
    send_single(from_secret, to, amount, memo?)
            Send a transaction using a single private key
    aggregate_keys(keys, threshold?)
            Aggregate a list of addresses into a single address
    aggregate_sign_step_one(participant_secret, to, amount, memo?, recent_blockhash?)
            Start aggregate signing
    recent_block_hash()
            Get the hash of a recent block
    aggregate_sign_step_two(step_one_data, participant_secret, to, amount, all_public_nonces, memo?, recent_blockhash?)
            Step 2 of aggregate signing
    aggregate_signatures_and_broadcast(partial_signatures, transaction_details, aggregate_wallet)
            Aggregate signatures and broadcast transaction

NETWORKS:
    mainnet, devnet, testnet (default: devnet)
        "#
        .to_string()
    }
}

/// Result types for CLI operations

#[derive(Debug, Clone)]
pub struct GenerateResult {
    pub public_key: String,
    pub secret_key: String,
}

#[derive(Debug, Clone)]
pub struct AggregateKeysResult {
    pub aggregated_public_key: String,
    pub participant_keys: Vec<String>,
    pub threshold: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepOneResult {
    pub secret_nonce: String,
    pub public_nonce: String,
    pub participant_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggSignStepTwoResult {
    pub partial_signature: String,
    pub public_nonce: String,
    pub participant_key: String,
}

/// Transaction details for aggregate signatures and broadcast
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDetailsParams {
    pub amount: f64,
    pub to: String,
    pub from: String,
    pub network: String,
    pub memo: String,
    pub recent_blockhash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregateWalletParams {
    pub aggregated_public_key: String,
    pub participant_keys: Vec<String>,
    pub threshold: usize,
}

impl Default for TSSCli {
    fn default() -> Self {
        Self::new(SolanaNetwork::Devnet)
    }
}
