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
        step_one_data_json: &str,
        participant_secret_hex: &str,
        to: &str,
        amount: f64,
        all_public_nonces_hex: &[String],
        memo: Option<String>,
        recent_blockhash: Option<String>,
    ) -> Result<AggSignStepTwoResult, Error> {
        let step_one_data: AggSignStepOneData = serde_json::from_str(step_one_data_json)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

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
        partial_signatures_json: &str,
        transaction_details_json: &str,
        aggregate_wallet_json: &str,
    ) -> Result<String, Error> {
        let partial_signatures: Vec<AggSignStepTwoData> =
            serde_json::from_str(partial_signatures_json)
                .map_err(|e| Error::SerializationError(e.to_string()))?;

        let transaction_details: TSSTransactionDetails =
            serde_json::from_str(transaction_details_json)
                .map_err(|e| Error::SerializationError(e.to_string()))?;

        let aggregate_wallet: AggregateWallet = serde_json::from_str(aggregate_wallet_json)
            .map_err(|e| Error::SerializationError(e.to_string()))?;

        self.signing_service
            .aggregate_signatures_and_broadcast(
                &partial_signatures,
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

#[derive(Debug, Clone)]
pub struct AggSignStepOneResult {
    pub secret_nonce: String,
    pub public_nonce: String,
    pub participant_key: String,
}

#[derive(Debug, Clone)]
pub struct AggSignStepTwoResult {
    pub partial_signature: String,
    pub public_nonce: String,
    pub participant_key: String,
}

impl Default for TSSCli {
    fn default() -> Self {
        Self::new(SolanaNetwork::Devnet)
    }
}
