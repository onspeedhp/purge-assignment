use crate::{
    error::Error,
    mpc::create_mpc_signer,
    solana::transaction::{format_balance, sol_to_lamports, validate_public_key},
    tss::types::{AggregateWallet, SolanaNetwork, TSSKeypair},
};
use solana_client::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

/// TSS Wallet implementation supporting all solana-tss functions
/// Equivalent to TSSWallet class in TypeScript
pub struct TSSWallet {
    rpc_client: RpcClient,
    network: SolanaNetwork,
}

impl TSSWallet {
    /// Create a new TSS wallet
    /// Equivalent to new TSSWallet(network) in TypeScript
    pub fn new(network: SolanaNetwork) -> Self {
        let rpc_client = RpcClient::new(network.rpc_url().to_string());
        Self {
            rpc_client,
            network,
        }
    }

    /// Generate a new TSS keypair
    /// Equivalent to: solana-tss generate
    pub fn generate_keypair(&self) -> Result<TSSKeypair, Error> {
        // Try to use MPC signer if available (like TypeScript)
        match self.try_create_mpc_keypair() {
            Ok(mpc_signer) => Ok(TSSKeypair {
                public_key: mpc_signer.public_key,
                secret_key: mpc_signer.secret_key,
            }),
            Err(_) => {
                // Fallback to regular keypair generation (like TypeScript)
                Ok(TSSKeypair::new())
            }
        }
    }

    /// Check the balance of an address
    /// Equivalent to: solana-tss balance <address>
    pub async fn get_balance(&self, public_key: &Pubkey) -> Result<f64, Error> {
        let balance = self
            .rpc_client
            .get_balance(public_key)
            .map_err(Error::BalaceFailed)?;

        Ok(crate::solana::transaction::lamports_to_sol(balance))
    }

    /// Request an airdrop from the faucet (devnet/testnet only)
    /// Equivalent to: solana-tss airdrop <address> <amount>
    pub async fn request_airdrop(&self, public_key: &Pubkey, amount: f64) -> Result<String, Error> {
        if self.network == SolanaNetwork::MainnetBeta {
            return Err(Error::WrongNetwork(
                "Airdrop not available on mainnet".to_string(),
            ));
        }

        let lamports = sol_to_lamports(amount);
        let signature = self
            .rpc_client
            .request_airdrop(public_key, lamports)
            .map_err(Error::AirdropFailed)?;

        // Wait for confirmation
        self.rpc_client
            .confirm_transaction(&signature)
            .map_err(Error::ConfirmingTransactionFailed)?;

        Ok(signature.to_string())
    }

    /// Aggregate multiple public keys into a single multisig address
    /// Equivalent to: solana-tss aggregate-keys <key1> <key2> ... <keyN>
    pub fn aggregate_keys(
        &self,
        participant_keys: Vec<Pubkey>,
        threshold: Option<usize>,
    ) -> AggregateWallet {
        AggregateWallet::new(participant_keys, threshold)
    }

    /// Get recent blockhash for transaction signing
    /// Equivalent to: solana-tss recent-block-hash
    pub async fn get_recent_blockhash(&self) -> Result<String, Error> {
        let blockhash = self
            .rpc_client
            .get_latest_blockhash()
            .map_err(Error::RecentHashFailed)?;

        Ok(blockhash.to_string())
    }

    /// Switch to a different Solana network
    /// Equivalent to switchNetwork() in TypeScript
    pub fn switch_network(&mut self, network: SolanaNetwork) {
        self.network = network.clone();
        self.rpc_client = RpcClient::new(network.rpc_url().to_string());
    }

    /// Get current network
    /// Equivalent to getCurrentNetwork() in TypeScript
    pub fn get_current_network(&self) -> &SolanaNetwork {
        &self.network
    }

    /// Get connection instance
    /// Equivalent to getConnection() in TypeScript
    pub fn get_connection(&self) -> &RpcClient {
        &self.rpc_client
    }

    /// Validate a public key string
    /// Equivalent to static validatePublicKey() in TypeScript
    pub fn validate_public_key(&self, key_string: &str) -> Result<Pubkey, Error> {
        validate_public_key(key_string)
    }

    /// Format balance for display
    /// Equivalent to static formatBalance() in TypeScript
    pub fn format_balance(&self, lamports: u64) -> String {
        format_balance(lamports)
    }

    /// Try to create an MPC keypair (fallback method)
    /// Equivalent to the MPC signer creation logic in TypeScript
    fn try_create_mpc_keypair(&self) -> Result<crate::mpc::MPCSigner, Error> {
        Ok(create_mpc_signer())
    }
}

impl Default for TSSWallet {
    fn default() -> Self {
        Self::new(SolanaNetwork::Devnet)
    }
}

