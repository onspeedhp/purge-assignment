use std::sync::Arc;
use std::collections::HashMap;
use anyhow::Result;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tracing::{info, error, warn, debug};
use yellowstone_grpc_client::GeyserGrpcClient;
use yellowstone_grpc_proto::prelude::*;
use futures::StreamExt;
use bs58;
use std::time::Duration;

use crate::database::AssetDatabase;
use crate::models::{AccountSubscription, TokenMetadata};

pub struct SubscriptionService {
    database: Arc<AssetDatabase>,
    active_subscriptions: Arc<Mutex<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl SubscriptionService {
    pub fn new(
        _client: Arc<GeyserGrpcClient<impl yellowstone_grpc_client::Interceptor>>,
        database: Arc<AssetDatabase>,
    ) -> Self {
        Self {
            database,
            active_subscriptions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn start_subscription(&self, subscription: AccountSubscription) -> Result<()> {
        info!("Starting gRPC subscription for wallet: {}", subscription.wallet_address);
        
        // Check if subscription already exists
        let mut active_subs = self.active_subscriptions.lock().await;
        if active_subs.contains_key(&subscription.id) {
            warn!("Subscription already active for wallet: {}", subscription.wallet_address);
            return Ok(());
        }

        // Clone the database for the async task
        let database = self.database.clone();
        let subscription_id = subscription.id.clone();
        let wallet_address = subscription.wallet_address.clone();
        let wallet_address_for_log = wallet_address.clone();

        // Spawn the gRPC subscription task
        let handle = tokio::spawn(async move {
            if let Err(e) = Self::handle_grpc_subscription(database, subscription).await {
                error!("gRPC subscription failed for {}: {:?}", wallet_address, e);
            }
        });

        // Store the handle for potential cleanup
        active_subs.insert(subscription_id, handle);
        
        info!("Started gRPC subscription for wallet: {}", wallet_address_for_log);
        Ok(())
    }

    async fn handle_grpc_subscription(
        database: Arc<AssetDatabase>,
        subscription: AccountSubscription,
    ) -> Result<()> {
        let wallet_address = subscription.wallet_address.clone();
        let mut retry_count = 0;
        let max_retries = 5;
        let base_delay = Duration::from_secs(2);

        loop {
            match Self::run_grpc_subscription(database.clone(), subscription.clone()).await {
                Ok(_) => {
                    info!("gRPC subscription completed for {}", wallet_address);
                    break;
                }
                Err(e) => {
                    retry_count += 1;
                    if retry_count > max_retries {
                        error!("Max retries exceeded for wallet {}: {:?}", wallet_address, e);
                        break;
                    }

                    let delay = base_delay * retry_count;
                    warn!("gRPC subscription failed for {} (attempt {}), retrying in {:?}: {:?}", 
                          wallet_address, retry_count, delay, e);
                    
                    tokio::time::sleep(delay).await;
                }
            }
        }

        Ok(())
    }

    async fn run_grpc_subscription(
        database: Arc<AssetDatabase>,
        subscription: AccountSubscription,
    ) -> Result<()> {
        info!("Setting up gRPC subscription for wallet: {}", subscription.wallet_address);
        
        // Get gRPC endpoint from environment
        let endpoint = std::env::var("GEYSER_GRPC_ENDPOINT")
            .unwrap_or_else(|_| "https://api.mainnet-beta.solana.com:443".to_string());
        
        // Create a new client for this subscription
        let mut client = crate::yellowstone_client::setup_client(endpoint).await
            .map_err(|e| anyhow::anyhow!("Failed to create gRPC client: {}", e))?;
        
        // Create account filter - monitor the specific USDC token account we found
        let mut accounts_filter = HashMap::new();
        accounts_filter.insert(
            format!("usdc_account_{}", subscription.wallet_address),
            SubscribeRequestFilterAccounts {
                account: vec!["Uf5DEkQ9nDnJrxTksUqadfvjywz658ytTmbFYXwUUMo".to_string()], // USDC token account
                owner: vec![],
                filters: vec![],
                nonempty_txn_signature: Some(false),
            },
        );

        // Create transaction filter to monitor transactions involving this wallet
        let mut transactions_filter = HashMap::new();
        transactions_filter.insert(
            format!("txn_{}", subscription.wallet_address),
            SubscribeRequestFilterTransactions {
                account_include: vec![subscription.wallet_address.clone()],
                account_exclude: vec![],
                account_required: vec![],
                vote: Some(false),
                failed: Some(false),
                signature: None,
            },
        );

        // Create subscription request
        let subscribe_request = SubscribeRequest {
            accounts: accounts_filter,
            blocks: HashMap::new(),
            blocks_meta: HashMap::new(),
            entry: HashMap::new(),
            commitment: Some(CommitmentLevel::Confirmed.into()),
            accounts_data_slice: vec![],
            transactions: transactions_filter,
            transactions_status: HashMap::new(),
            slots: HashMap::new(),
            ping: None,
            from_slot: None,
        };

        info!("Starting gRPC stream for wallet: {}", subscription.wallet_address);

        // Start the subscription
        let mut stream = client.subscribe_once(subscribe_request).await?;

        info!("gRPC stream established for wallet: {}", subscription.wallet_address);

        // Process incoming events
        while let Some(update) = stream.next().await {
            match update {
                Ok(update) => {
                    if let Err(e) = Self::process_grpc_update(&database, &subscription, update).await {
                        error!("Failed to process gRPC update: {:?}", e);
                    }
                }
                Err(e) => {
                    error!("Stream error for wallet {}: {:?}", subscription.wallet_address, e);
                    return Err(e.into());
                }
            }
        }

        warn!("gRPC stream ended for wallet: {}", subscription.wallet_address);
        Ok(())
    }


    async fn process_grpc_update(
        database: &AssetDatabase,
        subscription: &AccountSubscription,
        update: SubscribeUpdate,
    ) -> Result<()> {
        match update.update_oneof {
            Some(subscribe_update::UpdateOneof::Account(account_update)) => {
                info!("🔍 Received account update for wallet: {}", subscription.wallet_address);
                Self::process_account_update(database, subscription, account_update).await?;
            }
            Some(subscribe_update::UpdateOneof::Transaction(tx_update)) => {
                info!("🔍 Received transaction update for wallet: {} at slot {}",
                      subscription.wallet_address, tx_update.slot);
                Self::process_transaction_update(database, subscription, tx_update).await?;
            }
            Some(subscribe_update::UpdateOneof::Block(block_update)) => {
                debug!("Received block update at slot: {}", block_update.slot);
            }
            Some(subscribe_update::UpdateOneof::Ping(_ping)) => {
                debug!("Received ping");
            }
            Some(subscribe_update::UpdateOneof::Pong(pong)) => {
                debug!("Received pong: {}", pong.id);
            }
            Some(subscribe_update::UpdateOneof::Slot(slot_update)) => {
                debug!("Received slot update: {}", slot_update.slot);
            }
            _ => {
                debug!("Received other update type");
            }
        }
        Ok(())
    }

    async fn process_account_update(
        database: &AssetDatabase,
        subscription: &AccountSubscription,
        account_update: SubscribeUpdateAccount,
    ) -> Result<()> {
        let account = account_update.account.ok_or_else(|| anyhow::anyhow!("Missing account data"))?;
        let pubkey = bs58::encode(&account.pubkey).into_string();
        let slot = account_update.slot;

        info!("Processing account update for {} at slot {}", pubkey, slot);

        // Update last processed slot
        database.update_last_processed_slot(&subscription.id, slot as i64).await?;

        // Check if this is the main wallet account or a token account
        if pubkey == subscription.wallet_address {
            info!("🏦 Main wallet account update for {} at slot {}", pubkey, slot);
            // This is the main account - could be SOL balance change
            // For now, we'll just log it. In a full implementation, we'd track SOL balance
        } else {
            info!("🪙 Token account update for {} at slot {} (data length: {})", 
                  pubkey, slot, account.data.len());
            // This is likely a token account - process it
            let data = account.data;
            Self::process_token_account_data(database, subscription, &data, &pubkey).await?;
        }

        Ok(())
    }

    async fn process_transaction_update(
        database: &AssetDatabase,
        subscription: &AccountSubscription,
        tx_update: SubscribeUpdateTransaction,
    ) -> Result<()> {
        info!("Processing transaction for wallet: {} at slot {}", 
              subscription.wallet_address, tx_update.slot);

        // Update last processed slot
        database.update_last_processed_slot(&subscription.id, tx_update.slot as i64).await?;

        // For now, we'll trigger a balance refresh for all token accounts
        // In a more sophisticated implementation, we'd parse the transaction
        // to see which specific accounts were affected
        info!("Transaction detected - would refresh token balances for wallet: {}", 
              subscription.wallet_address);
        
        // TODO: In a full implementation, we would:
        // 1. Parse the transaction to identify which token accounts were affected
        // 2. Query the current state of those accounts
        // 3. Update the database with the new balances
        
        // For now, let's just log that we detected a transaction
        // The account updates should handle the actual balance changes
        
        Ok(())
    }

    async fn process_token_account_data(
        database: &AssetDatabase,
        subscription: &AccountSubscription,
        data: &[u8],
        pubkey: &str,
    ) -> Result<()> {
        // SPL Token Account data structure:
        // - First 32 bytes: mint address
        // - Next 32 bytes: owner address  
        // - Next 8 bytes: amount (u64)
        // - Next 4 bytes: delegate (optional)
        // - Next 1 byte: state
        // - Next 1 byte: is_native (optional)
        // - Next 8 bytes: delegated_amount
        // - Next 1 byte: close_authority (optional)

        if data.len() < 165 { // Standard SPL token account size
            debug!("Account data too short for token account: {} ({} bytes)", pubkey, data.len());
            return Ok(());
        }

        // Extract mint address (first 32 bytes)
        let mint_address = bs58::encode(&data[0..32]).into_string();
        
        // Extract owner address (next 32 bytes)
        let owner_address = bs58::encode(&data[32..64]).into_string();
        
        // Extract amount (bytes 64-72)
        let amount = u64::from_le_bytes([
            data[64], data[65], data[66], data[67],
            data[68], data[69], data[70], data[71],
        ]);

        // Extract state (byte 76)
        let state = data[76];
        
        // Extract is_native (byte 77)
        let is_native = data[77] != 0;

        // Only process if this is a token account for our user
        if owner_address != subscription.wallet_address {
            debug!("Token account {} owned by {}, not our user {}", pubkey, owner_address, subscription.wallet_address);
            return Ok(());
        }

        // Check if account is initialized (state = 1)
        if state != 1 {
            debug!("Token account {} not initialized (state: {})", pubkey, state);
            return Ok(());
        }

        info!("Processing token account {}: mint={}, amount={}, owner={}", 
              pubkey, mint_address, amount, owner_address);

        // Fetch token metadata
        let token_metadata = Self::fetch_token_metadata(&mint_address).await?;

        // Get or create asset
        let asset = database.get_or_create_asset(
            &mint_address,
            &token_metadata.symbol,
            &token_metadata.name,
            token_metadata.decimals,
            token_metadata.logo_url.as_deref(),
            is_native,
        ).await?;

        // Update user asset balance
        database.update_user_asset_balance(
            &subscription.user_id,
            &asset.id,
            &subscription.wallet_address,
            amount as i64,
        ).await?;

        info!("✅ Updated token balance for {}: {} units of {} ({})", 
              subscription.wallet_address, amount, token_metadata.symbol, mint_address);

        Ok(())
    }

    async fn fetch_token_metadata(mint_address: &str) -> Result<TokenMetadata> {
        // Try to fetch from Jupiter API first
        match Self::fetch_from_jupiter(mint_address).await {
            Ok(metadata) => {
                info!("Fetched metadata from Jupiter for {}", mint_address);
                return Ok(metadata);
            }
            Err(e) => {
                debug!("Failed to fetch from Jupiter for {}: {:?}", mint_address, e);
            }
        }

        // Fallback to basic metadata
        info!("Using fallback metadata for {}", mint_address);
        Ok(TokenMetadata {
            symbol: "UNKNOWN".to_string(),
            name: "Unknown Token".to_string(),
            decimals: 9,
            logo_url: None,
        })
    }

    async fn fetch_from_jupiter(mint_address: &str) -> Result<TokenMetadata> {
        let url = format!("https://quote-api.jup.ag/v6/tokens/{}", mint_address);
        let client = reqwest::Client::new();
        let response = client.get(&url).timeout(Duration::from_secs(5)).send().await?;
        
        if !response.status().is_success() {
            return Err(anyhow::anyhow!("HTTP error: {}", response.status()));
        }

        let token_info: serde_json::Value = response.json().await?;
        
        Ok(TokenMetadata {
            symbol: token_info["symbol"].as_str().unwrap_or("UNKNOWN").to_string(),
            name: token_info["name"].as_str().unwrap_or("Unknown Token").to_string(),
            decimals: token_info["decimals"].as_u64().unwrap_or(9) as i32,
            logo_url: token_info["logoURI"].as_str().map(|s| s.to_string()),
        })
    }

}
