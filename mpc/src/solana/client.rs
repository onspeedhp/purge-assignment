use solana_client::rpc_client::RpcClient;
use solana_sdk::{hash::Hash, pubkey::Pubkey, signature::Signature, transaction::Transaction};
use std::sync::Arc;
use tokio::task;

/// Async wrapper for RpcClient to avoid blocking calls in async context
pub struct AsyncRpcClient {
    client: Arc<RpcClient>,
}

impl AsyncRpcClient {
    pub fn new(url: String) -> Self {
        Self {
            client: Arc::new(RpcClient::new(url)),
        }
    }

    pub async fn request_airdrop(
        &self,
        pubkey: &Pubkey,
        lamports: u64,
    ) -> Result<Signature, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        let pubkey = *pubkey;
        Ok(task::spawn_blocking(move || client.request_airdrop(&pubkey, lamports)).await??)
    }

    pub async fn get_balance(
        &self,
        pubkey: &Pubkey,
    ) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        let pubkey = *pubkey;
        Ok(task::spawn_blocking(move || client.get_balance(&pubkey)).await??)
    }

    pub async fn get_latest_blockhash(
        &self,
    ) -> Result<Hash, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        Ok(task::spawn_blocking(move || client.get_latest_blockhash()).await??)
    }

    pub async fn send_and_confirm_transaction(
        &self,
        transaction: &Transaction,
    ) -> Result<Signature, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        let transaction = transaction.clone();
        Ok(
            task::spawn_blocking(move || client.send_and_confirm_transaction(&transaction))
                .await??,
        )
    }

    pub async fn confirm_transaction(
        &self,
        signature: &Signature,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let client = self.client.clone();
        let signature = *signature;
        Ok(task::spawn_blocking(move || client.confirm_transaction(&signature)).await??)
    }
}
