use std::str::FromStr;

use serde::{Deserialize, Serialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use spl_associated_token_account::get_associated_token_address;
use tracing::{error, info};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenBalance {
    pub balance: u64,
    pub token_mint: String,
    pub symbol: String,
    pub decimals: i32,
}

pub struct SolanaRpcClient {
    pub rpc_url: String,
    pub client: reqwest::Client,
    pub rpc_client: RpcClient,
}

impl SolanaRpcClient {
    pub fn new(rpc_url: String) -> Self {
        Self {
            rpc_client: RpcClient::new(rpc_url.clone()),
            rpc_url,
            client: reqwest::Client::new(),
        }
    }

    pub async fn get_token_account_balance(
        &self,
        wallet_address: &str,
        token_mint: &str,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let wallet_pubkey = Pubkey::from_str(wallet_address)
            .map_err(|e| format!("Invalid wallet address: {}", e))?;
        let mint_pubkey = Pubkey::from_str(token_mint)
            .map_err(|e| format!("Invalid token mint: {}", e))?;
            
        let ata_mint = get_associated_token_address(&wallet_pubkey, &mint_pubkey);

        match self.rpc_client.get_token_account_balance(&ata_mint).await {
            Ok(balance) => {
                Ok(balance.amount.parse::<u64>().unwrap_or(0))
            }
            Err(e) => {
                // If account doesn't exist, return 0 balance instead of error
                if e.to_string().contains("could not find account") {
                    Ok(0)
                } else {
                    Err(e.into())
                }
            }
        }
    }

    /// Get SOL balance for a wallet address
    pub async fn get_sol_balance(
        &self,
        wallet_address: &str,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [wallet_address]
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request_body)
            .send()
            .await?;

        let result: serde_json::Value = response.json().await?;

        if let Some(balance) = result["result"]["value"].as_u64() {
            info!("SOL balance for {}: {} lamports", wallet_address, balance);
            Ok(balance)
        } else {
            error!("Failed to get SOL balance for {}", wallet_address);
            Err("Failed to parse SOL balance".into())
        }
    }

    /// Get token accounts for a wallet address
    pub async fn get_token_accounts(
        &self,
        wallet_address: &str,
    ) -> Result<Vec<TokenAccount>, Box<dyn std::error::Error>> {
        let request_body = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getTokenAccountsByOwner",
            "params": [
                wallet_address,
                {
                    "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
                },
                {
                    "encoding": "jsonParsed"
                }
            ]
        });

        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request_body)
            .send()
            .await?;

        let result: serde_json::Value = response.json().await?;

        if let Some(accounts) = result["result"]["value"].as_array() {
            let mut token_accounts = Vec::new();

            for account in accounts {
                if let Ok(token_account) = serde_json::from_value::<TokenAccount>(account.clone()) {
                    token_accounts.push(token_account);
                }
            }

            info!(
                "Found {} token accounts for {}",
                token_accounts.len(),
                wallet_address
            );
            Ok(token_accounts)
        } else {
            error!("Failed to get token accounts for {}", wallet_address);
            Err("Failed to parse token accounts".into())
        }
    }

    /// Get token balances for a wallet (SOL + all tokens)
    pub async fn get_all_balances(
        &self,
        wallet_address: &str,
    ) -> Result<(u64, Vec<TokenBalance>), Box<dyn std::error::Error>> {
        // Get SOL balance
        let sol_balance = self.get_sol_balance(wallet_address).await?;

        // Get token accounts
        let token_accounts = self.get_token_accounts(wallet_address).await?;

        let mut token_balances = Vec::new();

        for account in token_accounts {
            if let Some(parsed_data) = account.account.data.parsed {
                if let Some(info) = parsed_data.info {
                    let balance = info.token_amount.amount.parse::<u64>().unwrap_or(0);

                    // Only include tokens with non-zero balance
                    if balance > 0 {
                        token_balances.push(TokenBalance {
                            balance,
                            token_mint: info.mint,
                            symbol: "UNKNOWN".to_string(), // Will be filled from database
                            decimals: info.token_amount.decimals,
                        });
                    }
                }
            }
        }

        info!(
            "Wallet {} has {} SOL and {} token types",
            wallet_address,
            sol_balance,
            token_balances.len()
        );
        Ok((sol_balance, token_balances))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAccount {
    pub account: AccountData,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountData {
    pub data: ParsedData,
    pub executable: bool,
    pub lamports: u64,
    pub owner: String,
    pub rent_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedData {
    pub parsed: Option<ParsedInfo>,
    pub program: String,
    pub space: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedInfo {
    pub info: Option<TokenInfo>,
    pub r#type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    pub mint: String,
    pub owner: String,
    pub token_amount: TokenAmount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenAmount {
    pub amount: String,
    pub decimals: i32,
    pub ui_amount: Option<f64>,
    pub ui_amount_string: String,
}
