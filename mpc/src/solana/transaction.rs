use crate::error::Error;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    instruction::Instruction, message::Message, pubkey::Pubkey, transaction::Transaction,
    system_instruction,
};
use std::str::FromStr;

/// Create a Solana transfer transaction
/// Equivalent to createTransferTx() in TypeScript
pub async fn create_transfer_tx(
    rpc_client: &RpcClient,
    from: Pubkey,
    to: Pubkey,
    lamports: u64,
) -> Result<Transaction, Error> {
    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .map_err(Error::RecentHashFailed)?;

    let instruction = system_instruction::transfer(&from, &to, lamports);
    let message = Message::new(&[instruction], Some(&from));
    let mut transaction = Transaction::new_unsigned(message);
    transaction.message.recent_blockhash = recent_blockhash;

    Ok(transaction)
}

/// Create a transfer transaction with memo
/// Equivalent to createTransferTx() with memo in TypeScript
pub async fn create_transfer_tx_with_memo(
    rpc_client: &RpcClient,
    from: Pubkey,
    to: Pubkey,
    lamports: u64,
    memo: &str,
) -> Result<Transaction, Error> {
    let recent_blockhash = rpc_client
        .get_latest_blockhash()
        .map_err(Error::RecentHashFailed)?;

    let transfer_instruction = system_instruction::transfer(&from, &to, lamports);

    // Memo program instruction (like TypeScript)
    let memo_instruction = Instruction {
        program_id: Pubkey::from_str("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr").map_err(
            |_| {
                Error::BadBase58(bs58::decode::Error::InvalidCharacter {
                    character: ' ',
                    index: 0,
                })
            },
        )?,
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    };

    let message = Message::new(&[transfer_instruction, memo_instruction], Some(&from));
    let mut transaction = Transaction::new_unsigned(message);
    transaction.message.recent_blockhash = recent_blockhash;

    Ok(transaction)
}

/// Create a transaction from transaction details
/// Equivalent to createTransactionFromDetails() in TypeScript
pub async fn create_transaction_from_details(
    rpc_client: &RpcClient,
    details: &crate::tss::types::TSSTransactionDetails,
) -> Result<Transaction, Error> {
    let lamports = (details.amount * 1_000_000_000.0) as u64; // Convert SOL to lamports

    let mut transaction = if let Some(ref memo) = details.memo {
        create_transfer_tx_with_memo(rpc_client, details.from, details.to, lamports, memo).await?
    } else {
        create_transfer_tx(rpc_client, details.from, details.to, lamports).await?
    };

    // Set the specific blockhash (like TypeScript tx.recentBlockhash = details.recentBlockhash)
    if let Ok(blockhash) = details.recent_blockhash.parse::<solana_sdk::hash::Hash>() {
        transaction.message.recent_blockhash = blockhash;
    }

    Ok(transaction)
}

/// Convert SOL to lamports
/// Equivalent to LAMPORTS_PER_SOL conversion in TypeScript
pub fn sol_to_lamports(sol: f64) -> u64 {
    (sol * 1_000_000_000.0) as u64
}

/// Convert lamports to SOL
/// Equivalent to balance / LAMPORTS_PER_SOL in TypeScript
pub fn lamports_to_sol(lamports: u64) -> f64 {
    lamports as f64 / 1_000_000_000.0
}

/// Format balance for display
/// Equivalent to formatBalance() in TypeScript
pub fn format_balance(lamports: u64) -> String {
    let sol = lamports_to_sol(lamports);
    format!("{:.9} SOL", sol)
}

/// Validate a public key string
/// Equivalent to validatePublicKey() in TypeScript
pub fn validate_public_key(key_string: &str) -> Result<Pubkey, Error> {
    key_string.parse().map_err(|_| {
        Error::BadBase58(bs58::decode::Error::InvalidCharacter {
            character: ' ',
            index: 0,
        })
    })
}

