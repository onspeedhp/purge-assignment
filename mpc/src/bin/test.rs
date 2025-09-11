//! # FROST MPC Complete Test
//!
//! This is the ONLY test you need to run.
//! It tests the complete distributed MPC flow using real API calls.

use frost_mpc::distributed_mpc::DistributedMPC;
use frost_mpc::solana::SolanaMPCClient;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{pubkey::Pubkey, system_instruction, transaction::Transaction};
use std::process::Command;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== FROST MPC Complete Test ===");
    println!("This tests the complete distributed MPC flow");
    println!();

    // Step 1: Setup databases
    println!("Step 1: Setting up databases...");
    let output = Command::new("./setup_databases.sh")
        .output()
        .expect("Failed to run setup_databases.sh");

    if !output.status.success() {
        println!("❌ Database setup failed");
        return Err("Database setup failed".into());
    }
    println!("✅ Databases created successfully");

    // Step 2: Check if servers are running
    println!("\nStep 2: Checking if servers are running...");
    let mut servers_running = 0;
    for port in [8081, 8082, 8083] {
        match reqwest::get(&format!("http://localhost:{}/health", port)).await {
            Ok(resp) if resp.status().is_success() => {
                println!("  ✅ Server {} is running", port);
                servers_running += 1;
            }
            _ => {
                println!("  ❌ Server {} is not running", port);
            }
        }
    }

    if servers_running == 0 {
        println!("\n❌ No servers are running!");
        println!("Please start 3 MPC servers:");
        println!("  Terminal 1: cargo run --bin frost-mpc -- --port 8081");
        println!("  Terminal 2: cargo run --bin frost-mpc -- --port 8082");
        println!("  Terminal 3: cargo run --bin frost-mpc -- --port 8083");
        println!("\nThen run this test again: cargo run --bin test");
        return Ok(());
    } else if servers_running < 3 {
        println!(
            "\n⚠️  Only {}/3 servers are running. Some tests may fail.",
            servers_running
        );
    }

    // Step 3: Test FROST distributed MPC using real API
    println!("\nStep 3: Testing FROST Distributed MPC...");
    test_frost_distributed_mpc().await?;

    // Step 4: Test Solana integration with Faucet and On-Chain Transaction
    println!("\nStep 4: Testing Solana Integration with Faucet and On-Chain Transaction...");
    test_solana_mpc_with_faucet().await?;

    println!("\n🎉 ALL TESTS PASSED!");
    println!("✅ FROST MPC is working correctly");
    println!("✅ Solana integration is working correctly");
    println!("✅ Distributed signing is working correctly");

    Ok(())
}

/// Test FROST distributed MPC using real API calls
async fn test_frost_distributed_mpc() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Creating DistributedMPC instance...");
    let mut mpc = DistributedMPC::new();

    println!("  Testing key generation...");
    let user_id = "test_user_123";
    let threshold = 2; // 2 out of 3 threshold

    let keygen_result = mpc.generate_key_shares(user_id, threshold).await?;
    println!("    ✅ Key generation successful");
    println!(
        "    Group public key: {}",
        hex::encode(&keygen_result.group_public_key)
    );
    println!("    Participants: {:?}", keygen_result.participants);

    println!("  Testing message signing...");
    let message = b"Hello, FROST MPC!";
    let session_id = "test_session_123";

    let signing_result = mpc.sign_message(user_id, message, session_id).await?;
    println!("    ✅ Message signing successful");
    println!(
        "    Message: {}",
        String::from_utf8_lossy(&signing_result.message)
    );
    println!("    Signature: {}", hex::encode(&signing_result.signature));
    println!("    Signature valid: {}", signing_result.is_valid);

    if !signing_result.is_valid {
        return Err("Signature verification failed".into());
    }

    println!("  ✅ FROST distributed MPC test passed!");
    Ok(())
}

/// Test Solana MPC integration using real API calls
async fn test_solana_mpc() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Creating SolanaMPCClient instance...");
    let mut solana_mpc = SolanaMPCClient::new();

    println!("  Testing Solana keypair generation...");
    let user_id = "solana_test_user_123";
    let threshold = 2; // 2 out of 3 threshold

    let keypair = solana_mpc
        .generate_solana_keypair(user_id, threshold)
        .await?;
    println!("    ✅ Solana keypair generation successful");
    println!("    Solana public key: {}", keypair.pubkey());

    println!("  Testing Solana transaction signing...");
    use solana_sdk::{hash::Hash, pubkey::Pubkey};

    let to_pubkey = Pubkey::new_unique();
    let _recent_blockhash = Hash::new_unique();
    let transaction = SolanaMPCClient::create_transfer_transaction(
        keypair.pubkey(),
        &to_pubkey,
        1_000_000, // 0.001 SOL
    );

    let session_id = "solana_test_session_123";
    let signing_result = solana_mpc
        .sign_solana_transaction(user_id, &keypair, &transaction, session_id)
        .await?;

    println!("    ✅ Solana transaction signing successful");
    println!("    Transaction signature: {}", signing_result.signature);
    println!("    Signature valid: {}", signing_result.is_valid);

    if !signing_result.is_valid {
        return Err("Solana signature verification failed".into());
    }

    println!("  ✅ Solana MPC test passed!");
    Ok(())
}

/// Test Solana MPC with Faucet and On-Chain Transaction
async fn test_solana_mpc_with_faucet() -> Result<(), Box<dyn std::error::Error>> {
    println!("  Creating Solana MPC client...");
    let mut solana_mpc = SolanaMPCClient::new();

    println!("  Generating FROST keypair...");
    let user_id = "faucet_test_user_456";
    let threshold = 2; // Use 2-of-3 threshold
    let keypair = solana_mpc
        .generate_solana_keypair(user_id, threshold)
        .await?;

    println!("  FROST Public Key: {}", keypair.pubkey());
    println!(
        "  FROST Public Key (hex): {}",
        hex::encode(keypair.pubkey().to_bytes())
    );

    // Step 1: Request SOL from faucet
    println!("  Step 1: Requesting SOL from faucet...");
    let faucet_url = "http://localhost:8899"; // Local Solana test validator
    let rpc_client = RpcClient::new(faucet_url.to_string());

    // Check if we can connect to local validator
    match rpc_client.get_health() {
        Ok(_) => println!("  ✅ Connected to local Solana validator"),
        Err(e) => {
            println!("  ❌ Cannot connect to local Solana validator: {}", e);
            println!("  Please start local validator with: solana-test-validator");
            return Err("Local validator not running".into());
        }
    }

    // Request airdrop from faucet
    let lamports = 1_000_000_000; // 1 SOL
    println!("  Requesting {} lamports from faucet...", lamports);

    match rpc_client.request_airdrop(&keypair.pubkey(), lamports) {
        Ok(signature) => {
            println!("  ✅ Airdrop successful! Signature: {}", signature);

            // Wait for confirmation
            println!("  Waiting for confirmation...");
            match rpc_client.confirm_transaction(&signature) {
                Ok(confirmed) => {
                    if confirmed {
                        println!("  ✅ Transaction confirmed!");
                    } else {
                        println!("  ⚠️  Transaction not confirmed yet");
                    }
                }
                Err(e) => println!("  ⚠️  Could not confirm transaction: {}", e),
            }
        }
        Err(e) => {
            println!("  ❌ Airdrop failed: {}", e);
            return Err("Faucet request failed".into());
        }
    }

    // Step 2: Check balance
    println!("  Step 2: Checking balance...");
    match rpc_client.get_balance(&keypair.pubkey()) {
        Ok(balance) => {
            println!(
                "  Current balance: {} lamports ({} SOL)",
                balance,
                balance as f64 / 1_000_000_000.0
            );
        }
        Err(e) => {
            println!("  ⚠️  Could not get balance: {}", e);
        }
    }

    // Step 3: Create a transaction to send SOL to another address
    println!("  Step 3: Creating transfer transaction...");
    let recipient = Pubkey::new_unique();
    println!("  Recipient address: {}", recipient);

    // Get recent blockhash
    let recent_blockhash = rpc_client.get_latest_blockhash()?;
    println!("  Recent blockhash: {}", recent_blockhash);

    // Create transfer instruction
    let transfer_instruction = system_instruction::transfer(
        &keypair.pubkey(),
        &recipient,
        100_000_000, // 0.1 SOL
    );

    // Create transaction
    let mut transaction =
        Transaction::new_with_payer(&[transfer_instruction], Some(&keypair.pubkey()));
    transaction.message.recent_blockhash = recent_blockhash;

    println!("  Transaction created, signing with FROST MPC...");

    // Step 4: Sign transaction with FROST MPC
    let session_id = "faucet_test_session_456";
    let signing_result = solana_mpc
        .sign_solana_transaction(user_id, &keypair, &transaction, session_id)
        .await?;

    println!("  ✅ FROST MPC signing successful!");
    println!("  Transaction signature: {}", signing_result.signature);
    println!("  Signature valid: {}", signing_result.is_valid);

    if !signing_result.is_valid {
        return Err("FROST signature verification failed".into());
    }

    // Step 5: Send transaction to network
    println!("  Step 5: Sending transaction to localhost network...");

    // The signing_result already contains the signed transaction
    let signed_transaction = &signing_result.transaction;

    // Send transaction
    match rpc_client.send_and_confirm_transaction(signed_transaction) {
        Ok(signature) => {
            println!("  ✅ Transaction sent successfully!");
            println!("  Transaction signature: {}", signature);

            // Check final balances
            println!("  Checking final balances...");
            if let Ok(sender_balance) = rpc_client.get_balance(&keypair.pubkey()) {
                println!(
                    "  Sender balance: {} lamports ({} SOL)",
                    sender_balance,
                    sender_balance as f64 / 1_000_000_000.0
                );
            }
            if let Ok(recipient_balance) = rpc_client.get_balance(&recipient) {
                println!(
                    "  Recipient balance: {} lamports ({} SOL)",
                    recipient_balance,
                    recipient_balance as f64 / 1_000_000_000.0
                );
            }
        }
        Err(e) => {
            println!("  ❌ Transaction failed: {}", e);
            return Err(format!("Transaction failed: {}", e).into());
        }
    }

    println!("  ✅ Complete Solana MPC with Faucet test passed!");
    Ok(())
}
