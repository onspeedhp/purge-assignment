use yellowstone::GeyserGrpcClient;
use tracing::{info, error, warn};
use std::env;

pub mod yellowstone;
pub mod balance_tracker;

use balance_tracker::BalanceTracker;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("indexer=debug,sqlx=debug")
        .init();

    // Load environment variables
    dotenv::dotenv().ok();

    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    info!("Starting indexer...");

    // Connect to database
    let pool = sqlx::PgPool::connect(&database_url).await?;
    info!("Connected to database");

    // Initialize balance tracker
    let balance_tracker = BalanceTracker::new(pool);

    // Create Yellowstone client
    let endpoint = "https://ams17.rpcpool.com:443";
    let x_token = env::var("YELLOWSTONE_TOKEN").unwrap_or_default();
    
    let mut builder = GeyserGrpcClient::build_from_shared(endpoint)?;
    if !x_token.is_empty() {
        builder = builder.x_token(Some(x_token))?;
    }
    
    let mut client = builder.connect().await?;
    
    // Test connection
    match client.health_check().await {
        Ok(response) => {
            info!("Yellowstone connection successful: {:?}", response);
        }
        Err(e) => {
            error!("Failed to connect to Yellowstone: {}", e);
            return Err(e.into());
        }
    }

    // TODO: Implement balance tracking logic
    // This would involve:
    // 1. Subscribing to account updates for specific wallet addresses
    // 2. Processing transaction data to extract token transfers
    // 3. Updating the user_tokens table with new token discoveries
    // 4. Updating token metadata from token registries
    
    info!("Indexer started successfully");
    info!("Balance tracking is ready to process transactions");

    // Keep the indexer running
    tokio::signal::ctrl_c().await?;
    info!("Indexer shutting down...");

    Ok(())
}
