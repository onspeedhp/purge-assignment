use yellowstone_grpc_client::{GeyserGrpcClient, ClientTlsConfig};
use tracing::{info, error};
use std::env;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("indexer=debug,sqlx=debug")
        .init();

    dotenv::dotenv().ok();

    if let Err(e) = dotenv::from_path(".env") {
        eprintln!("Warning: Could not load indexer/.env file: {}", e);
        eprintln!("Make sure indexer/.env exists with DATABASE_URL");
    }
    
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");

    Ok(())
}
