use actix_web::{App, HttpServer, web};
use std::{env, sync::Arc};
use store::Store;
use tracing::{error, info};
use yellowstone_grpc_client::{ClientTlsConfig, GeyserGrpcClient};

mod yellowstone_client;
use yellowstone_client::*;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("indexer=debug,sqlx=debug")
        .init();

    dotenv::dotenv().ok();

    if let Err(e) = dotenv::from_path(".env") {
        eprintln!("Warning: Could not load indexer/.env file: {}", e);
        eprintln!("Make sure indexer/.env exists with DATABASE_URL");
    }

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let geyser_grpc_endpoint =
        env::var("GEYSER_GRPC_ENDPOINT").expect("GEYSER_GRPC_ENDPOINT must be set");

    info!("Connecting to database... {}", database_url);
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    info!("Database connected successfully!");
    let store = Store::new(pool);

    let client = setup_client(geyser_grpc_endpoint)
        .await
        .expect("Failed to connect to Yellowstone client");
    info!("Yellowstone client connected successfully!");

    let client = Arc::new(client);

    info!("Starting server on http://127.0.0.1:8090");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(client.clone()))
            .wrap(tracing_actix_web::TracingLogger::default())
    })
    .bind("127.0.0.1:8090")?
    .run()
    .await
}
