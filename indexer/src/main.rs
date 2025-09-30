use actix_web::{App, HttpResponse, HttpServer, web};
use std::{env, sync::Arc};
use store::Store;
use tracing::{error, info};

mod database;
mod handlers;
mod models;
mod subscription;
mod yellowstone_client;

use database::AssetDatabase;
use handlers::IndexerHandlers;
use subscription::SubscriptionService;
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
    let store = Store::new(pool.clone());

    let client = setup_client(geyser_grpc_endpoint)
        .await
        .expect("Failed to connect to Yellowstone client");
    info!("Yellowstone client connected successfully!");

    let client = Arc::new(client);

    let asset_database = Arc::new(AssetDatabase::new(pool));
    let subscription_service = Arc::new(SubscriptionService::new(
        client.clone(),
        asset_database.clone(),
    ));
    let handlers = Arc::new(IndexerHandlers::new(
        asset_database.clone(),
        subscription_service.clone(),
    ));

    let subscriptions = asset_database
        .get_active_subscriptions()
        .await
        .expect("Failed to get active subscriptions");

    for subscription in subscriptions {
        if let Err(e) = subscription_service.start_subscription(subscription).await {
            error!("Failed to start subscription: {:?}", e);
        }
    }

    info!("Starting server on http://127.0.0.1:8090");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(client.clone()))
            .app_data(web::Data::new(handlers.clone()))
            .service(
                web::scope("/api/v1")
                    .route("/subscribe", web::post().to(handle_subscribe))
                    .route("/unsubscribe", web::post().to(handle_unsubscribe)),
            )
            .wrap(tracing_actix_web::TracingLogger::default())
    })
    .bind("127.0.0.1:8090")?
    .run()
    .await
}

// Handler functions
async fn handle_subscribe(
    handlers: web::Data<Arc<IndexerHandlers>>,
    req: web::Json<crate::models::SubscribeRequest>,
) -> actix_web::Result<HttpResponse> {
    handlers.subscribe_to_account(req).await
}

async fn handle_unsubscribe(
    handlers: web::Data<Arc<IndexerHandlers>>,
    req: web::Json<crate::models::UnsubscribeRequest>,
) -> actix_web::Result<HttpResponse> {
    handlers.unsubscribe_from_account(req).await
}
