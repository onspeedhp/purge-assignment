use actix_web::{web, App, HttpServer};
use std::env;
use store::{Store, redis::RedisStore};
use tracing::info;
use tracing_subscriber;
use redis::Client as RedisClient;

mod routes;
mod auth;
mod solana_client;
use routes::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("backend=debug,sqlx=debug,actix_web=info")
        .init();

    if let Err(e) = dotenv::from_path(".env") {
        eprintln!("Warning: Could not load backend/.env file: {}", e);
        eprintln!("Make sure backend/.env exists with DATABASE_URL, JWT_SECRET, and REDIS_URL");
    }
    
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    let redis_url = env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379/".to_string());
    
    info!("Connecting to database... {}", database_url);
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    info!("Database connected successfully!");
    let store = Store::new(pool);

    info!("Connecting to Redis... {}", redis_url);
    let redis_client = RedisClient::open(redis_url)
        .expect("Failed to create Redis client");
    
    info!("Redis client created successfully!");
    let redis_store = RedisStore::new(redis_client);

    info!("Starting server on http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(redis_store.clone()))
            .wrap(tracing_actix_web::TracingLogger::default())
            .service(sign_up)  
            .service(sign_in)
            .service(get_user)
            .service(quote)
            .service(swap)
            .service(sol_balance)
            .service(token_balance)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
