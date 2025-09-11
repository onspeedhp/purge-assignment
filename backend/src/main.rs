use actix_web::{web, App, HttpServer};
use dotenv::dotenv;
use std::env;
use store::Store;
use tracing::info;
use tracing_subscriber;

mod routes;
use routes::*;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("backend=debug,sqlx=debug,actix_web=info")
        .init();

    dotenv().ok();
    
    let database_url = env::var("DATABASE_URL")
        .expect("DATABASE_URL must be set");
    
    info!("Connecting to database...");
    let pool = sqlx::PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");
    
    info!("Database connected successfully!");
    let store = Store::new(pool);

    info!("Starting server on http://127.0.0.1:8080");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(store.clone()))
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
