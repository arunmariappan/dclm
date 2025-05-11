mod db;
mod key_ingestion;
mod certificate_formatting;
mod crypto;

use actix_web::{web, App, HttpServer};
use db::init_db_pool;
use key_ingestion::ingest_key_handler;
use certificate_formatting::format_certificate_handler;
use log::{info, debug, error};
use sqlx::Postgres;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging with debug level
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    info!("Starting certificate management microservices...");

    // Log proxy settings
    if let Ok(proxy) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("HTTP_PROXY")) {
        debug!("Using proxy: {}", proxy);
    } else {
        debug!("No proxy configured");
    }

    // Initialize database pool
    let db_pool = init_db_pool().await.expect("Failed to initialize database pool");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .route("/ingest-key", web::post().to(ingest_key_handler))
            .route("/format-certificate", web::post().to(format_certificate_handler))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}