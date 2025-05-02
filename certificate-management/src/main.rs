mod db;
mod crypto;
mod key_ingestion;
mod certificate_formatting;

use actix_web::{web, App, HttpServer};
use azure_identity::{ClientSecretCredential, TokenCredentialOptions};
use db::init_db_pool;
use key_ingestion::ingest_key_handler;
use certificate_formatting::format_certificate_handler;
use log::info;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load .env file
    dotenv::dotenv().ok(); // .ok() ignores errors if .env file is missing
    env_logger::init();
    info!("Starting certificate management microservices...");

    // Initialize database pool
    let db_pool = init_db_pool().await.expect("Failed to initialize database pool");

    // Initialize Azure credentials
    let credential = Arc::new(ClientSecretCredential::new(
        azure_core::new_http_client(),
        std::env::var("AZURE_CLIENT_ID").expect("AZURE_CLIENT_ID not set"),
        std::env::var("AZURE_CLIENT_SECRET").expect("AZURE_CLIENT_SECRET not set"),
        std::env::var("AZURE_TENANT_ID").expect("AZURE_TENANT_ID not set"),
        TokenCredentialOptions::default(),
    ));

    let vault_url = std::env::var("KEY_VAULT_URL").expect("KEY_VAULT_URL not set");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db_pool.clone()))
            .app_data(web::Data::new(credential.clone()))
            .app_data(web::Data::new(vault_url.clone()))
            .route("/ingest-key", web::post().to(ingest_key_handler))
            .route("/format-certificate", web::post().to(format_certificate_handler))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}