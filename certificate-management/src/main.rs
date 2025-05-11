mod db;
mod key_ingestion;
mod certificate_formatting;
mod crypto;

use actix_web::{web, App, HttpServer};
use db::init_db_pool;
use key_ingestion::ingest_key_handler;
use certificate_formatting::format_certificate_handler;
use log::{info, debug};
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Clone, Debug)]
pub struct Config {
    #[serde(rename = "AZURE_CLIENT_ID")]
    azure_client_id: String,
    #[serde(rename = "AZURE_CLIENT_SECRET")]
    azure_client_secret: String,
    #[serde(rename = "AZURE_TENANT_ID")]
    azure_tenant_id: String,
    #[serde(rename = "KEY_VAULT_URL")]
    key_vault_url: String,
    #[serde(rename = "DATABASE_URL")]
    database_url: String,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug")).init();
    info!("Starting certificate management microservices...");

    let config_content = fs::read_to_string("appsettings.json")?;
    let config: Config = serde_json::from_str(&config_content)?;
    debug!("Configuration loaded: {:?}", config);

    let db_pool = init_db_pool(&config.database_url)
        .await
        .expect("Failed to initialize database pool");

    let config_data = web::Data::new(config.clone());
    let db_pool_data = web::Data::new(db_pool);

    HttpServer::new(move || {
        App::new()
            .app_data(config_data.clone())
            .app_data(db_pool_data.clone())
            .route("/ingest-key", web::post().to(ingest_key_handler))
            .route("/format-certificate", web::post().to(format_certificate_handler))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}