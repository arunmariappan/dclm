use actix_web::{web, HttpResponse, ResponseError};
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use std::fs;
use uuid::Uuid;
use reqwest::Client;
use sqlx::Postgres;
use thiserror::Error;
use crate::crypto::{hash_private_key, validate_private_key, validate_public_key, CryptoError};
use crate::db::{store_key, DbError};

#[derive(Deserialize)]
pub struct KeyRequest {
    private_key: String,
    public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: u32,
}

#[derive(Serialize)]
struct SecretValue {
    value: String,
}

// Define a struct to match the JSON structure
#[derive(Deserialize, Debug)]
struct Config {
    #[serde(rename = "AZURE_CLIENT_ID")]
    azure_client_id: String,
    #[serde(rename = "AZURE_CLIENT_SECRET")]
    azure_client_secret: String,
    #[serde(rename = "AZURE_TENANT_ID")]
    azure_tenant_id: String,
    #[serde(rename = "KEY_VAULT_URL")]
    key_vault_url: String
}

// Unified error enum for the application
#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DbError(#[from] DbError),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("HTTP request error: {0}")]
    ReqwestError(#[from] reqwest::Error),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

// Implement Actix-Web's ResponseError trait for custom error handling
impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        error!("Error occurred: {}", self);
        HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "hash": null,
            "error": self.to_string()
        }))
    }
}

pub async fn ingest_key_handler(
    req: web::Json<KeyRequest>,
    db_pool: web::Data<sqlx::Pool<Postgres>>,
) -> Result<HttpResponse, AppError> {
    debug!(
        "Received /ingest-key request with private_key (length: {}), public_key (length: {})",
        req.private_key.len(),
        req.public_key.len()
    );

    // Read the appsettings.json file
    debug!("Attempting to read appsettings.json");
    let config_content = fs::read_to_string("appsettings.json")?;
    
    // Deserialize the JSON into the Config struct
    debug!("Deserializing configuration");
    let config: Config = serde_json::from_str(&config_content)?;
    debug!("Configuration loaded successfully: {:?}", config);

    let client_id = &config.azure_client_id;
    let client_secret = &config.azure_client_secret;
    let tenant_id = &config.azure_tenant_id;
    let vault_url = &config.key_vault_url;

    info!("Processing key ingestion for Key Vault URL: {}", vault_url);
    debug!("Tenant ID: {}", tenant_id);

    // Step 1: Validate keys
    validate_private_key(&req.private_key)?;
    validate_public_key(&req.public_key)?;

    // Step 2: Validate secret size (Key Vault limit: 25 KB)
    if req.private_key.len() > 25_000 {
        error!("Private key too large: {} bytes", req.private_key.len());
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "hash": null,
            "error": "Private key exceeds Key Vault size limit (25 KB)"
        })));
    }

    // Step 3: Hash the private key
    let hash = hash_private_key(&req.private_key)?;
    debug!("Generated hash for private key: {}", hash);

    // Step 4: Create HTTP client with proxy settings
    let mut client_builder = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("certificate-management/0.1.0");
    if let Ok(proxy_url) = std::env::var("HTTPS_PROXY").or_else(|_| std::env::var("HTTP_PROXY")) {
        if let Ok(proxy) = reqwest::Proxy::all(&proxy_url) {
            client_builder = client_builder.proxy(proxy);
            debug!("Using proxy for Key Vault request: {}", proxy_url);
        }
    }
    let client = client_builder.build()?;

    // Step 5: Obtain OAuth 2.0 token
    let token_url = format!(
        "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
        tenant_id
    );
    let token_params = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "https://vault.azure.net/.default"),
    ];
    debug!("Requesting token from: {}", token_url);
    let token_response = client
        .post(&token_url)
        .form(&token_params)
        .send()
        .await?
        .json::<TokenResponse>()
        .await?;
    debug!(
        "Received token: type={}, expires_in={}",
        token_response.token_type, token_response.expires_in
    );

    // Step 6: Set secret in Key Vault
    let secret_name = format!("key-{}", Uuid::new_v4());
    let secret_url = format!("{}/secrets/{}?api-version=7.4", vault_url, secret_name);
    let secret_body = SecretValue {
        value: req.private_key.clone(),
    };
    debug!("Setting secret '{}' at: {}", secret_name, secret_url);
    let key_vault_response = client
        .put(&secret_url)
        .header("Authorization", format!("Bearer {}", token_response.access_token))
        .header("Content-Type", "application/json")
        .json(&secret_body)
        .send()
        .await?;

    if !key_vault_response.status().is_success() {
        let status = key_vault_response.status();
        let body = key_vault_response.text().await.unwrap_or_default();
        error!(
            "Failed to set secret '{}': status={}, body={}",
            secret_name, status, body
        );
        return Ok(HttpResponse::BadRequest().json(serde_json::json!({
            "status": "error",
            "hash": null,
            "error": format!("Failed to set secret: status={}, body={}", status, body)
        })));
    }
    info!("Secret '{}' set successfully in Key Vault", secret_name);

    // Step 7: Store hash and public key in PostgreSQL
    store_key(&db_pool, &hash, &req.public_key).await?;
    info!("Stored hash and public key in database");

    // Return success response
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "hash": hash
    })))
}