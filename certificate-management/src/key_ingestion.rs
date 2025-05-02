use actix_web::{web, HttpResponse, Responder};
use azure_identity::ClientSecretCredential;
use azure_security_keyvault::KeyVaultClient;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;

use crate::{
    crypto::{hash_private_key, validate_private_key, validate_public_key, CryptoError},
    db::{store_key_data, DbError},
};

#[derive(Error, Debug)]
pub enum KeyIngestionError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Key Vault error: {0}")]
    KeyVaultError(String),
    #[error("Database error: {0}")]
    DbError(#[from] DbError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[derive(Deserialize)]
pub struct KeyIngestionRequest {
    private_key: String,
    public_key: String,
}

#[derive(Serialize)]
pub struct KeyIngestionResponse {
    status: String,
    hash: Option<String>,
    error: Option<String>,
}

pub async fn ingest_key_handler(
    req: web::Json<KeyIngestionRequest>,
    pool: web::Data<PgPool>,
    credential: web::Data<Arc<ClientSecretCredential>>,
    vault_url: web::Data<String>,
) -> impl Responder {
    match ingest_key(&req, &pool, &credential, &vault_url).await {
        Ok(hash) => HttpResponse::Ok().json(KeyIngestionResponse {
            status: "success".to_string(),
            hash: Some(hash),
            error: None,
        }),
        Err(e) => HttpResponse::BadRequest().json(KeyIngestionResponse {
            status: "error".to_string(),
            hash: None,
            error: Some(e.to_string()),
        }),
    }
}

async fn ingest_key(
    req: &KeyIngestionRequest,
    pool: &PgPool,
    credential: &Arc<ClientSecretCredential>,
    vault_url: &str,
) -> Result<String, KeyIngestionError> {
    // Validate inputs
    validate_private_key(&req.private_key).map_err(|e| {
        KeyIngestionError::ValidationError(format!("Invalid private key: {}", e))
    })?;
    validate_public_key(&req.public_key).map_err(|e| {
        KeyIngestionError::ValidationError(format!("Invalid public key: {}", e))
    })?;

    // Calculate hash
    let hash = hash_private_key(&req.private_key)?;

    // Initialize Key Vault client
    let client = KeyVaultClient::new(vault_url, credential.clone())
        .map_err(|e| KeyIngestionError::KeyVaultError(e.to_string()))?;

    // Store private key in Key Vault
    client
        .set_secret(&hash, &req.private_key)
        .await
        .map_err(|e| KeyIngestionError::KeyVaultError(e.to_string()))?;

    // Store hash and public key in database
    store_key_data(pool, &hash, &req.public_key).await?;

    Ok(hash)
}