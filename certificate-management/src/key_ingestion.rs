use actix_web::{web, HttpResponse, ResponseError};
use azure_identity::ClientSecretCredential;
use azure_security_keyvault_secrets::{SecretClient, models::{SetSecretParameters, SecretAttributes}};
use azure_core::credentials::Secret;
use log::{debug, error, info};
use serde::{Deserialize, Serialize};
use sqlx::Postgres;
use thiserror::Error;
use uuid::Uuid;
use typespec_client_core::http::request::RequestContent;

use crate::crypto::{hash_private_key, validate_private_key, validate_public_key, CryptoError};
use crate::db::{store_key, DbError};
use crate::Config;

#[derive(Deserialize)]
pub struct KeyRequest {
    private_key: String,
    public_key: String,
}

#[derive(Serialize)]
pub struct KeyResponse {
    status: String,
    hash: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Database error: {0}")]
    DbError(#[from] DbError),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Key Vault error: {0}")]
    KeyVaultError(String)
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        error!("Error occurred: {:?}", self);
        HttpResponse::InternalServerError().json(KeyResponse {
            status: "error".to_string(),
            hash: None,
            error: Some(self.to_string()),
        })
    }
}

pub async fn ingest_key_handler(
    req: web::Json<KeyRequest>,
    db_pool: web::Data<sqlx::Pool<Postgres>>,
    config: web::Data<Config>,
) -> Result<HttpResponse, AppError> {
    debug!(
        "Received /ingest-key request with private_key (length: {}), public_key (length: {})",
        req.private_key.len(),
        req.public_key.len()
    );

    // Step 1: Validate keys
    validate_private_key(&req.private_key)?;
    validate_public_key(&req.public_key)?;

    // Step 2: Validate secret size (Key Vault limit: 25 KB)
    if req.private_key.len() > 25_000 {
        error!("Private key too large: {} bytes", req.private_key.len());
        return Ok(HttpResponse::BadRequest().json(KeyResponse {
            status: "error".to_string(),
            hash: None,
            error: Some("Private key exceeds Key Vault size limit (25 KB)".to_string()),
        }));
    }

    // Step 3: Sanitize private key
    let private_key = req.private_key.trim();
    if private_key.contains('\0') || !private_key.is_ascii() {
        error!("Private key contains invalid characters: first 50 chars: {:?}", 
               private_key.chars().take(50).collect::<String>());
        return Ok(HttpResponse::BadRequest().json(KeyResponse {
            status: "error".to_string(),
            hash: None,
            error: Some("Private key contains invalid characters".to_string()),
        }));
    }

    // Step 4: Hash the private key
    let hash = hash_private_key(&private_key)?;
    debug!("Generated hash for private key: {}", hash);

    // Step 5: Store secret in Key Vault using Azure SDK with service principal
    let creds = ClientSecretCredential::new(
        config.azure_tenant_id.as_str(),
        config.azure_client_id.clone(),
        Secret::from(config.azure_client_secret.clone()),
        None
    ).map_err(|e| AppError::KeyVaultError(format!("Error creating credential: {}", e)))?;
    let secret_client = SecretClient::new(&config.key_vault_url, creds, None)
        .map_err(|e| AppError::KeyVaultError(format!("Error creating Key Vault client: {}", e)))?;
    let secret_name = format!("key-{}", Uuid::new_v4());
    debug!("Storing secret '{}' in Key Vault, private_key length: {}, first 50 chars: {:?}", 
           secret_name, 
           private_key.len(),
           private_key.chars().take(50).collect::<String>()
    );

    // Set actual private key with tags
    let params = SetSecretParameters {
        value: Some(private_key.to_string()),
        tags: Some(std::collections::HashMap::from([("hash".to_string(), hash.clone())])),
        content_type: None,
        secret_attributes: Some(SecretAttributes::default()),
    };
    match secret_client
        .set_secret(&secret_name, RequestContent::from(serde_json::to_vec(&params).map_err(|e| AppError::KeyVaultError(format!("Serialization error: {}", e)))?), None)
        .await
    {
        Ok(_) => info!("Secret '{}' stored in Key Vault with hash tag", secret_name),
        Err(e) => {
            error!("Key Vault set secret failed: {:?}", e);
            return Err(AppError::KeyVaultError(format!("Key Vault set secret failed: {}", e)));
        }
    }

    // Step 6: Store hash and public key in PostgreSQL
    store_key(&db_pool, &hash, &req.public_key, &secret_name).await?;
    info!("Stored hash, public key, and secret name in database");

    // Step 7: Return success response
    Ok(HttpResponse::Ok().json(KeyResponse {
        status: "success".to_string(),
        hash: Some(hash),
        error: None,
    }))
}