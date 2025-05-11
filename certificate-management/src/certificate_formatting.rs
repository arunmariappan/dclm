use actix_web::{web, HttpResponse, ResponseError};
use azure_identity::ClientSecretCredential;
use azure_security_keyvault_secrets::SecretClient;
use azure_core::credentials::Secret;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{format_pem, format_pfx, validate_certificate, CryptoError};
use crate::db::{get_secret_name, DbError};
use crate::Config;

#[derive(Deserialize)]
pub struct CertificateRequest {
    hash: String,
    certificate: String,
    format: String,
}

#[derive(Serialize)]
pub struct CertificateResponse {
    status: String,
    formatted_certificate: Option<String>,
    pfx_password: Option<String>,
    error: Option<String>,
}

#[derive(Debug, Error)]
pub enum CertificateFormattingError {
    #[error("Key Vault error: {0}")]
    KeyVaultError(String),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
    #[error("Database error: {0}")]
    DbError(#[from] DbError),
}

impl ResponseError for CertificateFormattingError {
    fn error_response(&self) -> HttpResponse {
        error!("Error occurred: {:?}", self);
        HttpResponse::BadRequest().json(CertificateResponse {
            status: "error".to_string(),
            formatted_certificate: None,
            pfx_password: None,
            error: Some(self.to_string()),
        })
    }
}

pub async fn format_certificate_handler(
    req: web::Json<CertificateRequest>,
    db_pool: web::Data<sqlx::Pool<sqlx::Postgres>>,
    config: web::Data<Config>,
) -> Result<HttpResponse, CertificateFormattingError> {
    debug!(
        "Received /format-certificate request with hash: {}, format: {}",
        req.hash, req.format
    );

    // Step 1: Validate certificate
    validate_certificate(&req.certificate)?;

    // Step 2: Retrieve secret name from database
    let secret_name = get_secret_name(&db_pool, &req.hash).await?;
    debug!("Retrieved secret name: {}", secret_name);

    // Validate secret name (Key Vault names: alphanumeric, hyphens, 1-127 chars)
    if !secret_name.chars().all(|c| c.is_alphanumeric() || c == '-') || secret_name.len() > 127 {
        return Err(CertificateFormattingError::KeyVaultError(
            format!("Invalid secret name: {}", secret_name)
        ));
    }

    // Step 3: Retrieve private key from Key Vault
    let creds = ClientSecretCredential::new(
        config.azure_tenant_id.as_str(),
        config.azure_client_id.clone(),
        Secret::from(config.azure_client_secret.clone()),
        None,
    )
    .map_err(|e| CertificateFormattingError::KeyVaultError(format!("Error creating credential: {}", e)))?;
    let secret_client = SecretClient::new(&config.key_vault_url, creds, None)
        .map_err(|e| CertificateFormattingError::KeyVaultError(format!("Error creating Key Vault client: {}", e)))?;

    debug!("Fetching secret '{}' from Key Vault URL: {}", secret_name, config.key_vault_url);

    let secret_response = secret_client
        .get_secret(&secret_name, "", None)  // Pass an empty string "" or None for the secret version
        .await
        .map_err(|e| CertificateFormattingError::KeyVaultError(format!("Error retrieving key: {}", e)))?;

    
    // Extract secret body
    let secret = secret_response
        .into_body()
        .await
        .map_err(|e| CertificateFormattingError::KeyVaultError(format!("Error extracting secret body: {}", e)))?;

    // Access the secret value safely
    let private_key = secret.value.unwrap_or_default();
    debug!("Retrieved private key from Key Vault (length: {})", private_key.len());

    // Step 4: Format certificate based on requested format
    match req.format.to_lowercase().as_str() {
        "pem" => {
            let formatted = format_pem(&private_key, &req.certificate)?;
            Ok(HttpResponse::Ok().json(CertificateResponse {
                status: "success".to_string(),
                formatted_certificate: Some(formatted),
                pfx_password: None,
                error: None,
            }))
        }
        "pfx" => {
            let (pfx_data, password) = format_pfx(&private_key, &req.certificate)?;
            Ok(HttpResponse::Ok().json(CertificateResponse {
                status: "success".to_string(),
                formatted_certificate: Some(pfx_data),
                pfx_password: Some(password),
                error: None,
            }))
        }
        _ => Ok(HttpResponse::BadRequest().json(CertificateResponse {
            status: "error".to_string(),
            formatted_certificate: None,
            pfx_password: None,
            error: Some("Invalid format: must be 'pem' or 'pfx'".to_string()),
        })),
    }
}