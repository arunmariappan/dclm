use actix_web::{web, HttpResponse, Responder};
use azure_identity::ClientSecretCredential;
use azure_security_keyvault::KeyVaultClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

use crate::crypto::{format_pem, format_pfx, validate_certificate, CryptoError};

#[derive(Error, Debug)]
pub enum CertificateFormattingError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Key Vault error: {0}")]
    KeyVaultError(String),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[derive(Deserialize)]
pub struct CertificateFormattingRequest {
    certificate: String,
    hash: String,
    format: String,
}

#[derive(Serialize)]
pub struct CertificateFormattingResponse {
    status: String,
    certificate: Option<String>,
    password: Option<String>,
    error: Option<String>,
}

pub async fn format_certificate_handler(
    req: web::Json<CertificateFormattingRequest>,
    credential: web::Data<Arc<ClientSecretCredential>>,
    vault_url: web::Data<String>,
) -> impl Responder {
    match format_certificate(&req, &credential, &vault_url).await {
        Ok((certificate, password)) => HttpResponse::Ok().json(CertificateFormattingResponse {
            status: "success".to_string(),
            certificate: Some(certificate),
            password,
            error: None,
        }),
        Err(e) => HttpResponse::BadRequest().json(CertificateFormattingResponse {
            status: "error".to_string(),
            certificate: None,
            password: None,
            error: Some(e.to_string()),
        }),
    }
}

async fn format_certificate(
    req: &CertificateFormattingRequest,
    credential: &Arc<ClientSecretCredential>,
    vault_url: &str,
) -> Result<(String, Option<String>), CertificateFormattingError> {
    // Validate inputs
    validate_certificate(&req.certificate).map_err(|e| {
        CertificateFormattingError::ValidationError(format!("Invalid certificate: {}", e))
    })?;
    if !["PEM", "PFX"].contains(&req.format.as_str()) {
        return Err(CertificateFormattingError::ValidationError(
            "Invalid format: must be PEM or PFX".to_string(),
        ));
    }

    // Initialize Key Vault client
    let client = KeyVaultClient::new(vault_url, credential.clone())
        .map_err(|e| CertificateFormattingError::KeyVaultError(e.to_string()))?;

    // Retrieve private key from Key Vault
    let secret = client
        .get_secret(&req.hash)
        .await
        .map_err(|e| CertificateFormattingError::KeyVaultError(e.to_string()))?;
    let private_key = secret.value;

    // Format certificate
    match req.format.as_str() {
        "PEM" => {
            let pem = format_pem(&private_key, &req.certificate)?;
            Ok((pem, None))
        }
        "PFX" => {
            let (pfx, password) = format_pfx(&private_key, &req.certificate)?;
            Ok((pfx, Some(password)))
        }
        _ => unreachable!(),
    }
}