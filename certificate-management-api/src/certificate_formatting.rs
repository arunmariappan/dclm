use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::crypto::{format_pem, format_pfx, validate_certificate, CryptoError};

#[derive(Debug, Error)]
pub enum CertificateFormattingError {
    #[error("Validation error: {0}")]
    ValidationError(String),
    #[error("Key Vault error: {0}")]
    KeyVaultError(String),
    #[error("Crypto error: {0}")]
    CryptoError(#[from] CryptoError),
}

#[derive(Deserialize)]
pub struct CertificateRequest {
    private_key: String, // Added to match format_pem/format_pfx
    certificate: String,
    format: String,
}

#[derive(Serialize)]
pub struct CertificateResponse {
    formatted_certificate: Option<String>,
    pfx_password: Option<String>, // Added for PFX password
    error: Option<String>,
}

pub async fn format_certificate_handler(
    req: web::Json<CertificateRequest>,
) -> HttpResponse {
    match validate_certificate(&req.certificate) {
        Ok(_) => match req.format.as_str() {
            "pem" => match format_pem(&req.private_key, &req.certificate) {
                Ok(formatted) => HttpResponse::Ok().json(CertificateResponse {
                    formatted_certificate: Some(formatted),
                    pfx_password: None,
                    error: None,
                }),
                Err(e) => HttpResponse::BadRequest().json(CertificateResponse {
                    formatted_certificate: None,
                    pfx_password: None,
                    error: Some(e.to_string()),
                }),
            },
            "pfx" => match format_pfx(&req.private_key, &req.certificate) {
                Ok((pfx_data, password)) => HttpResponse::Ok().json(CertificateResponse {
                    formatted_certificate: Some(pfx_data),
                    pfx_password: Some(password),
                    error: None,
                }),
                Err(e) => HttpResponse::BadRequest().json(CertificateResponse {
                    formatted_certificate: None,
                    pfx_password: None,
                    error: Some(e.to_string()),
                }),
            },
            _ => HttpResponse::BadRequest().json(CertificateResponse {
                formatted_certificate: None,
                pfx_password: None,
                error: Some("Invalid format".to_string()),
            }),
        },
        Err(e) => HttpResponse::BadRequest().json(CertificateResponse {
            formatted_certificate: None,
            pfx_password: None,
            error: Some(e.to_string()),
        }),
    }
}