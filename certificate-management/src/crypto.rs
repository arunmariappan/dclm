use base64::{engine::general_purpose, Engine as _};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::{Digest, Sha512};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("OpenSSL error: {0}")]
    OpenSslError(#[from] openssl::error::ErrorStack),
}

pub fn hash_private_key(private_key: &str) -> Result<String, CryptoError> {
    let mut hasher = Sha512::new();
    hasher.update(private_key);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

pub fn validate_private_key(private_key: &str) -> Result<(), CryptoError> {
    let key_bytes = general_purpose::STANDARD
        .decode(private_key)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    PKey::private_key_from_pem(&key_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    Ok(())
}

pub fn validate_public_key(public_key: &str) -> Result<(), CryptoError> {
    let key_bytes = general_purpose::STANDARD
        .decode(public_key)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    PKey::public_key_from_pem(&key_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    Ok(())
}

pub fn validate_certificate(cert: &str) -> Result<(), CryptoError> {
    let cert_bytes = general_purpose::STANDARD
        .decode(cert)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    X509::from_pem(&cert_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    Ok(())
}

pub fn format_pem(private_key: &str, cert: &str) -> Result<String, CryptoError> {
    let private_key_bytes = general_purpose::STANDARD
        .decode(private_key)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let cert_bytes = general_purpose::STANDARD
        .decode(cert)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let pem = format!(
        "{}\n{}",
        String::from_utf8(private_key_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?,
        String::from_utf8(cert_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?
    );
    Ok(general_purpose::STANDARD.encode(pem))
}

pub fn format_pfx(private_key: &str, cert: &str) -> Result<(String, String), CryptoError> {
    let private_key_bytes = general_purpose::STANDARD
        .decode(private_key)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let cert_bytes = general_purpose::STANDARD
        .decode(cert)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    let pkey = PKey::private_key_from_pem(&private_key_bytes)?;
    let x509 = X509::from_pem(&cert_bytes)?;
    let password: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect();
    let pkcs12 = Pkcs12::builder()
        .build(&password, "certificate", &pkey, &x509)?;
    let pfx_der = pkcs12.to_der()?;
    Ok((general_purpose::STANDARD.encode(pfx_der), password))
}