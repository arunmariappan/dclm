use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;
use rand::Rng;
use sha2::{Digest, Sha512};
use thiserror::Error;
use zeroize::Zeroize;

/// Custom error type for cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid certificate format: {0}")]
    InvalidCertificate(String),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("Key pair mismatch")]
    KeyPairMismatch,
    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
}

/// Validates a Base64-encoded PEM certificate.
pub fn validate_certificate(certificate: &str) -> Result<(), CryptoError> {
    let certificate = certificate.trim();
    // Decode Base64
    let decoded = BASE64
        .decode(certificate)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Base64 decode failed: {}", e)))?;
    // Parse as PEM
    let cert = X509::from_pem(&decoded)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse PEM certificate: {}", e)))?;
    // Verify public key presence
    if cert.public_key().is_err() {
        return Err(CryptoError::InvalidCertificate("Invalid public key in certificate".to_string()));
    }
    Ok(())
}

/// Validates a Base64-encoded PEM private key.
pub fn validate_private_key(private_key: &str) -> Result<(), CryptoError> {
    let private_key = private_key.trim();
    // Check for null bytes
    if private_key.contains('\0') {
        return Err(CryptoError::InvalidKey("Private key contains null bytes".to_string()));
    }
    // Decode Base64
    let decoded = BASE64
        .decode(private_key)
        .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
    // Parse as PEM
    let _pkey = PKey::private_key_from_pem(&decoded)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?;
    // Note: Cannot zeroize PKey<Private> due to missing Zeroize trait implementation in openssl crate.
    // Consider alternative libraries or custom implementation for production.
    Ok(())
}

/// Validates a Base64-encoded PEM public key.
pub fn validate_public_key(public_key: &str) -> Result<(), CryptoError> {
    let public_key = public_key.trim();
    // Check for null bytes
    if public_key.contains('\0') {
        return Err(CryptoError::InvalidKey("Public key contains null bytes".to_string()));
    }
    // Decode Base64
    let decoded = BASE64
        .decode(public_key)
        .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
    // Parse as PEM
    let _pkey = PKey::public_key_from_pem(&decoded)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM public key: {}", e)))?;
    // No zeroization for public key (not sensitive)
    Ok(())
}

/// Computes SHA-512 hash of a private key.
pub fn hash_private_key(private_key: &str) -> Result<String, CryptoError> {
    let mut hasher = Sha512::new();
    hasher.update(private_key);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

/// Verifies that a private key matches a certificate's public key.
pub fn verify_key_pair(private_key: &PKey<Private>, cert: &X509) -> Result<(), CryptoError> {
    let cert_pubkey = cert
        .public_key()
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to get certificate public key: {}", e)))?;
    let private_pubkey = private_key
        .public_key_to_pem()
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to get private key's public key: {}", e)))?;
    let cert_pubkey_pem = cert_pubkey
        .public_key_to_pem()
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to encode certificate public key: {}", e)))?;
    if private_pubkey != cert_pubkey_pem {
        return Err(CryptoError::KeyPairMismatch);
    }
    Ok(())
}

/// Formats a private key and certificate into PEM format.
pub fn format_pem(private_key: &str, certificate: &str) -> Result<String, CryptoError> {
    let private_key = private_key.trim();
    let certificate = certificate.trim();

    // Validate inputs
    validate_private_key(private_key)?;
    validate_certificate(certificate)?;

    // Decode Base64 for private key
    let private_key_decoded = BASE64
        .decode(private_key)
        .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
    // Parse private key
    let pkey = PKey::private_key_from_pem(&private_key_decoded)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?;

    // Decode Base64 for certificate
    let cert_decoded = BASE64
        .decode(certificate)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Base64 decode failed: {}", e)))?;
    // Parse certificate
    let cert = X509::from_pem(&cert_decoded)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?;

    // Verify key pair
    verify_key_pair(&pkey, &cert)?;

    // Combine into PEM format
    let cert_pem = cert
        .to_pem()
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to encode certificate: {}", e)))?;
    let key_pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to encode private key: {}", e)))?;

    // Note: Cannot zeroize PKey<Private> due to missing Zeroize trait implementation in openssl crate.
    let mut result = String::from_utf8(cert_pem)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Invalid UTF-8 in certificate: {}", e)))?;
    result.push_str(&String::from_utf8(key_pem)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid UTF-8 in private key: {}", e)))?);
    Ok(result)
}

/// Formats a private key and certificate into PFX format, returning the Base64-encoded PFX and password.
pub fn format_pfx(private_key: &str, certificate: &str) -> Result<(String, String), CryptoError> {
    let private_key = private_key.trim();
    let certificate = certificate.trim();

    // Validate inputs
    validate_private_key(private_key)?;
    validate_certificate(certificate)?;

    // Decode Base64 for private key
    let private_key_decoded = BASE64
        .decode(private_key)
        .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
    // Parse private key
    let pkey = PKey::private_key_from_pem(&private_key_decoded)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?;

    // Decode Base64 for certificate
    let cert_decoded = BASE64
        .decode(certificate)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Base64 decode failed: {}", e)))?;
    // Parse certificate
    let cert = X509::from_pem(&cert_decoded)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?;

    // Verify key pair
    verify_key_pair(&pkey, &cert)?;

    // Generate random password (32 characters, alphanumeric)
    let mut password = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(32)
        .map(char::from)
        .collect::<String>();

    // Create PKCS12 archive
    let mut pkcs12_builder = Pkcs12::builder();
    let pkcs12 = pkcs12_builder
        .name("certificate")
        .pkey(&pkey)
        .cert(&cert)
        .build2(&password)
        .map_err(|e| CryptoError::OpenSSLError(e))?;
    let pfx_der = pkcs12
        .to_der()
        .map_err(|e| CryptoError::OpenSSLError(e))?;
    let pfx_b64 = BASE64.encode(&pfx_der);

    // Store password in return value before zeroizing
    let result = Ok((pfx_b64, password.clone()));

    // Zeroize sensitive data
    password.zeroize();

    // Note: Cannot zeroize PKey<Private> due to missing Zeroize trait implementation in openssl crate.
    result
}