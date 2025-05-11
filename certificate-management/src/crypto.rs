use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::x509::X509;
use rand::Rng;
use sha2::{Digest, Sha512};
use thiserror::Error;
use openssl::pkcs12::Pkcs12;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid certificate format: {0}")]
    InvalidCertificate(String),
    #[error("Invalid key format: {0}")]
    InvalidKey(String),
    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),
    #[error("Base64 decode error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

pub fn validate_certificate(certificate: &str) -> Result<(), CryptoError> {
    // Check if certificate is PEM format
    if certificate.contains("-----BEGIN CERTIFICATE-----") {
        let cert = X509::from_pem(certificate.as_bytes())
            .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse PEM: {}", e)))?;
        if cert.public_key().is_err() {
            return Err(CryptoError::InvalidCertificate("Invalid public key in certificate".to_string()));
        }
        Ok(())
    } else {
        // Try base64 decoding for raw certificate
        let decoded = BASE64
            .decode(certificate.trim())
            .map_err(|e| CryptoError::InvalidCertificate(format!("Base64 decode failed: {}", e)))?;
        let cert = X509::from_der(&decoded)
            .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse DER: {}", e)))?;
        if cert.public_key().is_err() {
            return Err(CryptoError::InvalidCertificate("Invalid public key in certificate".to_string()));
        }
        Ok(())
    }
}
/*
pub fn validate_private_key(private_key: &str) -> Result<(), CryptoError> {
    let private_key = private_key.trim();
    // Try PEM format
    if private_key.contains("-----BEGIN PRIVATE KEY-----") || private_key.contains("-----BEGIN RSA PRIVATE KEY-----") {
        PKey::private_key_from_pem(private_key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?;
        Ok(())
    } else {
        // Try base64 decoding for DER or PEM
        let decoded = BASE64
            .decode(private_key)
            .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
        // Try DER
        if let Ok(pkey) = PKey::private_key_from_der(&decoded) {
            return Ok(());
        }
        // Try PEM as base64-encoded string
        let pem_str = String::from_utf8(decoded)
            .map_err(|e| CryptoError::InvalidKey(format!("Invalid UTF-8 in base64-decoded key: {}", e)))?;
        if pem_str.contains("-----BEGIN") {
            PKey::private_key_from_pem(pem_str.as_bytes())
                .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse base64-decoded PEM: {}", e)))?;
            Ok(())
        } else {
            Err(CryptoError::InvalidKey("Unsupported private key format".to_string()))
        }
    }
}

pub fn validate_public_key(public_key: &str) -> Result<(), CryptoError> {
    let public_key = public_key.trim();
    if public_key.contains("-----BEGIN PUBLIC KEY-----") {
        PKey::public_key_from_pem(public_key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM public key: {}", e)))?;
        Ok(())
    } else {
        let decoded = BASE64
            .decode(public_key)
            .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
        PKey::public_key_from_der(&decoded)
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse DER public key: {}", e)))?;
        Ok(())
    }
}

pub fn hash_private_key(private_key: &str) -> Result<String, CryptoError> {
    let mut hasher = Sha512::new();
    hasher.update(private_key.as_bytes());
    let result = hasher.finalize();
    Ok(hex::encode(result))
}
*/
pub fn hash_private_key(private_key: &str) -> Result<String, CryptoError> {
    let mut hasher = Sha512::new();
    hasher.update(private_key);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

pub fn validate_private_key(private_key: &str) -> Result<(), CryptoError> {
    let key_bytes = BASE64
        .decode(private_key)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    PKey::private_key_from_pem(&key_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    Ok(())
}

/*
pub fn validate_private_key(private_key: &str) -> Result<(), CryptoError> {
    let cleaned_key = private_key.trim();
    /*
    // Check if it's a valid PKCS#8 private key
    if cleaned_key.contains("-----BEGIN PRIVATE KEY-----") {
        PKey::private_key_from_pem(cleaned_key.as_bytes())
            .map(|_| ()) // ✅ Converts `Result<PKey<Private>, _>` into `Result<(), _>`
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PKCS#8 private key: {}", e)))?;
        return Ok(());
    } */

    // Try parsing as RSA private key explicitly
    if cleaned_key.contains("-----BEGIN RSA PRIVATE KEY-----") {
        Rsa::private_key_from_pem(cleaned_key.as_bytes())
            .map(|_| ()) // ✅ Ensures function returns `Result<(), _>` instead of an RSA key
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse RSA private key: {}", e)))?;
        return Ok(());
    }

    Err(CryptoError::InvalidKey("Unsupported private key format".to_string()))
}
*/
pub fn validate_public_key(public_key: &str) -> Result<(), CryptoError> {
    let key_bytes = BASE64
        .decode(public_key)
        .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    PKey::public_key_from_pem(&key_bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
    Ok(())
}

pub fn format_pem(private_key: &str, certificate: &str) -> Result<String, CryptoError> {
    let private_key = private_key.trim();
    // Parse private key
    let pkey = if private_key.contains("-----BEGIN") {
        PKey::private_key_from_pem(private_key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?
    } else {
        // Try base64 decoding
        let decoded = BASE64
            .decode(private_key)
            .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
        // Try DER
        if let Ok(pkey) = PKey::private_key_from_der(&decoded) {
            pkey
        } else {
            // Try base64-decoded PEM
            let pem_str = String::from_utf8(decoded)
                .map_err(|e| CryptoError::InvalidKey(format!("Invalid UTF-8 in base64-decoded key: {}", e)))?;
            PKey::private_key_from_pem(pem_str.as_bytes())
                .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse base64-decoded PEM: {}", e)))?
        }
    };

    // Parse certificate
    let cert = if certificate.contains("-----BEGIN CERTIFICATE-----") {
        X509::from_pem(certificate.as_bytes())
            .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?
    } else {
        let decoded = BASE64
            .decode(certificate.trim())
            .map_err(|e| CryptoError::InvalidCertificate(format!("Base64 decode failed: {}", e)))?;
        X509::from_der(&decoded)
            .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse DER certificate: {}", e)))?
    };

    // Combine into PEM format
    let cert_pem = cert
        .to_pem()
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to encode certificate: {}", e)))?;
    let key_pem = pkey
        .private_key_to_pem_pkcs8()
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to encode private key: {}", e)))?;
    let mut result = String::from_utf8(cert_pem)
        .map_err(|e| CryptoError::InvalidCertificate(format!("Invalid UTF-8 in certificate: {}", e)))?;
    result.push_str(&String::from_utf8(key_pem)
        .map_err(|e| CryptoError::InvalidKey(format!("Invalid UTF-8 in private key: {}", e)))?);
    Ok(result)
}

/*
pub fn format_pfx(private_key: &str, certificate: &str) -> Result<(String, String), CryptoError> {
    let private_key = private_key.trim();
    // Parse private key
    let pkey = if private_key.contains("-----BEGIN") {
        PKey::private_key_from_pem(private_key.as_bytes())
            .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?
    } else {
        // Try base64 decoding
        let decoded = BASE64
            .decode(private_key)
            .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;
        // Try DER
        if let Ok(pkey) = PKey::private_key_from_der(&decoded) {
            pkey
        } else {
            // Try base64-decoded PEM
            let pem_str = String::from_utf8(decoded)
                .map_err(|e| CryptoError::InvalidKey(format!("Invalid UTF-8 in base64-decoded key: {}", e)))?;
            PKey::private_key_from_pem(pem_str.as_bytes())
                .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse base64-decoded PEM: {}", e)))?
        }
    };

    // Parse certificate
    let cert = if certificate.contains("-----BEGIN CERTIFICATE-----") {
        X509::from_pem(certificate.as_bytes())
            .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?
    } else {
        let decoded = BASE64
            .decode(certificate.trim())
            .map_err(|e| CryptoError::InvalidCertificate(format!("Base64 decode failed: {}", e)))?;
        X509::from_der(&decoded)
            .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse DER certificate: {}", e)))?
    };

    // Generate random password
    let password: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    // Create PKCS12 archive
    let pkcs12_builder = Pkcs12::builder();
    let pkcs12 = pkcs12_builder
        .build(&password, "certificate", &pkey, &cert)
        .map_err(|e| CryptoError::OpenSSLError(e))?;
    let pfx_der = pkcs12
        .to_der()
        .map_err(|e| CryptoError::OpenSSLError(e))?;
    let pfx_b64 = BASE64.encode(&pfx_der);
    Ok((pfx_b64, password))
}

pub fn format_pfx(private_key: &str, certificate: &str) -> Result<(String, String), CryptoError> {
    let cleaned_key = private_key.trim();

    let pkey = PKey::private_key_from_pem(cleaned_key.as_bytes())
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?;

    let cert = X509::from_pem(certificate.as_bytes())
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?;

    let password: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    // Use `build()` instead of `build2()`
    let pkcs12 = Pkcs12::builder()
        .build(&password, "certificate", &pkey, &cert)
        .map_err(|e| CryptoError::OpenSSLError(e))?;
    
    let pfx_der = pkcs12.to_der().map_err(|e| CryptoError::OpenSSLError(e))?;
    
    Ok((BASE64.encode(&pfx_der), password))
} */

pub fn format_pfx(private_key: &str, certificate: &str) -> Result<(String, String), CryptoError> {
    let decoded_key = BASE64.decode(private_key.trim())
        .map_err(|e| CryptoError::InvalidKey(format!("Base64 decode failed: {}", e)))?;

    let pkey = PKey::private_key_from_pem(&decoded_key)
        .map_err(|e| CryptoError::InvalidKey(format!("Failed to parse PEM private key: {}", e)))?;

    let cert = X509::from_pem(certificate.as_bytes())
        .map_err(|e| CryptoError::InvalidCertificate(format!("Failed to parse certificate: {}", e)))?;

    let password: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    let pkcs12 = Pkcs12::builder()
        .build(&password, "certificate", &pkey, &cert)
        .map_err(|e| CryptoError::OpenSSLError(e))?;
    
    let pfx_der = pkcs12.to_der().map_err(|e| CryptoError::OpenSSLError(e))?;
    
    Ok((BASE64.encode(&pfx_der), password))
}

