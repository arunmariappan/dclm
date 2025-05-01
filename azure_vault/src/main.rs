use azure_identity::ClientSecretCredential;
use azure_security_keyvault_secrets::{SecretClient, models::SetSecretParameters, ResourceExt};
use std::error::Error;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Azure Key Vault and authentication details
    let client_id = "40494ed1-b862-40ff-bf83-d5e709128a61";
    let tenant_id = "b6b76e47-d4c0-46ca-8f87-8a7874af4d15";
    let client_secret = "";
    let vault_url = "https://dclmcertvault.vault.azure.net/";

    // Initialize credentials using ClientSecretCredential
    let credential = ClientSecretCredential::new(
        tenant_id.to_string(),   // Convert to String
        client_id.to_string(),   // Convert to String
        client_secret.to_string(), // Pass as String
        None,                    // Optional: Token credential options
    )?;

    // Create a SecretClient
    let client = SecretClient::new(vault_url, Arc::new(credential), None)?;

    // Create a new secret
    let secret_name = "secret-name";
    let secret_set_parameters = SetSecretParameters {
        value: Some("secret-value".to_string()), // Wrap in Some
        ..Default::default()
    };

    let secret_response = client
        .set_secret(secret_name, secret_set_parameters, None) // Pass None for options
        .await?;
    let secret = secret_response.body; // Extract Secret from Response

    println!(
        "Secret Name: {}, Value: {}, Version: {}",
        secret.resource_id()?.name,
        secret.value.unwrap_or_default(), // Handle Option<String>
        secret.resource_id()?.version.unwrap_or_default() // Handle Option<String>
    );

    Ok(())
}