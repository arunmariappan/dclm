use serde::Deserialize;
use std::fs;

#[derive(Clone, Deserialize)]
pub struct Config {
    pub azure_tenant_id: String,
    pub azure_client_id: String,
    pub azure_client_secret: String,
    pub key_vault_url: String,
    pub database_url: Option<String>,
}

impl Config {
    pub fn from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config = serde_json::from_str(&content)?;
        Ok(config)
    }
}