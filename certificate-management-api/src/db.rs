use sqlx::{Pool, Postgres};
use std::fs;
use serde::Deserialize;
use thiserror::Error;

// Define a struct to match the JSON structure
#[derive(Deserialize)]
struct Config {
    #[serde(rename = "DATABASE_URL")]
    database_url: String,
}

// Custom error enum to handle all possible errors
#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqlxError(#[from] sqlx::Error),
    #[error("Failed to read configuration file: {0}")]
    IoError(#[from] std::io::Error), // `#[from]` ensures `From<std::io::Error>` is implemented
    #[error("Failed to parse configuration JSON: {0}")]
    JsonError(#[from] serde_json::Error), // `#[from]` ensures `From<serde_json::Error>` is implemented
}


pub async fn init_db_pool() -> Result<Pool<Postgres>, DbError> {
    // Read the appsettings.json file
    let config_content = fs::read_to_string("appsettings.json")?;
    
    // Deserialize the JSON into the Config struct
    let config: Config = serde_json::from_str(&config_content)?;

    let database_url = &config.database_url;
    let pool = Pool::connect(database_url).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS keys (
            hash TEXT PRIMARY KEY,
            public_key TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await?;
    Ok(pool)
}

pub async fn store_key(pool: &Pool<Postgres>, hash: &str, public_key: &str) -> Result<(), DbError> {
    sqlx::query("INSERT INTO keys (hash, public_key) VALUES ($1, $2)")
        .bind(hash)
        .bind(public_key)
        .execute(pool)
        .await?;
    Ok(())
}