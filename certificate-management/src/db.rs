use sqlx::{Pool, Postgres};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqlxError(#[from] sqlx::Error),
}

pub async fn init_db_pool(database_url: &str) -> Result<Pool<Postgres>, DbError> {
    let pool = Pool::connect(database_url).await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS keys (
            hash TEXT PRIMARY KEY,
            public_key TEXT NOT NULL,
            secret_name TEXT NOT NULL
        )",
    )
    .execute(&pool)
    .await?;
    Ok(pool)
}

pub async fn store_key(
    pool: &Pool<Postgres>,
    hash: &str,
    public_key: &str,
    secret_name: &str,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO keys (hash, public_key, secret_name) VALUES ($1, $2, $3)")
        .bind(hash)
        .bind(public_key)
        .bind(secret_name)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn get_secret_name(pool: &Pool<Postgres>, hash: &str) -> Result<String, DbError> {
    let row: (String,) = sqlx::query_as("SELECT secret_name FROM keys WHERE hash = $1")
        .bind(hash)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}