use sqlx::{Pool, Postgres};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DbError {
    #[error("Database error: {0}")]
    SqlxError(#[from] sqlx::Error),
}

pub async fn init_db_pool() -> Result<Pool<Postgres>, DbError> {
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = Pool::connect(&database_url).await?;
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

pub async fn store_key_data(
    pool: &Pool<Postgres>,
    hash: &str,
    public_key: &str,
) -> Result<(), DbError> {
    sqlx::query("INSERT INTO keys (hash, public_key) VALUES ($1, $2)")
        .bind(hash)
        .bind(public_key)
        .execute(pool)
        .await?;
    Ok(())
}