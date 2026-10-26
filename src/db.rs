use std::{path::Path, str::FromStr, time::Duration};

use anyhow::Context;
use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions},
};

pub async fn connect(data_dir: &Path) -> anyhow::Result<SqlitePool> {
    for sub in ["files", "previews", "uploads"] {
        let dir = data_dir.join(sub);
        std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    }

    let options = SqliteConnectOptions::from_str("sqlite:")?
        .filename(data_dir.join("ark.db"))
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(options)
        .await
        .context("opening ark.db")?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("running migrations")?;
    Ok(pool)
}

pub async fn get_setting(db: &SqlitePool, key: &str) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar("SELECT value FROM settings WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await
}

pub async fn set_setting(db: &SqlitePool, key: &str, value: &str) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO settings (key, value) VALUES (?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(key)
    .bind(value)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn audit(
    db: &SqlitePool,
    actor: &str,
    action: &str,
    target: Option<&str>,
    details: Option<serde_json::Value>,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO audit_log (actor, action, target, details, created_at) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(details.map(|d| d.to_string()))
    .bind(crate::util::now())
    .execute(db)
    .await?;
    Ok(())
}
