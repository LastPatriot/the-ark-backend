use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use chrono::Utc;
use sqlx::SqlitePool;

use crate::{
    error::{AppError, AppResult},
    util,
    vault::Vault,
};

const LOCK_AFTER: i64 = 5;
const BASE_LOCK_SECS: i64 = 5 * 60;
const MAX_LOCK_SECS: i64 = 24 * 60 * 60;

pub fn validate_pin(pin: &str) -> AppResult<()> {
    if (4..=8).contains(&pin.len()) && pin.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "invalid_pin_format",
            "PIN must be 4 to 8 digits",
        ))
    }
}

/// Argon2id PHC string. Runs on the blocking pool; hashing is deliberately slow.
pub async fn hash_secret(secret: String) -> AppResult<String> {
    tokio::task::spawn_blocking(move || {
        Argon2::default()
            .hash_password(secret.as_bytes())
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("argon2 hash: {e}"))
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(AppError::from)
}

/// Returns the index of the first hash that matches `secret`.
pub async fn find_match(secret: String, hashes: Vec<String>) -> AppResult<Option<usize>> {
    tokio::task::spawn_blocking(move || {
        hashes.iter().position(|h| {
            PasswordHash::new(h).is_ok_and(|parsed| {
                Argon2::default()
                    .verify_password(secret.as_bytes(), &parsed)
                    .is_ok()
            })
        })
    })
    .await
    .map_err(|e| AppError::Internal(e.into()))
}

/// A stored PIN as needed to check one. Select it with [`STORED_PIN_COLUMNS`].
#[derive(sqlx::FromRow)]
pub struct StoredPin {
    pub id: String,
    pub hash: String,
    /// Encrypted copy (src/vault.rs); None for PINs from before Ark kept them.
    pub sealed: Option<String>,
}

pub const STORED_PIN_COLUMNS: &str = "id, pin_hash AS hash, pin_sealed AS sealed";

/// Active (not revoked, expired or used up) PINs: the ones that can unlock.
pub const ACTIVE_PIN: &str = "revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?1)
     AND (max_uses IS NULL OR uses < max_uses)";

/// Indexes of every PIN in `pins` that `entered` matches. Compares against the
/// decrypted copy where there is one, so checking every PIN in Ark stays fast; argon2
/// only runs for PINs without a copy.
pub async fn matching<'a>(
    vault: &Vault,
    entered: &str,
    pins: impl IntoIterator<Item = &'a StoredPin>,
) -> AppResult<Vec<usize>> {
    let mut found = Vec::new();
    let mut legacy = Vec::new();
    for (i, p) in pins.into_iter().enumerate() {
        match p.sealed.as_deref().and_then(|s| vault.open(&p.id, s)) {
            Some(plain) => {
                if constant_time_eq(plain.as_bytes(), entered.as_bytes()) {
                    found.push(i);
                }
            }
            None => legacy.push((i, p.hash.clone())),
        }
    }
    if !legacy.is_empty() {
        let secret = entered.to_string();
        let hits = tokio::task::spawn_blocking(move || {
            legacy
                .into_iter()
                .filter(|(_, h)| {
                    PasswordHash::new(h).is_ok_and(|parsed| {
                        Argon2::default()
                            .verify_password(secret.as_bytes(), &parsed)
                            .is_ok()
                    })
                })
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        })
        .await
        .map_err(|e| AppError::Internal(e.into()))?;
        found.extend(hits);
        found.sort_unstable();
    }
    Ok(found)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Fails with 429 while `key` is locked out.
pub async fn check_lock(db: &SqlitePool, key: &str) -> AppResult<()> {
    let locked_until: Option<Option<String>> =
        sqlx::query_scalar("SELECT locked_until FROM login_attempts WHERE key = ?")
            .bind(key)
            .fetch_optional(db)
            .await?;
    if let Some(Some(until)) = locked_until
        && let Ok(until) = chrono::DateTime::parse_from_rfc3339(&until)
    {
        let remaining = (until.with_timezone(&Utc) - Utc::now()).num_seconds();
        if remaining > 0 {
            return Err(AppError::TooManyAttempts {
                retry_after_secs: remaining,
            });
        }
    }
    Ok(())
}

/// Records a failure. From the 5th failure on, each one locks the key: 5 minutes,
/// then doubling per further failure (capped at 24 h).
pub async fn record_failure(db: &SqlitePool, key: &str) -> AppResult<()> {
    let failures: i64 = sqlx::query_scalar(
        "INSERT INTO login_attempts (key, failures) VALUES (?, 1)
         ON CONFLICT (key) DO UPDATE SET failures = failures + 1
         RETURNING failures",
    )
    .bind(key)
    .fetch_one(db)
    .await?;
    if let Some(secs) = lock_secs(failures) {
        let until = util::fmt_time(Utc::now() + chrono::Duration::seconds(secs));
        sqlx::query("UPDATE login_attempts SET locked_until = ? WHERE key = ?")
            .bind(until)
            .bind(key)
            .execute(db)
            .await?;
        tracing::warn!(
            key,
            failures,
            lock_secs = secs,
            "locked out after failed attempts"
        );
    }
    Ok(())
}

pub async fn record_success(db: &SqlitePool, key: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM login_attempts WHERE key = ?")
        .bind(key)
        .execute(db)
        .await?;
    Ok(())
}

fn lock_secs(failures: i64) -> Option<i64> {
    if failures < LOCK_AFTER {
        return None;
    }
    let doublings = (failures - LOCK_AFTER).min(20) as u32;
    Some((BASE_LOCK_SECS << doublings).min(MAX_LOCK_SECS))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_format() {
        assert!(validate_pin("1234").is_ok());
        assert!(validate_pin("12345678").is_ok());
        assert!(validate_pin("123").is_err());
        assert!(validate_pin("123456789").is_err());
        assert!(validate_pin("12a4").is_err());
    }

    #[test]
    fn lock_schedule() {
        assert_eq!(lock_secs(4), None);
        assert_eq!(lock_secs(5), Some(300));
        assert_eq!(lock_secs(6), Some(600));
        assert_eq!(lock_secs(7), Some(1200));
        assert_eq!(lock_secs(100), Some(MAX_LOCK_SECS));
    }

    #[tokio::test]
    async fn hash_roundtrip() {
        let h = hash_secret("4321".into()).await.unwrap();
        let other = hash_secret("1111".into()).await.unwrap();
        assert_eq!(
            find_match("4321".into(), vec![other.clone(), h])
                .await
                .unwrap(),
            Some(1)
        );
        assert_eq!(find_match("9999".into(), vec![other]).await.unwrap(), None);
    }
}
