//! Cloud backup with rclone (milestone 4). Every new file is queued for upload to
//! `ARK_SYNC_REMOTE` (any rclone remote: S3, B2, Google Drive, ...); purged files are
//! queued for deletion there. The worker runs one job at a time, only while the
//! internet is reachable, and retries failures with exponential backoff.

use std::{
    process::Stdio,
    sync::atomic::{AtomicU8, Ordering},
    time::Duration,
};

use chrono::Utc;
use serde::Serialize;
use sqlx::SqlitePool;
use tokio::{net::TcpStream, process::Command, sync::Notify};
use utoipa::ToSchema;

use crate::{AppState, routes::folders::folder_path, storage, util};

const MAX_ATTEMPTS: i64 = 10;
const MAX_BACKOFF_SECS: i64 = 6 * 60 * 60;
const IDLE: Duration = Duration::from_secs(30);

const ONLINE: u8 = 1;
const OFFLINE: u8 = 2;

#[derive(Default)]
pub struct SyncState {
    /// 0 until the first check, then `ONLINE` or `OFFLINE`.
    online: AtomicU8,
    wake: Notify,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SyncStatus {
    pub enabled: bool,
    /// rclone destination (`ARK_SYNC_REMOTE`).
    pub remote: Option<String>,
    /// Null until the first connectivity check.
    pub online: Option<bool>,
    pub pending: i64,
    /// Gave up after 10 attempts; `POST /api/v1/admin/sync/retry` requeues them.
    pub failed: i64,
    pub done: i64,
    pub last_synced_at: Option<String>,
    pub last_error: Option<String>,
}

fn enabled(state: &AppState) -> bool {
    state.cfg.sync_remote.is_some()
}

/// `<remote>/<path>`, or `<remote><path>` when the remote ends in `:` or `/`.
fn remote_target(remote: &str, path: &str) -> String {
    if remote.ends_with(':') || remote.ends_with('/') {
        format!("{remote}{path}")
    } else {
        format!("{remote}/{path}")
    }
}

async fn enqueue(
    db: &SqlitePool,
    file_id: &str,
    action: &str,
    remote_path: &str,
) -> sqlx::Result<()> {
    sqlx::query(
        "INSERT INTO sync_queue (file_id, action, remote_path, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(file_id)
    .bind(action)
    .bind(remote_path)
    .bind(util::now())
    .execute(db)
    .await?;
    Ok(())
}

/// Queues a newly stored file. The remote path mirrors the folder slugs at upload
/// time: `sunday-service/day-1/photo.jpg`.
pub async fn queue_upload(state: &AppState, file_id: &str) -> anyhow::Result<()> {
    if !enabled(state) {
        return Ok(());
    }
    let (folder_id, disk_name): (String, String) =
        sqlx::query_as("SELECT folder_id, disk_name FROM files WHERE id = ?")
            .bind(file_id)
            .fetch_one(&state.db)
            .await?;
    let (slug, path) = folder_path(&state.db, &folder_id).await?;
    let remote_path = [slug.as_str(), path.as_str(), disk_name.as_str()]
        .iter()
        .filter(|p| !p.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("/");
    enqueue(&state.db, file_id, "upload", &remote_path).await?;
    state.sync.wake.notify_one();
    Ok(())
}

/// Called before a file row is purged: drops its pending upload and, if a copy
/// already reached the remote, queues its deletion there.
pub async fn queue_delete(state: &AppState, file_id: &str) -> sqlx::Result<()> {
    sqlx::query(
        "DELETE FROM sync_queue WHERE file_id = ? AND action = 'upload' AND status != 'done'",
    )
    .bind(file_id)
    .execute(&state.db)
    .await?;
    if !enabled(state) {
        return Ok(());
    }
    let uploaded: Option<String> = sqlx::query_scalar(
        "SELECT remote_path FROM sync_queue WHERE file_id = ? AND action = 'upload' AND status = 'done'
         ORDER BY id DESC LIMIT 1",
    )
    .bind(file_id)
    .fetch_optional(&state.db)
    .await?;
    if let Some(remote_path) = uploaded {
        enqueue(&state.db, file_id, "delete", &remote_path).await?;
        state.sync.wake.notify_one();
    }
    Ok(())
}

pub async fn status(state: &AppState) -> sqlx::Result<SyncStatus> {
    let (pending, failed, done): (i64, i64, i64) = sqlx::query_as(
        "SELECT COALESCE(SUM(status = 'pending'), 0), COALESCE(SUM(status = 'failed'), 0),
                COALESCE(SUM(status = 'done'), 0) FROM sync_queue",
    )
    .fetch_one(&state.db)
    .await?;
    let last_synced_at: Option<String> =
        sqlx::query_scalar("SELECT MAX(synced_at) FROM sync_queue")
            .fetch_one(&state.db)
            .await?;
    let last_error: Option<String> = sqlx::query_scalar(
        "SELECT last_error FROM sync_queue WHERE status != 'done' AND last_error IS NOT NULL
         ORDER BY id DESC LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await?
    .flatten();
    Ok(SyncStatus {
        enabled: enabled(state),
        remote: state.cfg.sync_remote.clone(),
        online: match state.sync.online.load(Ordering::Relaxed) {
            ONLINE => Some(true),
            OFFLINE => Some(false),
            _ => None,
        },
        pending,
        failed,
        done,
        last_synced_at,
        last_error,
    })
}

/// Requeues failed jobs. Returns how many.
pub async fn retry_failed(state: &AppState) -> sqlx::Result<u64> {
    let n = sqlx::query(
        "UPDATE sync_queue SET status = 'pending', attempts = 0, next_attempt_at = NULL WHERE status = 'failed'",
    )
    .execute(&state.db)
    .await?
    .rows_affected();
    state.sync.wake.notify_one();
    Ok(n)
}

pub fn spawn(state: AppState) {
    let Some(remote) = state.cfg.sync_remote.clone() else {
        return;
    };
    tokio::spawn(async move {
        tracing::info!(remote, "cloud sync enabled");
        if let Err(e) = backfill(&state).await {
            tracing::error!(error = ?e, "sync backfill failed");
        }
        loop {
            let online = internet_reachable(&state.cfg.sync_check).await;
            let was = state
                .sync
                .online
                .swap(if online { ONLINE } else { OFFLINE }, Ordering::Relaxed);
            if online && was != ONLINE {
                tracing::info!("internet reachable; syncing");
            } else if !online && was != OFFLINE {
                tracing::info!("internet unreachable; sync paused");
            }
            if online {
                match process_next(&state, &remote).await {
                    Ok(true) => continue,
                    Ok(false) => {}
                    Err(e) => tracing::error!(error = ?e, "sync worker"),
                }
            }
            tokio::select! {
                _ = state.sync.wake.notified() => {}
                _ = tokio::time::sleep(IDLE) => {}
            }
        }
    });
}

/// Queues live files that were stored before sync was turned on.
async fn backfill(state: &AppState) -> anyhow::Result<()> {
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM files f WHERE deleted_at IS NULL
           AND NOT EXISTS (SELECT 1 FROM sync_queue q WHERE q.file_id = f.id AND q.action = 'upload')
         ORDER BY created_at",
    )
    .fetch_all(&state.db)
    .await?;
    for id in &ids {
        queue_upload(state, id).await?;
    }
    if !ids.is_empty() {
        tracing::info!(files = ids.len(), "queued existing files for cloud sync");
    }
    Ok(())
}

async fn internet_reachable(check: &str) -> bool {
    tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(check))
        .await
        .is_ok_and(|r| r.is_ok())
}

#[derive(sqlx::FromRow)]
struct Job {
    id: i64,
    file_id: String,
    action: String,
    remote_path: String,
    attempts: i64,
}

/// Runs one due job. Returns false when nothing is due.
async fn process_next(state: &AppState, remote: &str) -> anyhow::Result<bool> {
    let job: Option<Job> = sqlx::query_as(
        "SELECT id, file_id, action, remote_path, attempts FROM sync_queue
         WHERE status = 'pending' AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
         ORDER BY id LIMIT 1",
    )
    .bind(util::now())
    .fetch_optional(&state.db)
    .await?;
    let Some(job) = job else { return Ok(false) };

    let target = remote_target(remote, &job.remote_path);
    let result = match job.action.as_str() {
        "upload" => {
            let local: Option<(String, String)> = sqlx::query_as(
                "SELECT d.disk_dir, f.disk_name FROM files f JOIN folders d ON d.id = f.folder_id WHERE f.id = ?",
            )
            .bind(&job.file_id)
            .fetch_optional(&state.db)
            .await?;
            match local {
                Some((dir, name)) => {
                    let path = storage::checked_path(&state.cfg, &dir, &name).await?;
                    rclone(
                        &state.cfg.rclone,
                        &["copyto".as_ref(), path.as_os_str(), target.as_ref()],
                    )
                    .await
                }
                // Purged before it was uploaded: nothing to do.
                None => Ok(()),
            }
        }
        _ => match rclone(&state.cfg.rclone, &["deletefile".as_ref(), target.as_ref()]).await {
            Err(e) if e.to_string().contains("not found") => Ok(()),
            other => other,
        },
    };

    match result {
        Ok(()) => {
            sqlx::query("UPDATE sync_queue SET status = 'done', synced_at = ?, last_error = NULL WHERE id = ?")
                .bind(util::now())
                .bind(job.id)
                .execute(&state.db)
                .await?;
            tracing::debug!(job = job.id, action = job.action, target, "synced");
        }
        Err(e) => {
            let attempts = job.attempts + 1;
            let delay = (60i64 << (attempts - 1).min(20)).min(MAX_BACKOFF_SECS);
            let status = if attempts >= MAX_ATTEMPTS {
                "failed"
            } else {
                "pending"
            };
            tracing::warn!(job = job.id, action = job.action, attempts, error = %e, "sync failed");
            sqlx::query(
                "UPDATE sync_queue SET status = ?, attempts = ?, last_error = ?, next_attempt_at = ? WHERE id = ?",
            )
            .bind(status)
            .bind(attempts)
            .bind(e.to_string())
            .bind(util::fmt_time(Utc::now() + chrono::Duration::seconds(delay)))
            .bind(job.id)
            .execute(&state.db)
            .await?;
        }
    }
    Ok(true)
}

async fn rclone(bin: &str, args: &[&std::ffi::OsStr]) -> anyhow::Result<()> {
    let out = Command::new(bin)
        .args(args)
        .args([
            "--retries",
            "1",
            "--low-level-retries",
            "5",
            "--contimeout",
            "15s",
            "--timeout",
            "5m",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                anyhow::anyhow!("{bin} not found (install rclone or set ARK_RCLONE)")
            }
            _ => e.into(),
        })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let line = err.trim().lines().last().unwrap_or("").to_string();
        anyhow::bail!("rclone {}: {line}", out.status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(
            remote_target("b2:ark/church", "sunday/a.jpg"),
            "b2:ark/church/sunday/a.jpg"
        );
        assert_eq!(
            remote_target("gdrive:", "sunday/a.jpg"),
            "gdrive:sunday/a.jpg"
        );
        assert_eq!(remote_target("s3:bucket/", "a.jpg"), "s3:bucket/a.jpg");
    }
}
