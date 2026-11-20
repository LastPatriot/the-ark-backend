//! Cleanup: hourly, purges trash older than 30 days; every 10 minutes, discards unfinished
//! uploads nobody can resume (their session ended) or that sat idle for 7 days.

use std::time::Duration;

use chrono::Utc;

use super::sync;
use crate::{AppState, db, routes::uploads, storage, util};

const TRASH_DAYS: i64 = 30;
const STALE_UPLOAD_DAYS: i64 = 7;
const UPLOAD_SWEEP: Duration = Duration::from_secs(10 * 60);

pub fn spawn(state: AppState) {
    let uploads_state = state.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(UPLOAD_SWEEP);
        loop {
            tick.tick().await;
            if let Err(e) = abandon_dead_uploads(&uploads_state).await {
                tracing::error!(error = ?e, "unfinished upload cleanup failed");
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            let cutoff = util::fmt_time(Utc::now() - chrono::Duration::days(TRASH_DAYS));
            match purge(&state, Some(&cutoff)).await {
                Ok(0) => {}
                Ok(n) => tracing::info!(files = n, "purged old trash"),
                Err(e) => tracing::error!(error = ?e, "trash purge failed"),
            }
        }
    });
}

/// Permanently deletes trashed files (all of them, or those trashed before `before`).
/// Returns the number of file rows removed.
pub async fn purge(state: &AppState, before: Option<&str>) -> anyhow::Result<u64> {
    let rows: Vec<(String, String, String)> = sqlx::query_as(
        "SELECT f.id, f.disk_name, d.disk_dir FROM files f JOIN folders d ON d.id = f.folder_id
         WHERE f.deleted_at IS NOT NULL AND (?1 IS NULL OR f.deleted_at < ?1)",
    )
    .bind(before)
    .fetch_all(&state.db)
    .await?;

    let mut purged = 0;
    for (id, disk_name, disk_dir) in rows {
        let path = storage::checked_path(&state.cfg, &disk_dir, &disk_name).await?;
        remove_if_exists(&path).await?;
        let previews: Vec<String> =
            sqlx::query_scalar("SELECT path FROM previews WHERE file_id = ?")
                .bind(&id)
                .fetch_all(&state.db)
                .await?;
        for p in previews {
            let path = storage::preview_path(&state.cfg, &p);
            if tokio::fs::metadata(&path).await.is_ok_and(|m| m.is_dir()) {
                tokio::fs::remove_dir_all(&path).await?;
            } else {
                remove_if_exists(&path).await?;
            }
        }

        sync::queue_delete(state, &id).await?;
        let mut tx = db::begin_write(&state.db).await?;
        sqlx::query("DELETE FROM previews WHERE file_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE uploads SET file_id = NULL WHERE file_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM files WHERE id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        purged += 1;
    }
    if purged > 0 {
        db::audit(
            &state.db,
            "system",
            "trash.purge",
            None,
            Some(serde_json::json!({ "files": purged, "before": before })),
        )
        .await?;
    }
    Ok(purged)
}

/// Discards unfinished uploads that can't be resumed: only the session that started an
/// upload may continue it, so once that session expired or was ended the partial data is
/// dead weight. Uploads idle for `STALE_UPLOAD_DAYS` go too. Returns how many.
pub async fn abandon_dead_uploads(state: &AppState) -> anyhow::Result<usize> {
    let now = util::now();
    let cutoff = util::fmt_time(Utc::now() - chrono::Duration::days(STALE_UPLOAD_DAYS));
    let ids: Vec<String> = sqlx::query_scalar(
        "SELECT u.id FROM uploads u LEFT JOIN sessions s ON s.id = u.session_id
         WHERE u.status = 'active'
           AND (u.updated_at < ?2 OR s.id IS NULL OR s.revoked_at IS NOT NULL OR s.expires_at <= ?1)",
    )
    .bind(&now)
    .bind(&cutoff)
    .fetch_all(&state.db)
    .await?;
    let mut n = 0;
    for id in &ids {
        if uploads::discard(state, id).await?.is_some() {
            n += 1;
        }
    }
    if n > 0 {
        tracing::info!(
            uploads = n,
            "discarded unfinished uploads that can't be resumed"
        );
    }
    Ok(n)
}

async fn remove_if_exists(path: &std::path::Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
