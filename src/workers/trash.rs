//! Hourly cleanup: purges trash older than 30 days and abandons stale uploads.

use std::time::Duration;

use chrono::Utc;

use super::sync;
use crate::{AppState, db, storage, util};

const TRASH_DAYS: i64 = 30;
const STALE_UPLOAD_DAYS: i64 = 7;

pub fn spawn(state: AppState) {
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
            if let Err(e) = abandon_stale_uploads(&state).await {
                tracing::error!(error = ?e, "stale upload cleanup failed");
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

async fn abandon_stale_uploads(state: &AppState) -> anyhow::Result<()> {
    let cutoff = util::fmt_time(Utc::now() - chrono::Duration::days(STALE_UPLOAD_DAYS));
    let ids: Vec<String> = sqlx::query_scalar(
        "UPDATE uploads SET status = 'aborted', updated_at = ?1
         WHERE status = 'active' AND updated_at < ?2 RETURNING id",
    )
    .bind(util::now())
    .bind(&cutoff)
    .fetch_all(&state.db)
    .await?;
    for id in &ids {
        remove_if_exists(&storage::part_path(&state.cfg, id)).await?;
    }
    if !ids.is_empty() {
        tracing::info!(uploads = ids.len(), "abandoned stale uploads");
    }
    Ok(())
}

async fn remove_if_exists(path: &std::path::Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}
