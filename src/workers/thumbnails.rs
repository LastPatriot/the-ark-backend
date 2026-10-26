//! Generates JPEG thumbnails for uploaded images, one at a time in a blocking task.

use std::{
    io::{BufWriter, Write},
    path::Path,
    time::Duration,
};

use image::{
    DynamicImage, ImageDecoder, ImageReader, codecs::jpeg::JpegEncoder, metadata::Orientation,
};

use crate::{
    AppState,
    routes::events::{EventKind, publish},
    storage,
};

/// Longest edge of a thumbnail, in pixels.
const THUMB_MAX: u32 = 480;
const THUMB_MIMES: [&str; 4] = ["image/jpeg", "image/png", "image/webp", "image/gif"];

pub fn thumb_name(file_id: &str) -> String {
    format!("{file_id}_thumb.jpg")
}

/// Queues a thumbnail for a new file when its type is supported.
pub async fn queue(state: &AppState, file_id: &str, mime: Option<&str>) -> sqlx::Result<()> {
    if !mime.is_some_and(|m| THUMB_MIMES.contains(&m)) {
        return Ok(());
    }
    sqlx::query("INSERT OR IGNORE INTO previews (file_id, kind, path) VALUES (?, 'thumb', ?)")
        .bind(file_id)
        .bind(thumb_name(file_id))
        .execute(&state.db)
        .await?;
    state.thumbs.notify_one();
    Ok(())
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        if let Err(e) = backfill(&state).await {
            tracing::error!(error = ?e, "thumbnail backfill failed");
        }
        loop {
            loop {
                match process_next(&state).await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        tracing::error!(error = ?e, "thumbnail worker");
                        break;
                    }
                }
            }
            tokio::select! {
                _ = state.thumbs.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
        }
    });
}

/// Queues images uploaded before thumbnails existed (or whose job row was lost).
async fn backfill(state: &AppState) -> sqlx::Result<()> {
    let ids: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, mime FROM files f
         WHERE deleted_at IS NULL AND mime LIKE 'image/%'
           AND NOT EXISTS (SELECT 1 FROM previews p WHERE p.file_id = f.id AND p.kind = 'thumb')",
    )
    .fetch_all(&state.db)
    .await?;
    for (id, mime) in ids {
        queue(state, &id, mime.as_deref()).await?;
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct Job {
    file_id: String,
    path: String,
    folder_id: String,
    name: String,
    disk_name: String,
    disk_dir: String,
    session_id: Option<String>,
}

/// Handles one pending thumbnail. Returns false when none is pending.
async fn process_next(state: &AppState) -> anyhow::Result<bool> {
    let job: Option<Job> = sqlx::query_as(
        "SELECT p.file_id, p.path, f.folder_id, f.name, f.disk_name, d.disk_dir, f.session_id
         FROM previews p JOIN files f ON f.id = p.file_id JOIN folders d ON d.id = f.folder_id
         WHERE p.kind = 'thumb' AND p.status = 'pending'
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await?;
    let Some(job) = job else { return Ok(false) };

    let src = storage::checked_path(&state.cfg, &job.disk_dir, &job.disk_name).await?;
    let dst = storage::preview_path(&state.cfg, &job.path);
    let started = std::time::Instant::now();
    let result = tokio::task::spawn_blocking(move || generate(&src, &dst)).await?;
    let status = match &result {
        Ok(()) => "ready",
        Err(e) => {
            tracing::warn!(file = job.file_id, error = %e, "thumbnail failed");
            "failed"
        }
    };
    sqlx::query("UPDATE previews SET status = ? WHERE file_id = ? AND kind = 'thumb'")
        .bind(status)
        .bind(&job.file_id)
        .execute(&state.db)
        .await?;
    if result.is_ok() {
        tracing::debug!(
            file = job.file_id,
            ms = started.elapsed().as_millis() as u64,
            "thumbnail ready"
        );
        publish(
            state,
            EventKind::FileUpdated,
            &job.folder_id,
            &job.file_id,
            Some(&job.name),
            job.session_id.as_deref(),
        )
        .await;
    }
    Ok(true)
}

fn generate(src: &Path, dst: &Path) -> anyhow::Result<()> {
    let mut decoder = ImageReader::open(src)?
        .with_guessed_format()?
        .into_decoder()?;
    let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
    let mut img = DynamicImage::from_decoder(decoder)?;
    img.apply_orientation(orientation);
    let thumb = img.thumbnail(THUMB_MAX, THUMB_MAX).into_rgb8();

    let tmp = dst.with_extension("tmp");
    let mut out = BufWriter::new(std::fs::File::create(&tmp)?);
    JpegEncoder::new_with_quality(&mut out, 80).encode_image(&thumb)?;
    out.flush()?;
    drop(out);
    std::fs::rename(&tmp, dst)?;
    Ok(())
}
