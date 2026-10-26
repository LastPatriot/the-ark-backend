//! Video previews with ffmpeg: a poster frame (JPEG, 480 px wide) and, when
//! `ARK_HLS` is on, a 720p H.264/AAC HLS rendition for smooth playback on phones.
//! One video at a time, separate from image thumbnails so a long transcode never
//! holds them up.

use std::{path::Path, process::Stdio, time::Duration};

use tokio::process::Command;

use crate::{
    AppState,
    routes::events::{EventKind, publish},
    storage,
};

pub fn poster_name(file_id: &str) -> String {
    format!("{file_id}_poster.jpg")
}

pub fn hls_dir_name(file_id: &str) -> String {
    format!("{file_id}_hls")
}

/// Queues previews for a new file when it is a video.
pub async fn queue(state: &AppState, file_id: &str, mime: Option<&str>) -> sqlx::Result<()> {
    if !mime.is_some_and(|m| m.starts_with("video/")) {
        return Ok(());
    }
    sqlx::query("INSERT OR IGNORE INTO previews (file_id, kind, path) VALUES (?, 'poster', ?)")
        .bind(file_id)
        .bind(poster_name(file_id))
        .execute(&state.db)
        .await?;
    if state.cfg.hls {
        sqlx::query("INSERT OR IGNORE INTO previews (file_id, kind, path) VALUES (?, 'hls', ?)")
            .bind(file_id)
            .bind(hls_dir_name(file_id))
            .execute(&state.db)
            .await?;
    }
    state.videos.notify_one();
    Ok(())
}

pub fn spawn(state: AppState) {
    tokio::spawn(async move {
        if let Err(e) = backfill(&state).await {
            tracing::error!(error = ?e, "video preview backfill failed");
        }
        loop {
            loop {
                match process_next(&state).await {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(e) => {
                        tracing::error!(error = ?e, "video preview worker");
                        break;
                    }
                }
            }
            tokio::select! {
                _ = state.videos.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(60)) => {}
            }
        }
    });
}

async fn backfill(state: &AppState) -> sqlx::Result<()> {
    let ids: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT id, mime FROM files f
         WHERE deleted_at IS NULL AND mime LIKE 'video/%'
           AND NOT EXISTS (SELECT 1 FROM previews p WHERE p.file_id = f.id AND p.kind = 'poster')",
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
    kind: String,
    path: String,
    folder_id: String,
    name: String,
    disk_name: String,
    disk_dir: String,
    session_id: Option<String>,
}

/// Handles one pending poster or HLS job, posters first. Returns false when none is pending.
async fn process_next(state: &AppState) -> anyhow::Result<bool> {
    let job: Option<Job> = sqlx::query_as(
        "SELECT p.file_id, p.kind, p.path, f.folder_id, f.name, f.disk_name, d.disk_dir, f.session_id
         FROM previews p JOIN files f ON f.id = p.file_id JOIN folders d ON d.id = f.folder_id
         WHERE p.kind IN ('poster', 'hls') AND p.status = 'pending'
         ORDER BY p.kind = 'poster' DESC, f.created_at
         LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await?;
    let Some(job) = job else { return Ok(false) };

    let src = storage::checked_path(&state.cfg, &job.disk_dir, &job.disk_name).await?;
    let dst = storage::preview_path(&state.cfg, &job.path);
    let started = std::time::Instant::now();
    let result = match job.kind.as_str() {
        "poster" => poster(&state.cfg.ffmpeg, &src, &dst).await,
        _ => hls(&state.cfg.ffmpeg, &src, &dst).await,
    };
    let status = match &result {
        Ok(()) => "ready",
        Err(e) => {
            tracing::warn!(file = job.file_id, kind = job.kind, error = %e, "video preview failed");
            "failed"
        }
    };
    sqlx::query("UPDATE previews SET status = ? WHERE file_id = ? AND kind = ?")
        .bind(status)
        .bind(&job.file_id)
        .bind(&job.kind)
        .execute(&state.db)
        .await?;
    if result.is_ok() {
        tracing::info!(
            file = job.file_id,
            kind = job.kind,
            secs = started.elapsed().as_secs(),
            "video preview ready"
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

async fn poster(ffmpeg: &str, src: &Path, dst: &Path) -> anyhow::Result<()> {
    let tmp = dst.with_extension("tmp.jpg");
    // One second in skips black lead-in frames; clips shorter than that use the first frame.
    let mut last_err = None;
    for seek in ["1", "0"] {
        let _ = tokio::fs::remove_file(&tmp).await;
        // Seeking past the end of a short clip fails; the next seek covers it.
        let result = run(Command::new(ffmpeg)
            .args(["-nostdin", "-loglevel", "error", "-y", "-ss", seek, "-i"])
            .arg(src)
            .args([
                "-frames:v",
                "1",
                "-vf",
                "scale='min(480,iw)':-2",
                "-q:v",
                "4",
            ])
            .arg(&tmp))
        .await;
        if result.is_ok() && tokio::fs::metadata(&tmp).await.is_ok_and(|m| m.len() > 0) {
            tokio::fs::rename(&tmp, dst).await?;
            return Ok(());
        }
        last_err = result.err();
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("ffmpeg produced no frame")))
}

async fn hls(ffmpeg: &str, src: &Path, dst: &Path) -> anyhow::Result<()> {
    let tmp = dst.with_extension("tmp");
    let _ = tokio::fs::remove_dir_all(&tmp).await;
    tokio::fs::create_dir_all(&tmp).await?;
    // Shorter side at most 720 px, so portrait phone videos stay 720p too.
    let scale = "scale='if(gt(iw,ih),-2,min(720,iw))':'if(gt(iw,ih),min(720,ih),-2)'";
    let result = run(Command::new(ffmpeg)
        .args(["-nostdin", "-loglevel", "error", "-y", "-i"])
        .arg(src)
        .args(["-map", "0:v:0", "-map", "0:a:0?", "-vf", scale])
        .args([
            "-c:v",
            "libx264",
            "-preset",
            "veryfast",
            "-crf",
            "23",
            "-profile:v",
            "main",
            "-pix_fmt",
            "yuv420p",
        ])
        .args(["-c:a", "aac", "-b:a", "128k", "-ac", "2"])
        .args([
            "-f",
            "hls",
            "-hls_time",
            "6",
            "-hls_playlist_type",
            "vod",
            "-hls_segment_filename",
        ])
        .arg(tmp.join("seg_%04d.ts"))
        .arg(tmp.join("index.m3u8")))
    .await;
    if let Err(e) = result {
        let _ = tokio::fs::remove_dir_all(&tmp).await;
        return Err(e);
    }
    let _ = tokio::fs::remove_dir_all(dst).await;
    tokio::fs::rename(&tmp, dst).await?;
    Ok(())
}

async fn run(cmd: &mut Command) -> anyhow::Result<()> {
    let out = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output()
        .await
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                anyhow::anyhow!("ffmpeg not found (install it or set ARK_FFMPEG)")
            }
            _ => e.into(),
        })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!(
            "ffmpeg {}: {}",
            out.status,
            err.trim().lines().last().unwrap_or("")
        );
    }
    Ok(())
}
