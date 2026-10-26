//! ZIP download of a selection. `POST /api/v1/zip` checks access and returns a short-
//! lived link; `GET /zip/{token}` streams the archive, so a plain link or `<a download>`
//! works and the browser shows progress. Entries are stored, not compressed: photos and
//! videos are already compressed, and storing keeps a Pi from becoming the bottleneck.

use std::{
    collections::{HashMap, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};

use async_zip::{Compression, ZipDateTimeBuilder, ZipEntryBuilder, tokio::write::ZipFileWriter};
use axum::{
    Json,
    body::Body,
    extract::{Path, State},
    http::{HeaderValue, header},
    response::{IntoResponse, Response},
};
use chrono::{Datelike, Timelike};
use futures_util::AsyncWriteExt;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;
use utoipa::ToSchema;

use crate::{
    AppState,
    auth::{Action, Auth},
    db,
    error::{AppError, AppResult, ErrorBody},
    storage, util,
};

const LINK_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_ENTRIES: usize = 10_000;

#[derive(Default)]
pub struct ZipJobs {
    jobs: Mutex<HashMap<String, ZipJob>>,
}

#[derive(Clone)]
struct ZipJob {
    session_id: String,
    filename: String,
    entries: Vec<Entry>,
    expires: Instant,
}

#[derive(Clone)]
struct Entry {
    zip_path: String,
    disk_dir: String,
    disk_name: String,
    created_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ZipRequest {
    /// Files (any version id; the given version is included).
    #[serde(default)]
    pub file_ids: Vec<String>,
    /// Folders, with their subfolders; current versions only.
    #[serde(default)]
    pub folder_ids: Vec<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ZipCreated {
    /// Download link, valid for 10 minutes with the same session.
    #[schema(example = "/zip/q8V0mJ2l3g8m0r5Yp1xZ7w")]
    pub url: String,
    pub files: usize,
    /// Sum of file sizes; the archive is slightly larger.
    pub total_bytes: i64,
}

#[derive(sqlx::FromRow)]
struct FileRow {
    folder_id: String,
    name: String,
    disk_name: String,
    disk_dir: String,
    size: i64,
    created_at: String,
}

/// Unique, extraction-safe path inside the archive.
fn unique_path(taken: &mut HashSet<String>, dir: &str, name: &str) -> String {
    let name = storage::sanitize_name(name);
    let join = |n: &str| {
        if dir.is_empty() {
            n.to_string()
        } else {
            format!("{dir}/{n}")
        }
    };
    let mut path = join(&name);
    let mut n = 2;
    while !taken.insert(path.to_lowercase()) {
        let (stem, ext) = match name.rfind('.') {
            Some(i) if i > 0 => (&name[..i], &name[i..]),
            _ => (name.as_str(), ""),
        };
        path = join(&format!("{stem} ({n}){ext}"));
        n += 1;
    }
    path
}

/// Prepare a ZIP of files and folders the session can download.
#[utoipa::path(
    post,
    path = "/api/v1/zip",
    tag = "downloads",
    request_body = ZipRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = ZipCreated),
        (status = 400, description = "Empty selection, or more than 10 000 files", body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, description = "Something in the selection is not downloadable", body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<ZipRequest>,
) -> AppResult<Json<ZipCreated>> {
    if req.file_ids.is_empty() && req.folder_ids.is_empty() {
        return Err(AppError::bad_request(
            "empty_selection",
            "Select at least one file or folder",
        ));
    }
    let mut entries = Vec::new();
    let mut taken = HashSet::new();
    let mut total_bytes = 0;
    let mut session_id = None;
    let mut push = |entries: &mut Vec<Entry>, dir: &str, f: FileRow| -> AppResult<()> {
        if entries.len() >= MAX_ENTRIES {
            return Err(AppError::bad_request(
                "too_many_files",
                format!("At most {MAX_ENTRIES} files per ZIP"),
            ));
        }
        total_bytes += f.size;
        entries.push(Entry {
            zip_path: unique_path(&mut taken, dir, &f.name),
            disk_dir: f.disk_dir,
            disk_name: f.disk_name,
            created_at: f.created_at,
        });
        Ok(())
    };

    for id in &req.file_ids {
        let f: FileRow = sqlx::query_as(
            "SELECT f.folder_id, f.name, f.disk_name, d.disk_dir, f.size, f.created_at
             FROM files f JOIN folders d ON d.id = f.folder_id
             WHERE f.id = ? AND f.deleted_at IS NULL AND d.archived_at IS NULL",
        )
        .bind(id)
        .fetch_optional(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
        let s = auth
            .require(&state.db, &f.folder_id, Action::Download)
            .await?;
        session_id.get_or_insert_with(|| s.id.clone());
        push(&mut entries, "", f)?;
    }

    let single_folder =
        (req.file_ids.is_empty() && req.folder_ids.len() == 1).then(|| req.folder_ids[0].clone());
    let mut zip_name = None;
    for id in &req.folder_ids {
        let name: String =
            sqlx::query_scalar("SELECT name FROM folders WHERE id = ? AND archived_at IS NULL")
                .bind(id)
                .fetch_optional(&state.db)
                .await?
                .ok_or(AppError::NotFound)?;
        let s = auth.require(&state.db, id, Action::Download).await?;
        session_id.get_or_insert_with(|| s.id.clone());
        if single_folder.as_deref() == Some(id) {
            zip_name = Some(name.clone());
        }

        // Walk the subtree; everything below an accessible folder is in scope.
        let mut queue = vec![(id.clone(), storage::sanitize_name(&name))];
        while let Some((folder_id, dir)) = queue.pop() {
            let files: Vec<FileRow> = sqlx::query_as(
                "SELECT f.folder_id, f.name, f.disk_name, d.disk_dir, f.size, f.created_at
                 FROM files f JOIN folders d ON d.id = f.folder_id
                 WHERE f.folder_id = ? AND f.is_current = 1 AND f.deleted_at IS NULL
                 ORDER BY f.name",
            )
            .bind(&folder_id)
            .fetch_all(&state.db)
            .await?;
            for f in files {
                push(&mut entries, &dir, f)?;
            }
            let children: Vec<(String, String)> = sqlx::query_as(
                "SELECT id, name FROM folders WHERE parent_id = ? AND archived_at IS NULL",
            )
            .bind(&folder_id)
            .fetch_all(&state.db)
            .await?;
            for (child, child_name) in children {
                queue.push((
                    child,
                    format!("{dir}/{}", storage::sanitize_name(&child_name)),
                ));
            }
        }
    }
    let session_id = session_id.ok_or(AppError::unauthorized())?;

    let token = util::random_token();
    let files = entries.len();
    let filename = format!(
        "{}.zip",
        storage::sanitize_name(&zip_name.unwrap_or_else(|| "ark-download".into()))
    );
    {
        let mut jobs = state.zips.jobs.lock().unwrap();
        let now = Instant::now();
        jobs.retain(|_, j| j.expires > now);
        jobs.insert(
            token.clone(),
            ZipJob {
                session_id,
                filename,
                entries,
                expires: now + LINK_TTL,
            },
        );
    }
    Ok(Json(ZipCreated {
        url: format!("/zip/{token}"),
        files,
        total_bytes,
    }))
}

/// Stream a prepared ZIP. Needs the session that prepared it (cookie or bearer).
#[utoipa::path(
    get,
    path = "/zip/{token}",
    tag = "downloads",
    params(("token" = String, Path, description = "From `POST /api/v1/zip`")),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, description = "ZIP archive", content_type = "application/zip", body = crate::routes::uploads::BinaryBody),
        (status = 401, body = ErrorBody),
        (status = 403, description = "Link belongs to another session", body = ErrorBody),
        (status = 404, description = "Unknown or expired link", body = ErrorBody),
    )
)]
pub async fn download(
    State(state): State<AppState>,
    auth: Auth,
    Path(token): Path<String>,
) -> AppResult<Response> {
    let job = {
        let jobs = state.zips.jobs.lock().unwrap();
        jobs.get(&token)
            .filter(|j| j.expires > Instant::now())
            .cloned()
    }
    .ok_or(AppError::NotFound)?;
    if auth.sessions.is_empty() {
        return Err(AppError::unauthorized());
    }
    let session = auth
        .sessions
        .iter()
        .find(|s| s.id == job.session_id)
        .ok_or(AppError::Forbidden)?;
    db::audit(
        &state.db,
        &session.actor,
        "zip.download",
        None,
        Some(serde_json::json!({ "files": job.entries.len() })),
    )
    .await?;

    let (reader, writer) = tokio::io::duplex(1 << 20);
    let cfg = state.cfg.clone();
    let entries = job.entries;
    tokio::spawn(async move {
        if let Err(e) = write_zip(&cfg, entries, writer).await {
            // Usually the client went away; the archive just ends early.
            tracing::info!(error = %e, "zip stream ended early");
        }
    });

    let disposition = format!(
        "attachment; filename=\"{}\"",
        job.filename.replace(['"', '\\'], "_")
    );
    Ok((
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            ),
            (
                header::CONTENT_DISPOSITION,
                HeaderValue::from_str(&disposition)
                    .unwrap_or(HeaderValue::from_static("attachment")),
            ),
            (
                header::X_CONTENT_TYPE_OPTIONS,
                HeaderValue::from_static("nosniff"),
            ),
        ],
        Body::from_stream(ReaderStream::with_capacity(reader, 256 * 1024)),
    )
        .into_response())
}

async fn write_zip(
    cfg: &crate::config::Config,
    entries: Vec<Entry>,
    out: tokio::io::DuplexStream,
) -> anyhow::Result<()> {
    let mut zip = ZipFileWriter::with_tokio(out);
    let mut buf = vec![0u8; 256 * 1024];
    for e in entries {
        let path = storage::checked_path(cfg, &e.disk_dir, &e.disk_name).await?;
        let mut file = tokio::fs::File::open(&path).await?;
        let mut builder = ZipEntryBuilder::new(e.zip_path.into(), Compression::Stored);
        if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&e.created_at) {
            builder = builder.last_modification_date(
                ZipDateTimeBuilder::new()
                    .year(t.year())
                    .month(t.month())
                    .day(t.day())
                    .hour(t.hour())
                    .minute(t.minute())
                    .second(t.second())
                    .build(),
            );
        }
        let mut w = zip.write_entry_stream(builder).await?;
        loop {
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            w.write_all(&buf[..n]).await?;
        }
        w.close().await?;
    }
    zip.close().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_paths() {
        let mut taken = HashSet::new();
        assert_eq!(unique_path(&mut taken, "", "a.jpg"), "a.jpg");
        assert_eq!(unique_path(&mut taken, "", "A.jpg"), "A (2).jpg");
        assert_eq!(unique_path(&mut taken, "", "a.jpg"), "a (3).jpg");
        assert_eq!(unique_path(&mut taken, "Day 1", "a.jpg"), "Day 1/a.jpg");
        // Separators never survive into an entry name.
        assert_eq!(unique_path(&mut taken, "", "../../x.txt"), "_.._x.txt");
    }
}
