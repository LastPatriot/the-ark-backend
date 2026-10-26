//! tus 1.0 core subset: creation, HEAD/PATCH resume, termination.

use std::{
    collections::HashMap,
    io::Read,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use tokio::{
    io::{AsyncSeekExt, AsyncWriteExt},
    sync::OwnedMutexGuard,
};
use tokio_util::sync::CancellationToken;
use utoipa::ToSchema;

use super::{
    events::{EventKind, publish},
    folders::resolve,
};
use crate::{
    AppState,
    auth::{Action, Auth, ancestor_chain},
    db,
    error::{AppError, AppResult, ErrorBody},
    storage, util,
    workers::thumbnails,
};

pub const TUS_VERSION: &str = "1.0.0";
pub const MAX_UPLOAD_BYTES: i64 = 64 << 30;
/// Response header carrying the id of the finished file, on the final PATCH and on HEAD
/// of a completed upload. Not part of tus.
pub const FILE_ID_HEADER: &str = "ark-file-id";
/// A PATCH that receives nothing for this long is treated as a dead connection.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Raw bytes, for the OpenAPI doc.
#[derive(ToSchema)]
#[schema(value_type = String, format = Binary)]
pub struct BinaryBody(#[allow(dead_code)] Vec<u8>);

/// Serializes requests on one upload. A new HEAD/PATCH tells the request currently
/// writing to stop: clients only retry once they think that request is dead (e.g. the
/// phone's Wi-Fi dropped), and on a half-open connection it could otherwise block the
/// resume until TCP gives up.
#[derive(Default)]
pub struct UploadLocks {
    slots: Mutex<HashMap<String, Arc<Slot>>>,
}

struct Slot {
    lock: Arc<tokio::sync::Mutex<()>>,
    cancel: Mutex<CancellationToken>,
}

struct UploadGuard {
    _guard: OwnedMutexGuard<()>,
    cancel: CancellationToken,
}

impl UploadLocks {
    async fn acquire(&self, id: &str) -> UploadGuard {
        let slot = self
            .slots
            .lock()
            .unwrap()
            .entry(id.to_string())
            .or_insert_with(|| {
                Arc::new(Slot {
                    lock: Arc::new(tokio::sync::Mutex::new(())),
                    cancel: Mutex::new(CancellationToken::new()),
                })
            })
            .clone();
        slot.cancel.lock().unwrap().cancel();
        let guard = slot.lock.clone().lock_owned().await;
        let cancel = CancellationToken::new();
        *slot.cancel.lock().unwrap() = cancel.clone();
        UploadGuard {
            _guard: guard,
            cancel,
        }
    }

    fn forget(&self, id: &str) {
        self.slots.lock().unwrap().remove(id);
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct UploadRow {
    id: String,
    folder_id: String,
    filename: String,
    size: i64,
    offset: i64,
    session_id: String,
    status: String,
    file_id: Option<String>,
}

async fn load_upload(db: &SqlitePool, id: &str) -> AppResult<Option<UploadRow>> {
    Ok(sqlx::query_as(
        "SELECT id, folder_id, filename, size, offset, session_id, status, file_id
         FROM uploads WHERE id = ?",
    )
    .bind(id)
    .fetch_optional(db)
    .await?)
}

/// The upload, if it belongs to one of the request's sessions. Returns the uploader's
/// audit label as well.
async fn load_owned(state: &AppState, auth: &Auth, id: &str) -> AppResult<(UploadRow, String)> {
    if auth.sessions.is_empty() {
        return Err(AppError::unauthorized());
    }
    let up = load_upload(&state.db, id)
        .await?
        .ok_or(AppError::NotFound)?;
    let session = auth
        .sessions
        .iter()
        .find(|s| s.id == up.session_id)
        .ok_or(AppError::NotFound)?;
    if up.status == "aborted" {
        return Err(AppError::NotFound);
    }
    Ok((up, session.actor.clone()))
}

fn check_tus_version(headers: &HeaderMap) -> AppResult<()> {
    match headers.get("tus-resumable") {
        Some(v) if v != TUS_VERSION => Err(AppError::Status(
            StatusCode::PRECONDITION_FAILED,
            "tus_version",
            format!("Only Tus-Resumable {TUS_VERSION} is supported"),
        )),
        _ => Ok(()),
    }
}

fn header_i64(headers: &HeaderMap, name: &'static str) -> AppResult<Option<i64>> {
    let Some(v) = headers.get(name) else {
        return Ok(None);
    };
    v.to_str()
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .filter(|n| *n >= 0)
        .map(Some)
        .ok_or_else(|| {
            AppError::bad_request(
                "invalid_header",
                format!("{name} must be a non-negative integer"),
            )
        })
}

/// `key base64value,key2 base64value2` -> map. Values are optional in tus.
fn parse_metadata(raw: &str) -> AppResult<HashMap<String, String>> {
    let mut out = HashMap::new();
    for pair in raw.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (key, value) = pair.split_once(' ').unwrap_or((pair, ""));
        let decoded = STANDARD
            .decode(value.trim())
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or_else(|| {
                AppError::bad_request(
                    "invalid_metadata",
                    format!("Upload-Metadata value for {key:?} is not base64 UTF-8"),
                )
            })?;
        out.insert(key.to_string(), decoded);
    }
    Ok(out)
}

fn offset_headers(up_offset: i64, file_id: Option<&str>) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("upload-offset", HeaderValue::from(up_offset));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(id) = file_id.and_then(|id| HeaderValue::from_str(id).ok()) {
        h.insert(FILE_ID_HEADER, id);
    }
    h
}

/// Bytes stored in `folder_id` and below, including old versions, trash and active uploads.
pub async fn usage(db: &SqlitePool, folder_id: &str) -> sqlx::Result<i64> {
    sqlx::query_scalar(
        "WITH RECURSIVE sub(id) AS (
             SELECT ?1 UNION ALL SELECT f.id FROM folders f JOIN sub ON f.parent_id = sub.id
         )
         SELECT COALESCE((SELECT SUM(size) FROM files WHERE folder_id IN sub), 0)
              + COALESCE((SELECT SUM(size - offset) FROM uploads
                          WHERE folder_id IN sub AND status = 'active'), 0)",
    )
    .bind(folder_id)
    .fetch_one(db)
    .await
}

/// Every folder in the chain with a `storage_limit` must have room for `extra` bytes.
async fn check_quota(db: &SqlitePool, folder_id: &str, extra: i64) -> AppResult<()> {
    for id in ancestor_chain(db, folder_id).await? {
        let limit: Option<i64> =
            sqlx::query_scalar("SELECT storage_limit FROM folders WHERE id = ?")
                .bind(&id)
                .fetch_one(db)
                .await?;
        if let Some(limit) = limit
            && usage(db, &id).await? + extra > limit
        {
            return Err(AppError::Status(
                StatusCode::PAYLOAD_TOO_LARGE,
                "quota_exceeded",
                "This folder is out of space".into(),
            ));
        }
    }
    Ok(())
}

/// tus capability discovery.
#[utoipa::path(
    options,
    path = "/api/v1/uploads",
    tag = "uploads",
    responses((status = 204, headers(
        ("Tus-Resumable" = String), ("Tus-Version" = String),
        ("Tus-Extension" = String), ("Tus-Max-Size" = i64),
    )))
)]
pub async fn options() -> impl IntoResponse {
    (
        StatusCode::NO_CONTENT,
        [
            ("tus-version", TUS_VERSION.to_string()),
            ("tus-extension", "creation,termination".to_string()),
            ("tus-max-size", MAX_UPLOAD_BYTES.to_string()),
        ],
    )
}

/// Start an upload (tus creation).
///
/// `Upload-Metadata` is comma-separated `key base64(value)` pairs: `filename` (or
/// `name`) and `folder` (top-level slug) are required, `path` (subfolder path) is
/// optional. A zero-length upload completes immediately.
#[utoipa::path(
    post,
    path = "/api/v1/uploads",
    tag = "uploads",
    params(
        ("Upload-Length" = i64, Header, description = "Total size in bytes"),
        ("Upload-Metadata" = String, Header, description = "filename and folder, base64",
            example = "filename aGVsbG8udHh0,folder c3VuZGF5LXNlcnZpY2U="),
        ("Tus-Resumable" = Option<String>, Header, example = "1.0.0"),
    ),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 201, description = "Created", headers(("Location" = String, description = "Upload URL"))),
        (status = 400, description = "Missing or malformed headers", body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, description = "Role or scope does not allow uploads", body = ErrorBody),
        (status = 404, description = "No such folder", body = ErrorBody),
        (status = 413, description = "Too large or folder quota exceeded", body = ErrorBody),
    )
)]
pub async fn create(
    State(state): State<AppState>,
    auth: Auth,
    headers: HeaderMap,
) -> AppResult<Response> {
    check_tus_version(&headers)?;
    let size = header_i64(&headers, "upload-length")?.ok_or_else(|| {
        AppError::bad_request(
            "missing_upload_length",
            "Upload-Length is required (deferred length is not supported)",
        )
    })?;
    if size > MAX_UPLOAD_BYTES {
        return Err(AppError::Status(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_large",
            format!("Uploads are limited to {MAX_UPLOAD_BYTES} bytes"),
        ));
    }
    let meta = parse_metadata(
        headers
            .get("upload-metadata")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    )?;
    let filename = meta
        .get("filename")
        .or_else(|| meta.get("name"))
        .and_then(|n| storage::display_name(n))
        .ok_or_else(|| {
            AppError::bad_request("missing_filename", "Upload-Metadata needs a filename")
        })?;
    let slug = meta
        .get("folder")
        .ok_or_else(|| AppError::bad_request("missing_folder", "Upload-Metadata needs a folder"))?;

    let folder = resolve(&state.db, slug, meta.get("path").map(String::as_str)).await?;
    let session = auth.require(&state.db, &folder.id, Action::Upload).await?;
    check_quota(&state.db, &folder.id, size).await?;

    let id = util::new_id();
    tokio::fs::File::create(storage::part_path(&state.cfg, &id)).await?;
    let now = util::now();
    sqlx::query(
        "INSERT INTO uploads (id, folder_id, filename, size, offset, session_id, created_at, updated_at)
         VALUES (?, ?, ?, ?, 0, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&folder.id)
    .bind(&filename)
    .bind(size)
    .bind(&session.id)
    .bind(&now)
    .bind(&now)
    .execute(&state.db)
    .await?;

    let mut resp_headers = offset_headers(0, None);
    if size == 0 {
        let up = load_upload(&state.db, &id)
            .await?
            .ok_or(AppError::NotFound)?;
        let file_id = finalize(&state, &up, &session.actor).await?;
        resp_headers = offset_headers(0, Some(&file_id));
    }
    resp_headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&format!("/api/v1/uploads/{id}")).map_err(anyhow::Error::from)?,
    );
    Ok((StatusCode::CREATED, resp_headers).into_response())
}

/// Current offset of an upload, to resume it. Stops any stalled PATCH on it first.
#[utoipa::path(
    head,
    path = "/api/v1/uploads/{id}",
    tag = "uploads",
    params(("id" = String, Path)),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, headers(
            ("Upload-Offset" = i64), ("Upload-Length" = i64),
            ("Ark-File-Id" = String, description = "Set once the upload is complete"),
        )),
        (status = 401, description = "No session"),
        (status = 404, description = "Unknown, terminated, or another session's upload"),
    )
)]
pub async fn head(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> AppResult<Response> {
    load_owned(&state, &auth, &id).await?;
    let _guard = state.uploads.acquire(&id).await;
    let up = load_upload(&state.db, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    let mut h = offset_headers(up.offset, up.file_id.as_deref());
    h.insert("upload-length", HeaderValue::from(up.size));
    Ok((StatusCode::OK, h).into_response())
}

enum Received {
    /// Body fully read.
    Done,
    /// Connection dropped, idle too long, or superseded by a newer request.
    Interrupted,
    /// Body was longer than the chunk limit or the rest of the upload.
    TooLong,
}

/// Append a chunk (tus PATCH). The body is written at `Upload-Offset`, which must match
/// the server's offset. The final chunk finalizes the file and returns `Ark-File-Id`.
#[utoipa::path(
    patch,
    path = "/api/v1/uploads/{id}",
    tag = "uploads",
    params(
        ("id" = String, Path),
        ("Upload-Offset" = i64, Header, description = "Must equal the current offset"),
        ("Tus-Resumable" = Option<String>, Header, example = "1.0.0"),
    ),
    request_body(content = BinaryBody, content_type = "application/offset+octet-stream"),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 204, description = "Chunk stored", headers(
            ("Upload-Offset" = i64, description = "New offset"),
            ("Ark-File-Id" = String, description = "Set when this chunk completed the upload"),
        )),
        (status = 400, description = "Missing Upload-Offset", body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 404, description = "Unknown, terminated, or another session's upload", body = ErrorBody),
        (status = 409, description = "Upload-Offset does not match; HEAD and retry", body = ErrorBody),
        (status = 413, description = "Chunk larger than ARK_MAX_CHUNK_MB or the rest of the upload", body = ErrorBody),
        (status = 415, description = "Wrong Content-Type", body = ErrorBody),
    )
)]
pub async fn patch(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> AppResult<Response> {
    check_tus_version(&headers)?;
    if headers
        .get(header::CONTENT_TYPE)
        .is_none_or(|v| v != "application/offset+octet-stream")
    {
        return Err(AppError::Status(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "content_type",
            "Content-Type must be application/offset+octet-stream".into(),
        ));
    }
    let client_offset = header_i64(&headers, "upload-offset")?.ok_or_else(|| {
        AppError::bad_request("missing_upload_offset", "Upload-Offset is required")
    })?;

    let (_, actor) = load_owned(&state, &auth, &id).await?;
    let guard = state.uploads.acquire(&id).await;
    let up = load_upload(&state.db, &id)
        .await?
        .ok_or(AppError::NotFound)?;

    if up.status == "complete" && client_offset == up.size {
        return Ok((
            StatusCode::NO_CONTENT,
            offset_headers(up.offset, up.file_id.as_deref()),
        )
            .into_response());
    }
    if up.status != "active" {
        return Err(AppError::NotFound);
    }
    if client_offset != up.offset {
        return Err(AppError::conflict(
            "offset_mismatch",
            format!(
                "Upload-Offset is {client_offset} but the server has {}",
                up.offset
            ),
        ));
    }

    let allowed = (up.size - up.offset).min(state.cfg.max_chunk_bytes() as i64) as u64;
    if header_i64(&headers, "content-length")?.is_some_and(|n| n as u64 > allowed) {
        return Err(too_long(allowed));
    }

    let part = storage::part_path(&state.cfg, &id);
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(&part)
        .await?;
    // Drop anything past the recorded offset left by a request that died mid-write.
    file.set_len(up.offset as u64).await?;
    file.seek(std::io::SeekFrom::Start(up.offset as u64))
        .await?;

    let mut written: u64 = 0;
    let mut stream = body.into_data_stream();
    let received = loop {
        let next = tokio::select! {
            _ = guard.cancel.cancelled() => break Received::Interrupted,
            next = tokio::time::timeout(IDLE_TIMEOUT, stream.next()) => next,
        };
        match next {
            Ok(Some(Ok(bytes))) => {
                let room = (allowed - written) as usize;
                let take = bytes.len().min(room);
                file.write_all(&bytes[..take]).await?;
                written += take as u64;
                if take < bytes.len() {
                    break Received::TooLong;
                }
            }
            Ok(None) => break Received::Done,
            Ok(Some(Err(_))) | Err(_) => break Received::Interrupted,
        }
    };
    file.sync_data().await?;
    drop(file);

    let offset = up.offset + written as i64;
    sqlx::query("UPDATE uploads SET offset = ?, updated_at = ? WHERE id = ?")
        .bind(offset)
        .bind(util::now())
        .bind(&id)
        .execute(&state.db)
        .await?;
    match received {
        Received::TooLong => return Err(too_long(allowed)),
        Received::Interrupted => {
            tracing::info!(
                upload = id,
                offset,
                "upload chunk interrupted; client can resume"
            );
        }
        Received::Done => {}
    }

    let mut file_id = None;
    if offset == up.size {
        let up = UploadRow { offset, ..up };
        file_id = Some(finalize(&state, &up, &actor).await?);
        state.uploads.forget(&id);
    }
    Ok((
        StatusCode::NO_CONTENT,
        offset_headers(offset, file_id.as_deref()),
    )
        .into_response())
}

fn too_long(allowed: u64) -> AppError {
    AppError::Status(
        StatusCode::PAYLOAD_TOO_LARGE,
        "chunk_too_large",
        format!("At most {allowed} bytes are accepted in this request"),
    )
}

/// Abort an upload (tus termination) and delete its partial data.
#[utoipa::path(
    delete,
    path = "/api/v1/uploads/{id}",
    tag = "uploads",
    params(("id" = String, Path)),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 204, description = "Terminated (a completed upload's file is kept)"),
        (status = 401, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn terminate(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    load_owned(&state, &auth, &id).await?;
    let _guard = state.uploads.acquire(&id).await;
    let result = sqlx::query(
        "UPDATE uploads SET status = 'aborted', updated_at = ? WHERE id = ? AND status = 'active'",
    )
    .bind(util::now())
    .bind(&id)
    .execute(&state.db)
    .await?;
    if result.rows_affected() > 0 {
        match tokio::fs::remove_file(storage::part_path(&state.cfg, &id)).await {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.into()),
            _ => {}
        }
    }
    state.uploads.forget(&id);
    Ok(StatusCode::NO_CONTENT)
}

async fn sha256_file(path: PathBuf) -> AppResult<String> {
    tokio::task::spawn_blocking(move || -> std::io::Result<String> {
        let mut f = std::fs::File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(util::hex(&hasher.finalize()))
    })
    .await
    .map_err(anyhow::Error::from)?
    .map_err(AppError::from)
}

/// Moves a complete `.part` into its folder and records it. Returns the file id; when a
/// current file in the folder has the same content, that file's id (dedup).
async fn finalize(state: &AppState, up: &UploadRow, actor: &str) -> AppResult<String> {
    let part = storage::part_path(&state.cfg, &up.id);
    let sha = sha256_file(part.clone()).await?;

    let existing: Option<String> = sqlx::query_scalar(
        "SELECT id FROM files WHERE folder_id = ? AND sha256 = ? AND is_current = 1 AND deleted_at IS NULL
         LIMIT 1",
    )
    .bind(&up.folder_id)
    .bind(&sha)
    .fetch_optional(&state.db)
    .await?;
    if let Some(file_id) = existing {
        tokio::fs::remove_file(&part).await?;
        mark_complete(&state.db, &up.id, &file_id).await?;
        tracing::info!(
            upload = up.id,
            file = file_id,
            "duplicate upload, kept existing file"
        );
        return Ok(file_id);
    }

    let disk_dir: String = sqlx::query_scalar("SELECT disk_dir FROM folders WHERE id = ?")
        .bind(&up.folder_id)
        .fetch_one(&state.db)
        .await?;
    let file_id = util::new_id();
    let mut tx = state.db.begin().await?;

    // Versions count every row with the name, trashed ones too, so disk names never repeat.
    let prev: Option<i64> = sqlx::query_scalar(
        "SELECT MAX(version) FROM files WHERE folder_id = ? AND name = ? COLLATE NOCASE",
    )
    .bind(&up.folder_id)
    .bind(&up.filename)
    .fetch_one(&mut *tx)
    .await?;
    let version = prev.unwrap_or(0) + 1;
    sqlx::query(
        "UPDATE files SET is_current = 0 WHERE folder_id = ? AND name = ? COLLATE NOCASE AND is_current = 1",
    )
    .bind(&up.folder_id)
    .bind(&up.filename)
    .execute(&mut *tx)
    .await?;

    let mut disk_name = storage::versioned_disk_name(&up.filename, version);
    let mut target = storage::checked_path(&state.cfg, &disk_dir, &disk_name).await?;
    if tokio::fs::try_exists(&target).await? {
        let tag = &file_id.replace('-', "")[26..];
        disk_name = storage::tagged_disk_name(&disk_name, tag);
        target = storage::checked_path(&state.cfg, &disk_dir, &disk_name).await?;
    }
    tokio::fs::rename(&part, &target).await?;

    let mime = mime_guess::from_path(&up.filename)
        .first()
        .map(|m| m.to_string());
    let recorded = async {
        sqlx::query(
            "INSERT INTO files (id, folder_id, name, disk_name, version, is_current, size, sha256, mime,
                                uploaded_by, session_id, created_at)
             VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&file_id)
        .bind(&up.folder_id)
        .bind(&up.filename)
        .bind(&disk_name)
        .bind(version)
        .bind(up.size)
        .bind(&sha)
        .bind(&mime)
        .bind(actor)
        .bind(&up.session_id)
        .bind(util::now())
        .execute(&mut *tx)
        .await?;
        sqlx::query("UPDATE uploads SET status = 'complete', file_id = ?, updated_at = ? WHERE id = ?")
            .bind(&file_id)
            .bind(util::now())
            .bind(&up.id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await
    }
    .await;
    if let Err(e) = recorded {
        // Put the data back so the client can retry the final HEAD/PATCH.
        let _ = tokio::fs::rename(&target, &part).await;
        return Err(e.into());
    }

    db::audit(
        &state.db,
        actor,
        "file.upload",
        Some(&file_id),
        Some(serde_json::json!({
            "folder_id": up.folder_id, "name": up.filename, "size": up.size, "version": version,
        })),
    )
    .await?;
    if let Err(e) = thumbnails::queue(state, &file_id, mime.as_deref()).await {
        tracing::error!(error = ?e, file = file_id, "queueing thumbnail");
    }
    publish(
        state,
        EventKind::FileAdded,
        &up.folder_id,
        &file_id,
        Some(&up.filename),
        Some(&up.session_id),
    )
    .await;
    Ok(file_id)
}

async fn mark_complete(db: &SqlitePool, upload_id: &str, file_id: &str) -> sqlx::Result<()> {
    sqlx::query("UPDATE uploads SET status = 'complete', file_id = ?, updated_at = ? WHERE id = ?")
        .bind(file_id)
        .bind(util::now())
        .bind(upload_id)
        .execute(db)
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata() {
        let m = parse_metadata("filename aGVsbG8udHh0, folder c3VuZGF5LXNlcnZpY2U=,empty").unwrap();
        assert_eq!(m["filename"], "hello.txt");
        assert_eq!(m["folder"], "sunday-service");
        assert_eq!(m["empty"], "");
        assert!(parse_metadata("filename !!!").is_err());
    }
}
