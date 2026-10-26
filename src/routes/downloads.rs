use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio_util::io::ReaderStream;

use crate::{
    AppState,
    auth::{Action, Auth, Role},
    error::{AppError, AppResult, ErrorBody},
    storage,
};

/// Download a file. Supports a single `Range` (resume, video seeking). Always served as
/// an attachment with `nosniff`, never rendered inline.
#[utoipa::path(
    get,
    path = "/dl/{file_id}",
    tag = "downloads",
    params(
        ("file_id" = String, Path),
        ("Range" = Option<String>, Header, example = "bytes=0-1023"),
    ),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, description = "Whole file", content_type = "application/octet-stream", body = crate::routes::uploads::BinaryBody),
        (status = 206, description = "Requested range", content_type = "application/octet-stream", body = crate::routes::uploads::BinaryBody),
        (status = 304, description = "If-None-Match matched the ETag"),
        (status = 401, body = ErrorBody),
        (status = 403, description = "Role or scope does not allow downloads", body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 416, description = "Range not satisfiable"),
    )
)]
pub async fn download(
    State(state): State<AppState>,
    auth: Auth,
    Path(file_id): Path<String>,
    headers: HeaderMap,
) -> AppResult<Response> {
    let row: Option<(String, String, String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT f.folder_id, f.name, f.disk_name, f.mime, f.sha256, d.disk_dir
         FROM files f JOIN folders d ON d.id = f.folder_id
         WHERE f.id = ? AND f.deleted_at IS NULL AND d.archived_at IS NULL",
    )
    .bind(&file_id)
    .fetch_optional(&state.db)
    .await?;
    let (folder_id, name, disk_name, mime, sha, disk_dir) = row.ok_or(AppError::NotFound)?;
    auth.require(&state.db, &folder_id, Action::Download)
        .await?;

    let path = storage::checked_path(&state.cfg, &disk_dir, &disk_name).await?;
    let mut file = match tokio::fs::File::open(&path).await {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::error!(file_id, path = %path.display(), "file row exists but data is missing");
            return Err(AppError::NotFound);
        }
        Err(e) => return Err(e.into()),
    };
    let size = file.metadata().await?.len();

    let etag = format!("\"{sha}\"");
    let mut h = HeaderMap::new();
    h.insert(
        header::ETAG,
        HeaderValue::from_str(&etag).map_err(anyhow::Error::from)?,
    );
    h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    h.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-cache"),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&content_disposition(&name)).map_err(anyhow::Error::from)?,
    );

    if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|v| v.as_bytes() == etag.as_bytes())
    {
        return Ok((StatusCode::NOT_MODIFIED, h).into_response());
    }

    // If-Range with a stale validator means "send the whole file".
    let range_ok = headers
        .get(header::IF_RANGE)
        .is_none_or(|v| v.as_bytes() == etag.as_bytes());
    let range = match headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
        Some(r) if range_ok => parse_range(r, size),
        _ => Ok(None),
    };

    let (status, start, len) = match range {
        Ok(None) => (StatusCode::OK, 0, size),
        Ok(Some((start, end))) => {
            h.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {start}-{end}/{size}"))
                    .map_err(anyhow::Error::from)?,
            );
            (StatusCode::PARTIAL_CONTENT, start, end - start + 1)
        }
        Err(()) => {
            h.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{size}")).map_err(anyhow::Error::from)?,
            );
            return Ok((StatusCode::RANGE_NOT_SATISFIABLE, h).into_response());
        }
    };

    let content_type = mime.as_deref().unwrap_or("application/octet-stream");
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(len));

    if start > 0 {
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    let body = Body::from_stream(ReaderStream::with_capacity(file.take(len), 256 * 1024));
    Ok((status, h, body).into_response())
}

/// A file's thumbnail (JPEG, longest edge 480 px). 404 until the worker has made it.
#[utoipa::path(
    get,
    path = "/preview/{file_id}/{kind}",
    tag = "downloads",
    params(("file_id" = String, Path), ("kind" = String, Path, description = "`thumb`")),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, description = "JPEG", content_type = "image/jpeg", body = crate::routes::uploads::BinaryBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, description = "No preview (yet)", body = ErrorBody),
    )
)]
pub async fn preview(
    State(state): State<AppState>,
    auth: Auth,
    Path((file_id, kind)): Path<(String, String)>,
) -> AppResult<Response> {
    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT f.folder_id, f.session_id, p.path
         FROM previews p JOIN files f ON f.id = p.file_id JOIN folders d ON d.id = f.folder_id
         WHERE p.file_id = ? AND p.kind = ? AND p.status = 'ready'
           AND f.deleted_at IS NULL AND d.archived_at IS NULL",
    )
    .bind(&file_id)
    .bind(&kind)
    .fetch_optional(&state.db)
    .await?;
    let (folder_id, owner, name) = row.ok_or(AppError::NotFound)?;
    let session = auth.require(&state.db, &folder_id, Action::List).await?;
    if session.role == Role::Uploader && owner.as_deref() != Some(session.id.as_str()) {
        return Err(AppError::Forbidden);
    }

    let data = match tokio::fs::read(storage::preview_path(&state.cfg, &name)).await {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(AppError::NotFound),
        Err(e) => return Err(e.into()),
    };
    Ok((
        [
            (header::CONTENT_TYPE, "image/jpeg"),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            // A file id's content never changes, so neither does its preview.
            (header::CACHE_CONTROL, "private, max-age=86400"),
        ],
        data,
    )
        .into_response())
}

/// Parses a single `bytes=` range into inclusive `(start, end)`.
/// `Ok(None)`: ignore the header and send everything (unknown unit, multiple ranges,
/// bad syntax). `Err(())`: 416.
fn parse_range(value: &str, size: u64) -> Result<Option<(u64, u64)>, ()> {
    let Some(spec) = value.trim().strip_prefix("bytes=") else {
        return Ok(None);
    };
    if spec.contains(',') {
        return Ok(None);
    }
    let Some((first, last)) = spec.trim().split_once('-') else {
        return Ok(None);
    };
    let (first, last) = (first.trim(), last.trim());
    let parse = |s: &str| s.parse::<u64>().ok();

    if first.is_empty() {
        // Suffix range: the last N bytes.
        let Some(n) = parse(last) else {
            return Ok(None);
        };
        if n == 0 || size == 0 {
            return Err(());
        }
        return Ok(Some((size.saturating_sub(n), size - 1)));
    }
    let Some(start) = parse(first) else {
        return Ok(None);
    };
    let end = if last.is_empty() {
        u64::MAX
    } else {
        match parse(last) {
            Some(e) if e >= start => e,
            _ => return Ok(None),
        }
    };
    if start >= size {
        return Err(());
    }
    Ok(Some((start, end.min(size - 1))))
}

/// `attachment` with an ASCII fallback name and the exact UTF-8 name (RFC 6266 / 5987).
fn content_disposition(name: &str) -> String {
    let ascii: String = name
        .chars()
        .map(|c| match c {
            '"' | '\\' => '_',
            c if c.is_ascii() && !c.is_ascii_control() => c,
            _ => '_',
        })
        .collect();
    let mut encoded = String::new();
    for b in name.bytes() {
        if b.is_ascii_alphanumeric() || b"!#$&+-.^_`|~".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    format!("attachment; filename=\"{ascii}\"; filename*=UTF-8''{encoded}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-99", 1000), Ok(Some((0, 99))));
        assert_eq!(parse_range("bytes=500-", 1000), Ok(Some((500, 999))));
        assert_eq!(parse_range("bytes=900-5000", 1000), Ok(Some((900, 999))));
        assert_eq!(parse_range("bytes=-100", 1000), Ok(Some((900, 999))));
        assert_eq!(parse_range("bytes=-5000", 1000), Ok(Some((0, 999))));
        assert_eq!(parse_range("bytes=1000-", 1000), Err(()));
        assert_eq!(parse_range("bytes=-0", 1000), Err(()));
        assert_eq!(parse_range("bytes=0-", 0), Err(()));
        assert_eq!(parse_range("bytes=5-1", 1000), Ok(None));
        assert_eq!(parse_range("bytes=0-1,5-9", 1000), Ok(None));
        assert_eq!(parse_range("items=0-1", 1000), Ok(None));
        assert_eq!(parse_range("bytes=abc", 1000), Ok(None));
    }

    #[test]
    fn disposition() {
        assert_eq!(
            content_disposition("photo.jpg"),
            "attachment; filename=\"photo.jpg\"; filename*=UTF-8''photo.jpg"
        );
        assert_eq!(
            content_disposition("Ọdún \"new\".mp4"),
            "attachment; filename=\"_d_n _new_.mp4\"; filename*=UTF-8''%E1%BB%8Cd%C3%BAn%20%22new%22.mp4"
        );
    }
}
