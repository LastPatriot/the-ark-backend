//! Admin: sessions, activity log, storage, trash and QR codes.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::{folders::folder_path, uploads::usage};
use crate::{
    AppState,
    auth::{Auth, Role},
    db,
    error::{AppError, AppResult, ErrorBody},
    qr,
    tunnel::{self, Mode, TunnelStatus},
    util,
    workers::{
        sync::{self, SyncStatus},
        trash,
    },
};

/// An active session. Session ids are credentials, so sessions are identified by a
/// `handle` derived from the id instead.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminSession {
    pub handle: String,
    pub role: Role,
    pub root_folder: Option<String>,
    /// `slug` or `slug/sub/path` of the root folder.
    pub folder: Option<String>,
    /// PIN or join-token label (role name for admin sessions).
    pub label: String,
    pub ip: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: String,
    role: Role,
    root_folder: Option<String>,
    label: String,
    ip: Option<String>,
    created_at: String,
    expires_at: String,
}

fn handle(session_id: &str) -> String {
    util::sha256_hex(session_id.as_bytes())[..16].to_string()
}

async fn active_sessions(state: &AppState) -> sqlx::Result<Vec<SessionRow>> {
    sqlx::query_as(
        "SELECT s.id, s.role, s.root_folder, COALESCE(p.label, t.label, s.role) AS label, s.ip,
                s.created_at, s.expires_at
         FROM sessions s
         LEFT JOIN pins p ON p.id = s.pin_id
         LEFT JOIN join_tokens t ON t.id = s.token_id
         WHERE s.revoked_at IS NULL AND s.expires_at > ?
         ORDER BY s.created_at DESC",
    )
    .bind(util::now())
    .fetch_all(&state.db)
    .await
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/sessions",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Vec<AdminSession>),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn list_sessions(
    State(state): State<AppState>,
    auth: Auth,
) -> AppResult<Json<Vec<AdminSession>>> {
    auth.admin()?;
    let mut out = Vec::new();
    for s in active_sessions(&state).await? {
        let folder = match &s.root_folder {
            Some(id) => {
                let (slug, path) = folder_path(&state.db, id).await?;
                Some(if path.is_empty() {
                    slug
                } else {
                    format!("{slug}/{path}")
                })
            }
            None => None,
        };
        out.push(AdminSession {
            handle: handle(&s.id),
            role: s.role,
            root_folder: s.root_folder,
            folder,
            label: s.label,
            ip: s.ip,
            created_at: s.created_at,
            expires_at: s.expires_at,
        });
    }
    Ok(Json(out))
}

/// End one session.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/sessions/{handle}",
    tag = "admin",
    params(("handle" = String, Path)),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 204, description = "Ended"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn end_session(
    State(state): State<AppState>,
    auth: Auth,
    Path(h): Path<String>,
) -> AppResult<StatusCode> {
    let admin = auth.admin()?;
    let session = active_sessions(&state)
        .await?
        .into_iter()
        .find(|s| handle(&s.id) == h)
        .ok_or(AppError::NotFound)?;
    crate::auth::end_session(&state.db, &session.id).await?;
    db::audit(
        &state.db,
        &admin.actor,
        "session.end",
        Some(&h),
        Some(serde_json::json!({ "label": session.label })),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct ActivityQuery {
    /// Return entries older than this id (from `next_before`).
    pub before: Option<i64>,
    /// 1–200, default 50.
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEntry {
    pub id: i64,
    /// `admin`, `system`, or a PIN/token label.
    pub actor: String,
    #[schema(example = "file.upload")]
    pub action: String,
    pub target: Option<String>,
    #[schema(value_type = Option<Object>)]
    pub details: Option<serde_json::Value>,
    pub created_at: String,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: i64,
    actor: String,
    action: String,
    target: Option<String>,
    details: Option<String>,
    created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ActivityPage {
    pub items: Vec<AuditEntry>,
    /// Pass as `before` for the next page; null on the last page.
    pub next_before: Option<i64>,
}

/// Audit log, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/activity",
    tag = "admin",
    params(ActivityQuery),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = ActivityPage),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn activity(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<ActivityQuery>,
) -> AppResult<Json<ActivityPage>> {
    auth.admin()?;
    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let rows: Vec<AuditRow> = sqlx::query_as(
        "SELECT id, actor, action, target, details, created_at FROM audit_log
         WHERE (?1 IS NULL OR id < ?1) ORDER BY id DESC LIMIT ?2",
    )
    .bind(q.before)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    let next_before = (rows.len() as i64 == limit)
        .then(|| rows.last().map(|r| r.id))
        .flatten();
    let items = rows
        .into_iter()
        .map(|r| AuditEntry {
            id: r.id,
            actor: r.actor,
            action: r.action,
            target: r.target,
            details: r.details.and_then(|d| serde_json::from_str(&d).ok()),
            created_at: r.created_at,
        })
        .collect();
    Ok(Json(ActivityPage { items, next_before }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FolderUsage {
    pub id: String,
    pub slug: String,
    pub name: String,
    /// Bytes, including subfolders, old versions, trash and in-progress uploads.
    pub used: i64,
    pub storage_limit: Option<i64>,
    pub archived: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StorageReport {
    /// Bytes on the data directory's disk.
    pub disk_total: u64,
    /// Bytes still available to Ark.
    pub disk_available: u64,
    pub used_total: i64,
    pub folders: Vec<FolderUsage>,
}

/// Used and free space per top-level folder.
#[utoipa::path(
    get,
    path = "/api/v1/admin/storage",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = StorageReport),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn storage_report(
    State(state): State<AppState>,
    auth: Auth,
) -> AppResult<Json<StorageReport>> {
    auth.admin()?;
    let tops: Vec<(String, String, String, Option<i64>, bool)> = sqlx::query_as(
        "SELECT id, slug, name, storage_limit, archived_at IS NOT NULL FROM folders
         WHERE parent_id IS NULL ORDER BY name COLLATE NOCASE",
    )
    .fetch_all(&state.db)
    .await?;
    let mut folders = Vec::with_capacity(tops.len());
    for (id, slug, name, storage_limit, archived) in tops {
        folders.push(FolderUsage {
            used: usage(&state.db, &id).await?,
            id,
            slug,
            name,
            storage_limit,
            archived,
        });
    }
    let dir = state.cfg.data_dir.clone();
    let (disk_total, disk_available) = tokio::task::spawn_blocking(move || {
        Ok::<_, std::io::Error>((fs4::total_space(&dir)?, fs4::available_space(&dir)?))
    })
    .await
    .map_err(anyhow::Error::from)??;
    Ok(Json(StorageReport {
        disk_total,
        disk_available,
        used_total: folders.iter().map(|f| f.used).sum(),
        folders,
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TrashItem {
    /// File version id; restore with `POST /api/v1/items/{id}/restore`.
    pub id: String,
    pub folder_id: String,
    /// `slug` or `slug/sub/path` of the folder.
    pub folder: String,
    pub name: String,
    pub version: i64,
    pub size: i64,
    pub deleted_at: String,
    /// When the trash worker deletes it for good.
    pub purge_after: String,
}

/// Everything in the trash, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/admin/trash",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Vec<TrashItem>),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn list_trash(
    State(state): State<AppState>,
    auth: Auth,
) -> AppResult<Json<Vec<TrashItem>>> {
    auth.admin()?;
    let rows: Vec<(String, String, String, i64, i64, String)> = sqlx::query_as(
        "SELECT id, folder_id, name, version, size, deleted_at FROM files
         WHERE deleted_at IS NOT NULL ORDER BY deleted_at DESC, name, version DESC",
    )
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for (id, folder_id, name, version, size, deleted_at) in rows {
        let (slug, path) = folder_path(&state.db, &folder_id).await?;
        let purge_after = chrono::DateTime::parse_from_rfc3339(&deleted_at)
            .map(|t| util::fmt_time(t.with_timezone(&Utc) + chrono::Duration::days(30)))
            .unwrap_or_default();
        out.push(TrashItem {
            id,
            folder_id,
            folder: if path.is_empty() {
                slug
            } else {
                format!("{slug}/{path}")
            },
            name,
            version,
            size,
            deleted_at,
            purge_after,
        });
    }
    Ok(Json(out))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PurgeResult {
    /// File versions deleted for good.
    pub purged: u64,
}

/// Empty the trash now.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/trash",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = PurgeResult),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn empty_trash(
    State(state): State<AppState>,
    auth: Auth,
) -> AppResult<Json<PurgeResult>> {
    let admin = auth.admin()?;
    let purged = trash::purge(&state, None).await?;
    db::audit(
        &state.db,
        &admin.actor,
        "trash.empty",
        None,
        Some(serde_json::json!({ "files": purged })),
    )
    .await?;
    Ok(Json(PurgeResult { purged }))
}

#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum QrFormat {
    #[default]
    Svg,
    Png,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct QrQuery {
    /// Folder link (`http://ark.local/f/{slug}`) or join link (`http://ark.local/j/{token}`).
    /// Must use the Ark hostname, never an IP.
    pub url: String,
    #[param(inline)]
    #[serde(default)]
    pub format: QrFormat,
}

/// True when `url` is `http://<hostname>[.local][:port]/...`.
fn is_ark_url(url: &str, hostname: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.split(':').next().unwrap_or("");
    rest.len() > authority.len()
        && (host.eq_ignore_ascii_case(hostname)
            || host.eq_ignore_ascii_case(&format!("{hostname}.local")))
}

/// QR code for a folder or join link.
#[utoipa::path(
    get,
    path = "/api/v1/admin/qr",
    tag = "admin",
    params(QrQuery),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, description = "SVG or PNG image", content(("image/svg+xml"), ("image/png"))),
        (status = 400, description = "URL is not an Ark link", body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn qr_code(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<QrQuery>,
) -> AppResult<Response> {
    auth.admin()?;
    let via_tunnel = state
        .tunnel
        .public_host()
        .is_some_and(|host| q.url.starts_with(&format!("https://{host}/")));
    if !via_tunnel && !is_ark_url(&q.url, &state.cfg.hostname) {
        return Err(AppError::bad_request(
            "invalid_url",
            format!("QR links must start with {}/", qr::public_base(&state.cfg)),
        ));
    }
    let resp = match q.format {
        QrFormat::Svg => {
            ([(header::CONTENT_TYPE, "image/svg+xml")], qr::svg(&q.url)?).into_response()
        }
        QrFormat::Png => ([(header::CONTENT_TYPE, "image/png")], qr::png(&q.url)?).into_response(),
    };
    Ok(resp)
}

/// Cloud backup status (`ARK_SYNC_REMOTE`).
#[utoipa::path(
    get,
    path = "/api/v1/admin/sync",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = SyncStatus),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn sync_status(State(state): State<AppState>, auth: Auth) -> AppResult<Json<SyncStatus>> {
    auth.admin()?;
    Ok(Json(sync::status(&state).await?))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RetryResult {
    pub requeued: u64,
}

/// Requeue sync jobs that gave up.
#[utoipa::path(
    post,
    path = "/api/v1/admin/sync/retry",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = RetryResult),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn sync_retry(State(state): State<AppState>, auth: Auth) -> AppResult<Json<RetryResult>> {
    let admin = auth.admin()?;
    let requeued = sync::retry_failed(&state).await?;
    db::audit(
        &state.db,
        &admin.actor,
        "sync.retry",
        None,
        Some(serde_json::json!({ "jobs": requeued })),
    )
    .await?;
    Ok(Json(RetryResult { requeued }))
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct TunnelRequest {
    /// Connector token of a named tunnel from the Cloudflare dashboard. Omit for a
    /// quick tunnel (random `*.trycloudflare.com` URL, no account needed).
    pub token: Option<String>,
    /// Public hostname routed to this tunnel in the dashboard, e.g. `ark.example.org`.
    /// Named tunnels only; used for status and QR codes.
    pub hostname: Option<String>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tunnel",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = TunnelStatus),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn tunnel_status(
    State(state): State<AppState>,
    auth: Auth,
) -> AppResult<Json<TunnelStatus>> {
    auth.admin()?;
    Ok(Json(state.tunnel.status()))
}

/// Start (or restart) the Cloudflare Tunnel; it also starts on every boot until
/// disabled. Waits up to 20 s for the tunnel to come up, then returns its status.
#[utoipa::path(
    put,
    path = "/api/v1/admin/tunnel",
    tag = "admin",
    request_body = TunnelRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, description = "Check `connected`, `public_url` and `last_error`", body = TunnelStatus),
        (status = 400, body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn tunnel_enable(
    State(state): State<AppState>,
    auth: Auth,
    body: Option<Json<TunnelRequest>>,
) -> AppResult<Json<TunnelStatus>> {
    let admin = auth.admin()?;
    let req = body.map(|Json(r)| r).unwrap_or_default();
    let mode = match req
        .token
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
    {
        None => Mode::Quick,
        Some(token) => {
            let hostname = req
                .hostname
                .map(|h| h.trim().trim_end_matches('/').to_ascii_lowercase());
            if let Some(h) = &hostname {
                let valid = !h.is_empty()
                    && h.contains('.')
                    && h.chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
                if !valid {
                    return Err(AppError::bad_request(
                        "invalid_hostname",
                        "hostname must be a bare host name like ark.example.org",
                    ));
                }
            }
            Mode::Named { token, hostname }
        }
    };
    let quick = mode == Mode::Quick;
    tunnel::enable(&state, mode).await?;
    db::audit(
        &state.db,
        &admin.actor,
        "tunnel.enable",
        None,
        Some(serde_json::json!({ "mode": if quick { "quick" } else { "named" } })),
    )
    .await?;

    for _ in 0..40 {
        let s = state.tunnel.status();
        if (s.connected && s.public_url.is_some())
            || (s.connected && !quick)
            || s.last_error.is_some()
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Ok(Json(state.tunnel.status()))
}

/// Stop the tunnel and forget its settings.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/tunnel",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 204, description = "Stopped"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn tunnel_disable(State(state): State<AppState>, auth: Auth) -> AppResult<StatusCode> {
    let admin = auth.admin()?;
    tunnel::disable(&state).await?;
    db::audit(&state.db, &admin.actor, "tunnel.disable", None, None).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ark_urls() {
        assert!(is_ark_url("http://ark.local/f/sunday", "ark"));
        assert!(is_ark_url("http://ark.local:8080/j/abc", "ark"));
        assert!(is_ark_url("http://ark/f/x", "ark"));
        assert!(!is_ark_url("http://192.168.1.10/f/x", "ark"));
        assert!(!is_ark_url("https://ark.local/f/x", "ark"));
        assert!(!is_ark_url("http://ark.local", "ark"));
        assert!(!is_ark_url("http://evil.com/ark.local/", "ark"));
    }
}
