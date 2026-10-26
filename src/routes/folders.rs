use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use axum_extra::extract::SignedCookieJar;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::{IntoParams, ToSchema};

use crate::{
    AppState,
    auth::{
        Action, Auth, NewSession, Role, admin::SessionResponse, ancestor_chain, create_session, pin,
    },
    db,
    error::{AppError, AppResult, ErrorBody, is_unique_violation},
    routes::events::{EventKind, publish},
    storage, util,
};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct FolderRow {
    pub id: String,
    pub slug: String,
    pub name: String,
    pub is_open: bool,
    pub default_role: Option<Role>,
    pub storage_limit: Option<i64>,
    pub archived_at: Option<String>,
    pub created_at: String,
}

pub const FOLDER_COLUMNS: &str =
    "id, slug, name, is_open, default_role, storage_limit, archived_at, created_at";

/// A folder as seen by a scoped session.
#[derive(Debug, Serialize, ToSchema)]
pub struct FolderSummary {
    pub id: String,
    pub slug: String,
    pub name: String,
    /// Path below the top-level folder, e.g. `day-1/photos`; empty for the top level.
    #[schema(example = "day-1/photos")]
    pub path: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct FileItem {
    pub id: String,
    pub name: String,
    pub size: i64,
    pub mime: Option<String>,
    pub version: i64,
    /// `draft`, `approved` or `final`.
    pub status_tag: Option<String>,
    /// PIN or join-token label of the uploader.
    pub uploaded_by: Option<String>,
    pub created_at: String,
    /// Ready previews: `thumb` (images), `poster` and `hls` (videos). Fetch from
    /// `/preview/{id}/{kind}`; HLS plays from `/preview/{id}/hls/index.m3u8`.
    #[schema(value_type = Vec<String>, example = json!(["thumb"]))]
    pub previews: sqlx::types::Json<Vec<String>>,
}

/// Columns for `FileItem`, selecting from `files`.
pub const FILE_ITEM_COLUMNS: &str = "id, name, size, mime, version, status_tag, uploaded_by, created_at,
    (SELECT json_group_array(kind) FROM previews p WHERE p.file_id = files.id AND p.status = 'ready') AS previews";

#[derive(Debug, Serialize, ToSchema)]
pub struct ItemsResponse {
    pub folder: FolderSummary,
    pub subfolders: Vec<FolderSummary>,
    /// Current, non-trashed files. Uploader sessions only see their own uploads.
    pub files: Vec<FileItem>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct PathQuery {
    /// Subfolder path below the top-level folder, e.g. `day-1/photos`.
    pub path: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UnlockRequest {
    /// 4–8 digits. Omit for open folders.
    #[schema(example = "2468")]
    pub pin: Option<String>,
    /// Unlock a subfolder instead of the top-level folder.
    pub path: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateSubfolderRequest {
    /// Parent path below the top-level folder; omit or empty for the top level.
    pub path: Option<String>,
    #[schema(example = "Day 1")]
    pub name: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeSession {
    pub folder_id: String,
    /// Top-level folder slug.
    pub folder_slug: String,
    /// Path of the session root below the top-level folder; empty for the top level.
    pub path: String,
    pub role: Role,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct MeResponse {
    pub sessions: Vec<MeSession>,
    pub hub: bool,
    pub admin: bool,
}

/// Resolves a top-level slug plus optional subfolder path to a live (non-archived)
/// folder. Old slugs from renames still resolve.
pub async fn resolve(db: &SqlitePool, slug: &str, path: Option<&str>) -> AppResult<FolderRow> {
    let mut folder = find_child(db, None, slug).await?;
    for seg in path.unwrap_or("").split('/').filter(|s| !s.is_empty()) {
        folder = find_child(db, Some(&folder.id), seg).await?;
    }
    Ok(folder)
}

async fn find_child(db: &SqlitePool, parent: Option<&str>, slug: &str) -> AppResult<FolderRow> {
    let sql = format!(
        "SELECT {FOLDER_COLUMNS} FROM folders
         WHERE archived_at IS NULL AND parent_id IS ?1
           AND (slug = ?2 OR id = (SELECT folder_id FROM folder_slug_history
                                   WHERE parent_id IS ?1 AND old_slug = ?2))
         ORDER BY slug = ?2 DESC LIMIT 1"
    );
    sqlx::query_as(sqlx::AssertSqlSafe(sql))
        .bind(parent)
        .bind(slug)
        .fetch_optional(db)
        .await?
        .ok_or(AppError::NotFound)
}

/// Top-level slug and sub-path for a folder id.
pub async fn folder_path(db: &SqlitePool, id: &str) -> AppResult<(String, String)> {
    let mut slugs: Vec<String> = sqlx::query_scalar(
        "WITH RECURSIVE chain(id, parent_id, slug, depth) AS (
             SELECT id, parent_id, slug, 0 FROM folders WHERE id = ?
             UNION ALL
             SELECT f.id, f.parent_id, f.slug, c.depth + 1
             FROM folders f JOIN chain c ON f.id = c.parent_id
         )
         SELECT slug FROM chain ORDER BY depth DESC",
    )
    .bind(id)
    .fetch_all(db)
    .await?;
    if slugs.is_empty() {
        return Err(AppError::NotFound);
    }
    let top = slugs.remove(0);
    Ok((top, slugs.join("/")))
}

pub fn join_path(parent: &str, slug: &str) -> String {
    if parent.is_empty() {
        slug.to_string()
    } else {
        format!("{parent}/{slug}")
    }
}

#[derive(sqlx::FromRow)]
struct PinCandidate {
    id: String,
    /// Null for hub PINs.
    folder_id: Option<String>,
    label: String,
    pin_hash: String,
    role: Role,
}

/// Exchange a folder PIN for a session scoped to that folder and its subfolders.
/// A folder without PINs of its own accepts the PINs of its nearest ancestor that has
/// some. Open folders need no PIN.
#[utoipa::path(
    post,
    path = "/api/v1/folders/{slug}/unlock",
    tag = "auth",
    params(("slug" = String, Path, description = "Top-level folder slug")),
    request_body = UnlockRequest,
    responses(
        (status = 200, description = "Session created; cookie set", body = SessionResponse),
        (status = 400, description = "Malformed PIN, or PIN missing for a locked folder", body = ErrorBody),
        (status = 401, description = "Wrong PIN", body = ErrorBody),
        (status = 404, description = "No such folder", body = ErrorBody),
        (status = 429, description = "Locked out after repeated failures", body = ErrorBody),
    )
)]
pub async fn unlock(
    State(state): State<AppState>,
    auth: Auth,
    jar: SignedCookieJar,
    Path(slug): Path<String>,
    Json(req): Json<UnlockRequest>,
) -> AppResult<(SignedCookieJar, Json<SessionResponse>)> {
    let folder = resolve(&state.db, &slug, req.path.as_deref()).await?;
    let chain = ancestor_chain(&state.db, &folder.id).await?;

    let Some(entered) = req.pin.filter(|p| !p.is_empty()) else {
        // Open folder: the nearest open folder in the chain sets the role.
        let mut open_role = None;
        for id in &chain {
            let row: Option<(bool, Option<Role>)> =
                sqlx::query_as("SELECT is_open, default_role FROM folders WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&state.db)
                    .await?;
            if let Some((true, Some(role))) = row {
                open_role = Some(role);
                break;
            }
        }
        let role = open_role
            .ok_or_else(|| AppError::bad_request("pin_required", "This folder needs a PIN"))?;
        return folder_session(&state, &auth, jar, &folder.id, role, None).await;
    };
    pin::validate_pin(&entered)?;

    let lock_key = format!("pin:{}:{}", folder.id, auth.ip);
    let now = util::now();
    let mut candidates: Vec<PinCandidate> = Vec::new();
    for id in &chain {
        candidates = sqlx::query_as(
            "SELECT id, folder_id, label, pin_hash, role FROM pins
             WHERE folder_id = ? AND revoked_at IS NULL
               AND (expires_at IS NULL OR expires_at > ?)
               AND (max_uses IS NULL OR uses < max_uses)",
        )
        .bind(id)
        .bind(&now)
        .fetch_all(&state.db)
        .await?;
        if !candidates.is_empty() {
            break;
        }
    }

    let matched = match_pin(&state.db, &lock_key, entered, candidates).await?;
    db::audit(
        &state.db,
        &matched.label,
        "folder.unlock",
        Some(&folder.id),
        Some(serde_json::json!({ "role": matched.role, "pin_folder": matched.folder_id })),
    )
    .await?;

    folder_session(
        &state,
        &auth,
        jar,
        &folder.id,
        matched.role,
        Some(&matched.id),
    )
    .await
}

/// Checks `entered` against `candidates` under the lockout for `lock_key`, and counts
/// the use of the matching PIN.
async fn match_pin(
    db: &SqlitePool,
    lock_key: &str,
    entered: String,
    mut candidates: Vec<PinCandidate>,
) -> AppResult<PinCandidate> {
    pin::check_lock(db, lock_key).await?;
    let hashes = candidates.iter().map(|c| c.pin_hash.clone()).collect();
    let Some(idx) = pin::find_match(entered, hashes).await? else {
        pin::record_failure(db, lock_key).await?;
        return Err(AppError::Unauthorized(
            "invalid_pin",
            "PIN is incorrect".into(),
        ));
    };
    pin::record_success(db, lock_key).await?;
    let matched = candidates.swap_remove(idx);
    sqlx::query("UPDATE pins SET uses = uses + 1 WHERE id = ?")
        .bind(&matched.id)
        .execute(db)
        .await?;
    Ok(matched)
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct HubUnlockRequest {
    #[schema(example = "9090")]
    pub pin: String,
}

/// Exchange the hub PIN for a hub session: the home page folder list and access to
/// every folder (no admin rights).
#[utoipa::path(
    post,
    path = "/api/v1/hub/unlock",
    tag = "auth",
    request_body = HubUnlockRequest,
    responses(
        (status = 200, description = "Hub session created; cookie set", body = SessionResponse),
        (status = 400, description = "Malformed PIN", body = ErrorBody),
        (status = 401, description = "Wrong PIN", body = ErrorBody),
        (status = 429, description = "Locked out after repeated failures", body = ErrorBody),
    )
)]
pub async fn hub_unlock(
    State(state): State<AppState>,
    auth: Auth,
    jar: SignedCookieJar,
    Json(req): Json<HubUnlockRequest>,
) -> AppResult<(SignedCookieJar, Json<SessionResponse>)> {
    pin::validate_pin(&req.pin)?;
    let candidates: Vec<PinCandidate> = sqlx::query_as(
        "SELECT id, folder_id, label, pin_hash, role FROM pins
         WHERE folder_id IS NULL AND role = 'hub' AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)
           AND (max_uses IS NULL OR uses < max_uses)",
    )
    .bind(util::now())
    .fetch_all(&state.db)
    .await?;
    let lock_key = format!("pin:hub:{}", auth.ip);
    let matched = match_pin(&state.db, &lock_key, req.pin, candidates).await?;
    db::audit(&state.db, &matched.label, "hub.unlock", None, None).await?;

    let (session_id, cookie) = create_session(
        &state,
        &auth,
        NewSession {
            root_folder: None,
            role: Role::Hub,
            pin_id: Some(&matched.id),
            token_id: None,
        },
    )
    .await?;
    Ok((
        jar.add(cookie),
        Json(SessionResponse {
            session_id,
            role: Role::Hub,
            root_folder: None,
        }),
    ))
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct HubFolder {
    pub id: String,
    pub slug: String,
    pub name: String,
    /// Open folders need no PIN.
    pub is_open: bool,
}

/// Top-level folders for the home page.
#[utoipa::path(
    get,
    path = "/api/v1/folders",
    tag = "folders",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Vec<HubFolder>),
        (status = 401, body = ErrorBody),
        (status = 403, description = "Needs a hub or admin session", body = ErrorBody),
    )
)]
pub async fn list_folders(
    State(state): State<AppState>,
    auth: Auth,
) -> AppResult<Json<Vec<HubFolder>>> {
    auth.hub()?;
    let rows = sqlx::query_as(
        "SELECT id, slug, name, is_open FROM folders
         WHERE parent_id IS NULL AND archived_at IS NULL ORDER BY name COLLATE NOCASE",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

async fn folder_session(
    state: &AppState,
    auth: &Auth,
    jar: SignedCookieJar,
    folder_id: &str,
    role: Role,
    pin_id: Option<&str>,
) -> AppResult<(SignedCookieJar, Json<SessionResponse>)> {
    let (session_id, cookie) = create_session(
        state,
        auth,
        NewSession {
            root_folder: Some(folder_id),
            role,
            pin_id,
            token_id: None,
        },
    )
    .await?;
    Ok((
        jar.add(cookie),
        Json(SessionResponse {
            session_id,
            role,
            root_folder: Some(folder_id.to_string()),
        }),
    ))
}

/// List subfolders and current files of a folder.
#[utoipa::path(
    get,
    path = "/api/v1/folders/{slug}/items",
    tag = "folders",
    params(("slug" = String, Path, description = "Top-level folder slug"), PathQuery),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = ItemsResponse),
        (status = 401, description = "No session", body = ErrorBody),
        (status = 403, description = "Folder outside the session scope", body = ErrorBody),
        (status = 404, description = "No such folder", body = ErrorBody),
    )
)]
pub async fn list_items(
    State(state): State<AppState>,
    auth: Auth,
    Path(slug): Path<String>,
    Query(q): Query<PathQuery>,
) -> AppResult<Json<ItemsResponse>> {
    let folder = resolve(&state.db, &slug, q.path.as_deref()).await?;
    let session = auth.require(&state.db, &folder.id, Action::List).await?;
    let (_, path) = folder_path(&state.db, &folder.id).await?;

    let subfolders: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT id, slug, name, created_at FROM folders
         WHERE parent_id = ? AND archived_at IS NULL ORDER BY name COLLATE NOCASE",
    )
    .bind(&folder.id)
    .fetch_all(&state.db)
    .await?;

    let own_only = (session.role == Role::Uploader).then_some(&session.id);
    let files: Vec<FileItem> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {FILE_ITEM_COLUMNS} FROM files
         WHERE folder_id = ? AND is_current = 1 AND deleted_at IS NULL
           AND (?2 IS NULL OR session_id = ?2)
         ORDER BY created_at DESC"
    )))
    .bind(&folder.id)
    .bind(own_only)
    .fetch_all(&state.db)
    .await?;

    Ok(Json(ItemsResponse {
        subfolders: subfolders
            .into_iter()
            .map(|(id, slug, name, created_at)| FolderSummary {
                path: join_path(&path, &slug),
                id,
                slug,
                name,
                created_at,
            })
            .collect(),
        folder: FolderSummary {
            id: folder.id,
            slug: folder.slug,
            name: folder.name,
            path,
            created_at: folder.created_at,
        },
        files,
    }))
}

/// Create a subfolder.
#[utoipa::path(
    post,
    path = "/api/v1/folders/{slug}/subfolders",
    tag = "folders",
    params(("slug" = String, Path, description = "Top-level folder slug")),
    request_body = CreateSubfolderRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 201, body = FolderSummary),
        (status = 400, description = "Name has no usable characters", body = ErrorBody),
        (status = 401, description = "No session", body = ErrorBody),
        (status = 403, description = "Role or scope does not allow it", body = ErrorBody),
        (status = 404, description = "No such parent folder", body = ErrorBody),
        (status = 409, description = "A subfolder with that slug exists", body = ErrorBody),
    )
)]
pub async fn create_subfolder(
    State(state): State<AppState>,
    auth: Auth,
    Path(slug): Path<String>,
    Json(req): Json<CreateSubfolderRequest>,
) -> AppResult<(StatusCode, Json<FolderSummary>)> {
    let parent = resolve(&state.db, &slug, req.path.as_deref()).await?;
    let session = auth
        .require(&state.db, &parent.id, Action::CreateSubfolder)
        .await?;

    let name = req.name.trim().to_string();
    let new_slug = util::slugify(&name);
    if new_slug.is_empty() {
        return Err(AppError::bad_request(
            "invalid_name",
            "Folder name needs at least one letter or digit",
        ));
    }

    let id = util::new_id();
    let now = util::now();
    sqlx::query(
        "INSERT INTO folders (id, parent_id, slug, name, disk_dir, created_at)
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&parent.id)
    .bind(&new_slug)
    .bind(&name)
    .bind(&id)
    .bind(&now)
    .execute(&state.db)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            AppError::conflict("slug_taken", "A subfolder with that name already exists")
        } else {
            e.into()
        }
    })?;
    storage::create_folder_dir(&state.cfg, &id).await?;
    db::audit(
        &state.db,
        &session.actor,
        "folder.create",
        Some(&id),
        Some(serde_json::json!({ "parent": parent.id, "name": name })),
    )
    .await?;

    publish(
        &state,
        EventKind::FolderAdded,
        &parent.id,
        &id,
        Some(&name),
        None,
    )
    .await;

    let (_, parent_path) = folder_path(&state.db, &parent.id).await?;
    Ok((
        StatusCode::CREATED,
        Json(FolderSummary {
            path: join_path(&parent_path, &new_slug),
            id,
            slug: new_slug,
            name,
            created_at: now,
        }),
    ))
}

/// The sessions this browser holds.
#[utoipa::path(
    get,
    path = "/api/v1/me",
    tag = "auth",
    security((), ("ark_session" = []), ("bearer" = [])),
    responses((status = 200, body = MeResponse))
)]
pub async fn me(State(state): State<AppState>, auth: Auth) -> AppResult<Json<MeResponse>> {
    let mut sessions = Vec::new();
    for s in &auth.sessions {
        if let Some(root) = &s.root_folder {
            let (folder_slug, path) = folder_path(&state.db, root).await?;
            sessions.push(MeSession {
                folder_id: root.clone(),
                folder_slug,
                path,
                role: s.role,
            });
        }
    }
    let has = |role| auth.sessions.iter().any(|s| s.role == role);
    Ok(Json(MeResponse {
        sessions,
        hub: has(Role::Hub) || has(Role::Admin),
        admin: has(Role::Admin),
    }))
}
