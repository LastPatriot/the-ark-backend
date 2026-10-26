use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::folders::{FOLDER_COLUMNS, FolderRow};
use crate::{
    AppState,
    auth::{Auth, Role, pin},
    db,
    error::{AppError, AppResult, ErrorBody, is_unique_violation},
    storage, util,
};

/// A top-level folder as the admin sees it.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminFolder {
    pub id: String,
    pub slug: String,
    pub name: String,
    /// Open folders need no PIN; visitors get `default_role`.
    pub is_open: bool,
    pub default_role: Option<Role>,
    /// Bytes; null = unlimited.
    pub storage_limit: Option<i64>,
    pub archived_at: Option<String>,
    pub created_at: String,
}

impl From<FolderRow> for AdminFolder {
    fn from(f: FolderRow) -> Self {
        Self {
            id: f.id,
            slug: f.slug,
            name: f.name,
            is_open: f.is_open,
            default_role: f.default_role,
            storage_limit: f.storage_limit,
            archived_at: f.archived_at,
            created_at: f.created_at,
        }
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateFolderRequest {
    #[schema(example = "Sunday Service")]
    pub name: String,
    /// Defaults to the slugified name.
    #[schema(example = "sunday-service")]
    pub slug: Option<String>,
    #[serde(default)]
    pub is_open: bool,
    /// Required when `is_open`; one of viewer, uploader, contributor, editor.
    pub default_role: Option<Role>,
    pub storage_limit: Option<i64>,
}

/// Omitted fields are left unchanged; `null` clears nullable ones.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateFolderRequest {
    pub name: Option<String>,
    /// Old slugs keep resolving after a change.
    pub slug: Option<String>,
    pub is_open: Option<bool>,
    #[serde(default, deserialize_with = "util::double_option")]
    #[schema(value_type = Option<Role>)]
    pub default_role: Option<Option<Role>>,
    #[serde(default, deserialize_with = "util::double_option")]
    #[schema(value_type = Option<i64>)]
    pub storage_limit: Option<Option<i64>>,
    /// `true` archives (hides) the folder, `false` restores it.
    pub archived: Option<bool>,
}

async fn load_top_folder(state: &AppState, id: &str) -> AppResult<FolderRow> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {FOLDER_COLUMNS} FROM folders WHERE id = ? AND parent_id IS NULL"
    )))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

fn check_open_role(is_open: bool, role: Option<Role>) -> AppResult<()> {
    match role {
        Some(r) if !r.is_folder_role() => Err(AppError::bad_request(
            "invalid_role",
            "default_role must be viewer, uploader, contributor or editor",
        )),
        None if is_open => Err(AppError::bad_request(
            "default_role_required",
            "Open folders need a default_role",
        )),
        _ => Ok(()),
    }
}

fn check_slug(slug: &str) -> AppResult<()> {
    if util::is_valid_slug(slug) {
        Ok(())
    } else {
        Err(AppError::bad_request(
            "invalid_slug",
            "Slug must be lowercase letters, digits and single dashes",
        ))
    }
}

fn slug_conflict(e: sqlx::Error) -> AppError {
    if is_unique_violation(&e) {
        AppError::conflict("slug_taken", "Another folder already uses that slug")
    } else {
        e.into()
    }
}

/// All top-level folders, archived ones included.
#[utoipa::path(
    get,
    path = "/api/v1/admin/folders",
    tag = "admin",
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Vec<AdminFolder>),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn list_folders(
    State(state): State<AppState>,
    auth: Auth,
) -> AppResult<Json<Vec<AdminFolder>>> {
    auth.admin()?;
    let rows: Vec<FolderRow> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {FOLDER_COLUMNS} FROM folders WHERE parent_id IS NULL ORDER BY name COLLATE NOCASE"
    )))
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

/// Create a top-level folder.
#[utoipa::path(
    post,
    path = "/api/v1/admin/folders",
    tag = "admin",
    request_body = CreateFolderRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 201, body = AdminFolder),
        (status = 400, body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 409, description = "Slug already used", body = ErrorBody),
    )
)]
pub async fn create_folder(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<CreateFolderRequest>,
) -> AppResult<(StatusCode, Json<AdminFolder>)> {
    let admin = auth.admin()?;
    let name = req.name.trim().to_string();
    let slug = req.slug.unwrap_or_else(|| util::slugify(&name));
    check_slug(&slug)?;
    check_open_role(req.is_open, req.default_role)?;

    let id = util::new_id();
    sqlx::query(
        "INSERT INTO folders (id, slug, name, disk_dir, is_open, default_role, storage_limit, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&slug)
    .bind(&name)
    .bind(&id)
    .bind(req.is_open)
    .bind(req.default_role)
    .bind(req.storage_limit)
    .bind(util::now())
    .execute(&state.db)
    .await
    .map_err(slug_conflict)?;
    storage::create_folder_dir(&state.cfg, &id).await?;
    db::audit(
        &state.db,
        &admin.actor,
        "folder.create",
        Some(&id),
        Some(serde_json::json!({ "name": name, "slug": slug })),
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(load_top_folder(&state, &id).await?.into()),
    ))
}

/// Rename, re-slug, open/close, set quota, archive or unarchive a top-level folder.
#[utoipa::path(
    patch,
    path = "/api/v1/admin/folders/{id}",
    tag = "admin",
    params(("id" = String, Path)),
    request_body = UpdateFolderRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = AdminFolder),
        (status = 400, body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, description = "Slug already used", body = ErrorBody),
    )
)]
pub async fn update_folder(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<UpdateFolderRequest>,
) -> AppResult<Json<AdminFolder>> {
    let admin = auth.admin()?;
    let current = load_top_folder(&state, &id).await?;

    let name = req
        .name
        .map(|n| n.trim().to_string())
        .unwrap_or(current.name.clone());
    let slug = req.slug.unwrap_or(current.slug.clone());
    check_slug(&slug)?;
    let is_open = req.is_open.unwrap_or(current.is_open);
    let default_role = req.default_role.unwrap_or(current.default_role);
    check_open_role(is_open, default_role)?;
    let storage_limit = req.storage_limit.unwrap_or(current.storage_limit);
    let archived_at = match req.archived {
        Some(true) => current.archived_at.clone().or_else(|| Some(util::now())),
        Some(false) => None,
        None => current.archived_at.clone(),
    };

    let mut tx = state.db.begin().await?;
    if slug != current.slug {
        sqlx::query(
            "INSERT INTO folder_slug_history (old_slug, parent_id, folder_id) VALUES (?, NULL, ?)
             ON CONFLICT (parent_id, old_slug) DO UPDATE SET folder_id = excluded.folder_id",
        )
        .bind(&current.slug)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query(
        "UPDATE folders SET name = ?, slug = ?, is_open = ?, default_role = ?, storage_limit = ?, archived_at = ?
         WHERE id = ?",
    )
    .bind(&name)
    .bind(&slug)
    .bind(is_open)
    .bind(default_role)
    .bind(storage_limit)
    .bind(&archived_at)
    .bind(&id)
    .execute(&mut *tx)
    .await
    .map_err(slug_conflict)?;
    tx.commit().await?;

    db::audit(
        &state.db,
        &admin.actor,
        "folder.update",
        Some(&id),
        Some(serde_json::json!({
            "name": name, "slug": slug, "is_open": is_open, "default_role": default_role,
            "storage_limit": storage_limit, "archived": archived_at.is_some(),
        })),
    )
    .await?;
    Ok(Json(load_top_folder(&state, &id).await?.into()))
}

/// Archive a top-level folder. Files are kept; unarchive with PATCH `{"archived": false}`.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/folders/{id}",
    tag = "admin",
    params(("id" = String, Path)),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 204, description = "Archived"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn archive_folder(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let admin = auth.admin()?;
    load_top_folder(&state, &id).await?;
    sqlx::query("UPDATE folders SET archived_at = COALESCE(archived_at, ?) WHERE id = ?")
        .bind(util::now())
        .bind(&id)
        .execute(&state.db)
        .await?;
    db::audit(&state.db, &admin.actor, "folder.archive", Some(&id), None).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// A PIN as the admin sees it. The PIN itself is never returned after creation.
#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct AdminPin {
    pub id: String,
    /// Null for the hub PIN.
    pub folder_id: Option<String>,
    pub label: String,
    pub role: Role,
    pub expires_at: Option<String>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub revoked_at: Option<String>,
    pub created_at: String,
}

const PIN_COLUMNS: &str =
    "id, folder_id, label, role, expires_at, max_uses, uses, revoked_at, created_at";

#[derive(Debug, Deserialize, IntoParams)]
pub struct PinsQuery {
    /// Only PINs of this folder.
    pub folder_id: Option<String>,
    /// Include revoked PINs.
    #[serde(default)]
    pub include_revoked: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePinRequest {
    /// Folder (top-level or subfolder) the PIN unlocks. Omit for the hub PIN.
    pub folder_id: Option<String>,
    #[schema(example = "Photographers")]
    pub label: String,
    /// 4–8 digits.
    #[schema(example = "2468")]
    pub pin: String,
    /// viewer, uploader, contributor or editor for folder PINs; hub for the hub PIN.
    pub role: Role,
    /// RFC 3339.
    pub expires_at: Option<String>,
    pub max_uses: Option<i64>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdatePinRequest {
    pub label: Option<String>,
    #[serde(default, deserialize_with = "util::double_option")]
    #[schema(value_type = Option<String>)]
    pub expires_at: Option<Option<String>>,
    #[serde(default, deserialize_with = "util::double_option")]
    #[schema(value_type = Option<i64>)]
    pub max_uses: Option<Option<i64>>,
}

async fn load_pin(state: &AppState, id: &str) -> AppResult<AdminPin> {
    sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {PIN_COLUMNS} FROM pins WHERE id = ?"
    )))
    .bind(id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(AppError::NotFound)
}

fn parse_expiry(s: Option<String>) -> AppResult<Option<String>> {
    s.map(|s| {
        util::normalize_time(&s)
            .ok_or_else(|| AppError::bad_request("invalid_time", "expires_at must be RFC 3339"))
    })
    .transpose()
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/pins",
    tag = "admin",
    params(PinsQuery),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Vec<AdminPin>),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn list_pins(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<PinsQuery>,
) -> AppResult<Json<Vec<AdminPin>>> {
    auth.admin()?;
    let pins = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {PIN_COLUMNS} FROM pins
         WHERE (?1 IS NULL OR folder_id = ?1) AND (?2 OR revoked_at IS NULL)
         ORDER BY created_at"
    )))
    .bind(q.folder_id)
    .bind(q.include_revoked)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(pins))
}

/// Create a folder PIN or the hub PIN.
#[utoipa::path(
    post,
    path = "/api/v1/admin/pins",
    tag = "admin",
    request_body = CreatePinRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 201, body = AdminPin),
        (status = 400, body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, description = "No such folder", body = ErrorBody),
        (status = 409, description = "Same PIN already active on this folder", body = ErrorBody),
    )
)]
pub async fn create_pin(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<CreatePinRequest>,
) -> AppResult<(StatusCode, Json<AdminPin>)> {
    let admin = auth.admin()?;
    pin::validate_pin(&req.pin)?;
    match (&req.folder_id, req.role) {
        (None, Role::Hub) => {}
        (None, _) => {
            return Err(AppError::bad_request(
                "invalid_role",
                "A PIN without folder_id is the hub PIN and needs role hub",
            ));
        }
        (Some(_), r) if !r.is_folder_role() => {
            return Err(AppError::bad_request(
                "invalid_role",
                "Folder PINs take viewer, uploader, contributor or editor",
            ));
        }
        (Some(folder_id), _) => {
            let exists: Option<i64> = sqlx::query_scalar("SELECT 1 FROM folders WHERE id = ?")
                .bind(folder_id)
                .fetch_optional(&state.db)
                .await?;
            exists.ok_or(AppError::NotFound)?;
        }
    }
    let label = req.label.trim().to_string();
    if label.is_empty() {
        return Err(AppError::bad_request("invalid_label", "label is required"));
    }
    let expires_at = parse_expiry(req.expires_at)?;

    // Two active PINs with the same digits on one folder would make the role ambiguous.
    let now = util::now();
    let existing: Vec<String> = sqlx::query_scalar(
        "SELECT pin_hash FROM pins WHERE folder_id IS ? AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > ?)",
    )
    .bind(&req.folder_id)
    .bind(&now)
    .fetch_all(&state.db)
    .await?;
    if pin::find_match(req.pin.clone(), existing).await?.is_some() {
        return Err(AppError::conflict(
            "pin_in_use",
            "That PIN is already active on this folder",
        ));
    }

    let id = util::new_id();
    let hash = pin::hash_secret(req.pin).await?;
    sqlx::query(
        "INSERT INTO pins (id, folder_id, label, pin_hash, role, expires_at, max_uses, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.folder_id)
    .bind(&label)
    .bind(hash)
    .bind(req.role)
    .bind(&expires_at)
    .bind(req.max_uses)
    .bind(&now)
    .execute(&state.db)
    .await?;
    db::audit(
        &state.db,
        &admin.actor,
        "pin.create",
        Some(&id),
        Some(serde_json::json!({
            "folder_id": req.folder_id, "label": label, "role": req.role,
        })),
    )
    .await?;

    Ok((StatusCode::CREATED, Json(load_pin(&state, &id).await?)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/pins/{id}",
    tag = "admin",
    params(("id" = String, Path)),
    request_body = UpdatePinRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = AdminPin),
        (status = 400, body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn update_pin(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<UpdatePinRequest>,
) -> AppResult<Json<AdminPin>> {
    let admin = auth.admin()?;
    let current = load_pin(&state, &id).await?;
    let label = req
        .label
        .map(|l| l.trim().to_string())
        .unwrap_or(current.label);
    let expires_at = match req.expires_at {
        Some(v) => parse_expiry(v)?,
        None => current.expires_at,
    };
    let max_uses = req.max_uses.unwrap_or(current.max_uses);
    sqlx::query("UPDATE pins SET label = ?, expires_at = ?, max_uses = ? WHERE id = ?")
        .bind(&label)
        .bind(&expires_at)
        .bind(max_uses)
        .bind(&id)
        .execute(&state.db)
        .await?;
    db::audit(
        &state.db,
        &admin.actor,
        "pin.update",
        Some(&id),
        Some(serde_json::json!({
            "label": label, "expires_at": expires_at, "max_uses": max_uses,
        })),
    )
    .await?;
    Ok(Json(load_pin(&state, &id).await?))
}

/// Revoke a PIN and end every session created from it.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/pins/{id}",
    tag = "admin",
    params(("id" = String, Path)),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 204, description = "Revoked"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn revoke_pin(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let admin = auth.admin()?;
    load_pin(&state, &id).await?;
    let now = util::now();
    let mut tx = state.db.begin().await?;
    sqlx::query("UPDATE pins SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?")
        .bind(&now)
        .bind(&id)
        .execute(&mut *tx)
        .await?;
    let ended =
        sqlx::query("UPDATE sessions SET revoked_at = ? WHERE pin_id = ? AND revoked_at IS NULL")
            .bind(&now)
            .bind(&id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    tx.commit().await?;
    db::audit(
        &state.db,
        &admin.actor,
        "pin.revoke",
        Some(&id),
        Some(serde_json::json!({ "sessions_ended": ended })),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
