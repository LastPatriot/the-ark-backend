//! Rename, move, tag, trash and restore files and subfolders.
//!
//! A file's versions are the rows sharing its folder and name (case-insensitive); one
//! of them is current. Rename, move and trash act on the whole family.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use utoipa::ToSchema;

use super::{
    events::{EventKind, publish},
    folders::{FileItem, FolderSummary, folder_path, join_path},
};
use crate::{
    AppState,
    auth::{Action, Auth, Session, ancestor_chain},
    db,
    error::{AppError, AppResult, ErrorBody, is_unique_violation},
    storage, util,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub enum StatusTag {
    Draft,
    Approved,
    Final,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateItemRequest {
    /// New display name. For a file this renames all its versions.
    pub name: Option<String>,
    /// Destination folder id. Must be inside the session's scope.
    pub move_to: Option<String>,
    /// Files only; `null` clears the tag. Applies to this version.
    #[serde(default, deserialize_with = "util::double_option")]
    #[schema(value_type = Option<StatusTag>)]
    pub status_tag: Option<Option<StatusTag>>,
}

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RestoreRequest {
    /// Make this version current instead of the newest one.
    pub version: Option<i64>,
}

#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Item {
    File(FileItem),
    Folder(FolderSummary),
}

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct FileVersion {
    pub id: String,
    pub version: i64,
    pub is_current: bool,
    pub size: i64,
    pub sha256: String,
    pub status_tag: Option<String>,
    pub uploaded_by: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct FileRow {
    id: String,
    folder_id: String,
    name: String,
    disk_name: String,
    version: i64,
    session_id: Option<String>,
    deleted_at: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SubfolderRow {
    id: String,
    parent_id: Option<String>,
    slug: String,
    name: String,
    created_at: String,
}

async fn load_file(db: &SqlitePool, id: &str) -> sqlx::Result<Option<FileRow>> {
    sqlx::query_as(
        "SELECT f.id, f.folder_id, f.name, f.disk_name, f.version, f.session_id, f.deleted_at
         FROM files f JOIN folders d ON d.id = f.folder_id
         WHERE f.id = ? AND d.archived_at IS NULL",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

async fn load_subfolder(db: &SqlitePool, id: &str) -> sqlx::Result<Option<SubfolderRow>> {
    sqlx::query_as(
        "SELECT id, parent_id, slug, name, created_at FROM folders WHERE id = ? AND archived_at IS NULL",
    )
    .bind(id)
    .fetch_optional(db)
    .await
}

async fn live_folder(db: &SqlitePool, id: &str) -> AppResult<String> {
    let disk_dir: Option<String> =
        sqlx::query_scalar("SELECT disk_dir FROM folders WHERE id = ? AND archived_at IS NULL")
            .bind(id)
            .fetch_optional(db)
            .await?;
    disk_dir.ok_or(AppError::NotFound)
}

pub async fn file_item(db: &SqlitePool, id: &str) -> sqlx::Result<FileItem> {
    sqlx::query_as(
        "SELECT id, name, size, mime, version, status_tag, uploaded_by, created_at FROM files WHERE id = ?",
    )
    .bind(id)
    .fetch_one(db)
    .await
}

/// Id of the current version of the live family `name` in `folder_id`, if any.
async fn current_of(db: &SqlitePool, folder_id: &str, name: &str) -> sqlx::Result<Option<String>> {
    sqlx::query_scalar(
        "SELECT id FROM files WHERE folder_id = ? AND name = ? COLLATE NOCASE
           AND deleted_at IS NULL AND is_current = 1",
    )
    .bind(folder_id)
    .bind(name)
    .fetch_optional(db)
    .await
}

/// Rename, move or tag a file, or rename/move a subfolder. Top-level folders are
/// managed through the admin API.
#[utoipa::path(
    patch,
    path = "/api/v1/items/{id}",
    tag = "items",
    params(("id" = String, Path, description = "File (any version) or subfolder id")),
    request_body = UpdateItemRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Item),
        (status = 400, body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, description = "Name taken at the destination, or file is in the trash", body = ErrorBody),
    )
)]
pub async fn update(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    Json(req): Json<UpdateItemRequest>,
) -> AppResult<Json<Item>> {
    if let Some(file) = load_file(&state.db, &id).await? {
        return update_file(&state, &auth, file, req).await.map(Json);
    }
    if let Some(folder) = load_subfolder(&state.db, &id).await? {
        return update_folder(&state, &auth, folder, req).await.map(Json);
    }
    Err(AppError::NotFound)
}

async fn update_file(
    state: &AppState,
    auth: &Auth,
    file: FileRow,
    req: UpdateItemRequest,
) -> AppResult<Item> {
    let session = auth
        .require(&state.db, &file.folder_id, Action::Modify)
        .await?;
    if file.deleted_at.is_some() {
        return Err(AppError::conflict(
            "in_trash",
            "Restore the file before changing it",
        ));
    }

    let new_name = match &req.name {
        Some(n) => storage::display_name(n)
            .ok_or_else(|| AppError::bad_request("invalid_name", "File name is empty"))?,
        None => file.name.clone(),
    };
    let target = req.move_to.clone().unwrap_or(file.folder_id.clone());
    let moving = target != file.folder_id;
    let target_dir = live_folder(&state.db, &target).await?;
    if moving {
        auth.require(&state.db, &target, Action::Modify).await?;
    }

    if moving || new_name != file.name {
        // A case-only rename in place keeps the same family; anything else must not
        // land on another live file.
        let same_family = !moving && new_name.eq_ignore_ascii_case(&file.name);
        if !same_family && current_of(&state.db, &target, &new_name).await?.is_some() {
            return Err(AppError::conflict(
                "name_taken",
                "A file with that name already exists there",
            ));
        }
        move_family(state, &file, &target, &target_dir, &new_name).await?;
    }

    if let Some(tag) = req.status_tag {
        sqlx::query("UPDATE files SET status_tag = ? WHERE id = ?")
            .bind(tag)
            .bind(&file.id)
            .execute(&state.db)
            .await?;
    }

    db::audit(
        &state.db,
        &session.actor,
        "file.update",
        Some(&file.id),
        Some(serde_json::json!({
            "name": new_name, "from_folder": file.folder_id, "to_folder": target,
            "status_tag": req.status_tag,
        })),
    )
    .await?;

    let owner = file.session_id.as_deref();
    if moving {
        publish(
            state,
            EventKind::FileDeleted,
            &file.folder_id,
            &file.id,
            Some(&file.name),
            owner,
        )
        .await;
        publish(
            state,
            EventKind::FileAdded,
            &target,
            &file.id,
            Some(&new_name),
            owner,
        )
        .await;
    } else {
        publish(
            state,
            EventKind::FileUpdated,
            &target,
            &file.id,
            Some(&new_name),
            owner,
        )
        .await;
    }
    Ok(Item::File(file_item(&state.db, &file.id).await?))
}

/// Renames and/or moves every live version of `file`'s family.
async fn move_family(
    state: &AppState,
    file: &FileRow,
    target: &str,
    target_dir: &str,
    new_name: &str,
) -> AppResult<()> {
    let family: Vec<FileRow> = sqlx::query_as(
        "SELECT id, folder_id, name, disk_name, version, session_id, deleted_at FROM files
         WHERE folder_id = ? AND name = ? COLLATE NOCASE AND deleted_at IS NULL",
    )
    .bind(&file.folder_id)
    .bind(&file.name)
    .fetch_all(&state.db)
    .await?;

    let moving = target != file.folder_id;
    // Trashed rows with the new name may already hold low version numbers there.
    let offset: i64 = if moving || !new_name.eq_ignore_ascii_case(&file.name) {
        sqlx::query_scalar(
            "SELECT COALESCE(MAX(version), 0) FROM files WHERE folder_id = ? AND name = ? COLLATE NOCASE",
        )
        .bind(target)
        .bind(new_name)
        .fetch_one(&state.db)
        .await?
    } else {
        0
    };

    // Move data first; on failure put back what already moved.
    let mut moved: Vec<(std::path::PathBuf, std::path::PathBuf, String, String)> = Vec::new();
    if moving {
        let src_dir = live_folder(&state.db, &file.folder_id).await?;
        for row in &family {
            let from = storage::checked_path(&state.cfg, &src_dir, &row.disk_name).await?;
            let mut disk_name = row.disk_name.clone();
            let mut to = storage::checked_path(&state.cfg, target_dir, &disk_name).await?;
            if tokio::fs::try_exists(&to).await? {
                let tag = &row.id.replace('-', "")[26..];
                disk_name = storage::tagged_disk_name(&disk_name, tag);
                to = storage::checked_path(&state.cfg, target_dir, &disk_name).await?;
            }
            if let Err(e) = tokio::fs::rename(&from, &to).await {
                for (from, to, _, _) in moved.iter().rev() {
                    let _ = tokio::fs::rename(to, from).await;
                }
                return Err(e.into());
            }
            moved.push((from, to, row.id.clone(), disk_name));
        }
    }

    let result = async {
        let mut tx = db::begin_write(&state.db).await?;
        for row in &family {
            let disk_name = moved
                .iter()
                .find(|m| m.2 == row.id)
                .map(|m| m.3.clone())
                .unwrap_or_else(|| row.disk_name.clone());
            sqlx::query(
                "UPDATE files SET folder_id = ?, name = ?, disk_name = ?, version = ? WHERE id = ?",
            )
            .bind(target)
            .bind(new_name)
            .bind(disk_name)
            .bind(row.version + offset)
            .bind(&row.id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await
    }
    .await;
    if let Err(e) = result {
        for (from, to, _, _) in moved.iter().rev() {
            let _ = tokio::fs::rename(to, from).await;
        }
        return Err(e.into());
    }
    Ok(())
}

async fn update_folder(
    state: &AppState,
    auth: &Auth,
    folder: SubfolderRow,
    req: UpdateItemRequest,
) -> AppResult<Item> {
    let Some(parent) = folder.parent_id.clone() else {
        return Err(AppError::Forbidden);
    };
    let session = auth.require(&state.db, &folder.id, Action::Modify).await?;
    if req.status_tag.is_some() {
        return Err(AppError::bad_request(
            "not_a_file",
            "Folders have no status tag",
        ));
    }

    let name = req
        .name
        .as_deref()
        .map(str::trim)
        .unwrap_or(&folder.name)
        .to_string();
    let slug = util::slugify(&name);
    if slug.is_empty() {
        return Err(AppError::bad_request(
            "invalid_name",
            "Folder name needs at least one letter or digit",
        ));
    }
    let new_parent = req.move_to.clone().unwrap_or(parent.clone());
    if new_parent != parent {
        live_folder(&state.db, &new_parent).await?;
        auth.require(&state.db, &new_parent, Action::Modify).await?;
        if ancestor_chain(&state.db, &new_parent)
            .await?
            .contains(&folder.id)
        {
            return Err(AppError::bad_request(
                "invalid_move",
                "A folder cannot move into itself",
            ));
        }
    }

    let mut tx = db::begin_write(&state.db).await?;
    if slug != folder.slug || new_parent != parent {
        sqlx::query(
            "INSERT INTO folder_slug_history (old_slug, parent_id, folder_id) VALUES (?, ?, ?)
             ON CONFLICT (parent_id, old_slug) DO UPDATE SET folder_id = excluded.folder_id",
        )
        .bind(&folder.slug)
        .bind(&parent)
        .bind(&folder.id)
        .execute(&mut *tx)
        .await?;
    }
    sqlx::query("UPDATE folders SET name = ?, slug = ?, parent_id = ? WHERE id = ?")
        .bind(&name)
        .bind(&slug)
        .bind(&new_parent)
        .bind(&folder.id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                AppError::conflict("slug_taken", "A folder with that name already exists there")
            } else {
                e.into()
            }
        })?;
    tx.commit().await?;

    db::audit(
        &state.db,
        &session.actor,
        "folder.update",
        Some(&folder.id),
        Some(serde_json::json!({ "name": name, "from_parent": parent, "to_parent": new_parent })),
    )
    .await?;
    publish(
        state,
        EventKind::FolderUpdated,
        &parent,
        &folder.id,
        Some(&name),
        None,
    )
    .await;
    if new_parent != parent {
        publish(
            state,
            EventKind::FolderAdded,
            &new_parent,
            &folder.id,
            Some(&name),
            None,
        )
        .await;
    }

    let (_, parent_path) = folder_path(&state.db, &new_parent).await?;
    Ok(Item::Folder(FolderSummary {
        path: join_path(&parent_path, &slug),
        id: folder.id,
        slug,
        name,
        created_at: folder.created_at,
    }))
}

/// Move a file (all versions) to the trash, or remove an empty subfolder. Trash is
/// purged after 30 days.
#[utoipa::path(
    delete,
    path = "/api/v1/items/{id}",
    tag = "items",
    params(("id" = String, Path, description = "File (any version) or subfolder id")),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 204, description = "In the trash"),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
        (status = 409, description = "Subfolder is not empty", body = ErrorBody),
    )
)]
pub async fn delete(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    if let Some(file) = load_file(&state.db, &id).await? {
        let session = auth
            .require(&state.db, &file.folder_id, Action::Trash)
            .await?;
        if file.deleted_at.is_some() {
            return Ok(StatusCode::NO_CONTENT);
        }
        sqlx::query(
            "UPDATE files SET deleted_at = ? WHERE folder_id = ? AND name = ? COLLATE NOCASE AND deleted_at IS NULL",
        )
        .bind(util::now())
        .bind(&file.folder_id)
        .bind(&file.name)
        .execute(&state.db)
        .await?;
        audit_item(&state.db, session, "file.trash", &file.id, &file.name).await?;
        publish(
            &state,
            EventKind::FileDeleted,
            &file.folder_id,
            &file.id,
            Some(&file.name),
            file.session_id.as_deref(),
        )
        .await;
        return Ok(StatusCode::NO_CONTENT);
    }

    let folder = load_subfolder(&state.db, &id)
        .await?
        .ok_or(AppError::NotFound)?;
    let Some(parent) = folder.parent_id.clone() else {
        return Err(AppError::Forbidden);
    };
    let session = auth.require(&state.db, &folder.id, Action::Trash).await?;
    let busy: Option<i64> = sqlx::query_scalar(
        "SELECT 1 WHERE EXISTS (SELECT 1 FROM files WHERE folder_id = ?1 AND deleted_at IS NULL)
                     OR EXISTS (SELECT 1 FROM folders WHERE parent_id = ?1 AND archived_at IS NULL)",
    )
    .bind(&folder.id)
    .fetch_optional(&state.db)
    .await?;
    if busy.is_some() {
        return Err(AppError::conflict(
            "not_empty",
            "Only empty folders can be deleted",
        ));
    }
    // Rows stay (trashed files may still point at the folder); archived = gone.
    sqlx::query("UPDATE folders SET archived_at = ? WHERE id = ?")
        .bind(util::now())
        .bind(&folder.id)
        .execute(&state.db)
        .await?;
    audit_item(
        &state.db,
        session,
        "folder.delete",
        &folder.id,
        &folder.name,
    )
    .await?;
    publish(
        &state,
        EventKind::FolderUpdated,
        &parent,
        &folder.id,
        Some(&folder.name),
        None,
    )
    .await;
    Ok(StatusCode::NO_CONTENT)
}

async fn audit_item(
    db: &SqlitePool,
    session: &Session,
    action: &str,
    id: &str,
    name: &str,
) -> AppResult<()> {
    db::audit(
        db,
        &session.actor,
        action,
        Some(id),
        Some(serde_json::json!({ "name": name })),
    )
    .await?;
    Ok(())
}

/// Restore a file from the trash, and/or make an older version current.
#[utoipa::path(
    post,
    path = "/api/v1/items/{id}/restore",
    tag = "items",
    params(("id" = String, Path, description = "File id (any version)")),
    request_body(content = RestoreRequest, description = "Optional; empty body restores from trash"),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, description = "The current version after restoring", body = FileItem),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, description = "No such file or version", body = ErrorBody),
    )
)]
pub async fn restore(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
    body: Option<Json<RestoreRequest>>,
) -> AppResult<Json<FileItem>> {
    let req = body.map(|Json(r)| r).unwrap_or_default();
    let file = load_file(&state.db, &id).await?.ok_or(AppError::NotFound)?;
    let session = auth
        .require(&state.db, &file.folder_id, Action::Trash)
        .await?;

    let mut tx = db::begin_write(&state.db).await?;
    let was_trashed = file.deleted_at.is_some();
    if let Some(deleted_at) = &file.deleted_at {
        // Everything trashed together with this file comes back together.
        sqlx::query(
            "UPDATE files SET deleted_at = NULL WHERE folder_id = ? AND name = ? COLLATE NOCASE AND deleted_at = ?",
        )
        .bind(&file.folder_id)
        .bind(&file.name)
        .bind(deleted_at)
        .execute(&mut *tx)
        .await?;
    }
    let current_version: Option<i64> = match req.version {
        Some(v) => {
            sqlx::query_scalar(
                "SELECT version FROM files WHERE folder_id = ? AND name = ? COLLATE NOCASE
               AND deleted_at IS NULL AND version = ?",
            )
            .bind(&file.folder_id)
            .bind(&file.name)
            .bind(v)
            .fetch_optional(&mut *tx)
            .await?
        }
        // Keep the version that was current (restored rows keep their flag); if a newer
        // upload arrived while this was in the trash, that one wins.
        None => {
            sqlx::query_scalar(
                "SELECT COALESCE(MAX(CASE WHEN is_current = 1 THEN version END), MAX(version))
             FROM files WHERE folder_id = ? AND name = ? COLLATE NOCASE AND deleted_at IS NULL",
            )
            .bind(&file.folder_id)
            .bind(&file.name)
            .fetch_one(&mut *tx)
            .await?
        }
    };
    let current_version = current_version.ok_or(AppError::NotFound)?;
    sqlx::query(
        "UPDATE files SET is_current = (version = ?)
         WHERE folder_id = ? AND name = ? COLLATE NOCASE AND deleted_at IS NULL",
    )
    .bind(current_version)
    .bind(&file.folder_id)
    .bind(&file.name)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;

    let current = current_of(&state.db, &file.folder_id, &file.name)
        .await?
        .ok_or(AppError::NotFound)?;
    db::audit(
        &state.db,
        &session.actor,
        "file.restore",
        Some(&current),
        Some(serde_json::json!({ "name": file.name, "from_trash": was_trashed, "version": current_version })),
    )
    .await?;
    let kind = if was_trashed {
        EventKind::FileAdded
    } else {
        EventKind::FileUpdated
    };
    publish(
        &state,
        kind,
        &file.folder_id,
        &current,
        Some(&file.name),
        file.session_id.as_deref(),
    )
    .await;
    Ok(Json(file_item(&state.db, &current).await?))
}

/// All live versions of a file, newest first.
#[utoipa::path(
    get,
    path = "/api/v1/files/{id}/versions",
    tag = "items",
    params(("id" = String, Path, description = "File id (any version)")),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Vec<FileVersion>),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn versions(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> AppResult<Json<Vec<FileVersion>>> {
    let file = load_file(&state.db, &id).await?.ok_or(AppError::NotFound)?;
    auth.require(&state.db, &file.folder_id, Action::Modify)
        .await?;
    let rows = sqlx::query_as(
        "SELECT id, version, is_current, size, sha256, status_tag, uploaded_by, created_at FROM files
         WHERE folder_id = ? AND name = ? COLLATE NOCASE AND deleted_at IS NULL
         ORDER BY version DESC",
    )
    .bind(&file.folder_id)
    .bind(&file.name)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}
