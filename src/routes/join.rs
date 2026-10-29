//! Join tokens: a QR code that unlocks one folder with a fixed role, no PIN.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use axum_extra::extract::SignedCookieJar;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::folders::folder_path;
use crate::{
    AppState,
    auth::{Auth, NewSession, Role, create_session},
    db,
    error::{AppError, AppResult, ErrorBody},
    qr, util,
};

#[derive(Debug, Serialize, ToSchema, sqlx::FromRow)]
pub struct AdminToken {
    pub id: String,
    pub folder_id: String,
    /// viewer, uploader, guest or contributor.
    pub role: Role,
    pub label: String,
    pub expires_at: Option<String>,
    pub max_uses: Option<i64>,
    pub uses: i64,
    pub revoked_at: Option<String>,
    pub created_at: String,
    /// Join link to put in a QR code (`GET /api/v1/admin/qr?url=...`). Null for revoked
    /// links and for links created before Ark kept them (revoke and recreate those).
    #[sqlx(skip)]
    #[schema(example = "http://ark.local/j/q8V0mJ2l3g8m0r5Yp1xZ7w")]
    pub url: Option<String>,
    #[serde(skip)]
    pub token_sealed: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CreatedToken {
    #[serde(flatten)]
    pub token: AdminToken,
    /// The raw token (the last part of `url`).
    pub secret: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateTokenRequest {
    pub folder_id: String,
    /// viewer, uploader, guest or contributor.
    pub role: Role,
    #[schema(example = "Entrance poster")]
    pub label: String,
    /// RFC 3339.
    pub expires_at: Option<String>,
    pub max_uses: Option<i64>,
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct TokensQuery {
    pub folder_id: Option<String>,
    #[serde(default)]
    pub include_revoked: bool,
}

const TOKEN_COLUMNS: &str =
    "id, folder_id, role, label, expires_at, max_uses, uses, revoked_at, created_at, token_sealed";

fn join_url(state: &AppState, secret: &str) -> String {
    format!("{}/j/{secret}", qr::public_base(&state.cfg))
}

/// Fills in the join link for the admin.
fn reveal(state: &AppState, mut t: AdminToken) -> AdminToken {
    if t.revoked_at.is_none() {
        t.url = t
            .token_sealed
            .as_deref()
            .and_then(|sealed| state.vault.open(&t.id, sealed))
            .map(|secret| join_url(state, &secret));
    }
    t
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tokens",
    tag = "admin",
    params(TokensQuery),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, body = Vec<AdminToken>),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
    )
)]
pub async fn list_tokens(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<TokensQuery>,
) -> AppResult<Json<Vec<AdminToken>>> {
    auth.admin()?;
    let rows: Vec<AdminToken> = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {TOKEN_COLUMNS} FROM join_tokens
         WHERE (?1 IS NULL OR folder_id = ?1) AND (?2 OR revoked_at IS NULL)
         ORDER BY created_at"
    )))
    .bind(q.folder_id)
    .bind(q.include_revoked)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows.into_iter().map(|t| reveal(&state, t)).collect()))
}

/// Create a join token. Its link stays available from `GET /api/v1/admin/tokens`.
#[utoipa::path(
    post,
    path = "/api/v1/admin/tokens",
    tag = "admin",
    request_body = CreateTokenRequest,
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 201, body = CreatedToken),
        (status = 400, body = ErrorBody),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, description = "No such folder", body = ErrorBody),
    )
)]
pub async fn create_token(
    State(state): State<AppState>,
    auth: Auth,
    Json(req): Json<CreateTokenRequest>,
) -> AppResult<(StatusCode, Json<CreatedToken>)> {
    let admin = auth.admin()?;
    if !matches!(
        req.role,
        Role::Viewer | Role::Uploader | Role::Guest | Role::Contributor
    ) {
        return Err(AppError::bad_request(
            "invalid_role",
            "Join tokens are viewer, uploader, guest or contributor",
        ));
    }
    let label = req.label.trim().to_string();
    if label.is_empty() {
        return Err(AppError::bad_request("invalid_label", "label is required"));
    }
    let expires_at = req
        .expires_at
        .map(|s| {
            util::normalize_time(&s)
                .ok_or_else(|| AppError::bad_request("invalid_time", "expires_at must be RFC 3339"))
        })
        .transpose()?;
    let exists: Option<i64> =
        sqlx::query_scalar("SELECT 1 FROM folders WHERE id = ? AND archived_at IS NULL")
            .bind(&req.folder_id)
            .fetch_optional(&state.db)
            .await?;
    exists.ok_or(AppError::NotFound)?;

    let id = util::new_id();
    let secret = util::random_token();
    sqlx::query(
        "INSERT INTO join_tokens (id, folder_id, token_hash, role, label, expires_at, max_uses, created_at, token_sealed)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.folder_id)
    .bind(util::sha256_hex(secret.as_bytes()))
    .bind(req.role)
    .bind(&label)
    .bind(&expires_at)
    .bind(req.max_uses)
    .bind(util::now())
    .bind(state.vault.seal(&id, &secret))
    .execute(&state.db)
    .await?;
    db::audit(
        &state.db,
        &admin.actor,
        "token.create",
        Some(&id),
        Some(serde_json::json!({
            "folder_id": req.folder_id, "label": label, "role": req.role,
        })),
    )
    .await?;

    let token = sqlx::query_as(sqlx::AssertSqlSafe(format!(
        "SELECT {TOKEN_COLUMNS} FROM join_tokens WHERE id = ?"
    )))
    .bind(&id)
    .fetch_one(&state.db)
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(CreatedToken {
            token: reveal(&state, token),
            secret,
        }),
    ))
}

/// Revoke a join token and end every session created from it.
#[utoipa::path(
    delete,
    path = "/api/v1/admin/tokens/{id}",
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
pub async fn revoke_token(
    State(state): State<AppState>,
    auth: Auth,
    Path(id): Path<String>,
) -> AppResult<StatusCode> {
    let admin = auth.admin()?;
    let now = util::now();
    let mut tx = db::begin_write(&state.db).await?;
    let found =
        sqlx::query("UPDATE join_tokens SET revoked_at = COALESCE(revoked_at, ?) WHERE id = ?")
            .bind(&now)
            .bind(&id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    if found == 0 {
        return Err(AppError::NotFound);
    }
    let ended =
        sqlx::query("UPDATE sessions SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL")
            .bind(&now)
            .bind(&id)
            .execute(&mut *tx)
            .await?
            .rows_affected();
    tx.commit().await?;
    db::audit(
        &state.db,
        &admin.actor,
        "token.revoke",
        Some(&id),
        Some(serde_json::json!({ "sessions_ended": ended })),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Join link target: validates the token, sets a session cookie for its folder and
/// redirects to the folder page.
#[utoipa::path(
    get,
    path = "/j/{token}",
    tag = "auth",
    params(("token" = String, Path)),
    responses(
        (status = 302, description = "Session cookie set; redirect to /f/{slug}/{path}"),
        (status = 404, description = "Unknown, expired, used up or revoked token", body = ErrorBody),
    )
)]
pub async fn join(
    State(state): State<AppState>,
    auth: Auth,
    jar: SignedCookieJar,
    Path(token): Path<String>,
) -> AppResult<Response> {
    let row: Option<(String, String, Role, String)> = sqlx::query_as(
        "SELECT t.id, t.folder_id, t.role, t.label FROM join_tokens t JOIN folders f ON f.id = t.folder_id
         WHERE t.token_hash = ? AND t.revoked_at IS NULL AND f.archived_at IS NULL
           AND (t.expires_at IS NULL OR t.expires_at > ?)
           AND (t.max_uses IS NULL OR t.uses < t.max_uses)",
    )
    .bind(util::sha256_hex(token.as_bytes()))
    .bind(util::now())
    .fetch_optional(&state.db)
    .await?;
    let (token_id, folder_id, role, label) = row.ok_or(AppError::NotFound)?;

    sqlx::query("UPDATE join_tokens SET uses = uses + 1 WHERE id = ?")
        .bind(&token_id)
        .execute(&state.db)
        .await?;
    let (_, cookie) = create_session(
        &state,
        &auth,
        NewSession {
            root_folder: Some(&folder_id),
            role,
            pin_id: None,
            token_id: Some(&token_id),
        },
    )
    .await?;
    db::audit(
        &state.db,
        &label,
        "folder.join",
        Some(&folder_id),
        Some(serde_json::json!({ "role": role })),
    )
    .await?;

    let (slug, path) = folder_path(&state.db, &folder_id).await?;
    let target = if path.is_empty() {
        format!("/f/{slug}")
    } else {
        format!("/f/{slug}/{path}")
    };
    Ok((
        StatusCode::FOUND,
        jar.add(cookie),
        [(header::LOCATION, target)],
    )
        .into_response())
}
