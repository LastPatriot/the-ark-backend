pub mod admin;
pub mod pin;

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{header, request::Parts},
};
use axum_extra::extract::cookie::{Cookie, SameSite, SignedCookieJar};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::net::SocketAddr;
use utoipa::ToSchema;

use crate::{
    AppState,
    error::{AppError, AppResult},
    util,
};

pub const COOKIE_PREFIX: &str = "ark_s_";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema, sqlx::Type)]
#[serde(rename_all = "lowercase")]
#[sqlx(rename_all = "lowercase")]
pub enum Role {
    Viewer,
    Uploader,
    Contributor,
    Editor,
    Hub,
    Admin,
}

impl Role {
    #[cfg(test)]
    pub const ALL: [Role; 6] = [
        Role::Viewer,
        Role::Uploader,
        Role::Contributor,
        Role::Editor,
        Role::Hub,
        Role::Admin,
    ];

    /// Hub and admin sessions are not bound to a root folder.
    pub fn is_unrestricted(self) -> bool {
        matches!(self, Role::Hub | Role::Admin)
    }

    /// Roles a folder PIN may grant.
    pub fn is_folder_role(self) -> bool {
        matches!(
            self,
            Role::Viewer | Role::Uploader | Role::Contributor | Role::Editor
        )
    }

    /// Preference when several sessions allow the same action. Viewer outranks uploader
    /// so a device holding both sees the full listing instead of only its own uploads.
    fn rank(self) -> u8 {
        match self {
            Role::Uploader => 0,
            Role::Viewer => 1,
            Role::Contributor => 2,
            Role::Editor => 3,
            Role::Hub => 4,
            Role::Admin => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// List a folder and its previews. Uploaders see only their own uploads.
    List,
    Download,
    Upload,
    CreateSubfolder,
    /// Rename, move, tag.
    Modify,
    /// Delete to trash, restore.
    Trash,
    /// See the home page folder list.
    SeeHub,
    /// Top-level folders, PINs, QR, settings.
    Manage,
}

/// The permission matrix from ARK_BACKEND.md section 5.
pub fn can(role: Role, action: Action) -> bool {
    use Action::*;
    use Role::*;
    match (role, action) {
        (Admin, _) => true,
        (_, Manage) => false,
        (Hub, _) => true,
        (_, SeeHub) => false,
        (Viewer, List | Download) => true,
        (Uploader, List | Upload) => true,
        (Contributor, List | Download | Upload | CreateSubfolder) => true,
        (Editor, _) => true,
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct Session {
    pub id: String,
    pub root_folder: Option<String>,
    pub role: Role,
    /// PIN/token label (or the role name for admin) used as the audit actor.
    pub actor: String,
}

/// All valid sessions presented by the request: every signed `ark_s_*` cookie plus an
/// optional `Authorization: Bearer <session_id>`. Never rejects; handlers call `require`.
pub struct Auth {
    pub sessions: Vec<Session>,
    pub ip: String,
    pub secure: bool,
}

impl FromRequestParts<AppState> for Auth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let mut ids: Vec<String> = Vec::new();
        if let Some(token) = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            ids.push(token.trim().to_string());
        }
        let jar = SignedCookieJar::from_headers(&parts.headers, state.cookie_key.clone());
        for c in jar.iter() {
            if c.name().starts_with(COOKIE_PREFIX) {
                ids.push(c.value().to_string());
            }
        }
        ids.sort();
        ids.dedup();

        let now = util::now();
        let mut sessions = Vec::with_capacity(ids.len());
        for id in ids {
            let row: Option<(String, Option<String>, Role, String)> = sqlx::query_as(
                "SELECT s.id, s.root_folder, s.role, COALESCE(p.label, t.label, s.role)
                 FROM sessions s
                 LEFT JOIN pins p ON p.id = s.pin_id
                 LEFT JOIN join_tokens t ON t.id = s.token_id
                 WHERE s.id = ? AND s.revoked_at IS NULL AND s.expires_at > ?",
            )
            .bind(&id)
            .bind(&now)
            .fetch_optional(&state.db)
            .await?;
            if let Some((id, root_folder, role, actor)) = row {
                sessions.push(Session {
                    id,
                    root_folder,
                    role,
                    actor,
                });
            }
        }

        let ip = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip().to_string())
            .unwrap_or_else(|| "unknown".into());
        let secure = parts
            .headers
            .get("x-forwarded-proto")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"https"));

        Ok(Self {
            sessions,
            ip,
            secure,
        })
    }
}

impl Auth {
    pub fn admin(&self) -> AppResult<&Session> {
        if self.sessions.is_empty() {
            return Err(AppError::unauthorized());
        }
        self.sessions
            .iter()
            .find(|s| can(s.role, Action::Manage))
            .ok_or(AppError::Forbidden)
    }

    pub fn hub(&self) -> AppResult<&Session> {
        if self.sessions.is_empty() {
            return Err(AppError::unauthorized());
        }
        self.sessions
            .iter()
            .filter(|s| can(s.role, Action::SeeHub))
            .max_by_key(|s| s.role.rank())
            .ok_or(AppError::Forbidden)
    }

    /// Returns the best session allowed to perform `action` on `folder_id`: its role must
    /// allow the action and the folder must be its root or a descendant of it.
    pub async fn require(
        &self,
        db: &SqlitePool,
        folder_id: &str,
        action: Action,
    ) -> AppResult<&Session> {
        if self.sessions.is_empty() {
            return Err(AppError::unauthorized());
        }
        let chain = ancestor_chain(db, folder_id).await?;
        self.sessions
            .iter()
            .filter(|s| can(s.role, action))
            .filter(|s| {
                s.role.is_unrestricted()
                    || s.root_folder.as_ref().is_some_and(|r| chain.contains(r))
            })
            .max_by_key(|s| s.role.rank())
            .ok_or(AppError::Forbidden)
    }
}

/// `folder_id` followed by each of its ancestors up to the top-level folder.
pub async fn ancestor_chain(db: &SqlitePool, folder_id: &str) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar(
        "WITH RECURSIVE chain(id, parent_id, depth) AS (
             SELECT id, parent_id, 0 FROM folders WHERE id = ?
             UNION ALL
             SELECT f.id, f.parent_id, c.depth + 1 FROM folders f JOIN chain c ON f.id = c.parent_id
         )
         SELECT id FROM chain ORDER BY depth",
    )
    .bind(folder_id)
    .fetch_all(db)
    .await
}

pub fn cookie_name(role: Role, root_folder: Option<&str>) -> String {
    match (role, root_folder) {
        (Role::Admin, _) => format!("{COOKIE_PREFIX}admin"),
        (Role::Hub, _) | (_, None) => format!("{COOKIE_PREFIX}hub"),
        // The tail of a v7 uuid is random; the head is a timestamp shared by folders
        // created close together.
        (_, Some(root)) => {
            let hex: String = root.chars().filter(|c| *c != '-').collect();
            format!("{COOKIE_PREFIX}{}", &hex[hex.len().saturating_sub(12)..])
        }
    }
}

pub struct NewSession<'a> {
    pub root_folder: Option<&'a str>,
    pub role: Role,
    pub pin_id: Option<&'a str>,
    pub token_id: Option<&'a str>,
}

/// Inserts a session and returns it with the cookie that carries it.
pub async fn create_session(
    state: &AppState,
    auth: &Auth,
    new: NewSession<'_>,
) -> AppResult<(String, Cookie<'static>)> {
    let id = util::random_token();
    let now = chrono::Utc::now();
    let hours = state.cfg.session_hours;
    let expires = now + chrono::Duration::hours(hours);
    sqlx::query(
        "INSERT INTO sessions (id, root_folder, role, pin_id, token_id, ip, created_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(new.root_folder)
    .bind(new.role)
    .bind(new.pin_id)
    .bind(new.token_id)
    .bind(&auth.ip)
    .bind(util::fmt_time(now))
    .bind(util::fmt_time(expires))
    .execute(&state.db)
    .await?;

    let cookie = Cookie::build((cookie_name(new.role, new.root_folder), id.clone()))
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .secure(auth.secure)
        .max_age(time::Duration::hours(hours))
        .build();
    Ok((id, cookie))
}

#[cfg(test)]
mod tests {
    use super::*;
    use Action::*;
    use Role::*;

    /// One row per action, columns in `Role::ALL` order:
    /// viewer, uploader, contributor, editor, hub, admin.
    const MATRIX: [(Action, [bool; 6]); 8] = [
        (List, [true, true, true, true, true, true]),
        (Download, [true, false, true, true, true, true]),
        (Upload, [false, true, true, true, true, true]),
        (CreateSubfolder, [false, false, true, true, true, true]),
        (Modify, [false, false, false, true, true, true]),
        (Trash, [false, false, false, true, true, true]),
        (SeeHub, [false, false, false, false, true, true]),
        (Manage, [false, false, false, false, false, true]),
    ];

    #[test]
    fn permission_matrix() {
        for (action, row) in MATRIX {
            for (role, expected) in Role::ALL.into_iter().zip(row) {
                assert_eq!(
                    can(role, action),
                    expected,
                    "can({role:?}, {action:?}) should be {expected}"
                );
            }
        }
    }

    #[test]
    fn viewer_preferred_over_uploader() {
        assert!(Viewer.rank() > Uploader.rank());
    }

    #[test]
    fn cookie_names() {
        assert_eq!(cookie_name(Admin, None), "ark_s_admin");
        assert_eq!(cookie_name(Hub, None), "ark_s_hub");
        assert_eq!(
            cookie_name(Viewer, Some("019a2b3c-4d5e-7f00-8123-456789abcdef")),
            "ark_s_456789abcdef"
        );
    }
}
