use std::sync::atomic::Ordering;

use axum::{Json, extract::State};
use axum_extra::extract::SignedCookieJar;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::{Auth, NewSession, Role, create_session, pin};
use crate::{
    AppState, db,
    error::{AppError, AppResult, ErrorBody},
};

pub const ADMIN_HASH_KEY: &str = "admin_password_hash";
const MIN_PASSWORD_LEN: usize = 8;

/// Returned by every endpoint that creates a session. The cookie is set as well;
/// `session_id` is for `Authorization: Bearer` in curl and scripts.
#[derive(Debug, Serialize, ToSchema)]
pub struct SessionResponse {
    pub session_id: String,
    pub role: Role,
    /// Scope root folder id; null for hub and admin sessions.
    pub root_folder: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetupRequest {
    /// One-time code printed to the server console on first run.
    pub setup_code: String,
    #[schema(min_length = 8)]
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub password: String,
}

/// First-run admin password. Also logs the admin in.
#[utoipa::path(
    post,
    path = "/api/v1/admin/setup",
    tag = "admin",
    request_body = SetupRequest,
    responses(
        (status = 200, description = "Admin password set; admin session created", body = SessionResponse),
        (status = 400, description = "Password too short", body = ErrorBody),
        (status = 401, description = "Wrong setup code", body = ErrorBody),
        (status = 409, description = "Setup already completed", body = ErrorBody),
        (status = 429, description = "Too many failed attempts", body = ErrorBody),
    )
)]
pub async fn setup(
    State(state): State<AppState>,
    auth: Auth,
    jar: SignedCookieJar,
    Json(req): Json<SetupRequest>,
) -> AppResult<(SignedCookieJar, Json<SessionResponse>)> {
    if state.setup.done.load(Ordering::Acquire) {
        return Err(AppError::conflict(
            "already_set_up",
            "Admin setup has already been completed",
        ));
    }
    let lock_key = format!("setup:{}", auth.ip);
    pin::check_lock(&state.db, &lock_key).await?;

    let code_ok = {
        let code = state.setup.code.lock().unwrap();
        code.as_deref()
            .is_some_and(|c| constant_time_eq(c.as_bytes(), req.setup_code.trim().as_bytes()))
    };
    if !code_ok {
        pin::record_failure(&state.db, &lock_key).await?;
        return Err(AppError::Unauthorized(
            "invalid_setup_code",
            "Setup code is incorrect".into(),
        ));
    }
    if req.password.chars().count() < MIN_PASSWORD_LEN {
        return Err(AppError::bad_request(
            "password_too_short",
            format!("Password must be at least {MIN_PASSWORD_LEN} characters"),
        ));
    }

    let hash = pin::hash_secret(req.password).await?;
    db::set_setting(&state.db, ADMIN_HASH_KEY, &hash).await?;
    state.setup.done.store(true, Ordering::Release);
    *state.setup.code.lock().unwrap() = None;
    pin::record_success(&state.db, &lock_key).await?;
    db::audit(&state.db, "admin", "admin.setup", None, None).await?;
    tracing::info!("admin setup completed");

    admin_session(&state, &auth, jar).await
}

/// Admin login. Rate limited per IP like PINs.
#[utoipa::path(
    post,
    path = "/api/v1/admin/login",
    tag = "admin",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Admin session created", body = SessionResponse),
        (status = 401, description = "Wrong password", body = ErrorBody),
        (status = 429, description = "Too many failed attempts", body = ErrorBody),
        (status = 503, description = "Setup not completed", body = ErrorBody),
    )
)]
pub async fn login(
    State(state): State<AppState>,
    auth: Auth,
    jar: SignedCookieJar,
    Json(req): Json<LoginRequest>,
) -> AppResult<(SignedCookieJar, Json<SessionResponse>)> {
    let lock_key = format!("admin:{}", auth.ip);
    pin::check_lock(&state.db, &lock_key).await?;

    let hash = db::get_setting(&state.db, ADMIN_HASH_KEY)
        .await?
        .ok_or(AppError::SetupRequired)?;
    if pin::find_match(req.password, vec![hash]).await?.is_none() {
        pin::record_failure(&state.db, &lock_key).await?;
        db::audit(
            &state.db,
            "admin",
            "admin.login_failed",
            None,
            Some(serde_json::json!({"ip": auth.ip})),
        )
        .await?;
        return Err(AppError::Unauthorized(
            "invalid_password",
            "Password is incorrect".into(),
        ));
    }
    pin::record_success(&state.db, &lock_key).await?;
    db::audit(&state.db, "admin", "admin.login", None, None).await?;

    admin_session(&state, &auth, jar).await
}

async fn admin_session(
    state: &AppState,
    auth: &Auth,
    jar: SignedCookieJar,
) -> AppResult<(SignedCookieJar, Json<SessionResponse>)> {
    let (session_id, cookie) = create_session(
        state,
        auth,
        NewSession {
            root_folder: None,
            role: Role::Admin,
            pin_id: None,
            token_id: None,
        },
    )
    .await?;
    Ok((
        jar.add(cookie),
        Json(SessionResponse {
            session_id,
            role: Role::Admin,
            root_folder: None,
        }),
    ))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
