use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use utoipa::ToSchema;

/// Error body returned by every endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    /// Machine-readable code, e.g. `forbidden`, `invalid_pin`.
    #[schema(example = "forbidden")]
    pub error: String,
    #[schema(example = "You do not have access to this folder")]
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("{1}")]
    BadRequest(&'static str, String),
    #[error("{1}")]
    Unauthorized(&'static str, String),
    #[error("You do not have access to this resource")]
    Forbidden,
    #[error("Not found")]
    NotFound,
    #[error("{1}")]
    Conflict(&'static str, String),
    #[error("Too many failed attempts, try again in {retry_after_secs} seconds")]
    TooManyAttempts { retry_after_secs: i64 },
    #[error("Admin setup has not been completed")]
    SetupRequired,
    /// Statuses that only a few endpoints use (413, 415, 412, ...).
    #[error("{2}")]
    Status(StatusCode, &'static str, String),
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn bad_request(code: &'static str, msg: impl Into<String>) -> Self {
        Self::BadRequest(code, msg.into())
    }

    pub fn unauthorized() -> Self {
        Self::Unauthorized("unauthorized", "Unlock this folder or log in first".into())
    }

    pub fn conflict(code: &'static str, msg: impl Into<String>) -> Self {
        Self::Conflict(code, msg.into())
    }

    fn status_and_code(&self) -> (StatusCode, &'static str) {
        match self {
            Self::BadRequest(code, _) => (StatusCode::BAD_REQUEST, code),
            Self::Unauthorized(code, _) => (StatusCode::UNAUTHORIZED, code),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict(code, _) => (StatusCode::CONFLICT, code),
            Self::TooManyAttempts { .. } => (StatusCode::TOO_MANY_REQUESTS, "too_many_attempts"),
            Self::SetupRequired => (StatusCode::SERVICE_UNAVAILABLE, "setup_required"),
            Self::Status(status, code, _) => (*status, code),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, code) = self.status_and_code();
        let message = match &self {
            Self::Internal(e) => {
                tracing::error!(error = ?e, "internal error");
                "Internal server error".to_string()
            }
            other => other.to_string(),
        };
        let mut resp = (
            status,
            Json(ErrorBody {
                error: code.into(),
                message,
            }),
        )
            .into_response();
        if let Self::TooManyAttempts { retry_after_secs } = self {
            resp.headers_mut().insert(
                header::RETRY_AFTER,
                HeaderValue::from(retry_after_secs.max(1)),
            );
        }
        resp
    }
}

/// True when a sqlx error is a UNIQUE constraint violation.
pub fn is_unique_violation(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .is_some_and(|d| d.is_unique_violation())
}
