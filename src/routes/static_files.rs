//! The built frontend (`web/dist`), with an SPA fallback to `index.html`.
//!
//! Release builds embed `web/dist` into the binary, so build the frontend before
//! `cargo build --release`. Debug builds read `web/dist` from disk on every request,
//! so a frontend rebuild shows up without restarting the backend.

use axum::{
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

use crate::error::AppError;

#[derive(RustEmbed)]
#[folder = "web/dist"]
#[allow_missing = true]
struct Dist;

/// First path segments the backend owns. Unknown paths under them are a 404, never
/// the app shell.
const BACKEND_PREFIXES: &[&str] = &[
    "api", "api-docs", "docs", "dl", "preview", "zip", "j", "healthz",
];

/// Router fallback: a file from `web/dist`, else `index.html` for app routes.
pub async fn serve(method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let path = uri.path().trim_start_matches('/');
    let first = path.split('/').next().unwrap_or_default();
    if BACKEND_PREFIXES.contains(&first) {
        return AppError::NotFound.into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        return AppError::Status(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            "method not allowed".into(),
        )
        .into_response();
    }

    if !path.is_empty() && path != "index.html" {
        if let Some(file) = Dist::get(path) {
            return file_response(path, file, &headers);
        }
        // A missing asset (a path ending in `name.ext`) is a 404, not the app shell.
        let last = path.rsplit('/').next().unwrap_or_default();
        if path.starts_with("assets/") || last.contains('.') {
            return AppError::NotFound.into_response();
        }
    }

    match Dist::get("index.html") {
        Some(file) => file_response("index.html", file, &headers),
        None => not_built(),
    }
}

fn file_response(path: &str, file: rust_embed::EmbeddedFile, req: &HeaderMap) -> Response {
    let etag = format!("\"{}\"", hex(&file.metadata.sha256_hash()));
    // Vite fingerprints everything under /assets/, so those never change in place.
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    if let Ok(v) = HeaderValue::from_str(&etag) {
        headers.insert(header::ETAG, v);
    }
    let matches = req
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"));
    if matches {
        return (StatusCode::NOT_MODIFIED, headers).into_response();
    }

    let mime = mime_guess::from_path(path).first_or_octet_stream();
    if let Ok(v) = HeaderValue::from_str(mime.as_ref()) {
        headers.insert(header::CONTENT_TYPE, v);
    }
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    (headers, file.data.into_owned()).into_response()
}

/// Shown at `/` when `web/dist/index.html` is missing.
fn not_built() -> Response {
    (
        StatusCode::SERVICE_UNAVAILABLE,
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        "<!doctype html><title>Ark</title><p>The Ark frontend isn't built yet. \
         Build it into <code>web/dist</code>, then rebuild the backend.</p>",
    )
        .into_response()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
