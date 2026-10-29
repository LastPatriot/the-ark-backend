mod auth;
mod config;
mod db;
mod discovery;
mod dns;
mod error;
mod openapi;
mod qr;
mod routes;
mod storage;
#[cfg(test)]
mod tests;
mod tunnel;
mod util;
mod vault;
mod workers;

use std::{
    io::IsTerminal,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::Context;
use axum::{
    Router,
    extract::{FromRef, Request, State},
    http::{HeaderName, HeaderValue},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response},
    routing::{delete, get, head, options, patch, post},
};
use axum_extra::extract::cookie::Key;
use base64::{Engine, engine::general_purpose::STANDARD};
use sqlx::SqlitePool;
use tower_http::{
    compression::CompressionLayer, set_header::SetResponseHeaderLayer, trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

use crate::{config::Config, error::AppError};

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub cfg: Arc<Config>,
    pub cookie_key: Key,
    pub vault: Arc<vault::Vault>,
    pub setup: Arc<SetupState>,
    pub uploads: Arc<routes::uploads::UploadLocks>,
    pub events: routes::events::Events,
    /// Wakes the thumbnail worker.
    pub thumbs: Arc<tokio::sync::Notify>,
    /// Wakes the video preview worker.
    pub videos: Arc<tokio::sync::Notify>,
    pub zips: Arc<routes::zip::ZipJobs>,
    pub tunnel: Arc<tunnel::Tunnel>,
    pub sync: Arc<workers::sync::SyncState>,
}

/// First-run state: until the admin password is set only `/admin/setup` works.
pub struct SetupState {
    pub done: AtomicBool,
    /// One-time code printed to the console; cleared once setup completes.
    pub code: Mutex<Option<String>>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("the_ark=info,tower_http=info")),
        )
        // journald and the Windows log file get plain text.
        .with_ansi(std::io::stdout().is_terminal())
        .init();

    let state = build_state(Config::load()?).await?;
    workers::thumbnails::spawn(state.clone());
    workers::video::spawn(state.clone());
    workers::sync::spawn(state.clone());
    workers::trash::spawn(state.clone());
    discovery::spawn(state.cfg.clone());
    dns::spawn(state.cfg.clone());
    if let Err(e) = tunnel::resume(&state).await {
        tracing::error!(error = ?e, "resuming tunnel");
    }
    let app = app(state.clone());

    let listener = tokio::net::TcpListener::bind(state.cfg.bind)
        .await
        .with_context(|| format!("binding {}", state.cfg.bind))?;
    tracing::info!(
        "Ark listening on http://{} (data dir {})",
        state.cfg.bind,
        state.cfg.data_dir.display()
    );
    if state.cfg.docs {
        tracing::info!("API docs at http://{}/docs", state.cfg.bind);
    }
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// Ctrl-C, or SIGTERM from systemd.
async fn shutdown_signal() {
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term => {}
    }
    tracing::info!("shutting down");
}

/// Opens the database and loads keys and setup state. Background tasks are started
/// separately.
pub async fn build_state(cfg: Config) -> anyhow::Result<AppState> {
    let db = db::connect(&cfg.data_dir).await?;
    let cookie_key = load_cookie_key(&db, &cfg).await?;
    let vault = Arc::new(vault::Vault::load(&cfg)?);
    let setup = load_setup_state(&db).await?;
    Ok(AppState {
        db,
        cfg: Arc::new(cfg),
        cookie_key,
        vault,
        setup: Arc::new(setup),
        uploads: Arc::default(),
        events: routes::events::channel(),
        thumbs: Arc::default(),
        videos: Arc::default(),
        zips: Arc::default(),
        tunnel: Arc::default(),
        sync: Arc::default(),
    })
}

pub fn app(state: AppState) -> Router {
    let uploads = Router::new()
        .route(
            "/uploads",
            options(routes::uploads::options).post(routes::uploads::create),
        )
        .route(
            "/uploads/{id}",
            head(routes::uploads::head)
                .patch(routes::uploads::patch)
                .delete(routes::uploads::terminate),
        )
        .layer(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("tus-resumable"),
            HeaderValue::from_static(routes::uploads::TUS_VERSION),
        ));

    let api = Router::new()
        .route("/me", get(routes::folders::me))
        .route("/logout", post(routes::folders::logout))
        .route("/hub/unlock", post(routes::folders::hub_unlock))
        .route("/folders", get(routes::folders::list_folders))
        .route("/folders/{slug}/unlock", post(routes::folders::unlock))
        .route("/folders/{slug}/items", get(routes::folders::list_items))
        .route(
            "/folders/{slug}/subfolders",
            post(routes::folders::create_subfolder),
        )
        .route(
            "/items/{id}",
            patch(routes::items::update).delete(routes::items::delete),
        )
        .route("/items/{id}/restore", post(routes::items::restore))
        .route("/files/{id}/versions", get(routes::items::versions))
        .route("/events", get(routes::events::events))
        .route("/zip", post(routes::zip::create))
        .route("/admin/setup", post(auth::admin::setup))
        .route("/admin/login", post(auth::admin::login))
        .route(
            "/admin/folders",
            get(routes::admin::list_folders).post(routes::admin::create_folder),
        )
        .route(
            "/admin/folders/{id}",
            patch(routes::admin::update_folder).delete(routes::admin::archive_folder),
        )
        .route(
            "/admin/pins",
            get(routes::admin::list_pins).post(routes::admin::create_pin),
        )
        .route(
            "/admin/pins/{id}",
            patch(routes::admin::update_pin).delete(routes::admin::revoke_pin),
        )
        .route(
            "/admin/tokens",
            get(routes::join::list_tokens).post(routes::join::create_token),
        )
        .route("/admin/tokens/{id}", delete(routes::join::revoke_token))
        .route("/admin/qr", get(routes::admin_ops::qr_code))
        .route("/admin/sessions", get(routes::admin_ops::list_sessions))
        .route(
            "/admin/sessions/{handle}",
            delete(routes::admin_ops::end_session),
        )
        .route("/admin/activity", get(routes::admin_ops::activity))
        .route("/admin/sync", get(routes::admin_ops::sync_status))
        .route("/admin/sync/retry", post(routes::admin_ops::sync_retry))
        .route(
            "/admin/tunnel",
            get(routes::admin_ops::tunnel_status)
                .put(routes::admin_ops::tunnel_enable)
                .delete(routes::admin_ops::tunnel_disable),
        )
        .route("/admin/storage", get(routes::admin_ops::storage_report))
        .route(
            "/admin/trash",
            get(routes::admin_ops::list_trash).delete(routes::admin_ops::empty_trash),
        )
        .merge(uploads)
        .route_layer(middleware::from_fn_with_state(state.clone(), setup_gate))
        .layer(CompressionLayer::new());

    // /dl stays uncompressed: compression would drop Content-Length and break Range.
    let mut app = Router::new()
        .route("/healthz", get(healthz))
        .route("/dl/{file_id}", get(routes::downloads::download))
        .route("/preview/{file_id}/{kind}", get(routes::downloads::preview))
        .route(
            "/preview/{file_id}/hls/{name}",
            get(routes::downloads::preview_hls),
        )
        .route("/j/{token}", get(routes::join::join))
        .route("/zip/{token}", get(routes::zip::download))
        .nest("/api/v1", api);
    if state.cfg.docs {
        // Until the frontend exists, its pages lead to the API docs.
        app = app
            .route("/", get(|| async { Redirect::temporary("/docs") }))
            .route("/f/{*path}", get(|| async { Redirect::temporary("/docs") }))
            .merge(
                SwaggerUi::new("/docs").url("/api-docs/openapi.json", openapi::ApiDoc::openapi()),
            );
    }
    app.layer(TraceLayer::new_for_http()).with_state(state)
}

/// Health check.
#[utoipa::path(
    get,
    path = "/healthz",
    tag = "system",
    responses((status = 200, description = "Server is up", body = String, example = "ok"))
)]
async fn healthz() -> &'static str {
    "ok"
}

/// Blocks the API with 503 `setup_required` until the admin password exists.
async fn setup_gate(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if !state.setup.done.load(Ordering::Acquire) && !req.uri().path().ends_with("/admin/setup") {
        return AppError::SetupRequired.into_response();
    }
    next.run(req).await
}

async fn load_cookie_key(db: &SqlitePool, cfg: &Config) -> anyhow::Result<Key> {
    let encoded = match &cfg.cookie_key {
        Some(k) => k.clone(),
        None => match db::get_setting(db, "cookie_key").await? {
            Some(k) => k,
            None => {
                let k = STANDARD.encode(Key::generate().master());
                db::set_setting(db, "cookie_key", &k).await?;
                k
            }
        },
    };
    let bytes = STANDARD
        .decode(encoded.trim())
        .context("ARK_COOKIE_KEY must be standard base64")?;
    Key::try_from(bytes.as_slice()).context("cookie key must be at least 64 bytes")
}

async fn load_setup_state(db: &SqlitePool) -> anyhow::Result<SetupState> {
    let done = db::get_setting(db, auth::admin::ADMIN_HASH_KEY)
        .await?
        .is_some();
    let code = (!done).then(|| {
        // Six digits, readable off a console.
        let n: u32 = rand::random_range(0..1_000_000);
        let code = format!("{n:06}");
        tracing::warn!("first run: admin setup code is {code} — POST /api/v1/admin/setup");
        println!("\n  Ark admin setup code: {code}\n");
        code
    });
    Ok(SetupState {
        done: AtomicBool::new(done),
        code: Mutex::new(code),
    })
}
