use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    extract::{Query, State},
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::Stream;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::{self, error::RecvError};
use utoipa::{IntoParams, ToSchema};

use super::folders::resolve;
use crate::{
    AppState,
    auth::{Action, Auth, Role, ancestor_chain},
    error::{AppResult, ErrorBody},
    util,
};

/// How often an open stream re-checks that its session is still valid.
const SESSION_CHECK: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    FileAdded,
    FileUpdated,
    FileDeleted,
    FolderAdded,
    FolderUpdated,
    /// An upload into the folder started. `id` is the upload id.
    UploadStarted,
    /// More bytes arrived (at most about once a second per upload), or an interrupted
    /// upload continued. Carries `offset` and `size`.
    UploadProgress,
    /// The uploader's connection dropped; the upload waits for them to resume.
    UploadPaused,
    /// The upload was cancelled. (A finished upload sends `file_added` instead.)
    UploadCancelled,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            EventKind::FileAdded => "file_added",
            EventKind::FileUpdated => "file_updated",
            EventKind::FileDeleted => "file_deleted",
            EventKind::FolderAdded => "folder_added",
            EventKind::FolderUpdated => "folder_updated",
            EventKind::UploadStarted => "upload_started",
            EventKind::UploadProgress => "upload_progress",
            EventKind::UploadPaused => "upload_paused",
            EventKind::UploadCancelled => "upload_cancelled",
        }
    }
}

/// Data of each SSE message. The SSE `event:` name equals `type`. Clients refetch the
/// listing (or the one item) on receipt. A `resync` event means events were dropped and
/// the whole listing should be refetched.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LiveEvent {
    #[serde(rename = "type")]
    pub kind: EventKind,
    /// Folder whose listing changed.
    pub folder_id: String,
    /// File or subfolder id; the upload id for `upload_*` events.
    pub id: String,
    pub name: Option<String>,
    /// `upload_*` events: bytes received so far.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<i64>,
    /// `upload_*` events: total size in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,
}

impl EventKind {
    /// Events about one session's file or upload, hidden from other uploader sessions.
    fn is_owned(self) -> bool {
        !matches!(self, EventKind::FolderAdded | EventKind::FolderUpdated)
    }

    /// Upload-in-progress events: only the uploader's own sessions and admin get them.
    fn is_upload(self) -> bool {
        matches!(
            self,
            EventKind::UploadStarted
                | EventKind::UploadProgress
                | EventKind::UploadPaused
                | EventKind::UploadCancelled
        )
    }
}

#[derive(Debug, Clone)]
pub struct Broadcast {
    pub(crate) event: LiveEvent,
    /// `folder_id` and its ancestors, for scope filtering.
    chain: Arc<Vec<String>>,
    /// Session that uploaded the file. Uploader sessions only see their own files;
    /// `upload_*` events only reach the uploader's own sessions and admin.
    owner_session: Option<String>,
}

pub type Events = broadcast::Sender<Broadcast>;

pub fn channel() -> Events {
    broadcast::channel(1024).0
}

/// Sends an event to every stream subscribed to `folder_id` or one of its ancestors.
pub async fn publish(
    state: &AppState,
    kind: EventKind,
    folder_id: &str,
    id: &str,
    name: Option<&str>,
    owner_session: Option<&str>,
) {
    send(state, kind, folder_id, id, name, owner_session, None).await;
}

/// Like `publish`, for `upload_*` events: `progress` is `(offset, size)`.
pub async fn publish_upload(
    state: &AppState,
    kind: EventKind,
    folder_id: &str,
    upload_id: &str,
    name: &str,
    owner_session: &str,
    progress: (i64, i64),
) {
    send(
        state,
        kind,
        folder_id,
        upload_id,
        Some(name),
        Some(owner_session),
        Some(progress),
    )
    .await;
}

async fn send(
    state: &AppState,
    kind: EventKind,
    folder_id: &str,
    id: &str,
    name: Option<&str>,
    owner_session: Option<&str>,
    progress: Option<(i64, i64)>,
) {
    let chain = match ancestor_chain(&state.db, folder_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = ?e, "event: loading folder chain");
            return;
        }
    };
    // No subscribers is not an error.
    let _ = state.events.send(Broadcast {
        event: LiveEvent {
            kind,
            folder_id: folder_id.to_string(),
            id: id.to_string(),
            name: name.map(str::to_string),
            offset: progress.map(|p| p.0),
            size: progress.map(|p| p.1),
        },
        chain: Arc::new(chain),
        owner_session: owner_session.map(str::to_string),
    });
}

#[derive(Debug, Deserialize, IntoParams)]
pub struct EventsQuery {
    /// Top-level folder slug.
    pub folder: String,
    /// Subfolder path; events for it and everything below it are sent.
    pub path: Option<String>,
}

struct StreamState {
    rx: broadcast::Receiver<Broadcast>,
    tick: tokio::time::Interval,
    state: AppState,
    session_id: String,
    /// Every session the browser presented, to match the owner of `upload_*` events.
    own_sessions: Vec<String>,
    admin: bool,
    uploader: bool,
    folder_id: String,
}

/// Live updates for a folder and its subfolders (Server-Sent Events). Not usable from
/// Swagger; try `curl -N -H "Authorization: Bearer <session_id>" ".../api/v1/events?folder=<slug>"`.
#[utoipa::path(
    get,
    path = "/api/v1/events",
    tag = "events",
    params(EventsQuery),
    security(("ark_session" = []), ("bearer" = [])),
    responses(
        (status = 200, description = "Event stream; each message's data is a LiveEvent", content_type = "text/event-stream", body = LiveEvent),
        (status = 401, body = ErrorBody),
        (status = 403, body = ErrorBody),
        (status = 404, body = ErrorBody),
    )
)]
pub async fn events(
    State(state): State<AppState>,
    auth: Auth,
    Query(q): Query<EventsQuery>,
) -> AppResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let folder = resolve(&state.db, &q.folder, q.path.as_deref()).await?;
    let session = auth.require(&state.db, &folder.id, Action::List).await?;

    let mut tick = tokio::time::interval(SESSION_CHECK);
    tick.reset();
    let init = StreamState {
        rx: state.events.subscribe(),
        tick,
        session_id: session.id.clone(),
        own_sessions: auth.sessions.iter().map(|s| s.id.clone()).collect(),
        admin: auth.sessions.iter().any(|s| s.role == Role::Admin),
        uploader: session.role == Role::Uploader,
        folder_id: folder.id,
        state,
    };

    let stream = futures_util::stream::unfold(init, |mut s| async move {
        loop {
            tokio::select! {
                msg = s.rx.recv() => match msg {
                    Ok(b) => {
                        if !b.chain.contains(&s.folder_id) {
                            continue;
                        }
                        if s.uploader && b.event.kind.is_owned() && b.owner_session.as_deref() != Some(&s.session_id) {
                            continue;
                        }
                        if b.event.kind.is_upload()
                            && !s.admin
                            && !b.owner_session.as_ref().is_some_and(|o| s.own_sessions.contains(o))
                        {
                            continue;
                        }
                        let event = Event::default()
                            .event(b.event.kind.as_str())
                            .json_data(&b.event)
                            .unwrap_or_default();
                        return Some((Ok(event), s));
                    }
                    Err(RecvError::Lagged(_)) => {
                        return Some((Ok(Event::default().event("resync").data("{}")), s));
                    }
                    Err(RecvError::Closed) => return None,
                },
                _ = s.tick.tick() => {
                    if !session_active(&s.state, &s.session_id).await {
                        return None;
                    }
                }
            }
        }
    });

    Ok(Sse::new(stream).keep_alive(KeepAlive::default()))
}

async fn session_active(state: &AppState, id: &str) -> bool {
    sqlx::query_scalar::<_, i64>(
        "SELECT 1 FROM sessions WHERE id = ? AND revoked_at IS NULL AND expires_at > ?",
    )
    .bind(id)
    .bind(util::now())
    .fetch_optional(&state.db)
    .await
    .is_ok_and(|r| r.is_some())
}
