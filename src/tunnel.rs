//! Cloudflare Tunnel: runs `cloudflared` as a supervised child process so Ark can be
//! reached from outside the venue network.
//!
//! Two modes: a quick tunnel (no Cloudflare account; a random `*.trycloudflare.com`
//! URL that changes on every start) or a named tunnel from the Cloudflare dashboard
//! (connector token; stable hostname configured there).

use std::{
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::Command,
};
use tokio_util::sync::CancellationToken;
use utoipa::ToSchema;

use crate::{AppState, db};

const MODE_KEY: &str = "tunnel_mode";
const TOKEN_KEY: &str = "tunnel_token";
const HOSTNAME_KEY: &str = "tunnel_hostname";
const MAX_BACKOFF: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Quick,
    Named {
        token: String,
        hostname: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct TunnelStatus {
    pub enabled: bool,
    /// `quick` or `named`.
    pub mode: Option<String>,
    /// cloudflared has a registered connection to Cloudflare.
    pub connected: bool,
    /// Public base URL, once known (quick tunnels report it; named ones use the
    /// configured hostname).
    pub public_url: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Default)]
pub struct Tunnel {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    mode: Option<Mode>,
    connected: bool,
    public_url: Option<String>,
    last_error: Option<String>,
    stop: Option<CancellationToken>,
}

impl Tunnel {
    pub fn status(&self) -> TunnelStatus {
        let i = self.inner.lock().unwrap();
        TunnelStatus {
            enabled: i.mode.is_some(),
            mode: i.mode.as_ref().map(|m| match m {
                Mode::Quick => "quick".into(),
                Mode::Named { .. } => "named".into(),
            }),
            connected: i.connected,
            public_url: i.public_url.clone(),
            last_error: i.last_error.clone(),
        }
    }

    /// Host of the public URL, for allowing it in QR codes.
    pub fn public_host(&self) -> Option<String> {
        let url = self.inner.lock().unwrap().public_url.clone()?;
        Some(url.strip_prefix("https://")?.split('/').next()?.to_string())
    }

    fn update(&self, f: impl FnOnce(&mut Inner)) {
        f(&mut self.inner.lock().unwrap());
    }
}

/// Starts the tunnel saved in settings, if any.
pub async fn resume(state: &AppState) -> anyhow::Result<()> {
    let mode = match db::get_setting(&state.db, MODE_KEY).await?.as_deref() {
        Some("quick") => Mode::Quick,
        Some("named") => Mode::Named {
            token: db::get_setting(&state.db, TOKEN_KEY)
                .await?
                .unwrap_or_default(),
            hostname: db::get_setting(&state.db, HOSTNAME_KEY).await?,
        },
        _ => return Ok(()),
    };
    start(state, mode);
    Ok(())
}

/// Saves the mode and (re)starts cloudflared with it.
pub async fn enable(state: &AppState, mode: Mode) -> anyhow::Result<()> {
    match &mode {
        Mode::Quick => {
            db::set_setting(&state.db, MODE_KEY, "quick").await?;
        }
        Mode::Named { token, hostname } => {
            db::set_setting(&state.db, MODE_KEY, "named").await?;
            db::set_setting(&state.db, TOKEN_KEY, token).await?;
            match hostname {
                Some(h) => db::set_setting(&state.db, HOSTNAME_KEY, h).await?,
                None => {
                    sqlx::query("DELETE FROM settings WHERE key = ?")
                        .bind(HOSTNAME_KEY)
                        .execute(&state.db)
                        .await?;
                }
            }
        }
    }
    start(state, mode);
    Ok(())
}

pub async fn disable(state: &AppState) -> anyhow::Result<()> {
    sqlx::query("DELETE FROM settings WHERE key IN (?, ?, ?)")
        .bind(MODE_KEY)
        .bind(TOKEN_KEY)
        .bind(HOSTNAME_KEY)
        .execute(&state.db)
        .await?;
    state.tunnel.update(|i| {
        if let Some(stop) = i.stop.take() {
            stop.cancel();
        }
        *i = Inner::default();
    });
    tracing::info!("tunnel disabled");
    Ok(())
}

fn start(state: &AppState, mode: Mode) {
    let stop = CancellationToken::new();
    state.tunnel.update(|i| {
        if let Some(old) = i.stop.replace(stop.clone()) {
            old.cancel();
        }
        i.public_url = match &mode {
            Mode::Named {
                hostname: Some(h), ..
            } => Some(format!("https://{h}")),
            _ => None,
        };
        i.mode = Some(mode.clone());
        i.connected = false;
        i.last_error = None;
    });
    let tunnel = state.tunnel.clone();
    let cloudflared = state.cfg.cloudflared.clone();
    let port = state.cfg.bind.port();
    tokio::spawn(supervise(tunnel, cloudflared, port, mode, stop));
}

/// Runs cloudflared until stopped, restarting it with backoff when it exits.
async fn supervise(
    tunnel: Arc<Tunnel>,
    cloudflared: String,
    port: u16,
    mode: Mode,
    stop: CancellationToken,
) {
    let origin = format!("http://127.0.0.1:{port}");
    let mut backoff = Duration::from_secs(2);
    while !stop.is_cancelled() {
        let mut cmd = Command::new(&cloudflared);
        cmd.args(["tunnel", "--no-autoupdate"]);
        match &mode {
            Mode::Quick => {
                cmd.args(["--url", &origin]);
            }
            // The token goes in the environment so it does not show up in `ps`.
            Mode::Named { token, .. } => {
                cmd.arg("run").env("TUNNEL_TOKEN", token);
            }
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        match cmd.spawn() {
            Ok(mut child) => {
                let kind = if matches!(mode, Mode::Quick) {
                    "quick"
                } else {
                    "named"
                };
                tracing::info!(mode = kind, "cloudflared started");
                let stderr = child.stderr.take().expect("piped");
                let t = tunnel.clone();
                let watch_output = async move {
                    let mut lines = BufReader::new(stderr).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        tracing::debug!(target: "the_ark::cloudflared", "{line}");
                        if let Some(url) = quick_tunnel_url(&line) {
                            tracing::info!("tunnel public URL: {url}");
                            t.update(|i| i.public_url = Some(url));
                        }
                        if line.contains("Registered tunnel connection") {
                            t.update(|i| {
                                i.connected = true;
                                i.last_error = None;
                            });
                        }
                        if line.contains(" ERR ") {
                            let msg = line
                                .split(" ERR ")
                                .nth(1)
                                .unwrap_or(&line)
                                .trim()
                                .to_string();
                            t.update(|i| i.last_error = Some(msg));
                        }
                    }
                };
                tokio::select! {
                    status = async { tokio::join!(child.wait(), watch_output).0 } => {
                        let msg = format!("cloudflared exited ({})", status.map(|s| s.to_string()).unwrap_or_else(|e| e.to_string()));
                        tracing::warn!("{msg}; restarting in {}s", backoff.as_secs());
                        tunnel.update(|i| {
                            i.connected = false;
                            i.last_error.get_or_insert(msg);
                            if matches!(mode, Mode::Quick) {
                                i.public_url = None;
                            }
                        });
                    }
                    // kill_on_drop stops cloudflared when `child` goes out of scope.
                    _ = stop.cancelled() => return,
                }
            }
            Err(e) => {
                let msg = if e.kind() == std::io::ErrorKind::NotFound {
                    format!("{cloudflared} not found (install cloudflared or set ARK_CLOUDFLARED)")
                } else {
                    format!("starting cloudflared: {e}")
                };
                tracing::error!("{msg}");
                tunnel.update(|i| i.last_error = Some(msg));
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = stop.cancelled() => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// The `https://<words>.trycloudflare.com` URL cloudflared prints for a quick tunnel.
fn quick_tunnel_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let url: String = line[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-'))
        .collect();
    url.ends_with(".trycloudflare.com").then_some(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quick_url() {
        let line = "2026-10-26T10:00:00Z INF |  https://brave-lion-sunday.trycloudflare.com                    |";
        assert_eq!(
            quick_tunnel_url(line).as_deref(),
            Some("https://brave-lion-sunday.trycloudflare.com")
        );
        assert_eq!(
            quick_tunnel_url("INF Requesting new quick Tunnel on trycloudflare.com..."),
            None
        );
        assert_eq!(
            quick_tunnel_url("INF see https://developers.cloudflare.com/docs"),
            None
        );
    }
}
