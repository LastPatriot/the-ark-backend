use std::{net::SocketAddr, path::PathBuf};

use anyhow::Context;
use serde::Deserialize;

/// Runtime configuration. Precedence: `ARK_*` env vars, then `ark.toml`, then defaults.
#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub data_dir: PathBuf,
    pub hostname: String,
    pub session_hours: i64,
    /// Base64 (standard) encoding of at least 64 bytes. Generated and stored in the DB when unset.
    pub cookie_key: Option<String>,
    pub max_chunk_mb: u64,
    pub docs: bool,
}

/// Mirrors `Config`; every key optional. Keys are the env names without `ARK_`, lowercased.
#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    bind: Option<String>,
    data_dir: Option<PathBuf>,
    hostname: Option<String>,
    session_hours: Option<i64>,
    cookie_key: Option<String>,
    max_chunk_mb: Option<u64>,
    docs: Option<bool>,
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = std::env::var("ARK_CONFIG").unwrap_or_else(|_| "ark.toml".into());
        let file: FileConfig = match std::fs::read_to_string(&path) {
            Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {path}"))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => FileConfig::default(),
            Err(e) => return Err(e).with_context(|| format!("reading {path}")),
        };

        let env = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());

        let bind = env("ARK_BIND")
            .or(file.bind)
            .unwrap_or_else(|| "0.0.0.0:80".into());
        let bind = bind
            .parse()
            .with_context(|| format!("ARK_BIND {bind:?} is not an address"))?;

        Ok(Self {
            bind,
            data_dir: env("ARK_DATA_DIR")
                .map(PathBuf::from)
                .or(file.data_dir)
                .unwrap_or_else(|| "./ark-data".into()),
            hostname: env("ARK_HOSTNAME")
                .or(file.hostname)
                .unwrap_or_else(|| "ark".into()),
            session_hours: parse_env("ARK_SESSION_HOURS")?
                .or(file.session_hours)
                .unwrap_or(12),
            cookie_key: env("ARK_COOKIE_KEY").or(file.cookie_key),
            max_chunk_mb: parse_env("ARK_MAX_CHUNK_MB")?
                .or(file.max_chunk_mb)
                .unwrap_or(16),
            docs: parse_env("ARK_DOCS")?.or(file.docs).unwrap_or(true),
        })
    }

    pub fn max_chunk_bytes(&self) -> u64 {
        self.max_chunk_mb * 1024 * 1024
    }
}

fn parse_env<T: std::str::FromStr>(key: &str) -> anyhow::Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => v
            .parse()
            .map(Some)
            .map_err(|e| anyhow::anyhow!("{key}={v:?}: {e}")),
        _ => Ok(None),
    }
}
