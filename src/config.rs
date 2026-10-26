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
    /// Run the local DNS server (answers `<hostname>` and `<hostname>.local`).
    pub dns: bool,
    pub dns_bind: SocketAddr,
    /// Resolver for every other name. Defaults to the first usable `nameserver` in
    /// /etc/resolv.conf, else 1.1.1.1. Set it to the router's IP on the demo network.
    pub dns_upstream: Option<SocketAddr>,
    /// ffmpeg binary for video posters and HLS previews.
    pub ffmpeg: String,
    /// Transcode videos to 720p HLS. Posters are made either way. Turn off on slow hosts.
    pub hls: bool,
    /// rclone destination for cloud backup, e.g. `b2:ark-backup/church`. Unset = no sync.
    pub sync_remote: Option<String>,
    pub rclone: String,
    /// `host:port` probed (TCP) to decide whether the internet is reachable.
    pub sync_check: String,
    pub cloudflared: String,
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
    dns: Option<bool>,
    dns_bind: Option<String>,
    dns_upstream: Option<String>,
    ffmpeg: Option<String>,
    hls: Option<bool>,
    sync_remote: Option<String>,
    rclone: Option<String>,
    sync_check: Option<String>,
    cloudflared: Option<String>,
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
        let dns_bind = env("ARK_DNS_BIND")
            .or(file.dns_bind)
            .unwrap_or_else(|| "0.0.0.0:53".into());
        let dns_bind = dns_bind
            .parse()
            .with_context(|| format!("ARK_DNS_BIND {dns_bind:?} is not an address"))?;
        let dns_upstream = env("ARK_DNS_UPSTREAM")
            .or(file.dns_upstream)
            .map(|s| parse_resolver(&s))
            .transpose()?;

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
            dns: parse_env("ARK_DNS")?.or(file.dns).unwrap_or(false),
            dns_bind,
            dns_upstream,
            ffmpeg: env("ARK_FFMPEG")
                .or(file.ffmpeg)
                .unwrap_or_else(|| "ffmpeg".into()),
            hls: parse_env("ARK_HLS")?.or(file.hls).unwrap_or(true),
            sync_remote: env("ARK_SYNC_REMOTE").or(file.sync_remote),
            rclone: env("ARK_RCLONE")
                .or(file.rclone)
                .unwrap_or_else(|| "rclone".into()),
            sync_check: env("ARK_SYNC_CHECK")
                .or(file.sync_check)
                .unwrap_or_else(|| "1.1.1.1:443".into()),
            cloudflared: env("ARK_CLOUDFLARED")
                .or(file.cloudflared)
                .unwrap_or_else(|| "cloudflared".into()),
        })
    }

    /// Defaults with everything under `data_dir`, for tests.
    #[cfg(test)]
    pub fn for_tests(data_dir: PathBuf) -> Self {
        Self {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir,
            hostname: "ark".into(),
            session_hours: 1,
            cookie_key: None,
            max_chunk_mb: 1,
            docs: false,
            dns: false,
            dns_bind: "127.0.0.1:0".parse().unwrap(),
            dns_upstream: None,
            ffmpeg: "ffmpeg".into(),
            hls: false,
            sync_remote: None,
            rclone: "rclone".into(),
            sync_check: "127.0.0.1:9".into(),
            cloudflared: "cloudflared".into(),
        }
    }

    pub fn max_chunk_bytes(&self) -> u64 {
        self.max_chunk_mb * 1024 * 1024
    }
}

/// `1.2.3.4` or `1.2.3.4:53`.
pub fn parse_resolver(s: &str) -> anyhow::Result<SocketAddr> {
    let s = s.trim();
    s.parse::<SocketAddr>()
        .or_else(|_| {
            s.parse::<std::net::IpAddr>()
                .map(|ip| SocketAddr::new(ip, 53))
        })
        .map_err(|_| anyhow::anyhow!("{s:?} is not a resolver address"))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The file deploy/windows/install.ps1 writes.
    #[test]
    fn windows_install_config_parses() {
        let text = r#"
# Ark configuration.
bind = "0.0.0.0:80"
data_dir = 'C:\ProgramData\Ark\data'
hostname = "ark"
session_hours = 12
docs = true
dns = true
dns_bind = "0.0.0.0:53"
# dns_upstream = "192.168.1.1"  # the router
"#;
        let f: FileConfig = toml::from_str(text).unwrap();
        assert_eq!(
            f.data_dir.unwrap(),
            PathBuf::from(r"C:\ProgramData\Ark\data")
        );
        assert_eq!(f.dns, Some(true));
        assert!(f.dns_upstream.is_none());
    }

    #[test]
    fn resolvers() {
        assert_eq!(
            parse_resolver("192.168.1.1").unwrap().to_string(),
            "192.168.1.1:53"
        );
        assert_eq!(
            parse_resolver(" 10.0.0.1:5353 ").unwrap().to_string(),
            "10.0.0.1:5353"
        );
        assert!(parse_resolver("router.lan").is_err());
    }
}
