//! mDNS: announces `<hostname>.local` and an `_http._tcp` service named "Ark" on every
//! LAN IPv4 address, re-announcing within 10 s when the addresses change.

use std::{net::IpAddr, sync::Arc, time::Duration};

use mdns_sd::{ServiceDaemon, ServiceInfo};

use crate::config::Config;

const SERVICE_TYPE: &str = "_http._tcp.local.";
const INSTANCE: &str = "Ark";
const WATCH_EVERY: Duration = Duration::from_secs(10);

pub fn spawn(cfg: Arc<Config>) {
    if cfg.bind.ip().is_loopback() {
        tracing::info!("bound to loopback; mDNS announce disabled");
        return;
    }
    tokio::spawn(async move {
        let daemon = match ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "mDNS unavailable; use the host IP instead of {}.local", cfg.hostname);
                return;
            }
        };
        let host = format!("{}.local.", cfg.hostname);
        let mut announced: Vec<IpAddr> = Vec::new();
        let mut fullname: Option<String> = None;
        let mut tick = tokio::time::interval(WATCH_EVERY);
        loop {
            tick.tick().await;
            let ips = lan_ipv4s();
            if ips == announced {
                continue;
            }
            if let Some(name) = fullname.take()
                && let Err(e) = daemon.unregister(&name)
            {
                tracing::warn!(error = %e, "mDNS unregister");
            }
            if !ips.is_empty() {
                let props: &[(&str, &str)] = &[("path", "/")];
                match ServiceInfo::new(
                    SERVICE_TYPE,
                    INSTANCE,
                    &host,
                    &ips[..],
                    cfg.bind.port(),
                    props,
                )
                .and_then(|info| {
                    let name = info.get_fullname().to_string();
                    daemon.register(info).map(|()| name)
                }) {
                    Ok(name) => {
                        tracing::info!(addrs = ?ips, "announcing http://{}", host.trim_end_matches('.'));
                        fullname = Some(name);
                    }
                    Err(e) => tracing::error!(error = %e, "mDNS register"),
                }
            } else {
                tracing::warn!("no LAN IPv4 address; mDNS announce paused");
            }
            announced = ips;
        }
    });
}

/// Non-loopback, non-link-local IPv4 addresses of interfaces that are up, sorted.
pub fn lan_ipv4s() -> Vec<IpAddr> {
    let mut ips: Vec<IpAddr> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i.is_oper_up() && !i.is_loopback() && !i.is_link_local() && i.ip().is_ipv4())
        .map(|i| i.ip())
        .collect();
    ips.sort();
    ips.dedup();
    ips
}
