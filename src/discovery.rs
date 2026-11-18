//! mDNS: announces `<hostname>.local` and an `_http._tcp` service named "Ark" on every
//! LAN IPv4 address, re-announcing within 10 s when the addresses change.
//!
//! It also re-announces every 30 s while nothing changes. Some Android phones (seen on
//! a Pixel over a phone hotspot) never use the unicast reply to their own `ark.local`
//! lookup and only resolve the name from multicast answers they overhear. Without the
//! periodic announcement, `ark.local` worked on them only right after another device
//! (an iPhone) had looked it up, and stopped again after the hotspot restarted. The
//! host record's TTL is 120 s, so a 30 s announcement keeps their cache warm.

use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use mdns_sd::{ServiceDaemon, ServiceInfo};

use crate::config::Config;

const SERVICE_TYPE: &str = "_http._tcp.local.";
const INSTANCE: &str = "Ark";
const WATCH_EVERY: Duration = Duration::from_secs(10);
const REANNOUNCE_EVERY: Duration = Duration::from_secs(30);

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
        // The registered service and when it was last announced.
        let mut current: Option<(ServiceInfo, Instant)> = None;
        let mut tick = tokio::time::interval(WATCH_EVERY);
        loop {
            tick.tick().await;
            let ips = lan_ipv4s();
            if ips == announced {
                // Same addresses: refresh the announcement so phones that only learn
                // from multicast keep resolving the name. `register` on an already
                // registered service re-announces it without a goodbye.
                if let Some((info, last)) = current.as_mut()
                    && last.elapsed() >= REANNOUNCE_EVERY
                {
                    if let Err(e) = daemon.register(info.clone()) {
                        tracing::warn!(error = %e, "mDNS re-announce");
                    }
                    *last = Instant::now();
                }
                continue;
            }
            if let Some((info, _)) = current.take()
                && let Err(e) = daemon.unregister(info.get_fullname())
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
                .and_then(|info| daemon.register(info.clone()).map(|()| info))
                {
                    Ok(info) => {
                        tracing::info!(addrs = ?ips, "announcing http://{}", host.trim_end_matches('.'));
                        current = Some((info, Instant::now()));
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
