//! Local DNS server for phones that don't resolve mDNS (older Android). The router's
//! DHCP hands out this host as DNS; we answer `<hostname>` and `<hostname>.local` with
//! the host's address on the client's network (TTL 30 s) and forward everything else.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::Context;
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{RData, Record, RecordType, rdata::A},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

use crate::{config::Config, discovery};

const TTL: u32 = 30;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(3);
const FALLBACK_UPSTREAM: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);

struct Resolver {
    /// Lowercase, without trailing dot.
    names: [String; 2],
    upstream: SocketAddr,
}

pub fn spawn(cfg: Arc<Config>) {
    if !cfg.dns {
        return;
    }
    tokio::spawn(async move {
        if let Err(e) = run(&cfg).await {
            tracing::error!(
                "local DNS stopped: {e:#} (port 53 needs admin rights / CAP_NET_BIND_SERVICE)"
            );
        }
    });
}

async fn run(cfg: &Config) -> anyhow::Result<()> {
    let host = cfg.hostname.to_ascii_lowercase();
    let upstream = cfg.dns_upstream.unwrap_or_else(system_upstream);
    let resolver = Arc::new(Resolver {
        names: [host.clone(), format!("{host}.local")],
        upstream,
    });
    let udp = Arc::new(
        UdpSocket::bind(cfg.dns_bind)
            .await
            .with_context(|| format!("binding UDP {}", cfg.dns_bind))?,
    );
    let tcp = TcpListener::bind(cfg.dns_bind)
        .await
        .with_context(|| format!("binding TCP {}", cfg.dns_bind))?;
    tracing::info!(bind = %cfg.dns_bind, %upstream, "local DNS answering {host} and {host}.local");

    let tcp_resolver = resolver.clone();
    tokio::spawn(async move {
        loop {
            match tcp.accept().await {
                Ok((stream, peer)) => {
                    let r = tcp_resolver.clone();
                    tokio::spawn(async move {
                        if let Err(e) = serve_tcp(stream, peer, &r).await {
                            tracing::debug!(%peer, error = %e, "DNS TCP");
                        }
                    });
                }
                Err(e) => tracing::warn!(error = %e, "DNS TCP accept"),
            }
        }
    });

    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = udp.recv_from(&mut buf).await?;
        let packet = buf[..n].to_vec();
        let (udp, r) = (udp.clone(), resolver.clone());
        tokio::spawn(async move {
            if let Some(resp) = r.handle(&packet, peer, false).await {
                let _ = udp.send_to(&resp, peer).await;
            }
        });
    }
}

/// DNS over TCP: messages prefixed by a 2-byte length.
async fn serve_tcp(mut stream: TcpStream, peer: SocketAddr, r: &Resolver) -> std::io::Result<()> {
    loop {
        let len = match tokio::time::timeout(Duration::from_secs(10), stream.read_u16()).await {
            Ok(Ok(len)) => len as usize,
            _ => return Ok(()),
        };
        let mut packet = vec![0u8; len];
        stream.read_exact(&mut packet).await?;
        if let Some(resp) = r.handle(&packet, peer, true).await {
            stream.write_u16(resp.len() as u16).await?;
            stream.write_all(&resp).await?;
        }
    }
}

impl Resolver {
    async fn handle(&self, packet: &[u8], peer: SocketAddr, tcp: bool) -> Option<Vec<u8>> {
        let msg = Message::from_vec(packet).ok()?;
        if let Some(answer) = self.local_answer(&msg, peer) {
            return answer.to_vec().ok();
        }
        let forwarded = if tcp {
            forward_tcp(packet, self.upstream).await
        } else {
            forward_udp(packet, self.upstream, msg.metadata.id).await
        };
        match forwarded {
            Ok(resp) => Some(resp),
            Err(e) => {
                tracing::debug!(error = %e, upstream = %self.upstream, "DNS forward failed");
                let mut fail = Message::error_msg(
                    msg.metadata.id,
                    msg.metadata.op_code,
                    ResponseCode::ServFail,
                );
                fail.metadata.recursion_desired = msg.metadata.recursion_desired;
                fail.metadata.recursion_available = true;
                fail.queries = msg.queries.clone();
                fail.to_vec().ok()
            }
        }
    }

    /// Our own names: an A record (or an empty NOERROR for other types).
    fn local_answer(&self, msg: &Message, peer: SocketAddr) -> Option<Message> {
        if msg.metadata.message_type != MessageType::Query
            || msg.metadata.op_code != OpCode::Query
            || msg.queries.len() != 1
        {
            return None;
        }
        let query = &msg.queries[0];
        let name = query.name().to_ascii().to_ascii_lowercase();
        if !self.names.iter().any(|n| n == name.trim_end_matches('.')) {
            return None;
        }

        let mut resp = Message::response(msg.metadata.id, OpCode::Query);
        resp.metadata.authoritative = true;
        resp.metadata.recursion_desired = msg.metadata.recursion_desired;
        resp.metadata.recursion_available = true;
        resp.add_query(query.clone());
        if query.query_type() == RecordType::A
            && let Some(ip) = address_for(peer)
        {
            resp.add_answer(Record::from_rdata(
                query.name().clone(),
                TTL,
                RData::A(A(ip)),
            ));
        }
        Some(resp)
    }
}

/// The host's IPv4 address on the route to `peer`: the address the phone can reach.
fn address_for(peer: SocketAddr) -> Option<Ipv4Addr> {
    let routed = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| s.connect(peer).map(|()| s))
        .and_then(|s| s.local_addr())
        .ok()
        .and_then(|a| match a.ip() {
            IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(ip),
            _ => None,
        });
    // Queries from this machine itself: hand out its LAN address, not 127.0.0.1.
    routed.or_else(|| {
        discovery::lan_ipv4s().into_iter().find_map(|ip| match ip {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
    })
}

async fn forward_udp(packet: &[u8], upstream: SocketAddr, id: u16) -> anyhow::Result<Vec<u8>> {
    let sock = UdpSocket::bind(if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    sock.connect(upstream).await?;
    sock.send(packet).await?;
    let mut buf = vec![0u8; 4096];
    let deadline = tokio::time::Instant::now() + UPSTREAM_TIMEOUT;
    loop {
        let n = tokio::time::timeout_at(deadline, sock.recv(&mut buf))
            .await
            .context("upstream timeout")??;
        // Ignore stray datagrams that are not the answer to this query.
        if n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn forward_tcp(packet: &[u8], upstream: SocketAddr) -> anyhow::Result<Vec<u8>> {
    tokio::time::timeout(UPSTREAM_TIMEOUT, async {
        let mut s = TcpStream::connect(upstream).await?;
        s.write_u16(packet.len() as u16).await?;
        s.write_all(packet).await?;
        let len = s.read_u16().await? as usize;
        let mut resp = vec![0u8; len];
        s.read_exact(&mut resp).await?;
        anyhow::Ok(resp)
    })
    .await
    .context("upstream timeout")?
}

/// First `nameserver` in /etc/resolv.conf that is not this host (which would loop),
/// else 1.1.1.1.
fn system_upstream() -> SocketAddr {
    let own = discovery::lan_ipv4s();
    std::fs::read_to_string("/etc/resolv.conf")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| l.trim().strip_prefix("nameserver"))
        .filter_map(|ip| ip.trim().parse::<IpAddr>().ok())
        .find(|ip| !own.contains(ip) && *ip != IpAddr::V4(Ipv4Addr::LOCALHOST))
        .map(|ip| SocketAddr::new(ip, 53))
        .unwrap_or(FALLBACK_UPSTREAM)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::Name};
    use std::str::FromStr;

    fn query(name: &str, rtype: RecordType) -> Message {
        let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(Name::from_str(name).unwrap(), rtype));
        m
    }

    fn resolver() -> Resolver {
        Resolver {
            names: ["ark".into(), "ark.local".into()],
            upstream: FALLBACK_UPSTREAM,
        }
    }

    #[test]
    fn answers_own_names_only() {
        let r = resolver();
        let peer: SocketAddr = "192.0.2.10:5353".parse().unwrap();
        for name in ["ark.local.", "ARK.Local", "ark."] {
            let resp = r
                .local_answer(&query(name, RecordType::A), peer)
                .expect(name);
            assert_eq!(resp.metadata.id, 4242);
            assert!(resp.metadata.authoritative);
            assert_eq!(resp.metadata.response_code, ResponseCode::NoError);
            for rec in &resp.answers {
                assert_eq!(rec.ttl, TTL);
            }
        }
        // AAAA for our name: NOERROR with no answers, so clients fall back to A.
        let resp = r
            .local_answer(&query("ark.local.", RecordType::AAAA), peer)
            .unwrap();
        assert!(resp.answers.is_empty());
        assert!(
            r.local_answer(&query("example.com.", RecordType::A), peer)
                .is_none()
        );
        assert!(
            r.local_answer(&query("ark.local.evil.com.", RecordType::A), peer)
                .is_none()
        );
    }
}
