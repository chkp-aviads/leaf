use std::io;
use std::net::SocketAddr;

use async_trait::async_trait;
use tracing::{debug, trace};
use wg_netstack::registry::{self, Live};

use crate::{proxy::*, session::Session};

pub struct Handler {
    /// Identifies the tunnel in `wg_netstack::registry`. Set by
    /// `settings.controlKey` in the leaf config.
    pub control_key: String,
}

impl Handler {
    pub(super) async fn live(&self) -> io::Result<std::sync::Arc<Live>> {
        registry::slot(&self.control_key)
            .live()
            .await
            .map_err(|e| io::Error::other(format!("wireguard tunnel unavailable: {e}")))
    }
}

/// Resolve a session destination to an address inside the tunnel.
///
/// A domain arrives here unresolved — `connect_addr()` returns
/// `OutboundConnect::Unknown`, so leaf's dispatcher never dials or resolves on
/// our behalf — and is resolved over the tunnel's own DNS servers. That matches
/// wireproxy, whose SOCKS5 `NameResolver` was the tunnel itself, and it matters:
/// resolving outside the tunnel would leak the query and can return an answer
/// that is only correct on the far side.
pub(super) async fn resolve_destination(
    live: &Live,
    destination: &crate::session::SocksAddr,
) -> io::Result<SocketAddr> {
    if let Some(ip) = destination.ip() {
        return Ok(SocketAddr::new(ip, destination.port()));
    }
    let host = destination.host();
    let servers = live.tunnel.dns_servers();
    let want_v4 = live.stack.source_address().is_ipv4();

    let records = wg_netstack::resolve::resolve(&live.stack, servers, &host, want_v4)
        .await
        .map_err(|e| io::Error::other(format!("in-tunnel DNS for {host} failed: {e}")))?;

    let record = records.first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("in-tunnel DNS returned no records for {host}"),
        )
    })?;
    trace!(%host, ip = %record.ip, "resolved in-tunnel");
    Ok(SocketAddr::new(record.ip, destination.port()))
}

#[async_trait]
impl OutboundStreamHandler for Handler {
    /// `Unknown` means "do not dial anything for me". It is also what keeps a
    /// domain destination unresolved until it reaches `handle` — see
    /// `connect_stream_outbound` in `proxy/mod.rs`.
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    async fn handle<'a>(
        &'a self,
        sess: &'a Session,
        _lhs: Option<&mut AnyStream>,
        _stream: Option<AnyStream>,
    ) -> io::Result<AnyStream> {
        let live = self.live().await?;
        let target = resolve_destination(&live, &sess.destination).await?;
        debug!(%target, "dialing through wireguard");
        let stream = live.stack.connect_tcp(target).await?;
        Ok(Box::new(stream))
    }
}
