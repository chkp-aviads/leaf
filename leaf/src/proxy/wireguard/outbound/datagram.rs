use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use tracing::trace;
use wg_netstack::registry::Live;

use crate::{proxy::*, session::Session};

use super::stream::{resolve_destination, Handler as StreamHandler};

pub struct Handler {
    pub control_key: String,
}

#[async_trait]
impl OutboundDatagramHandler for Handler {
    fn connect_addr(&self) -> OutboundConnect {
        OutboundConnect::Unknown
    }

    fn transport_type(&self) -> DatagramTransportType {
        DatagramTransportType::Unreliable
    }

    async fn handle<'a>(
        &'a self,
        _sess: &'a Session,
        _transport: Option<AnyOutboundTransport>,
    ) -> io::Result<AnyOutboundDatagram> {
        let live = StreamHandler {
            control_key: self.control_key.clone(),
        }
        .live()
        .await?;
        let socket = live.stack.bind_udp().await?;
        Ok(Box::new(Datagram {
            socket: Arc::new(socket),
            live,
            // Shared so the recv half can report the address the caller
            // actually asked for, rather than what DNS turned it into.
            origins: Arc::new(Mutex::new(HashMap::new())),
        }))
    }
}

/// A UDP socket living inside the tunnel.
///
/// `origins` maps a resolved `SocketAddr` back to the `SocksAddr` the caller
/// sent to. Without it, a client that sent to a domain would see replies
/// reported as coming from an IP it never named — which breaks SOCKS5 UDP
/// clients that match replies against the address they used. leaf's own
/// `DomainAssociatedOutboundDatagram` preserves the original address the same way.
struct Datagram {
    socket: Arc<tokio_smoltcp::UdpSocket>,
    live: Arc<Live>,
    origins: Arc<Mutex<HashMap<SocketAddr, SocksAddr>>>,
}

impl OutboundDatagram for Datagram {
    fn split(
        self: Box<Self>,
    ) -> (
        Box<dyn OutboundDatagramRecvHalf>,
        Box<dyn OutboundDatagramSendHalf>,
    ) {
        (
            Box::new(RecvHalf {
                socket: Arc::clone(&self.socket),
                origins: Arc::clone(&self.origins),
            }),
            Box::new(SendHalf {
                socket: self.socket,
                live: self.live,
                origins: self.origins,
                resolved: HashMap::new(),
            }),
        )
    }
}

struct RecvHalf {
    socket: Arc<tokio_smoltcp::UdpSocket>,
    origins: Arc<Mutex<HashMap<SocketAddr, SocksAddr>>>,
}

#[async_trait]
impl OutboundDatagramRecvHalf for RecvHalf {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocksAddr)> {
        let (n, from) = self.socket.recv_from(buf).await?;
        let addr = self
            .origins
            .lock()
            .get(&from)
            .cloned()
            .unwrap_or_else(|| SocksAddr::from(from));
        Ok((n, addr))
    }
}

struct SendHalf {
    socket: Arc<tokio_smoltcp::UdpSocket>,
    live: Arc<Live>,
    origins: Arc<Mutex<HashMap<SocketAddr, SocksAddr>>>,
    /// Per-session domain cache, so a chatty UDP flow to a domain does not
    /// re-query DNS on every datagram. Bounded by the destinations one session
    /// actually talks to, and dropped with the session.
    resolved: HashMap<String, SocketAddr>,
}

#[async_trait]
impl OutboundDatagramSendHalf for SendHalf {
    async fn send_to(&mut self, buf: &[u8], dst_addr: &SocksAddr) -> io::Result<usize> {
        let key = format!("{}:{}", dst_addr.host(), dst_addr.port());
        let target = match self.resolved.get(&key) {
            Some(addr) => *addr,
            None => {
                let addr = resolve_destination(&self.live, dst_addr).await?;
                self.resolved.insert(key, addr);
                self.origins.lock().insert(addr, dst_addr.clone());
                trace!(%addr, "udp destination resolved in-tunnel");
                addr
            }
        };
        self.socket.send_to(buf, target).await
    }

    async fn close(&mut self) -> io::Result<()> {
        // The smoltcp socket is released when the last Arc drops, which happens
        // as soon as leaf drops both halves.
        Ok(())
    }
}
