//! The WireGuard tunnel: a boringtun Noise state machine bolted to a UDP
//! socket, exposed to the TCP/IP stack as a `tokio_smoltcp::device::AsyncDevice`.
//!
//! Three tasks run per tunnel:
//!
//! * **rx** — read UDP, `decapsulate`, hand IP packets to the stack
//! * **tx** — take IP packets from the stack, `encapsulate`, write UDP
//! * **timers** — drive `update_timers` so rekeys and keepalives happen
//!
//! The `Tunn` mutex is never held across an `await`. Each task takes it, does
//! the crypto into a local buffer, releases it, and only then does I/O.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{Sink, Stream};
use parking_lot::Mutex;
use smoltcp::phy::{DeviceCapabilities, Medium};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::PollSender;
use tracing::{debug, trace, warn};

use crate::config::{WgConfig, MAX_MTU};

/// Every buffer handed to boringtun is this size.
///
/// Both boringtun panic sites are bounded by it:
/// * `encapsulate` needs `src.len() + 32`, and `src` is an IP packet from
///   smoltcp, capped at `MAX_MTU` (1500) by config validation.
/// * `decapsulate` needs `ct_len`, which is derived from the datagram we read
///   off the socket — so a buffer at least as large as the recv buffer is
///   always sufficient. Both use this same constant, which is the invariant.
///
/// Rounded up to 2 KiB rather than the tight 1532 so there is no arithmetic to
/// get wrong at a call site.
pub const MAX_DATAGRAM: usize = 2048;

/// How often `update_timers` runs. Matches boringtun's own device loop; the
/// shortest WireGuard timer (REKEY_TIMEOUT) is 5 s, so this is ample.
const TIMER_TICK: Duration = Duration::from_millis(250);

/// Bounded queues in both directions. IP is a lossy medium, so a full inbound
/// queue drops packets exactly as a full NIC ring would.
///
/// Coupled to the TCP buffer sizes in `stack.rs`: a receive window larger than
/// this many packets outruns the ring, and the resulting drops make TCP back off
/// -- measurably *reducing* throughput. Measured: 64 KiB buffers on a 32-packet
/// ring lost throughput and dropped packets; the same buffers on a 256-packet
/// ring nearly doubled it with no drops.
///
/// Costs `QUEUE_DEPTH * MTU` per tunnel (~384 KiB here), paid once, which is
/// cheap next to per-connection buffers. See the table in `stack.rs`.
const QUEUE_DEPTH: usize = 256;

pub type Packet = Vec<u8>;

#[derive(Debug, thiserror::Error)]
pub enum TunnelError {
    #[error("config has no [Interface] Address, so the tunnel has no source address to dial from")]
    NoInterfaceAddress,
    #[error("config has no [Peer] Endpoint to connect to")]
    NoEndpoint,
    #[error("endpoint {0:?} did not resolve to any address")]
    EndpointUnresolved(String),
    #[error("endpoint {0:?} is not a valid host:port: {1}")]
    EndpointMalformed(String, String),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelState {
    Down = 0,
    Handshaking = 1,
    Up = 2,
}

#[derive(Debug, Clone)]
pub struct TunnelStatus {
    pub state: TunnelState,
    pub last_handshake: Option<Duration>,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub dropped_inbound: u64,
}

#[derive(Debug, Default)]
struct Counters {
    dropped_inbound: AtomicU64,
}

pub struct WgTunnel {
    tunn: Mutex<Tunn>,
    socket: UdpSocket,
    peer: SocketAddr,
    /// The interface addresses from `[Interface] Address`, in config order.
    addresses: Vec<IpAddr>,
    /// `[Interface] DNS`, used by `resolve.rs`.
    dns: Vec<IpAddr>,
    mtu: u16,
    counters: Counters,
}

/// What `decapsulate` produced, with the borrow on the output buffer already
/// released so the buffer can be moved.
enum Decapsulated {
    Done,
    ToNetwork(usize),
    ToTunnel(usize),
    Failed(String),
}

impl WgTunnel {
    /// Resolve the peer endpoint, bind a socket of the matching family and
    /// build the Noise state machine. Does not start the tasks.
    pub async fn connect(cfg: &WgConfig) -> Result<(Arc<Self>, WgDevice, Vec<JoinHandle<()>>), TunnelError> {
        if cfg.addresses.is_empty() {
            // wireproxy tolerates this and produces a tunnel that silently
            // cannot source packets. Fail loudly instead.
            return Err(TunnelError::NoInterfaceAddress);
        }
        let peer_cfg = cfg.peers.first().ok_or(TunnelError::NoEndpoint)?;
        let endpoint = peer_cfg.endpoint.as_deref().ok_or(TunnelError::NoEndpoint)?;
        let peer = resolve_endpoint(endpoint).await?;

        // Bind to the same family as the peer, on an ephemeral port. `connect`
        // filters datagrams to the peer, which drops spoofed sources for free.
        // A standard WireGuard server replies from the port we dialled, so this
        // costs us no roaming support that we would otherwise have.
        let bind: SocketAddr = if peer.is_ipv4() {
            SocketAddr::from(([0u8, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = UdpSocket::bind(bind).await?;
        socket.connect(peer).await?;

        let tunn = Tunn::new(
            StaticSecret::from(cfg.private_key.0),
            PublicKey::from(peer_cfg.public_key.0),
            peer_cfg.preshared_key.as_ref().map(|k| k.0),
            // boringtun treats 0 as "no keepalive"; wireproxy's default is 0.
            (peer_cfg.persistent_keepalive != 0).then_some(peer_cfg.persistent_keepalive),
            0,
            None,
        );

        let tunnel = Arc::new(WgTunnel {
            tunn: Mutex::new(tunn),
            socket,
            peer,
            addresses: cfg.addresses.clone(),
            dns: cfg.dns.clone(),
            mtu: cfg.mtu,
            counters: Counters::default(),
        });

        // inbound: tunnel -> stack. outbound: stack -> tunnel.
        let (inbound_tx, inbound_rx) = mpsc::channel::<Packet>(QUEUE_DEPTH);
        let (outbound_tx, outbound_rx) = mpsc::channel::<Packet>(QUEUE_DEPTH);

        let device = WgDevice::new(inbound_rx, outbound_tx, cfg.mtu);
        let tasks = vec![
            tokio::spawn(rx_loop(Arc::clone(&tunnel), inbound_tx)),
            tokio::spawn(tx_loop(Arc::clone(&tunnel), outbound_rx)),
            tokio::spawn(timer_loop(Arc::clone(&tunnel))),
        ];

        // Handshake eagerly rather than waiting for the first packet, so status
        // reads as Up before any traffic is routed here.
        tunnel.begin_handshake(true).await;

        Ok((tunnel, device, tasks))
    }

    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    pub fn dns_servers(&self) -> &[IpAddr] {
        &self.dns
    }

    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn peer(&self) -> SocketAddr {
        self.peer
    }

    pub fn status(&self) -> TunnelStatus {
        let (since, tx, rx, _loss, _rtt) = self.tunn.lock().stats();
        // A live tunnel that has not completed a handshake is Handshaking, not
        // Down: `Down` means "no tunnel object at all" and is reported by the
        // registry, which is the only thing that can distinguish the two.
        let state = match since {
            Some(_) => TunnelState::Up,
            None => TunnelState::Handshaking,
        };
        TunnelStatus {
            state,
            last_handshake: since,
            tx_bytes: tx as u64,
            rx_bytes: rx as u64,
            dropped_inbound: self.counters.dropped_inbound.load(Ordering::Relaxed),
        }
    }

    /// Force a fresh handshake. Used on start and on wake: boringtun 0.7.1
    /// keeps its timers on `Instant`, which does not advance while the device
    /// sleeps, so after a resume we re-key rather than trusting its clock.
    pub async fn begin_handshake(&self, force: bool) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let out = {
            let mut tunn = self.tunn.lock();
            match tunn.format_handshake_initiation(&mut buf, force) {
                TunnResult::WriteToNetwork(pkt) => Some(pkt.len()),
                TunnResult::Done => None,
                TunnResult::Err(e) => {
                    warn!("handshake initiation failed: {e:?}");
                    None
                }
                _ => None,
            }
        };
        if let Some(n) = out {
            if let Some(datagram) = buf.get(..n) {
                if let Err(e) = self.socket.send(datagram).await {
                    warn!("sending handshake initiation failed: {e}");
                } else {
                    debug!(peer = %self.peer, "sent handshake initiation");
                }
            }
        }
    }

    /// Drive `decapsulate` to completion for one datagram.
    ///
    /// boringtun requires re-calling with an empty datagram until it reports
    /// `Done`; skipping that stalls the handshake.
    fn decapsulate_all(&self, datagram: &[u8]) -> (Vec<Packet>, Vec<Packet>) {
        let mut to_network = Vec::new();
        let mut to_tunnel = Vec::new();
        let mut tunn = self.tunn.lock();
        let mut input: &[u8] = datagram;
        loop {
            let mut out = vec![0u8; MAX_DATAGRAM];
            let result = match tunn.decapsulate(None, input, &mut out) {
                TunnResult::Done => Decapsulated::Done,
                TunnResult::Err(e) => Decapsulated::Failed(format!("{e:?}")),
                TunnResult::WriteToNetwork(pkt) => Decapsulated::ToNetwork(pkt.len()),
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    Decapsulated::ToTunnel(pkt.len())
                }
            };
            match result {
                Decapsulated::Done => break,
                Decapsulated::Failed(e) => {
                    trace!("decapsulate rejected a datagram: {e}");
                    break;
                }
                Decapsulated::ToNetwork(n) => {
                    out.truncate(n);
                    to_network.push(out);
                }
                Decapsulated::ToTunnel(n) => {
                    out.truncate(n);
                    to_tunnel.push(out);
                }
            }
            // Keep draining.
            input = &[];
        }
        (to_network, to_tunnel)
    }

    /// Encapsulate one IP packet. Returns the datagram to put on the wire, if any.
    fn encapsulate(&self, packet: &[u8]) -> Option<Packet> {
        // Invariant for the boringtun panic at noise/session.rs:198.
        debug_assert!(
            packet.len() + 32 <= MAX_DATAGRAM,
            "packet of {} exceeds the encapsulate buffer",
            packet.len()
        );
        if packet.len() + 32 > MAX_DATAGRAM {
            warn!(
                len = packet.len(),
                "dropping oversized packet rather than overflowing the encapsulate buffer"
            );
            return None;
        }
        let mut out = vec![0u8; MAX_DATAGRAM];
        let n = {
            let mut tunn = self.tunn.lock();
            match tunn.encapsulate(packet, &mut out) {
                TunnResult::WriteToNetwork(pkt) => pkt.len(),
                TunnResult::Done => return None,
                TunnResult::Err(e) => {
                    trace!("encapsulate failed: {e:?}");
                    return None;
                }
                _ => return None,
            }
        };
        out.truncate(n);
        Some(out)
    }
}

async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr, TunnelError> {
    // Resolved here, not at config-parse time, and re-resolved on wake. This is
    // the system resolver deliberately: the WireGuard server's address must be
    // reachable outside the tunnel.
    if let Ok(addr) = endpoint.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let mut addrs = tokio::net::lookup_host(endpoint).await.map_err(|e| {
        TunnelError::EndpointMalformed(endpoint.to_owned(), e.to_string())
    })?;
    addrs
        .next()
        .ok_or_else(|| TunnelError::EndpointUnresolved(endpoint.to_owned()))
}

async fn rx_loop(tunnel: Arc<WgTunnel>, to_stack: mpsc::Sender<Packet>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let n = match tunnel.socket.recv(&mut buf).await {
            Ok(n) => n,
            Err(e) => {
                warn!("wireguard socket recv failed: {e}");
                return;
            }
        };
        let Some(datagram) = buf.get(..n) else { continue };
        let (to_network, to_tunnel) = tunnel.decapsulate_all(datagram);

        for datagram in to_network {
            if let Err(e) = tunnel.socket.send(&datagram).await {
                warn!("wireguard socket send failed: {e}");
                return;
            }
        }
        for packet in to_tunnel {
            // A full queue means the stack is behind. Dropping is the correct
            // behaviour for an IP medium; TCP above will retransmit.
            if to_stack.try_send(packet).is_err() {
                tunnel.counters.dropped_inbound.fetch_add(1, Ordering::Relaxed);
                trace!("inbound queue full, dropped a packet");
            }
        }
    }
}

async fn tx_loop(tunnel: Arc<WgTunnel>, mut from_stack: mpsc::Receiver<Packet>) {
    while let Some(packet) = from_stack.recv().await {
        if let Some(datagram) = tunnel.encapsulate(&packet) {
            if let Err(e) = tunnel.socket.send(&datagram).await {
                warn!("wireguard socket send failed: {e}");
                return;
            }
        }
    }
}

async fn timer_loop(tunnel: Arc<WgTunnel>) {
    let mut ticker = tokio::time::interval(TIMER_TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        ticker.tick().await;
        let mut buf = vec![0u8; MAX_DATAGRAM];
        let n = {
            let mut tunn = tunnel.tunn.lock();
            match tunn.update_timers(&mut buf) {
                TunnResult::WriteToNetwork(pkt) => Some(pkt.len()),
                TunnResult::Done => None,
                TunnResult::Err(e) => {
                    // Notably WireGuardError::ConnectionExpired, which means we
                    // should re-handshake; boringtun does that on next traffic.
                    debug!("update_timers: {e:?}");
                    None
                }
                _ => None,
            }
        };
        if let Some(n) = n {
            if let Some(datagram) = buf.get(..n) {
                if let Err(e) = tunnel.socket.send(datagram).await {
                    warn!("wireguard socket send failed: {e}");
                    return;
                }
            }
        }
    }
}

/// The `smoltcp` device backing the in-tunnel TCP/IP stack.
///
/// `tokio_smoltcp::device::AsyncDevice` is exactly `Stream<Item = io::Result<Vec<u8>>>`
/// plus `Sink<Vec<u8>>`, which is the shape a WireGuard tunnel already has —
/// decapsulated packets in, packets to encapsulate out.
pub struct WgDevice {
    rx: mpsc::Receiver<Packet>,
    tx: PollSender<Packet>,
    caps: DeviceCapabilities,
}

impl WgDevice {
    fn new(rx: mpsc::Receiver<Packet>, tx: mpsc::Sender<Packet>, mtu: u16) -> Self {
        let mut caps = DeviceCapabilities::default();
        // Medium::Ip: no ethernet header, no ARP, no neighbour discovery —
        // WireGuard is a point-to-point IP tunnel.
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = usize::from(mtu.min(MAX_MTU));
        caps.max_burst_size = Some(QUEUE_DEPTH);
        Self {
            rx,
            tx: PollSender::new(tx),
            caps,
        }
    }
}

impl Stream for WgDevice {
    type Item = io::Result<Packet>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|opt| opt.map(Ok))
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "wireguard tunnel is shut down")
}

impl Sink<Packet> for WgDevice {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tx.poll_reserve(cx).map_err(|_| closed())
    }

    fn start_send(mut self: Pin<&mut Self>, item: Packet) -> Result<(), Self::Error> {
        self.tx.send_item(item).map_err(|_| closed())
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // The channel is the buffer; there is nothing further to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.tx.close();
        Poll::Ready(Ok(()))
    }
}

impl tokio_smoltcp::device::AsyncDevice for WgDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}
