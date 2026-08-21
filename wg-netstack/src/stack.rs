//! The in-tunnel TCP/IP stack: dials TCP and binds UDP *inside* the WireGuard
//! tunnel, which is the one capability wireproxy had that leaf lacks.
//!
//! leaf's existing `netstack-smoltcp` cannot be reused: it only accepts
//! connections originated by a TUN device, and exposes no dial path.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio_smoltcp::{BufferSize, Net, NetConfig, TcpStream, UdpSocket};
use tracing::{debug, warn};

use crate::tunnel::{WgDevice, WgTunnel};

/// Per-connection memory, and the dominant term in the tunnel's footprint.
///
/// Throughput is receive-window limited, so it scales with the buffer until
/// something else binds -- and what binds first is `QUEUE_DEPTH`, the device
/// ring. Measured against a real server (1 MB download, three runs each,
/// Mbit/s):
///
/// | buffers | ring 32 | ring 64 | ring 128 | ring 256 | per conn |
/// |---------|---------|---------|----------|----------|----------|
/// |  8 KiB  |   3.5   |    -    |     -    |     -    |  16 KiB  |
/// | 16 KiB  |   7.7   |    -    |     -    |     -    |  32 KiB  |
/// | 32 KiB  |  ~11    |  ~13    |   ~12    |   ~11    |  64 KiB  |
/// | 64 KiB  |  14 *   |    -    |   ~21    |   ~26    | 128 KiB  |
/// | 128 KiB |    -    |    -    |     -    |   ~43    | 256 KiB  |
///
/// (*) 64 KiB on a 32-packet ring was the one configuration that *lost*
/// throughput and dropped packets: the window outran the ring and TCP backed
/// off. Raising the ring fixes it entirely -- the buffer was never the problem.
/// The two constants have to move together.
///
/// The chosen point: 64 KiB buffers on a 256-packet ring. The ring costs about
/// `QUEUE_DEPTH * MTU` once per tunnel (~384 KiB), which is cheap next to
/// per-connection buffers, and it is what unlocks the scaling. 128 KiB buffers
/// are measurably faster still, but at 256 KiB per connection the worst case
/// stops fitting a network extension's budget.
const TCP_RX_BUFFER: usize = 64 * 1024;
const TCP_TX_BUFFER: usize = 64 * 1024;
const UDP_RX_BUFFER: usize = 8 * 1024;
const UDP_TX_BUFFER: usize = 8 * 1024;

/// Hard ceiling on concurrent in-tunnel sockets.
///
/// This is what makes the memory budget bounded rather than merely typical.
/// leaf will accept as many SOCKS5 CONNECTs as arrive, and each in-tunnel socket
/// costs `TCP_RX_BUFFER + TCP_TX_BUFFER`; without a cap a connection burst is an
/// OOM-kill in an extension with a jetsam budget. Refusing the 65th connection
/// degrades one request. Being killed drops every request and the tunnel.
///
/// Worst case here: 64 * 128 KiB = 8 MB, reached only at peak concurrency since
/// buffers are allocated per live socket and released on close.
///
/// ponytail: this is the knob to trade against TCP_*_BUFFER. cap * per-conn is
/// the number that has to fit the budget.
pub const MAX_TCP_SOCKETS: usize = 64;

/// UDP sessions are cheaper and shorter-lived, but still bounded.
pub const MAX_UDP_SOCKETS: usize = 32;

/// Fixed seed material is fine: smoltcp uses `random_seed` to pick initial TCP
/// sequence numbers, and the tunnel already provides confidentiality and
/// integrity. Derived from the interface address so two tunnels differ.
fn seed_from(addresses: &[IpAddr]) -> u64 {
    let mut seed: u64 = 0x9E37_79B9_7F4A_7C15;
    for addr in addresses {
        for byte in match addr {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        } {
            seed = seed.rotate_left(7) ^ u64::from(byte);
        }
    }
    seed
}

/// Decrements a live-socket counter when dropped, so the cap tracks reality
/// rather than a high-water mark.
struct SocketSlot {
    counter: Arc<AtomicUsize>,
}

impl SocketSlot {
    /// Claims a slot, or returns None when the cap is reached.
    fn claim(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        // compare-exchange rather than fetch_add so a rejected claim never
        // transiently over-counts and rejects an unrelated concurrent dial.
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return None;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(Self {
                        counter: Arc::clone(counter),
                    })
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for SocketSlot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

/// An in-tunnel TCP stream that releases its slot when closed.
pub struct WgTcpStream {
    inner: TcpStream,
    _slot: SocketSlot,
}

impl tokio::io::AsyncRead for WgTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for WgTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// An in-tunnel UDP socket that releases its slot when closed.
pub struct WgUdpSocket {
    inner: UdpSocket,
    _slot: SocketSlot,
}

impl WgUdpSocket {
    pub async fn send_to(&self, buf: &[u8], target: SocketAddr) -> io::Result<usize> {
        self.inner.send_to(buf, target).await
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

pub struct WgStack {
    net: Net,
    /// The source address the stack dials from. See `primary_address`.
    primary: IpAddr,
    live_tcp: Arc<AtomicUsize>,
    live_udp: Arc<AtomicUsize>,
}

/// Pick the address the stack will source packets from.
///
/// Known ceiling: `tokio_smoltcp::NetConfig` accepts a single `IpCidr`, so one
/// stack has one source address and therefore dials one address family. Real
/// wg-quick configs *are* sometimes dual-stack (the wireproxy corpus has
/// `Address = 100.96.0.190,2606:...:6f5f/128`), so this prefers IPv4 — present
/// in essentially every config — and reports a clear error if asked to dial a
/// family it has no source address for.
///
/// ponytail: to lift this, either run a second `Net` for IPv6 or patch
/// `NetConfig` to take a list. Both are cheap; neither is worth doing before a
/// real config demands in-tunnel IPv6.
fn primary_address(addresses: &[IpAddr]) -> Option<IpAddr> {
    addresses
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addresses.first())
        .copied()
}

fn to_ip_address(addr: IpAddr) -> IpAddress {
    match addr {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

impl WgStack {
    /// Build the stack over a tunnel's device.
    ///
    /// Must be called inside a tokio runtime: `Net::new` spawns the stack's
    /// reactor task. Dropping the `WgStack` stops that reactor.
    pub fn new(device: WgDevice, tunnel: &WgTunnel) -> io::Result<Self> {
        let addresses = tunnel.addresses();
        let primary = primary_address(addresses).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "tunnel has no interface address to dial from",
            )
        })?;
        if addresses.len() > 1 {
            warn!(
                primary = %primary,
                ignored = addresses.len() - 1,
                "config has multiple interface addresses; this stack dials from one \
                 (see primary_address)"
            );
        }

        let mut interface_config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        interface_config.random_seed = seed_from(addresses);

        // A host prefix, matching wireproxy: it discards the configured prefix
        // length and lets the netstack apply /32 or /128.
        let prefix = if primary.is_ipv4() { 32 } else { 128 };
        let cidr = IpCidr::new(to_ip_address(primary), prefix);

        // WireGuard is point-to-point, so there is no real gateway. But smoltcp
        // still needs a route to consider an off-link destination reachable, and
        // in Medium::Ip the next hop is never resolved (no ARP/NDP), so the
        // gateway address is only a routing-table placeholder. Point it at our
        // own address, which is guaranteed to be a valid address of the right
        // family.
        let gateway = vec![to_ip_address(primary)];

        let mut config = NetConfig::new(interface_config, cidr, gateway);
        config.buffer_size = BufferSize {
            tcp_rx_size: TCP_RX_BUFFER,
            tcp_tx_size: TCP_TX_BUFFER,
            udp_rx_size: UDP_RX_BUFFER,
            udp_tx_size: UDP_TX_BUFFER,
            ..Default::default()
        };

        let net = Net::new(device, config);
        debug!(source = %primary, mtu = tunnel.mtu(), "in-tunnel stack up");
        Ok(Self {
            net,
            primary,
            live_tcp: Arc::new(AtomicUsize::new(0)),
            live_udp: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// The address this stack sources packets from.
    pub fn source_address(&self) -> IpAddr {
        self.primary
    }

    fn check_family(&self, dst: IpAddr) -> io::Result<()> {
        if dst.is_ipv4() == self.primary.is_ipv4() {
            return Ok(());
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!(
                "cannot dial {dst} from in-tunnel source {}: the tunnel has no \
                 interface address of that family",
                self.primary
            ),
        ))
    }

    /// Live in-tunnel socket counts, for status reporting and tests.
    pub fn live_sockets(&self) -> (usize, usize) {
        (
            self.live_tcp.load(Ordering::Relaxed),
            self.live_udp.load(Ordering::Relaxed),
        )
    }

    /// Open a TCP connection to `dst` from inside the tunnel.
    ///
    /// Fails with `ConnectionRefused` once `MAX_TCP_SOCKETS` are live, which
    /// leaf turns into a failed session -- one degraded request instead of an
    /// out-of-memory kill that takes the whole tunnel down.
    pub async fn connect_tcp(&self, dst: SocketAddr) -> io::Result<WgTcpStream> {
        self.check_family(dst.ip())?;
        let slot = SocketSlot::claim(&self.live_tcp, MAX_TCP_SOCKETS).ok_or_else(|| {
            warn!(
                limit = MAX_TCP_SOCKETS,
                "refusing in-tunnel TCP connect: socket cap reached"
            );
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("in-tunnel socket cap reached ({MAX_TCP_SOCKETS} live)"),
            )
        })?;
        let inner = self.net.tcp_connect(dst).await?;
        Ok(WgTcpStream { inner, _slot: slot })
    }

    /// Bind a UDP socket inside the tunnel on an ephemeral port.
    pub async fn bind_udp(&self) -> io::Result<WgUdpSocket> {
        let slot = SocketSlot::claim(&self.live_udp, MAX_UDP_SOCKETS).ok_or_else(|| {
            warn!(
                limit = MAX_UDP_SOCKETS,
                "refusing in-tunnel UDP bind: socket cap reached"
            );
            io::Error::new(
                io::ErrorKind::ConnectionRefused,
                format!("in-tunnel UDP socket cap reached ({MAX_UDP_SOCKETS} live)"),
            )
        })?;
        let unspecified = if self.primary.is_ipv4() {
            SocketAddr::from(([0u8, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let inner = self.net.udp_bind(unspecified).await?;
        Ok(WgUdpSocket { inner, _slot: slot })
    }
}
