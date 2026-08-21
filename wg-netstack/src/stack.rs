//! The in-tunnel TCP/IP stack: dials TCP and binds UDP *inside* the WireGuard
//! tunnel, which is the one capability wireproxy had that leaf lacks.
//!
//! leaf's existing `netstack-smoltcp` cannot be reused: it only accepts
//! connections originated by a TUN device, and exposes no dial path.

use std::io;
use std::net::{IpAddr, SocketAddr};

use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio_smoltcp::{BufferSize, Net, NetConfig, TcpStream, UdpSocket};
use tracing::{debug, warn};

use crate::tunnel::{WgDevice, WgTunnel};

/// Per-connection memory. 8 KiB each way is 16 KiB per TCP socket, which is the
/// dominant term in the tunnel's footprint under load.
///
/// These are the throughput/memory knob, and throughput is receive-window
/// limited, so it scales with the buffer until something else binds. Measured
/// against a real server (1 MB download, single run each):
///
/// |  buffers |    throughput | dropped | per conn |
/// |----------|---------------|---------|----------|
/// |   8 KiB  |   3.5 Mbit/s  |       0 |  16 KiB  |
/// |  16 KiB  |   7.7 Mbit/s  |       0 |  32 KiB  |
/// |  32 KiB  |  16.1 Mbit/s  |       0 |  64 KiB  |
/// |  64 KiB  |  14.0 Mbit/s  |      27 | 128 KiB  |
///
/// Note the 64 KiB row: it is *slower* than 32 KiB and drops packets, because a
/// window that large outruns `QUEUE_DEPTH` packets in the device ring and TCP
/// backs off. The two constants are coupled -- raising these past 32 KiB
/// requires raising QUEUE_DEPTH in `tunnel.rs` as well, or the extra memory buys
/// negative throughput.
///
/// ponytail: 8 KiB is the lean default. 32 KiB is the throughput sweet spot at
/// 4x the per-connection cost; pick per the extension's memory budget.
const TCP_RX_BUFFER: usize = 8 * 1024;
const TCP_TX_BUFFER: usize = 8 * 1024;
const UDP_RX_BUFFER: usize = 8 * 1024;
const UDP_TX_BUFFER: usize = 8 * 1024;

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

pub struct WgStack {
    net: Net,
    /// The source address the stack dials from. See `primary_address`.
    primary: IpAddr,
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
        Ok(Self { net, primary })
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

    /// Open a TCP connection to `dst` from inside the tunnel.
    pub async fn connect_tcp(&self, dst: SocketAddr) -> io::Result<TcpStream> {
        self.check_family(dst.ip())?;
        self.net.tcp_connect(dst).await
    }

    /// Bind a UDP socket inside the tunnel on an ephemeral port.
    pub async fn bind_udp(&self) -> io::Result<UdpSocket> {
        let unspecified = if self.primary.is_ipv4() {
            SocketAddr::from(([0u8, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        self.net.udp_bind(unspecified).await
    }
}
