//! An in-process WireGuard peer, for hermetic integration tests.
//!
//! Lives in the library rather than a `tests/` directory because two crates
//! need it: `wg-netstack`'s own integration tests and leaf's
//! `test_wireguard`. Gated behind the non-default `test-harness` feature, so
//! none of it reaches a shipped build.
//!
//! This is deliberately a *separate* implementation from `wg_netstack::tunnel`:
//! if both sides shared the production code, a symmetric bug (wrong nonce
//! handling, a missed drain loop) would cancel out and the test would pass.
//! Here the peer is hand-rolled, so the two sides genuinely cross-check.
//!
//! The peer plays responder: it binds a UDP socket, answers handshakes from
//! whatever source dials it, and runs its own smoltcp stack that *accepts*
//! connections and echoes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    dead_code
)]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use futures::{Sink, Stream};
use parking_lot::Mutex;
use smoltcp::phy::{DeviceCapabilities, Medium};
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_smoltcp::{Net, NetConfig};
use tokio_util::sync::PollSender;

const MAX: usize = 2048;
const MTU: usize = 1420;

/// The peer's own in-tunnel address. The client dials this for "on-link" tests.
pub const PEER_ADDR: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 1);
/// The client's in-tunnel address.
pub const CLIENT_ADDR: Ipv4Addr = Ipv4Addr::new(10, 9, 0, 2);
/// An address the peer does not own, reached only via the client's default
/// route. Accepted because the peer's stack runs with `any_ip`.
pub const OFFLINK_ADDR: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);

// ---------------------------------------------------------------------------
// A minimal Stream+Sink device, the shape tokio-smoltcp wants.
// ---------------------------------------------------------------------------

struct ChanDevice {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: PollSender<Vec<u8>>,
    caps: DeviceCapabilities,
}

impl Stream for ChanDevice {
    type Item = io::Result<Vec<u8>>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|o| o.map(Ok))
    }
}

impl Sink<Vec<u8>> for ChanDevice {
    type Error = io::Error;
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx.poll_reserve(cx).map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
    fn start_send(mut self: Pin<&mut Self>, item: Vec<u8>) -> io::Result<()> {
        self.tx.send_item(item).map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.tx.close();
        Poll::Ready(Ok(()))
    }
}

impl tokio_smoltcp::device::AsyncDevice for ChanDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.caps
    }
}

fn ip_caps() -> DeviceCapabilities {
    let mut caps = DeviceCapabilities::default();
    caps.medium = Medium::Ip;
    caps.max_transmission_unit = MTU;
    caps.max_burst_size = Some(32);
    caps
}

// ---------------------------------------------------------------------------
// The peer
// ---------------------------------------------------------------------------

pub struct TestPeer {
    /// Dial this from the client side.
    pub endpoint: SocketAddr,
    /// Put this in the client's `[Peer] PublicKey`.
    pub public_key: [u8; 32],
    /// The peer's in-tunnel stack, for binding listeners.
    pub net: Arc<Net>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl TestPeer {
    /// `client_public` is the client's public key, which a real server would
    /// have been configured with out of band.
    pub async fn start(client_secret: [u8; 32], peer_secret: [u8; 32]) -> TestPeer {
        let peer_static = StaticSecret::from(peer_secret);
        let public_key = *PublicKey::from(&peer_static).as_bytes();
        let client_public = PublicKey::from(&StaticSecret::from(client_secret));

        let socket = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap());
        let endpoint = socket.local_addr().unwrap();

        let tunn = Arc::new(Mutex::new(Tunn::new(
            peer_static,
            client_public,
            None,
            None,
            0,
            None,
        )));

        let (to_stack, stack_rx) = mpsc::channel::<Vec<u8>>(32);
        let (stack_tx, mut from_stack) = mpsc::channel::<Vec<u8>>(32);

        let device = ChanDevice {
            rx: stack_rx,
            tx: PollSender::new(stack_tx),
            caps: ip_caps(),
        };

        let mut iface = smoltcp::iface::Config::new(HardwareAddress::Ip);
        iface.random_seed = 0x5EED;
        let mut config = NetConfig::new(
            iface,
            IpCidr::new(IpAddress::Ipv4(PEER_ADDR), 24),
            vec![IpAddress::Ipv4(PEER_ADDR)],
        );
        config.buffer_size = tokio_smoltcp::BufferSize {
            tcp_rx_size: 8192,
            tcp_tx_size: 8192,
            ..Default::default()
        };
        let net = Arc::new(Net::new(device, config));
        // Accept connections addressed to hosts we do not own, so the client's
        // default route can be exercised against an off-link destination.
        net.set_any_ip(true);

        // Where the client is dialling from; learned from the first datagram.
        let client_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

        // UDP -> decapsulate -> stack
        let rx_task = {
            let socket = Arc::clone(&socket);
            let tunn = Arc::clone(&tunn);
            let client_addr = Arc::clone(&client_addr);
            tokio::spawn(async move {
                let mut buf = vec![0u8; MAX];
                loop {
                    let (n, from) = match socket.recv_from(&mut buf).await {
                        Ok(v) => v,
                        Err(_) => return,
                    };
                    *client_addr.lock() = Some(from);

                    let mut to_net: Vec<Vec<u8>> = Vec::new();
                    let mut to_tun: Vec<Vec<u8>> = Vec::new();
                    {
                        let mut t = tunn.lock();
                        let mut input: &[u8] = &buf[..n];
                        loop {
                            let mut out = vec![0u8; MAX];
                            enum R {
                                Done,
                                Net(usize),
                                Tun(usize),
                                Err,
                            }
                            let r = match t.decapsulate(None, input, &mut out) {
                                TunnResult::Done => R::Done,
                                TunnResult::Err(_) => R::Err,
                                TunnResult::WriteToNetwork(p) => R::Net(p.len()),
                                TunnResult::WriteToTunnelV4(p, _)
                                | TunnResult::WriteToTunnelV6(p, _) => R::Tun(p.len()),
                            };
                            match r {
                                R::Done | R::Err => break,
                                R::Net(l) => {
                                    out.truncate(l);
                                    to_net.push(out);
                                }
                                R::Tun(l) => {
                                    out.truncate(l);
                                    to_tun.push(out);
                                }
                            }
                            input = &[];
                        }
                    }
                    for d in to_net {
                        let _ = socket.send_to(&d, from).await;
                    }
                    for p in to_tun {
                        if to_stack.send(p).await.is_err() {
                            return;
                        }
                    }
                }
            })
        };

        // stack -> encapsulate -> UDP
        let tx_task = {
            let socket = Arc::clone(&socket);
            let tunn = Arc::clone(&tunn);
            let client_addr = Arc::clone(&client_addr);
            tokio::spawn(async move {
                while let Some(packet) = from_stack.recv().await {
                    let datagram = {
                        let mut t = tunn.lock();
                        let mut out = vec![0u8; MAX];
                        match t.encapsulate(&packet, &mut out) {
                            TunnResult::WriteToNetwork(p) => {
                                let l = p.len();
                                out.truncate(l);
                                Some(out)
                            }
                            _ => None,
                        }
                    };
                    let dst = *client_addr.lock();
                    if let (Some(d), Some(dst)) = (datagram, dst) {
                        let _ = socket.send_to(&d, dst).await;
                    }
                }
            })
        };

        // timers
        let timer_task = {
            let socket = Arc::clone(&socket);
            let tunn = Arc::clone(&tunn);
            let client_addr = Arc::clone(&client_addr);
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
                loop {
                    tick.tick().await;
                    let datagram = {
                        let mut t = tunn.lock();
                        let mut out = vec![0u8; MAX];
                        match t.update_timers(&mut out) {
                            TunnResult::WriteToNetwork(p) => {
                                let l = p.len();
                                out.truncate(l);
                                Some(out)
                            }
                            _ => None,
                        }
                    };
                    let dst = *client_addr.lock();
                    if let (Some(d), Some(dst)) = (datagram, dst) {
                        let _ = socket.send_to(&d, dst).await;
                    }
                }
            })
        };

        TestPeer {
            endpoint,
            public_key,
            net,
            _tasks: vec![rx_task, tx_task, timer_task],
        }
    }

    /// Accept TCP on `port` (any destination address) and echo until EOF.
    ///
    /// Each accepted connection gets a **freshly bound** listener rather than
    /// reusing one. `tokio_smoltcp` 0.6.0's `TcpStream::accept` re-listens the
    /// swapped-in socket with `listener.local_addr`, a `SocketAddr` — so for a
    /// wildcard bind the new endpoint is `0.0.0.0:port`, which no inbound
    /// segment ever matches. The result is that a listener serves exactly one
    /// connection and then goes deaf.
    ///
    /// This only affects the accept path, which the production outbound never
    /// uses (it dials), so it is a harness workaround and not a shipped
    /// concern. Worth reporting upstream.
    pub async fn spawn_tcp_echo(&self, port: u16) {
        // Must exceed the peak concurrent-connection count in any test, since
        // each worker is effectively one backlog slot: a SYN arriving with no
        // listening socket is refused outright, not queued.
        const ACCEPT_WORKERS: usize = 32;
        for _ in 0..ACCEPT_WORKERS {
            let net = Arc::clone(&self.net);
            tokio::spawn(async move {
                loop {
                    let listen = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
                    let Ok(mut listener) = net.tcp_bind(listen).await else {
                        return;
                    };
                    let accepted = listener.accept().await;
                    // Drop before echoing: this listener's socket is now the
                    // deaf one described above.
                    drop(listener);
                    let Ok((stream, _peer)) = accepted else {
                        continue;
                    };
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut stream: tokio_smoltcp::TcpStream = stream;
                        let mut buf = vec![0u8; 4096];
                        loop {
                            match stream.read(&mut buf).await {
                                Ok(0) | Err(_) => break,
                                Ok(n) => {
                                    if stream.write_all(&buf[..n]).await.is_err() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                }
            });
        }
    }

    /// Build the wg-quick config the client should use to reach this peer.
    pub fn client_config(&self, client_secret: [u8; 32]) -> String {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        format!(
            "[Interface]\n\
             PrivateKey = {}\n\
             Address = {}/24\n\
             DNS = {}\n\
             MTU = {}\n\
             \n\
             [Peer]\n\
             PublicKey = {}\n\
             Endpoint = {}\n\
             AllowedIPs = 0.0.0.0/0\n",
            b64.encode(client_secret),
            CLIENT_ADDR,
            PEER_ADDR,
            MTU,
            b64.encode(self.public_key),
            self.endpoint,
        )
    }
}

impl TestPeer {
    /// A UDP echo service inside the tunnel, for the UDP ASSOCIATE path.
    pub async fn spawn_udp_echo(&self, port: u16) {
        let socket = self
            .net
            .udp_bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port)))
            .await
            .expect("peer udp_bind");
        tokio::spawn(async move {
            let socket = socket;
            let mut buf = vec![0u8; 2048];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let _ = socket.send_to(&buf[..n], from).await;
                    }
                    Err(_) => return,
                }
            }
        });
    }

    /// A tiny authoritative DNS responder on port 53 inside the tunnel.
    ///
    /// Answers A queries for `answers.0` with `answers.1` at the given TTL, and
    /// returns NXDOMAIN for anything else, so both the success and the
    /// no-records paths are covered.
    pub async fn spawn_dns(&self, zone: &'static str, addr: Ipv4Addr, ttl: u32) {
        use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
        use hickory_proto::rr::{rdata, DNSClass, RData, Record, RecordType};

        let socket = self
            .net
            .udp_bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53)))
            .await
            .expect("peer dns bind");
        tokio::spawn(async move {
            let socket = socket;
            let mut buf = vec![0u8; 2048];
            loop {
                let (n, from) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                let Ok(query) = Message::from_vec(&buf[..n]) else {
                    continue;
                };
                let mut response = Message::new();
                response
                    .set_id(query.id())
                    .set_message_type(MessageType::Response)
                    .set_op_code(OpCode::Query)
                    .set_recursion_available(true);
                for q in query.queries() {
                    response.add_query(q.clone());
                }

                let q = query.queries().first().cloned();
                match q {
                    Some(q)
                        if q.query_type() == RecordType::A
                            && q.name().to_utf8().trim_end_matches('.') == zone =>
                    {
                        let mut rec = Record::with(q.name().clone(), RecordType::A, ttl);
                        rec.set_dns_class(DNSClass::IN);
                        rec.set_data(Some(RData::A(rdata::A(addr))));
                        response.add_answer(rec);
                        response.set_response_code(ResponseCode::NoError);
                    }
                    _ => {
                        response.set_response_code(ResponseCode::NXDomain);
                    }
                }
                if let Ok(wire) = response.to_vec() {
                    let _ = socket.send_to(&wire, from).await;
                }
            }
        });
    }
}
