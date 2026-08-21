//! End-to-end: real UDP sockets, a real WireGuard handshake, a real TCP
//! connection carried inside the tunnel — with no external server.
//!
//! The peer side is an independent implementation (see `harness`), so this
//! genuinely cross-checks the production tunnel rather than testing it against
//! a mirror of itself.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use wg_netstack::testpeer as harness;

/// Opt-in tracing: `RUST_LOG=debug cargo test ... -- --nocapture`
fn init_tracing() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("off")),
            )
            .with_test_writer()
            .try_init();
    });
}

use std::net::SocketAddr;
use std::time::Duration;

use harness::{TestPeer, OFFLINK_ADDR, PEER_ADDR};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wg_netstack::{TunnelState, WgConfig, WgStack, WgTunnel};

const CLIENT_SECRET: [u8; 32] = [0x11; 32];
const PEER_SECRET: [u8; 32] = [0x22; 32];
const ECHO_PORT: u16 = 8080;

/// Bring up a peer, a client tunnel and an in-tunnel stack.
async fn setup() -> (TestPeer, WgStack) {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_tcp_echo(ECHO_PORT).await;

    let conf = peer.client_config(CLIENT_SECRET);
    let cfg = WgConfig::parse(&conf).expect("harness config should parse");
    let (tunnel, device, _tasks) = WgTunnel::connect(&cfg).await.expect("tunnel should connect");
    let stack = WgStack::new(device, &tunnel).expect("stack should build");

    // Let the handshake complete before dialling.
    for _ in 0..50 {
        if tunnel.status().state == TunnelState::Up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Keep the tunnel and its tasks alive for the duration of the test by
    // leaking them into the stack's lifetime.
    std::mem::forget(tunnel);
    std::mem::forget(_tasks);
    (peer, stack)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_echo_through_the_tunnel_onlink() {
    let (_peer, stack) = setup().await;

    let dst = SocketAddr::from((PEER_ADDR, ECHO_PORT));
    let mut conn = tokio::time::timeout(Duration::from_secs(5), stack.connect_tcp(dst))
        .await
        .expect("connect_tcp timed out")
        .expect("connect_tcp failed");

    conn.write_all(b"hello through wireguard").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"hello through wireguard");
}

/// The one that validates the synthetic default route in `stack.rs`: the
/// destination is not the peer's own address, so smoltcp must route it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_echo_through_the_tunnel_offlink() {
    let (_peer, stack) = setup().await;

    let dst = SocketAddr::from((OFFLINK_ADDR, ECHO_PORT));
    let mut conn = tokio::time::timeout(Duration::from_secs(5), stack.connect_tcp(dst))
        .await
        .expect("connect_tcp to an off-link address timed out (default route?)")
        .expect("connect_tcp to an off-link address failed (default route?)");

    conn.write_all(b"offlink").await.unwrap();
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
        .await
        .expect("read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"offlink");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn larger_than_one_segment_round_trips() {
    let (_peer, stack) = setup().await;

    let dst = SocketAddr::from((PEER_ADDR, ECHO_PORT));
    let mut conn = tokio::time::timeout(Duration::from_secs(5), stack.connect_tcp(dst))
        .await
        .expect("connect timed out")
        .unwrap();

    // Bigger than the MTU and bigger than one smoltcp tx buffer, so this
    // exercises segmentation, windowing and the encapsulate path under load.
    let payload: Vec<u8> = (0..24_000u32).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let writer = tokio::spawn(async move {
        conn.write_all(&payload).await.unwrap();
        conn.flush().await.unwrap();
        let mut got = vec![0u8; expected.len()];
        let mut read = 0;
        while read < got.len() {
            let n = conn.read(&mut got[read..]).await.unwrap();
            if n == 0 {
                break;
            }
            read += n;
        }
        got.truncate(read);
        got
    });

    let got = tokio::time::timeout(Duration::from_secs(20), writer)
        .await
        .expect("bulk transfer timed out")
        .unwrap();
    assert_eq!(got.len(), 24_000, "short read: got {} bytes", got.len());
    assert!(got == (0..24_000u32).map(|i| (i % 251) as u8).collect::<Vec<u8>>());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_reports_handshake_and_counters() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_tcp_echo(ECHO_PORT).await;
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap();
    let (tunnel, device, _tasks) = WgTunnel::connect(&cfg).await.unwrap();
    let stack = WgStack::new(device, &tunnel).unwrap();

    for _ in 0..100 {
        if tunnel.status().state == TunnelState::Up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let status = tunnel.status();
    assert_eq!(status.state, TunnelState::Up, "handshake never completed");
    assert!(status.last_handshake.is_some());

    // Move some bytes and confirm the counters advance.
    let dst = SocketAddr::from((PEER_ADDR, ECHO_PORT));
    let mut conn = stack.connect_tcp(dst).await.unwrap();
    conn.write_all(b"counters").await.unwrap();
    let mut buf = [0u8; 32];
    let _ = conn.read(&mut buf).await.unwrap();

    let after = tunnel.status();
    assert!(after.tx_bytes > 0, "tx_bytes should have advanced");
    assert!(after.rx_bytes > 0, "rx_bytes should have advanced");
    assert_eq!(after.dropped_inbound, 0, "no packets should have been dropped");
}

/// A wrong peer key must fail to establish, not hang forever pretending to work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mismatched_keys_never_come_up() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    // The client believes the peer has a different public key.
    let mut conf = peer.client_config(CLIENT_SECRET);
    {
        use base64::Engine as _;
        let wrong = base64::engine::general_purpose::STANDARD.encode([0x99u8; 32]);
        let start = conf.find("PublicKey = ").unwrap() + "PublicKey = ".len();
        let end = conf[start..].find('\n').unwrap() + start;
        conf.replace_range(start..end, &wrong);
    }
    let cfg = WgConfig::parse(&conf).unwrap();
    let (tunnel, _device, _tasks) = WgTunnel::connect(&cfg).await.unwrap();

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_ne!(
        tunnel.status().state,
        TunnelState::Up,
        "a tunnel with the wrong peer key must not report Up"
    );
    assert!(tunnel.status().last_handshake.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unresolvable_endpoint_is_an_error() {
    let conf = "
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.9.0.2/24
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
Endpoint = this-host-does-not-exist.invalid:51820
";
    let cfg = WgConfig::parse(conf).unwrap();
    assert!(
        WgTunnel::connect(&cfg).await.is_err(),
        "an unresolvable endpoint must fail at connect time"
    );
}

/// wireproxy tolerates a config with no `Address` and silently produces a
/// tunnel that cannot source packets. We reject it.
#[tokio::test]
async fn config_without_address_is_rejected() {
    let conf = "
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
Endpoint = 127.0.0.1:51820
";
    let cfg = WgConfig::parse(conf).unwrap();
    match WgTunnel::connect(&cfg).await {
        Err(wg_netstack::TunnelError::NoInterfaceAddress) => {}
        Err(other) => panic!("wrong error: {other}"),
        Ok(_) => panic!("a config with no Address must be rejected"),
    }
}

// ---------------------------------------------------------------------------
// UDP and DNS through the tunnel
// ---------------------------------------------------------------------------

const UDP_ECHO_PORT: u16 = 9090;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn udp_round_trips_through_the_tunnel() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_udp_echo(UDP_ECHO_PORT).await;
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap();
    let (tunnel, device, tasks) = WgTunnel::connect(&cfg).await.unwrap();
    let stack = WgStack::new(device, &tunnel).unwrap();
    wait_up(&tunnel).await;

    let socket = stack.bind_udp().await.expect("bind_udp");
    let dst = SocketAddr::from((PEER_ADDR, UDP_ECHO_PORT));
    socket.send_to(b"udp through wireguard", dst).await.unwrap();

    let mut buf = vec![0u8; 256];
    let (n, from) = tokio::time::timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("udp recv timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"udp through wireguard");
    assert_eq!(from.port(), UDP_ECHO_PORT);
    drop(tasks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_resolves_in_tunnel_with_ttl() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_dns("echo.internal", std::net::Ipv4Addr::new(10, 9, 0, 77), 42)
        .await;
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap();
    let (tunnel, device, tasks) = WgTunnel::connect(&cfg).await.unwrap();
    let stack = WgStack::new(device, &tunnel).unwrap();
    wait_up(&tunnel).await;

    let servers = tunnel.dns_servers().to_vec();
    assert_eq!(servers, vec![std::net::IpAddr::from(PEER_ADDR)]);

    let records = tokio::time::timeout(
        Duration::from_secs(8),
        wg_netstack::resolve::resolve(&stack, &servers, "echo.internal", true),
    )
    .await
    .expect("dns timed out")
    .expect("dns should succeed");

    assert_eq!(records.len(), 1, "expected one A record, got {records:?}");
    assert_eq!(records[0].ip, std::net::IpAddr::from(std::net::Ipv4Addr::new(10, 9, 0, 77)));
    assert_eq!(records[0].ttl, 42, "the TTL must survive; Picard's API needs it");

    // The JSON is what actually crosses into Swift.
    let json = wg_netstack::resolve::records_to_json(&records);
    assert_eq!(json, r#"[{"ip":"10.9.0.77","ttl":42}]"#);
    drop(tasks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_nxdomain_is_empty_not_an_error() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_dns("echo.internal", std::net::Ipv4Addr::new(10, 9, 0, 77), 42)
        .await;
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap();
    let (tunnel, device, tasks) = WgTunnel::connect(&cfg).await.unwrap();
    let stack = WgStack::new(device, &tunnel).unwrap();
    wait_up(&tunnel).await;

    let servers = tunnel.dns_servers().to_vec();
    let records = tokio::time::timeout(
        Duration::from_secs(8),
        wg_netstack::resolve::resolve(&stack, &servers, "nope.internal", true),
    )
    .await
    .expect("dns timed out")
    .expect("NXDOMAIN should be Ok(empty), so Picard's fallback chain still runs");
    assert!(records.is_empty(), "got {records:?}");
    drop(tasks);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_literal_address_short_circuits() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap();
    let (tunnel, device, tasks) = WgTunnel::connect(&cfg).await.unwrap();
    let stack = WgStack::new(device, &tunnel).unwrap();

    // No DNS server needed, and no query sent.
    let records = wg_netstack::resolve::resolve(&stack, &[], "8.8.4.4", true)
        .await
        .expect("a literal address needs no server");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].ttl, 0);

    // Right literal, wrong family: empty, not an error.
    let v6 = wg_netstack::resolve::resolve(&stack, &[], "8.8.4.4", false)
        .await
        .unwrap();
    assert!(v6.is_empty());
    drop(tasks);
}

async fn wait_up(tunnel: &std::sync::Arc<WgTunnel>) {
    for _ in 0..100 {
        if tunnel.status().state == TunnelState::Up {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

// ---------------------------------------------------------------------------
// Registry lifecycle: lazy connect, reconfigure, stop, wake
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slot_connects_lazily_and_reconnects_after_stop() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_tcp_echo(ECHO_PORT).await;

    init_tracing();
    let slot = wg_netstack::registry::slot("test-lifecycle");
    slot.clear();

    // Configured but untouched: nothing is allocated and status is Down.
    slot.set_config(WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap());
    assert_eq!(
        slot.status().state,
        TunnelState::Down,
        "a configured but unused slot must not have connected"
    );

    // First use brings it up.
    let live = slot.live().await.expect("first use should connect");
    let dst = SocketAddr::from((PEER_ADDR, ECHO_PORT));
    let mut conn = tokio::time::timeout(Duration::from_secs(5), live.stack.connect_tcp(dst))
        .await
        .expect("connect timed out")
        .unwrap();
    conn.write_all(b"lazy").await.unwrap();
    let mut buf = [0u8; 16];
    let n = conn.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"lazy");

    // Second use is the same tunnel.
    let again = slot.live().await.unwrap();
    assert!(
        std::sync::Arc::ptr_eq(&live, &again),
        "a live slot must be reused, not reconnected"
    );

    // Stop releases it; the config survives and the next use reconnects.
    drop(conn);
    drop(live);
    drop(again);
    slot.stop();
    assert_eq!(slot.status().state, TunnelState::Down);
    assert!(slot.is_configured(), "stop must keep the config");

    let relive = slot.live().await.expect("should reconnect after stop");
    // A different destination, deliberately. `tokio_smoltcp::Net` restarts its
    // ephemeral port counter at 10001 for every new stack, so the first dial
    // after a reconnect reuses the exact 4-tuple of the first dial before it.
    // See `reconnect_reusing_the_same_4_tuple_is_refused_by_a_smoltcp_peer`.
    let dst2 = SocketAddr::from((harness::OFFLINK_ADDR, ECHO_PORT));
    let mut conn2 = tokio::time::timeout(Duration::from_secs(5), relive.stack.connect_tcp(dst2))
        .await
        .expect("reconnect dial timed out")
        .unwrap();
    conn2.write_all(b"again").await.unwrap();
    let n = conn2.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"again");

    slot.clear();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconfiguring_discards_the_old_tunnel() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_tcp_echo(ECHO_PORT).await;

    let slot = wg_netstack::registry::slot("test-reconfigure");
    slot.clear();
    slot.set_config(WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap());
    let first = slot.live().await.unwrap();

    // A new config must invalidate the live tunnel even though the contents
    // happen to be equivalent -- generation, not deep equality.
    slot.set_config(WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap());
    let second = slot.live().await.unwrap();
    assert!(
        !std::sync::Arc::ptr_eq(&first, &second),
        "set_config must discard the tunnel built from the previous generation"
    );

    slot.clear();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wake_forces_a_rekey_and_traffic_still_flows() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_tcp_echo(ECHO_PORT).await;

    let slot = wg_netstack::registry::slot("test-wake");
    slot.clear();
    slot.set_config(WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap());
    let live = slot.live().await.unwrap();
    wait_up(&live.tunnel).await;
    let before = live.tunnel.status().last_handshake;
    assert!(before.is_some());

    slot.wake().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The tunnel must still carry traffic after a forced rekey.
    let dst = SocketAddr::from((PEER_ADDR, ECHO_PORT));
    let mut conn = tokio::time::timeout(Duration::from_secs(5), live.stack.connect_tcp(dst))
        .await
        .expect("post-wake dial timed out")
        .expect("post-wake dial failed");
    conn.write_all(b"post-wake").await.unwrap();
    let mut buf = [0u8; 16];
    let n = tokio::time::timeout(Duration::from_secs(5), conn.read(&mut buf))
        .await
        .expect("post-wake read timed out")
        .unwrap();
    assert_eq!(&buf[..n], b"post-wake");
    assert_eq!(live.tunnel.status().state, TunnelState::Up);

    slot.clear();
}

/// Many concurrent dials over one tunnel, which is the shape leaf produces:
/// each SOCKS5 CONNECT becomes an independent in-tunnel TCP socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn many_concurrent_connections_over_one_tunnel() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_tcp_echo(ECHO_PORT).await;
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap();
    let (tunnel, device, tasks) = WgTunnel::connect(&cfg).await.unwrap();
    let stack = std::sync::Arc::new(WgStack::new(device, &tunnel).unwrap());
    wait_up(&tunnel).await;

    let dst = SocketAddr::from((PEER_ADDR, ECHO_PORT));
    let mut handles = Vec::new();
    for i in 0..24u32 {
        let stack = std::sync::Arc::clone(&stack);
        handles.push(tokio::spawn(async move {
            let mut conn = stack.connect_tcp(dst).await?;
            let msg = format!("conn-{i:04}");
            conn.write_all(msg.as_bytes()).await?;
            let mut buf = vec![0u8; msg.len()];
            let mut read = 0;
            while read < buf.len() {
                let n = conn.read(&mut buf[read..]).await?;
                if n == 0 {
                    break;
                }
                read += n;
            }
            Ok::<_, std::io::Error>((msg, String::from_utf8_lossy(&buf[..read]).to_string()))
        }));
    }

    let mut ok = 0;
    for h in handles {
        let (sent, got) = tokio::time::timeout(Duration::from_secs(20), h)
            .await
            .expect("a concurrent connection timed out")
            .unwrap()
            .expect("a concurrent connection failed");
        assert_eq!(sent, got, "echo mismatch on a concurrent connection");
        ok += 1;
    }
    assert_eq!(ok, 24);
    assert_eq!(
        tunnel.status().dropped_inbound,
        0,
        "24 concurrent connections should not overflow the inbound queue"
    );
    drop(tasks);
}

/// Documents a known limitation rather than asserting desired behaviour.
///
/// `tokio_smoltcp::Net` hardcodes its ephemeral port counter to start at 10001
/// (`Net::new2`, no seed parameter), so a rebuilt stack re-issues the same
/// local ports in the same order. Dial the same destination as before the
/// reconnect and the 4-tuple is identical; the peer still holds a socket for it
/// and drops the SYN.
///
/// Severity depends entirely on the *peer's* TCP stack. Linux and BSD accept a
/// SYN matching a TIME_WAIT socket when the ISN is higher (RFC 1122 §4.2.2.13),
/// so a real WireGuard server recovers. smoltcp — which is what this harness's
/// peer runs — does not, so the connection hangs until the SYN retry budget is
/// spent.
///
/// ponytail: the fix is a seedable port counter, which needs a patch to
/// tokio-smoltcp. Not worth owning a vendored copy of that crate for this
/// alone; revisit if a real peer ever shows the same behaviour, or if the
/// accept-path bug in `harness::spawn_tcp_echo` also needs fixing.
#[ignore = "documents a known tokio-smoltcp port-reuse limitation; peer-dependent"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_reusing_the_same_4_tuple_is_refused_by_a_smoltcp_peer() {
    let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
    peer.spawn_tcp_echo(ECHO_PORT).await;
    let slot = wg_netstack::registry::slot("test-4tuple");
    slot.clear();
    slot.set_config(WgConfig::parse(&peer.client_config(CLIENT_SECRET)).unwrap());

    let dst = SocketAddr::from((PEER_ADDR, ECHO_PORT));
    let live = slot.live().await.unwrap();
    let mut c1 = live.stack.connect_tcp(dst).await.unwrap();
    c1.write_all(b"first").await.unwrap();
    let mut buf = [0u8; 16];
    let _ = c1.read(&mut buf).await.unwrap();
    drop(c1);
    drop(live);
    slot.stop();

    // Same destination, and the fresh stack will reuse local port 10001.
    let relive = slot.live().await.unwrap();
    let redial = tokio::time::timeout(Duration::from_secs(5), relive.stack.connect_tcp(dst)).await;
    assert!(
        redial.is_ok(),
        "if this now passes, tokio-smoltcp gained port seeding or the peer \
         started accepting TIME_WAIT SYNs -- delete the #[ignore]"
    );
    slot.clear();
}
