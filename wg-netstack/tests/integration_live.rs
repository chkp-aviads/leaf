//! Live test against a real WireGuard server.
//!
//! `#[ignore]`d and env-gated, so `cargo test` stays hermetic and CI never
//! depends on a reachable peer or on credentials existing:
//!
//! ```sh
//! WG_TEST_CONF=/path/to/wg.conf cargo test -p wg-netstack --test integration_live -- --ignored --nocapture
//! ```
//!
//! The config file is read from the path given and is never copied into the
//! repository, echoed, or logged: it contains a WireGuard private key. Failures
//! report structure ("no A records for host") rather than config contents.
//!
//! Optional overrides:
//!   WG_TEST_HOST       hostname to resolve and fetch over the tunnel (default example.com)
//!   WG_TEST_PORT       TCP port on that host (default 80)
//!   WG_TEST_BULK_HOST  host for the bulk transfer (default speed.cloudflare.com)
//!   WG_TEST_BULK_PATH  path for the bulk transfer (default /__down?bytes=1000000)

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::net::SocketAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use wg_netstack::{TunnelState, WgConfig, WgStack, WgTunnel};

/// Returns None (and explains why) when the env gate is unset, so an ignored
/// test that is run deliberately still says something useful.
fn load_config() -> Option<WgConfig> {
    let path = match std::env::var("WG_TEST_CONF") {
        Ok(p) if !p.trim().is_empty() => p,
        _ => {
            eprintln!("WG_TEST_CONF is not set; nothing to test against");
            return None;
        }
    };
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read WG_TEST_CONF at {path}: {e}"));
    // Deliberately does not include the text in the panic message.
    let cfg = WgConfig::parse(&text)
        .unwrap_or_else(|e| panic!("WG_TEST_CONF did not parse: {e}"));
    Some(cfg)
}

fn target_host() -> String {
    std::env::var("WG_TEST_HOST").unwrap_or_else(|_| "example.com".to_string())
}

fn target_port() -> u16 {
    std::env::var("WG_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(80)
}

async fn bring_up(cfg: &WgConfig) -> (std::sync::Arc<WgTunnel>, WgStack, Vec<tokio::task::JoinHandle<()>>) {
    // Structure only -- never the key material.
    eprintln!(
        "config: {} address(es), {} dns server(s), mtu {}, {} peer(s)",
        cfg.addresses.len(),
        cfg.dns.len(),
        cfg.mtu,
        cfg.peers.len()
    );

    let (tunnel, device, tasks) = WgTunnel::connect(cfg)
        .await
        .expect("tunnel setup failed (endpoint unresolvable or socket refused?)");
    let stack = WgStack::new(device, &tunnel).expect("stack setup failed");

    // A real handshake is a network round trip; allow for a slow link.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    while std::time::Instant::now() < deadline {
        if tunnel.status().state == TunnelState::Up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let status = tunnel.status();
    assert_eq!(
        status.state,
        TunnelState::Up,
        "handshake never completed within 15s -- is the endpoint reachable from this network?"
    );
    eprintln!(
        "tunnel up: handshake {:?} ago, source {}",
        status.last_handshake.unwrap_or_default(),
        stack.source_address()
    );
    (tunnel, stack, tasks)
}

/// The end-to-end proof: handshake, in-tunnel DNS, then a real TCP fetch.
#[ignore = "requires WG_TEST_CONF and a reachable WireGuard server"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_tunnel_resolves_and_fetches() {
    let Some(cfg) = load_config() else { return };
    let (tunnel, stack, _tasks) = bring_up(&cfg).await;

    // --- DNS inside the tunnel ---
    let host = target_host();
    let servers = tunnel.dns_servers().to_vec();
    assert!(
        !servers.is_empty(),
        "config has no [Interface] DNS, so there is nothing to resolve against"
    );

    let records = tokio::time::timeout(
        Duration::from_secs(10),
        wg_netstack::resolve::resolve(&stack, &servers, &host, true),
    )
    .await
    .expect("in-tunnel DNS timed out")
    .expect("in-tunnel DNS failed");
    assert!(
        !records.is_empty(),
        "in-tunnel DNS returned no A records for {host}"
    );
    eprintln!(
        "resolved {host} -> {} (ttl {}s), {} record(s)",
        records[0].ip,
        records[0].ttl,
        records.len()
    );

    // --- TCP through the tunnel ---
    let port = target_port();
    let dst = SocketAddr::new(records[0].ip, port);
    let mut conn = tokio::time::timeout(Duration::from_secs(15), stack.connect_tcp(dst))
        .await
        .expect("in-tunnel TCP connect timed out")
        .expect("in-tunnel TCP connect failed");
    eprintln!("connected to {dst} through the tunnel");

    let request = format!(
        "HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: wg-netstack-live-test\r\nConnection: close\r\n\r\n"
    );
    conn.write_all(request.as_bytes()).await.expect("write failed");
    conn.flush().await.expect("flush failed");

    let mut buf = vec![0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(15), conn.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read failed");
    assert!(n > 0, "server closed without sending anything");
    let response = String::from_utf8_lossy(&buf[..n]);
    let first_line = response.lines().next().unwrap_or_default();
    eprintln!("response: {first_line}");
    assert!(
        response.starts_with("HTTP/"),
        "expected an HTTP response, got {:?}",
        &response[..response.len().min(80)]
    );

    // --- counters must reflect the traffic ---
    let status = tunnel.status();
    eprintln!(
        "counters: tx {} B, rx {} B, dropped inbound {}",
        status.tx_bytes, status.rx_bytes, status.dropped_inbound
    );
    assert!(status.tx_bytes > 0 && status.rx_bytes > 0);
    assert_eq!(
        status.dropped_inbound, 0,
        "packets were dropped; the stack fell behind on a trivial request"
    );
}

/// Bulk transfer over a real link, to exercise segmentation, windowing and
/// retransmission -- none of which a sub-MTU response touches.
///
/// Defaults to Cloudflare's speed-test endpoint because it is purpose-built for
/// this and returns a requested byte count; override if your network blocks it.
/// The hermetic suite covers the same mechanics on loopback
/// (`larger_than_one_segment_round_trips`); the point here is real MTU, real
/// RTT and real loss.
#[ignore = "requires WG_TEST_CONF and a reachable WireGuard server"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_tunnel_bulk_download() {
    const MIN_ACCEPTABLE: usize = 256 * 1024;

    let Some(cfg) = load_config() else { return };
    let (tunnel, stack, _tasks) = bring_up(&cfg).await;

    let host = std::env::var("WG_TEST_BULK_HOST")
        .unwrap_or_else(|_| "speed.cloudflare.com".to_string());
    let path = std::env::var("WG_TEST_BULK_PATH")
        .unwrap_or_else(|_| "/__down?bytes=1000000".to_string());

    let servers = tunnel.dns_servers().to_vec();
    let records = wg_netstack::resolve::resolve(&stack, &servers, &host, true)
        .await
        .expect("dns failed");
    assert!(!records.is_empty(), "no A records for {host}");

    let dst = SocketAddr::new(records[0].ip, 80);
    let mut conn = tokio::time::timeout(Duration::from_secs(15), stack.connect_tcp(dst))
        .await
        .expect("connect timed out")
        .expect("connect failed");

    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: wg-netstack-live-test\r\nConnection: close\r\n\r\n"
    );
    conn.write_all(request.as_bytes()).await.unwrap();
    conn.flush().await.unwrap();

    let started = std::time::Instant::now();
    let mut total = 0usize;
    let mut buf = vec![0u8; 16 * 1024];
    let deadline = started + Duration::from_secs(60);
    loop {
        if std::time::Instant::now() > deadline {
            eprintln!("stopping at the 60s deadline");
            break;
        }
        match tokio::time::timeout(Duration::from_secs(15), conn.read(&mut buf)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => total += n,
            Ok(Err(e)) => panic!("read failed after {total} bytes: {e}"),
            Err(_) => {
                eprintln!("read stalled after {total} bytes");
                break;
            }
        }
    }
    let elapsed = started.elapsed();
    let mbps = (total as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;
    eprintln!(
        "downloaded {total} bytes in {:.2}s ({mbps:.1} Mbit/s) through the tunnel",
        elapsed.as_secs_f64()
    );

    let status = tunnel.status();
    eprintln!(
        "counters: tx {} B, rx {} B, dropped inbound {}",
        status.tx_bytes, status.rx_bytes, status.dropped_inbound
    );

    assert!(
        total >= MIN_ACCEPTABLE,
        "only moved {total} bytes, which does not exercise segmentation or \
         windowing -- expected at least {MIN_ACCEPTABLE}"
    );
    // Not asserted as zero: on a real link a full window can legitimately
    // outrun the stack briefly. Surfaced so a regression in queue depth is visible.
    if status.dropped_inbound > 0 {
        eprintln!(
            "NOTE: {} inbound packet(s) dropped under load; consider raising QUEUE_DEPTH",
            status.dropped_inbound
        );
    }
}

/// This config carries `AllowedIPs = ::/0` but no IPv6 interface address, which
/// is the shape the single-source-address ceiling in `stack.rs` cares about.
/// Asserting the error is clear rather than a silent misbehaviour.
#[ignore = "requires WG_TEST_CONF"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_tunnel_reports_unsupported_family_clearly() {
    let Some(cfg) = load_config() else { return };
    let has_v6 = cfg.addresses.iter().any(|a| a.is_ipv6());
    let (_tunnel, stack, _tasks) = bring_up(&cfg).await;

    if has_v6 {
        eprintln!("config is dual-stack; skipping the single-family assertion");
        return;
    }
    // 2606:4700:4700::1111 is Cloudflare's v6 resolver.
    let v6: SocketAddr = "[2606:4700:4700::1111]:80".parse().unwrap();
    match stack.connect_tcp(v6).await {
        Err(err) => {
            eprintln!("expected refusal: {err}");
            assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);
        }
        Ok(_) => panic!("an IPv4-only tunnel must not claim to dial IPv6"),
    }
}
