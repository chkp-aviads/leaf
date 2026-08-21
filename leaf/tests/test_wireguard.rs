//! leaf's SOCKS5 and HTTP inbounds carrying real traffic into a WireGuard
//! tunnel, end to end, with no external server.
//!
//! The far side is `wg_netstack::testpeer`, an independent WireGuard
//! implementation, so this exercises the whole chain a client actually walks:
//!
//!   socks5/http client -> leaf inbound -> dispatcher -> wireguard outbound
//!     -> boringtun -> UDP -> test peer -> in-tunnel echo service

#![cfg(all(
    feature = "outbound-wireguard",
    feature = "inbound-socks",
    feature = "inbound-http",
))]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::Duration;

use wg_netstack::testpeer::{TestPeer, PEER_ADDR};
use wg_netstack::WgConfig;

const CLIENT_SECRET: [u8; 32] = [0x33; 32];
const PEER_SECRET: [u8; 32] = [0x44; 32];
const ECHO_PORT: u16 = 7070;

/// Minimal blocking SOCKS5 CONNECT, so the test drives leaf the way a real
/// client does rather than through leaf's own outbound code.
fn socks5_connect(
    proxy: SocketAddr,
    dst_ip: std::net::Ipv4Addr,
    dst_port: u16,
    auth: Option<(&str, &str)>,
) -> std::io::Result<TcpStream> {
    let mut s = TcpStream::connect(proxy)?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    s.set_write_timeout(Some(Duration::from_secs(10)))?;

    match auth {
        Some((user, pass)) => {
            s.write_all(&[0x05, 0x01, 0x02])?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r)?;
            assert_eq!(r, [0x05, 0x02], "server should select user/pass auth");
            let mut req = vec![0x01, user.len() as u8];
            req.extend_from_slice(user.as_bytes());
            req.push(pass.len() as u8);
            req.extend_from_slice(pass.as_bytes());
            s.write_all(&req)?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar)?;
            if ar[1] != 0x00 {
                return Err(std::io::Error::other("socks5 auth rejected"));
            }
        }
        None => {
            s.write_all(&[0x05, 0x01, 0x00])?;
            let mut r = [0u8; 2];
            s.read_exact(&mut r)?;
            assert_eq!(r, [0x05, 0x00], "server should select no-auth");
        }
    }

    // CONNECT to an IPv4 destination.
    let mut req = vec![0x05, 0x01, 0x00, 0x01];
    req.extend_from_slice(&dst_ip.octets());
    req.extend_from_slice(&dst_port.to_be_bytes());
    s.write_all(&req)?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::other(format!(
            "socks5 CONNECT failed with reply code {}",
            head[1]
        )));
    }
    // Consume BND.ADDR/BND.PORT.
    match head[3] {
        0x01 => {
            let mut skip = [0u8; 6];
            s.read_exact(&mut skip)?;
        }
        0x04 => {
            let mut skip = [0u8; 18];
            s.read_exact(&mut skip)?;
        }
        0x03 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            let mut skip = vec![0u8; len[0] as usize + 2];
            s.read_exact(&mut skip)?;
        }
        other => return Err(std::io::Error::other(format!("bad ATYP {other}"))),
    }
    Ok(s)
}

fn echo_once(mut conn: TcpStream, payload: &[u8]) -> std::io::Result<Vec<u8>> {
    conn.write_all(payload)?;
    conn.flush()?;
    let mut got = vec![0u8; payload.len()];
    let mut read = 0;
    while read < got.len() {
        let n = conn.read(&mut got[read..])?;
        if n == 0 {
            break;
        }
        read += n;
    }
    got.truncate(read);
    Ok(got)
}

/// Stand up the peer, install the wg config under `control_key`, and start leaf.
fn setup(
    rt: &tokio::runtime::Runtime,
    control_key: &'static str,
    leaf_config: String,
) -> (TestPeer, LeafGuard) {
    let peer = rt.block_on(async {
        let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
        peer.spawn_tcp_echo(ECHO_PORT).await;
        peer
    });

    // The wg-quick config arrives over the control API, never through the leaf
    // config -- so no key material is in the JSON below.
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).expect("wg config");
    wg_netstack::registry::slot(control_key).set_config(cfg);

    let ids = common::run_leaf_instances(rt, vec![leaf_config]).expect("leaf should start");
    std::thread::sleep(Duration::from_millis(300));
    (peer, LeafGuard(ids))
}

/// Shuts leaf down when it goes out of scope, **including on panic**.
///
/// This has to be a guard rather than a call at the end of each test.
/// `run_leaf_instances` uses `spawn_blocking`, and `leaf::start` does not
/// return until shutdown, so `Runtime::drop` waits on it forever. Without the
/// guard a failing assertion unwinds past the cleanup and the test hangs
/// instead of reporting -- which turns any future regression into a CI timeout
/// with no output.
///
/// `leaf::shutdown` uses `blocking_send`, so it must not run inside a runtime
/// context; Drop here runs on the test thread, which is correct.
struct LeafGuard(Vec<leaf::RuntimeId>);

impl Drop for LeafGuard {
    fn drop(&mut self) {
        for id in &self.0 {
            leaf::shutdown(*id);
        }
        for id in &self.0 {
            for _ in 0..500 {
                if !leaf::is_running(*id) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

#[test]
fn socks5_connect_through_wireguard() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = r#"
    {
        "inbounds": [
            { "protocol": "socks", "address": "127.0.0.1", "port": 21801 }
        ],
        "outbounds": [
            { "tag": "wg", "protocol": "wireguard",
              "settings": { "controlKey": "leaf-test-plain" } }
        ]
    }
    "#;
    let (_peer, _leaf) = setup(&rt, "leaf-test-plain", config.to_string());

    let conn = socks5_connect(
        "127.0.0.1:21801".parse().unwrap(),
        PEER_ADDR,
        ECHO_PORT,
        None,
    )
    .expect("socks5 CONNECT through wireguard should succeed");
    let got = echo_once(conn, b"leaf -> wireguard -> echo").expect("echo");
    assert_eq!(&got, b"leaf -> wireguard -> echo");
}

#[test]
fn socks5_with_auth_through_wireguard() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = r#"
    {
        "inbounds": [
            { "protocol": "socks", "address": "127.0.0.1", "port": 21802,
              "settings": { "username": "picard", "password": "s3cret" } }
        ],
        "outbounds": [
            { "tag": "wg", "protocol": "wireguard",
              "settings": { "controlKey": "leaf-test-auth" } }
        ]
    }
    "#;
    let (_peer, _leaf) = setup(&rt, "leaf-test-auth", config.to_string());
    let proxy: SocketAddr = "127.0.0.1:21802".parse().unwrap();

    let conn = socks5_connect(proxy, PEER_ADDR, ECHO_PORT, Some(("picard", "s3cret")))
        .expect("correct credentials should be accepted");
    let got = echo_once(conn, b"authenticated").expect("echo");
    assert_eq!(&got, b"authenticated");

    // Wrong password must be rejected.
    assert!(
        socks5_connect(proxy, PEER_ADDR, ECHO_PORT, Some(("picard", "wrong"))).is_err(),
        "a wrong password must not be accepted"
    );
}

/// The HTTP CONNECT front end, including the Basic auth added for this work --
/// leaf's http inbound had no authentication at all before.
#[test]
fn http_connect_with_auth_through_wireguard() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = r#"
    {
        "inbounds": [
            { "protocol": "http", "address": "127.0.0.1", "port": 21803,
              "settings": { "username": "picard", "password": "s3cret" } }
        ],
        "outbounds": [
            { "tag": "wg", "protocol": "wireguard",
              "settings": { "controlKey": "leaf-test-http" } }
        ]
    }
    "#;
    let (_peer, _leaf) = setup(&rt, "leaf-test-http", config.to_string());
    let proxy: SocketAddr = "127.0.0.1:21803".parse().unwrap();

    let creds = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode("picard:s3cret")
    };

    // With credentials: CONNECT succeeds and the tunnel carries the body.
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(
        format!(
            "CONNECT {PEER_ADDR}:{ECHO_PORT} HTTP/1.1\r\n\
             Host: {PEER_ADDR}:{ECHO_PORT}\r\n\
             Proxy-Authorization: Basic {creds}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let mut head = [0u8; 39];
    s.read_exact(&mut head).unwrap();
    let head = String::from_utf8_lossy(&head);
    assert!(
        head.starts_with("HTTP/1.1 200"),
        "expected 200 from CONNECT, got {head:?}"
    );
    let got = echo_once(s, b"http connect body").expect("echo");
    assert_eq!(&got, b"http connect body");

    // Without credentials: a 407 challenge, not a silent drop.
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(
        format!("CONNECT {PEER_ADDR}:{ECHO_PORT} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes(),
    )
    .unwrap();
    let mut buf = vec![0u8; 128];
    let n = s.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 407"),
        "expected a 407 challenge, got {resp:?}"
    );
    assert!(
        resp.contains("Proxy-Authenticate: Basic"),
        "the 407 must carry a challenge header, got {resp:?}"
    );

    // A wrong password is also a 407.
    let bad = {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode("picard:wrong")
    };
    let mut s = TcpStream::connect(proxy).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(
        format!(
            "CONNECT {PEER_ADDR}:{ECHO_PORT} HTTP/1.1\r\nHost: x\r\n\
             Proxy-Authorization: Basic {bad}\r\n\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let n = s.read(&mut buf).unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(
        resp.starts_with("HTTP/1.1 407"),
        "a wrong password must be rejected, got {resp:?}"
    );
}

/// An outbound whose tunnel was never configured must fail the session cleanly
/// -- no hang, no panic in the extension.
///
/// Note what leaf actually does: the SOCKS5 inbound sends its success reply
/// *before* the outbound is dialled (visible in the log as `connect=failed`
/// arriving after the client is already connected). So the handshake succeeds
/// and the failure surfaces as an immediate EOF, not a SOCKS5 error reply. That
/// is normal proxy behaviour -- replying early avoids buffering the request --
/// but it means a client cannot distinguish "no route" from "server hung up".
#[test]
fn unconfigured_tunnel_fails_the_session_cleanly() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = r#"
    {
        "inbounds": [
            { "protocol": "socks", "address": "127.0.0.1", "port": 21804 }
        ],
        "outbounds": [
            { "tag": "wg", "protocol": "wireguard",
              "settings": { "controlKey": "leaf-test-never-configured" } }
        ]
    }
    "#;
    let ids = common::run_leaf_instances(&rt, vec![config.to_string()]).unwrap();
    let _leaf = LeafGuard(ids);
    std::thread::sleep(Duration::from_millis(300));

    let conn = socks5_connect(
        "127.0.0.1:21804".parse().unwrap(),
        PEER_ADDR,
        ECHO_PORT,
        None,
    );

    match conn {
        // The common case: handshake succeeded, then the session dies.
        Ok(stream) => {
            let got = echo_once(stream, b"should not round trip").unwrap_or_default();
            assert!(
                got.is_empty(),
                "an unconfigured tunnel must not carry data, got {got:?}"
            );
        }
        // Also acceptable: leaf refused before replying.
        Err(_) => {}
    }
}

/// SOCKS5 UDP ASSOCIATE through the tunnel.
///
/// This is the path Picard's `UDPProxy` uses, and the reason the wireguard
/// outbound registers a datagram handler at all -- leaf's `quic` outbound, which
/// this one is otherwise modelled on, ships only a stream handler and so cannot
/// carry UDP.
#[test]
fn socks5_udp_associate_through_wireguard() {
    const UDP_ECHO_PORT: u16 = 7071;
    let rt = tokio::runtime::Runtime::new().unwrap();
    let config = r#"
    {
        "inbounds": [
            { "protocol": "socks", "address": "127.0.0.1", "port": 21805 }
        ],
        "outbounds": [
            { "tag": "wg", "protocol": "wireguard",
              "settings": { "controlKey": "leaf-test-udp" } }
        ]
    }
    "#;

    // A UDP echo service inside the tunnel, rather than the TCP one.
    let peer = rt.block_on(async {
        let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
        peer.spawn_udp_echo(UDP_ECHO_PORT).await;
        peer
    });
    let cfg = WgConfig::parse(&peer.client_config(CLIENT_SECRET)).expect("wg config");
    wg_netstack::registry::slot("leaf-test-udp").set_config(cfg);
    let ids = common::run_leaf_instances(&rt, vec![config.to_string()]).unwrap();
    let _leaf = LeafGuard(ids);
    std::thread::sleep(Duration::from_millis(300));

    // The control connection must stay open for the association to live.
    let proxy: SocketAddr = "127.0.0.1:21805".parse().unwrap();
    let mut ctrl = TcpStream::connect(proxy).unwrap();
    ctrl.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    ctrl.write_all(&[0x05, 0x01, 0x00]).unwrap();
    let mut r = [0u8; 2];
    ctrl.read_exact(&mut r).unwrap();
    assert_eq!(r, [0x05, 0x00]);

    // UDP ASSOCIATE with an unspecified client address.
    ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut head = [0u8; 4];
    ctrl.read_exact(&mut head).unwrap();
    assert_eq!(head[1], 0x00, "UDP ASSOCIATE should succeed");
    assert_eq!(head[3], 0x01, "expected an IPv4 relay address");
    let mut relay = [0u8; 6];
    ctrl.read_exact(&mut relay).unwrap();
    let relay_port = u16::from_be_bytes([relay[4], relay[5]]);
    let relay_addr: SocketAddr = (std::net::Ipv4Addr::LOCALHOST, relay_port).into();

    // Send a datagram wrapped in a SOCKS5 UDP header.
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let payload = b"udp via leaf and wireguard";
    let mut dgram = vec![0x00, 0x00, 0x00, 0x01];
    dgram.extend_from_slice(&PEER_ADDR.octets());
    dgram.extend_from_slice(&UDP_ECHO_PORT.to_be_bytes());
    dgram.extend_from_slice(payload);
    socket.send_to(&dgram, relay_addr).unwrap();

    let mut buf = vec![0u8; 2048];
    let (n, _from) = socket.recv_from(&mut buf).expect("no UDP reply came back");
    // Strip RSV(2) + FRAG(1) + ATYP(1) + IPv4(4) + port(2).
    assert!(n > 10, "reply too short: {n} bytes");
    assert_eq!(buf[3], 0x01, "expected an IPv4 address in the reply header");
    assert_eq!(
        &buf[10..n],
        payload,
        "UDP payload should round-trip through the tunnel"
    );
}
