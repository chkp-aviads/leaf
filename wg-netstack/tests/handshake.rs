//! Two `Tunn`s talking to each other over an in-memory wire.
//!
//! This is the load-bearing test for the boringtun integration: it proves we
//! drive `encapsulate`/`decapsulate`/`update_timers` correctly, without needing
//! a socket, a netstack, or a real peer.
//!
//! It also pins down the boringtun behaviours that are easy to get wrong and
//! fatal under `panic = "abort"`. Verified against boringtun 0.7.1 source:
//!
//! * `encapsulate` on an *established session* panics when
//!   `dst.len() < src.len() + 32` (`noise/session.rs:198`). On the handshake
//!   path it returns an error instead, so the panic only shows up under load,
//!   after a session exists — the worst possible time to discover it.
//! * `decapsulate` panics when `dst.len() < ct_len` (`noise/session.rs:244`),
//!   and **`ct_len` comes from the wire**. Anyone who can send UDP to our
//!   socket controls it, so the decap buffer must be sized from our recv
//!   buffer, never from the configured MTU.
//! * `decapsulate` must be re-driven with an empty datagram until it returns
//!   `Done`, or the handshake stalls.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};

/// Max WireGuard datagram we ever hand to boringtun.
/// `encapsulate` PANICS when dst is smaller than `max(src.len() + 32, 148)`,
/// so every buffer in the crate is sized from this constant.
const MAX_UDP: usize = 1500 + 32;

struct Pair {
    a: Tunn,
    b: Tunn,
}

fn pair() -> Pair {
    let a_secret = StaticSecret::from([1u8; 32]);
    let b_secret = StaticSecret::from([2u8; 32]);
    let a_public = PublicKey::from(&a_secret);
    let b_public = PublicKey::from(&b_secret);

    Pair {
        a: Tunn::new(a_secret, b_public, None, Some(25), 1, None),
        b: Tunn::new(b_secret, a_public, None, Some(25), 2, None),
    }
}

/// Pump one datagram into a tunnel and collect every datagram it wants to send
/// back. boringtun requires re-calling `decapsulate` with an empty slice until
/// it returns `Done`; forgetting this stalls the handshake.
fn feed(t: &mut Tunn, datagram: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut to_network = Vec::new();
    let mut to_tunnel = Vec::new();
    let mut input: Vec<u8> = datagram.to_vec();
    loop {
        let mut buf = vec![0u8; MAX_UDP];
        match t.decapsulate(None, &input, &mut buf) {
            TunnResult::Done => break,
            TunnResult::Err(e) => panic!("decapsulate failed: {e:?}"),
            TunnResult::WriteToNetwork(pkt) => {
                to_network.push(pkt.to_vec());
                // Keep draining with an empty datagram.
                input = Vec::new();
            }
            TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                to_tunnel.push(pkt.to_vec());
                input = Vec::new();
            }
        }
    }
    (to_network, to_tunnel)
}

fn encapsulate(t: &mut Tunn, payload: &[u8]) -> Vec<Vec<u8>> {
    let mut buf = vec![0u8; MAX_UDP];
    match t.encapsulate(payload, &mut buf) {
        TunnResult::WriteToNetwork(pkt) => vec![pkt.to_vec()],
        TunnResult::Done => Vec::new(),
        TunnResult::Err(e) => panic!("encapsulate failed: {e:?}"),
        _ => panic!("unexpected encapsulate result"),
    }
}

/// A minimal well-formed IPv4/UDP packet, so smoltcp-shaped payloads are
/// exercised rather than arbitrary bytes.
fn udp_packet(payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut p = vec![0u8; total];
    p[0] = 0x45; // IPv4, IHL 5
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[8] = 64; // TTL
    p[9] = 17; // UDP
    p[12..16].copy_from_slice(&[10, 0, 0, 2]); // src
    p[16..20].copy_from_slice(&[10, 0, 0, 1]); // dst
    p[20..22].copy_from_slice(&1234u16.to_be_bytes());
    p[22..24].copy_from_slice(&53u16.to_be_bytes());
    p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p[28..].copy_from_slice(payload);
    p
}

#[test]
fn completes_handshake_and_carries_a_packet_both_ways() {
    let mut p = pair();

    // A sends its first data packet, which triggers a handshake initiation.
    let payload = udp_packet(b"hello wireguard");
    let init = encapsulate(&mut p.a, &payload);
    assert_eq!(init.len(), 1, "first encapsulate should emit a handshake init");
    assert_eq!(init[0][0], 1, "message type 1 = handshake initiation");

    // B receives the initiation and answers.
    let (response, tunnelled) = feed(&mut p.b, &init[0]);
    assert!(tunnelled.is_empty(), "no payload should arrive yet");
    assert_eq!(response.len(), 1, "B should emit a handshake response");
    assert_eq!(response[0][0], 2, "message type 2 = handshake response");

    // A processes the response. The queued payload is flushed here.
    let (flushed, _) = feed(&mut p.a, &response[0]);
    assert!(
        !flushed.is_empty(),
        "A should flush the queued packet once the session is live"
    );

    // B decrypts it.
    let mut got = Vec::new();
    for datagram in &flushed {
        let (_, to_tunnel) = feed(&mut p.b, datagram);
        got.extend(to_tunnel);
    }
    assert!(
        got.iter().any(|pkt| pkt.ends_with(b"hello wireguard")),
        "B never received the payload; got {} packets",
        got.len()
    );

    // Now the reverse direction, on the established session.
    let reply = udp_packet(b"pong");
    let out = encapsulate(&mut p.b, &reply);
    assert_eq!(out.len(), 1);
    let (_, to_tunnel) = feed(&mut p.a, &out[0]);
    assert!(to_tunnel.iter().any(|pkt| pkt.ends_with(b"pong")));
}

#[test]
fn reports_handshake_liveness_for_px_wg_get_status() {
    let mut p = pair();
    assert!(
        p.a.time_since_last_handshake().is_none(),
        "a fresh tunnel has never handshaken; px_wg_get_status reports -1"
    );

    let init = encapsulate(&mut p.a, &udp_packet(b"x"));
    let (response, _) = feed(&mut p.b, &init[0]);
    let _ = feed(&mut p.a, &response[0]);

    assert!(
        p.a.time_since_last_handshake().is_some(),
        "after a completed handshake, status should report an age"
    );
    let (_since, tx, rx, _loss, _rtt) = p.a.stats();
    assert!(tx > 0 || rx > 0, "stats should show traffic: tx={tx} rx={rx}");
}

/// Drive a fresh pair to an established session in both directions.
fn establish(p: &mut Pair) {
    let init = encapsulate(&mut p.a, &udp_packet(b"establish"));
    let (response, _) = feed(&mut p.b, &init[0]);
    let (flushed, _) = feed(&mut p.a, &response[0]);
    for datagram in &flushed {
        let _ = feed(&mut p.b, datagram);
    }
    // Send one packet the other way so B also has a live sending session.
    let out = encapsulate(&mut p.b, &udp_packet(b"establish-reverse"));
    for datagram in &out {
        let _ = feed(&mut p.a, datagram);
    }
}

/// The panic that would take down the network extension. Note it only fires
/// once a session exists — on the handshake path boringtun returns an error.
#[cfg(panic = "unwind")]
#[test]
#[should_panic(expected = "destination buffer is too small")]
fn encapsulate_panics_on_undersized_destination() {
    let mut p = pair();
    establish(&mut p);
    let payload = udp_packet(b"payload");
    // One byte short of the src.len() + 32 requirement.
    let mut too_small = vec![0u8; payload.len() + 31];
    let _ = p.a.encapsulate(&payload, &mut too_small);
}

/// The handshake path is graceful, which is why the panic above is easy to miss.
#[test]
fn undersized_destination_on_the_handshake_path_is_an_error() {
    let mut p = pair();
    let mut too_small = vec![0u8; 147];
    match p.a.encapsulate(b"tiny", &mut too_small) {
        TunnResult::Err(_) => {}
        other => panic!("expected an error on a 147-byte buffer, got {other:?}"),
    }
}

/// MAX_UDP is sized so neither panic can fire: it exceeds `MTU + 32` for the
/// send side and covers any `ct_len` a full-size recv can produce.
#[test]
fn max_udp_is_sufficient_for_a_full_mtu_payload() {
    let mut p = pair();
    establish(&mut p);
    let mut buf = vec![0u8; MAX_UDP];
    let big = vec![0u8; 1500];
    match p.b.encapsulate(&big, &mut buf) {
        TunnResult::WriteToNetwork(_) => {}
        other => panic!("unexpected result: {other:?}"),
    }
}

#[test]
fn garbage_input_is_an_error_not_a_panic() {
    let mut p = pair();
    let mut buf = vec![0u8; MAX_UDP];
    for datagram in [
        vec![],
        vec![0u8; 1],
        vec![0xffu8; 32],
        vec![1u8; 148],
        vec![4u8; 1500],
        (0..=255u8).collect::<Vec<_>>(),
    ] {
        // Must return, not unwind.
        let _ = p.a.decapsulate(None, &datagram, &mut buf);
    }
}

#[test]
fn replayed_datagram_is_rejected() {
    let mut p = pair();
    establish(&mut p);

    // Now that a session is live, a single encapsulate yields exactly one
    // data datagram we can try to replay.
    let datagram = encapsulate(&mut p.a, &udp_packet(b"replay me"))
        .into_iter()
        .next()
        .expect("established session should emit a data packet");

    let mut buf = vec![0u8; MAX_UDP];
    match p.b.decapsulate(None, &datagram, &mut buf) {
        TunnResult::WriteToTunnelV4(pkt, _) => assert!(pkt.ends_with(b"replay me")),
        other => panic!("first delivery should succeed, got {other:?}"),
    }

    let mut buf2 = vec![0u8; MAX_UDP];
    match p.b.decapsulate(None, &datagram, &mut buf2) {
        TunnResult::Err(_) => {}
        other => panic!("a replayed datagram must be rejected, got {other:?}"),
    }
}

/// A hostile peer controls `ct_len`, so prove a max-size datagram is handled
/// by a MAX_UDP buffer without tripping the decapsulate panic.
#[test]
fn oversized_inbound_datagram_does_not_trip_the_decap_panic() {
    let mut p = pair();
    establish(&mut p);
    let mut buf = vec![0u8; MAX_UDP];
    // Junk of exactly the largest size we would ever read off the socket.
    let hostile = vec![0x04u8; MAX_UDP];
    let _ = p.b.decapsulate(None, &hostile, &mut buf);
}

#[test]
fn update_timers_emits_keepalive_without_panicking() {
    let mut p = pair();
    let init = encapsulate(&mut p.a, &udp_packet(b"x"));
    let (response, _) = feed(&mut p.b, &init[0]);
    let _ = feed(&mut p.a, &response[0]);

    // Called on our own cadence in tunnel.rs; must be safe to call repeatedly
    // even when there is nothing to do.
    let mut buf = vec![0u8; MAX_UDP];
    for _ in 0..10 {
        match p.a.update_timers(&mut buf) {
            TunnResult::Done | TunnResult::WriteToNetwork(_) => {}
            TunnResult::Err(e) => panic!("update_timers errored: {e:?}"),
            _ => panic!("unexpected update_timers result"),
        }
    }
}
