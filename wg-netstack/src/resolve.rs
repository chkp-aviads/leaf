//! DNS resolution *through* the tunnel.
//!
//! This is what `wgResolveDNS` did in the Go build, and what Picard's
//! `VPNDNSResolver` consumes via `SASEVPNProtocol.resolveDNSRecords`. That Swift
//! contract is `[(ip: String, ttl: Int)]`, which is why TTLs are carried here
//! rather than being dropped — leaf's own `DnsClient::lookup` returns bare
//! `IpAddr`s and could not satisfy it.
//!
//! Queries go to the servers from `[Interface] DNS`, over UDP port 53, inside
//! the tunnel — the same thing wireproxy's netstack did in `exchange`.

use std::net::IpAddr;
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RData, RecordType};
use tracing::{debug, trace};

use crate::stack::WgStack;

/// Per-attempt timeout. wireproxy's netstack used 5 s; Picard imposes its own
/// deadline on top via `CPNEUrlfPolicy.dnsTimeout`.
const QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Attempts per server before moving to the next one.
const ATTEMPTS_PER_SERVER: usize = 2;

/// A resolved address and the TTL the server reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostRecord {
    pub ip: IpAddr,
    pub ttl: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("no DNS servers configured in [Interface] DNS")]
    NoServers,
    #[error("{0:?} is not a valid DNS name: {1}")]
    BadName(String, String),
    #[error("all DNS servers failed or timed out")]
    NoResponse,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Query IDs. Inside an authenticated, encrypted tunnel there is no off-path
/// attacker to spoof a response, so a counter seeded from the clock is
/// sufficient and avoids a `rand` dependency.
fn next_query_id() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    static SEEDED: std::sync::OnceLock<u16> = std::sync::OnceLock::new();
    let seed = *SEEDED.get_or_init(|| {
        // Low bits of the monotonic clock; only needs to differ per process.
        let now = crate::clock::now();
        (format!("{now:?}").len() as u16).wrapping_mul(2654) ^ 0x9E37
    });
    seed.wrapping_add(NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Resolve `host` inside the tunnel.
///
/// `ipv4` selects the record type: `true` queries A, `false` queries AAAA.
/// There is no "both" mode, matching the Go `wgResolveDNS` contract that
/// Picard's `resolveDNSRecords(host:ipv4:)` is built on.
pub async fn resolve(
    stack: &WgStack,
    servers: &[IpAddr],
    host: &str,
    ipv4: bool,
) -> Result<Vec<HostRecord>, ResolveError> {
    // A literal address needs no query. wireproxy's netstack short-circuits the
    // same way, reporting TTL 0.
    if let Ok(ip) = host.parse::<IpAddr>() {
        if ip.is_ipv4() == ipv4 {
            return Ok(vec![HostRecord { ip, ttl: 0 }]);
        }
        // Right literal, wrong family: an empty answer, not an error. This
        // mirrors the fork's `LookupContextHostWithIPVersion` guard.
        return Ok(Vec::new());
    }

    if servers.is_empty() {
        return Err(ResolveError::NoServers);
    }

    let record_type = if ipv4 {
        RecordType::A
    } else {
        RecordType::AAAA
    };

    // `Name::from_utf8` rejects the malformed input we must not panic on.
    let name = Name::from_utf8(host)
        .map_err(|e| ResolveError::BadName(host.to_owned(), e.to_string()))?;

    let mut message = Message::new();
    message
        .set_id(next_query_id())
        .set_message_type(MessageType::Query)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(true)
        .add_query(Query::query(name, record_type));
    let query_id = message.id();
    let wire = message
        .to_vec()
        .map_err(|e| ResolveError::BadName(host.to_owned(), e.to_string()))?;

    // One in-tunnel socket for the whole resolution, reused across servers.
    let socket = stack.bind_udp().await?;
    let mut buf = vec![0u8; 1232]; // EDNS-free UDP answers fit well inside this.

    for server in servers {
        // Skip servers whose family the tunnel cannot source packets for,
        // rather than failing the whole resolution.
        if server.is_ipv4() != stack.source_address().is_ipv4() {
            trace!(%server, "skipping DNS server of a different family");
            continue;
        }
        let target = std::net::SocketAddr::new(*server, 53);

        for attempt in 0..ATTEMPTS_PER_SERVER {
            if let Err(e) = socket.send_to(&wire, target).await {
                debug!(%server, "DNS send failed: {e}");
                break;
            }
            let recv = tokio::time::timeout(QUERY_TIMEOUT, socket.recv_from(&mut buf)).await;
            let n = match recv {
                Ok(Ok((n, _from))) => n,
                Ok(Err(e)) => {
                    debug!(%server, attempt, "DNS recv failed: {e}");
                    continue;
                }
                Err(_) => {
                    debug!(%server, attempt, "DNS query timed out");
                    continue;
                }
            };
            let Some(payload) = buf.get(..n) else { continue };
            let response = match Message::from_vec(payload) {
                Ok(m) => m,
                Err(e) => {
                    debug!(%server, "malformed DNS response: {e}");
                    continue;
                }
            };
            if response.id() != query_id {
                trace!("ignoring DNS response with a mismatched id");
                continue;
            }
            // NXDOMAIN and NoError-with-no-answers are both "no records",
            // reported as an empty list rather than an error. wireproxy's fork
            // behaves the same way, so Picard's fallback chain is unchanged.
            if response.response_code() != ResponseCode::NoError {
                trace!(code = ?response.response_code(), "DNS server returned an error code");
                return Ok(Vec::new());
            }

            let mut out = Vec::new();
            for record in response.answers() {
                let ttl = record.ttl();
                match record.data() {
                    Some(RData::A(a)) if ipv4 => out.push(HostRecord {
                        ip: IpAddr::V4(a.0),
                        ttl,
                    }),
                    Some(RData::AAAA(a)) if !ipv4 => out.push(HostRecord {
                        ip: IpAddr::V6(a.0),
                        ttl,
                    }),
                    // CNAMEs in the chain are followed by the recursive
                    // resolver; we only need the address records it returned.
                    _ => {}
                }
            }
            debug!(host, ipv4, found = out.len(), "resolved in-tunnel");
            return Ok(out);
        }
    }

    Err(ResolveError::NoResponse)
}

/// The JSON shape the C API hands to Swift: `[{"ip":"1.2.3.4","ttl":300}]`.
///
/// Hand-rolled rather than pulling serde: the shape is fixed and two fields
/// wide, and `HostRecord` is the only thing that ever crosses this boundary.
pub fn records_to_json(records: &[HostRecord]) -> String {
    let mut out = String::from("[");
    for (i, r) in records.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        // IpAddr's Display never emits a character needing JSON escaping.
        out.push_str(&format!("{{\"ip\":\"{}\",\"ttl\":{}}}", r.ip, r.ttl));
    }
    out.push(']');
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn json_matches_the_swift_contract() {
        let records = vec![
            HostRecord {
                ip: "1.2.3.4".parse().unwrap(),
                ttl: 300,
            },
            HostRecord {
                ip: "2606:4700::1111".parse().unwrap(),
                ttl: 60,
            },
        ];
        assert_eq!(
            records_to_json(&records),
            r#"[{"ip":"1.2.3.4","ttl":300},{"ip":"2606:4700::1111","ttl":60}]"#
        );
    }

    #[test]
    fn empty_records_are_an_empty_json_array() {
        assert_eq!(records_to_json(&[]), "[]");
    }

    #[test]
    fn query_ids_are_distinct() {
        let a = next_query_id();
        let b = next_query_id();
        assert_ne!(a, b);
    }
}
