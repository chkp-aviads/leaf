//! wg-quick / wireproxy INI config parsing.
//!
//! Hand-written rather than pulling an INI crate: the format needs
//! case-insensitive keys, repeated `[Peer]` sections and comma lists, which the
//! general-purpose crates handle awkwardly. Roughly 200 lines and no dependency.
//!
//! Deliberate difference from wireproxy: `Endpoint` is kept as a string and
//! resolved when the tunnel starts, not at parse time. wireproxy resolves once
//! via the system resolver in `resolveIPPAndPort` and then never re-resolves,
//! so a roaming server is unreachable until the process restarts.

use std::net::IpAddr;

use base64::Engine as _;

/// Same default as wireproxy (`config.go:487`).
pub const DEFAULT_MTU: u16 = 1420;

/// Hard ceiling on the configured MTU.
///
/// This is a safety bound, not a preference. `Tunn::encapsulate` panics when
/// the destination buffer is smaller than `src.len() + 32`
/// (boringtun `noise/session.rs:198`), and our send buffers are sized
/// `MAX_MTU + 32`. A config declaring a larger MTU would let smoltcp hand us a
/// packet that overflows that buffer and aborts the whole network extension.
pub const MAX_MTU: u16 = 1500;

/// Below the IPv6 minimum link MTU there is no useful traffic, and smoltcp
/// rejects such interfaces anyway.
pub const MIN_MTU: u16 = 1280;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("line {line}: expected `key = value`, got {text:?}")]
    Malformed { line: usize, text: String },
    #[error("line {line}: key {key} outside of any section")]
    OrphanKey { line: usize, key: String },
    #[error("one and only one [Interface] is expected, found {found}")]
    InterfaceCount { found: usize },
    #[error("at least one [Peer] is expected")]
    NoPeers,
    #[error("[{section}] {key}: missing")]
    MissingKey { section: &'static str, key: &'static str },
    #[error("[{section}] {key}: {reason}")]
    BadValue {
        section: &'static str,
        key: &'static str,
        reason: String,
    },
}

/// A WireGuard key. Base64 on the wire, 32 raw bytes in memory.
///
/// `Debug` is redacted on purpose: `WireGuardUAPIConverter.swift` logs whole
/// configs at debug level today, which writes private keys to the log file.
#[derive(Clone, PartialEq, Eq)]
pub struct Key(pub [u8; 32]);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

#[derive(Debug, Clone)]
pub struct PeerConfig {
    pub public_key: Key,
    pub preshared_key: Option<Key>,
    /// `host:port`, unresolved. `None` means "responder only, wait to be dialled".
    pub endpoint: Option<String>,
    /// Seconds. 0 disables, matching wireproxy's default (`config.go:314`).
    pub persistent_keepalive: u16,
    /// Empty means "all", which `CreateIPCRequest` (`wireguard.go:52-55`)
    /// expands to `0.0.0.0/0` + `::/0`.
    pub allowed_ips: Vec<(IpAddr, u8)>,
}

#[derive(Debug, Clone)]
pub struct WgConfig {
    pub private_key: Key,
    /// Interface addresses in config order. May be dual-stack: the wireproxy
    /// corpus has `Address = 100.96.0.190,2606:...:6f5f/128`. May also be empty
    /// (the Harmony test config omits `Address` entirely).
    ///
    /// Prefix lengths are parsed and discarded, matching wireproxy: it keeps
    /// only `prefix.Addr()` and lets the netstack apply a host prefix.
    pub addresses: Vec<IpAddr>,
    pub dns: Vec<IpAddr>,
    pub mtu: u16,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerConfig>,
}

/// One `key = value` pair, tagged with the section it appeared under.
struct Entry {
    key: String,
    value: String,
}

enum Section {
    Interface(Vec<Entry>),
    Peer(Vec<Entry>),
    /// `[Socks5]`, `[http]`, `[TCPClientTunnel]`, ... — parsed and ignored.
    /// Picard's converter may still emit them, and wireproxy tolerated them.
    Other,
}

impl WgConfig {
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let sections = split_sections(text)?;

        let mut interfaces = sections.iter().filter_map(|s| match s {
            Section::Interface(e) => Some(e),
            _ => None,
        });
        let iface = interfaces.next();
        let extra = interfaces.count();
        let iface = match (iface, extra) {
            (Some(i), 0) => i,
            (Some(_), n) => return Err(ConfigError::InterfaceCount { found: n + 1 }),
            (None, _) => return Err(ConfigError::InterfaceCount { found: 0 }),
        };

        let private_key = match lookup(iface, "privatekey") {
            Some(v) => parse_key("Interface", "PrivateKey", v)?,
            None => {
                return Err(ConfigError::MissingKey {
                    section: "Interface",
                    key: "PrivateKey",
                })
            }
        };

        let addresses = match lookup(iface, "address") {
            Some(v) => parse_addr_list("Interface", "Address", v)?,
            None => Vec::new(),
        };
        let dns = match lookup(iface, "dns") {
            Some(v) => parse_addr_list("Interface", "DNS", v)?,
            None => Vec::new(),
        };
        let mtu = match lookup(iface, "mtu") {
            Some(v) => {
                let mtu: u16 = parse_num("Interface", "MTU", v)?;
                if !(MIN_MTU..=MAX_MTU).contains(&mtu) {
                    return Err(ConfigError::BadValue {
                        section: "Interface",
                        key: "MTU",
                        reason: format!("{mtu} is outside {MIN_MTU}..={MAX_MTU}"),
                    });
                }
                mtu
            }
            None => DEFAULT_MTU,
        };
        let listen_port = match lookup(iface, "listenport") {
            Some(v) => Some(parse_num("Interface", "ListenPort", v)?),
            None => None,
        };

        let mut peers = Vec::new();
        for section in &sections {
            let entries = match section {
                Section::Peer(e) => e,
                _ => continue,
            };
            let public_key = match lookup(entries, "publickey") {
                Some(v) => parse_key("Peer", "PublicKey", v)?,
                None => {
                    return Err(ConfigError::MissingKey {
                        section: "Peer",
                        key: "PublicKey",
                    })
                }
            };
            // wireproxy defaults this to an all-zero key (`config.go:312`).
            // boringtun wants `None` for "no PSK", and an all-zero PSK is
            // cryptographically equivalent, so normalise it away.
            let preshared_key = match lookup(entries, "presharedkey") {
                Some(v) => {
                    let k = parse_key("Peer", "PresharedKey", v)?;
                    if k.0 == [0u8; 32] {
                        None
                    } else {
                        Some(k)
                    }
                }
                None => None,
            };
            let allowed_ips = match lookup(entries, "allowedips") {
                Some(v) => parse_prefix_list("Peer", "AllowedIPs", v)?,
                None => Vec::new(),
            };
            let persistent_keepalive = match lookup(entries, "persistentkeepalive") {
                Some(v) => parse_num("Peer", "PersistentKeepalive", v)?,
                None => 0,
            };
            peers.push(PeerConfig {
                public_key,
                preshared_key,
                endpoint: lookup(entries, "endpoint").map(str::to_owned),
                persistent_keepalive,
                allowed_ips,
            });
        }
        if peers.is_empty() {
            return Err(ConfigError::NoPeers);
        }

        Ok(WgConfig {
            private_key,
            addresses,
            dns,
            mtu,
            listen_port,
            peers,
        })
    }
}

fn split_sections(text: &str) -> Result<Vec<Section>, ConfigError> {
    let mut out: Vec<Section> = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = strip_comment(raw);
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.push(match name.trim().to_ascii_lowercase().as_str() {
                "interface" => Section::Interface(Vec::new()),
                "peer" => Section::Peer(Vec::new()),
                _ => Section::Other,
            });
            continue;
        }
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => {
                return Err(ConfigError::Malformed {
                    line: idx + 1,
                    text: line.to_owned(),
                })
            }
        };
        if key.is_empty() {
            return Err(ConfigError::Malformed {
                line: idx + 1,
                text: line.to_owned(),
            });
        }
        let entry = Entry {
            key: key.to_ascii_lowercase(),
            value: value.to_owned(),
        };
        match out.last_mut() {
            Some(Section::Interface(e)) | Some(Section::Peer(e)) => e.push(entry),
            Some(Section::Other) => {}
            None => {
                return Err(ConfigError::OrphanKey {
                    line: idx + 1,
                    key: key.to_owned(),
                })
            }
        }
    }
    Ok(out)
}

/// Strips `#`/`;` comments. Safe against key material: base64 contains neither
/// character, and a comment only starts after whitespace, matching wg-quick.
fn strip_comment(line: &str) -> &str {
    let line = line.trim();
    if line.starts_with('#') || line.starts_with(';') {
        return "";
    }
    let cut = [" #", " ;", "\t#", "\t;"]
        .iter()
        .filter_map(|pat| line.find(pat))
        .min();
    match cut {
        Some(i) => line[..i].trim_end(),
        None => line,
    }
}

fn lookup<'a>(entries: &'a [Entry], key: &str) -> Option<&'a str> {
    entries
        .iter()
        .find(|e| e.key == key)
        .map(|e| e.value.as_str())
        .filter(|v| !v.is_empty())
}

fn parse_key(section: &'static str, key: &'static str, value: &str) -> Result<Key, ConfigError> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|e| ConfigError::BadValue {
            section,
            key,
            reason: format!("not valid base64: {e}"),
        })?;
    let bytes: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| ConfigError::BadValue {
        section,
        key,
        reason: format!("expected 32 bytes, got {}", v.len()),
    })?;
    Ok(Key(bytes))
}

/// `Address`/`DNS`: comma-separated, each item either a bare address or CIDR.
/// The prefix length is accepted and discarded (wireproxy does the same).
fn parse_addr_list(
    section: &'static str,
    key: &'static str,
    value: &str,
) -> Result<Vec<IpAddr>, ConfigError> {
    let mut out = Vec::new();
    for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let addr = item.split('/').next().unwrap_or(item);
        out.push(addr.parse::<IpAddr>().map_err(|e| ConfigError::BadValue {
            section,
            key,
            reason: format!("{item:?} is not an IP address: {e}"),
        })?);
    }
    Ok(out)
}

/// `AllowedIPs`: comma-separated CIDRs. A bare address means a host route.
fn parse_prefix_list(
    section: &'static str,
    key: &'static str,
    value: &str,
) -> Result<Vec<(IpAddr, u8)>, ConfigError> {
    let mut out = Vec::new();
    for item in value.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let (addr_str, prefix_str) = match item.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (item, None),
        };
        let addr: IpAddr = addr_str.parse().map_err(|e| ConfigError::BadValue {
            section,
            key,
            reason: format!("{item:?} is not an IP address: {e}"),
        })?;
        let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
        let prefix = match prefix_str {
            Some(p) => p.trim().parse::<u8>().map_err(|e| ConfigError::BadValue {
                section,
                key,
                reason: format!("{item:?} has a bad prefix length: {e}"),
            })?,
            None => max,
        };
        if prefix > max {
            return Err(ConfigError::BadValue {
                section,
                key,
                reason: format!("{item:?}: prefix /{prefix} exceeds /{max}"),
            });
        }
        out.push((addr, prefix));
    }
    Ok(out)
}

fn parse_num<T: std::str::FromStr>(
    section: &'static str,
    key: &'static str,
    value: &str,
) -> Result<T, ConfigError>
where
    T::Err: std::fmt::Display,
{
    value.trim().parse::<T>().map_err(|e| ConfigError::BadValue {
        section,
        key,
        reason: format!("{value:?} is not a number: {e}"),
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // ---- corpus ported from wireproxy/config_test.go -----------------------
    // Keys below are the ones already published in wireproxy's own public test
    // file; they are test vectors, not credentials.

    /// `TestHarmonySASEWireguardConf`. Note: no `Address`, no `DNS`, and a
    /// trailing `[http]` section that must be tolerated and ignored.
    #[test]
    fn harmony_sase_conf() {
        let cfg = WgConfig::parse(
            "
[Interface]
PrivateKey = uANgA6rh9cZDQLaTH9hqGTVy425OXgfmddukdHhFmHA=
ListenPort = 8000

[Peer]
AllowedIPs = 0.0.0.0/0
PublicKey = olcjjD50ZCemqnqn+Q9kqGAFoaDNE9sURUaXc1XAQFU=
Endpoint = 67.55.94.85:8055
PersistentKeepalive = 0


[http]
BindAddress = 127.0.0.1:52208",
        )
        .expect("harmony config should parse");

        assert_eq!(cfg.listen_port, Some(8000));
        assert_eq!(cfg.mtu, DEFAULT_MTU, "MTU should fall back to the default");
        assert!(cfg.addresses.is_empty(), "this config has no Address");
        assert!(cfg.dns.is_empty());
        assert_eq!(cfg.peers.len(), 1);
        let peer = &cfg.peers[0];
        assert_eq!(peer.endpoint.as_deref(), Some("67.55.94.85:8055"));
        assert_eq!(peer.persistent_keepalive, 0);
        assert_eq!(peer.allowed_ips, vec![("0.0.0.0".parse().unwrap(), 0)]);
        assert!(peer.preshared_key.is_none());
    }

    /// `TestWireguardConfWithoutSubnet` — bare address, no prefix.
    #[test]
    fn address_without_subnet() {
        let cfg = WgConfig::parse(
            "
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25",
        )
        .unwrap();

        assert_eq!(cfg.addresses, vec!["10.5.0.2".parse::<IpAddr>().unwrap()]);
        assert_eq!(cfg.dns, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(cfg.peers[0].persistent_keepalive, 25);
        assert_eq!(
            cfg.peers[0].allowed_ips,
            vec![
                ("0.0.0.0".parse().unwrap(), 0),
                ("::".parse().unwrap(), 0)
            ]
        );
    }

    /// `TestWireguardConfWithSubnet` — the prefix is accepted and discarded,
    /// matching wireproxy's `parseCIDRNetIP` which keeps only `prefix.Addr()`.
    #[test]
    fn address_with_subnet_drops_prefix() {
        let cfg = WgConfig::parse(
            "
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2/23
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820",
        )
        .unwrap();
        assert_eq!(cfg.addresses, vec!["10.5.0.2".parse::<IpAddr>().unwrap()]);
    }

    /// `TestWireguardConfWithManyAddress` — dual-stack, mixed bare/CIDR,
    /// no spaces after the commas.
    #[test]
    fn many_addresses_dual_stack() {
        let cfg = WgConfig::parse(
            "
[Interface]
PrivateKey = mBsVDahr1XIu9PPd17UmsDdB6E53nvmS47NbNqQCiFM=
Address = 100.96.0.190,2606:B300:FFFF:fe8a:2ac6:c7e8:b021:6f5f/128
DNS = 198.18.0.1,198.18.0.2

[Peer]
PublicKey = SHnh4C2aDXhp1gjIqceGhJrhOLSeNYcqWLKcYnzj00U=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 192.200.144.22:51820",
        )
        .unwrap();

        assert_eq!(cfg.addresses.len(), 2);
        assert!(cfg.addresses[0].is_ipv4());
        assert!(cfg.addresses[1].is_ipv6());
        assert_eq!(cfg.dns.len(), 2);
    }

    // ---- edge cases -------------------------------------------------------

    const MINIMAL: &str = "
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
";

    #[test]
    fn minimal_config() {
        let cfg = WgConfig::parse(MINIMAL).unwrap();
        assert_eq!(cfg.peers.len(), 1);
        assert!(cfg.peers[0].endpoint.is_none());
        assert!(
            cfg.peers[0].allowed_ips.is_empty(),
            "empty AllowedIPs stays empty here; the tunnel expands it to \
             0.0.0.0/0 + ::/0 like CreateIPCRequest does"
        );
    }

    #[test]
    fn keys_are_case_insensitive_and_sections_too() {
        let cfg = WgConfig::parse(
            "
[interface]
privatekey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
MTU = 1280
[PEER]
PUBLICKEY = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
",
        )
        .unwrap();
        assert_eq!(cfg.mtu, 1280);
    }

    #[test]
    fn multiple_peers_are_all_kept() {
        let cfg = WgConfig::parse(
            "
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
Endpoint = 1.1.1.1:1
[Peer]
PublicKey = SHnh4C2aDXhp1gjIqceGhJrhOLSeNYcqWLKcYnzj00U=
Endpoint = 2.2.2.2:2
",
        )
        .unwrap();
        assert_eq!(cfg.peers.len(), 2);
        assert_eq!(cfg.peers[1].endpoint.as_deref(), Some("2.2.2.2:2"));
    }

    #[test]
    fn comments_are_stripped() {
        let cfg = WgConfig::parse(
            "
# leading comment
[Interface]   # section comment
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
MTU = 1280 ; trailing semicolon comment
; whole line
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
",
        )
        .unwrap();
        assert_eq!(cfg.mtu, 1280);
    }

    #[test]
    fn base64_padding_is_not_mistaken_for_a_comment() {
        // The `=` padding and `+`/`/` alphabet must survive intact.
        let cfg = WgConfig::parse(MINIMAL).unwrap();
        assert_eq!(cfg.private_key.0.len(), 32);
        assert_ne!(cfg.private_key.0, [0u8; 32]);
    }

    #[test]
    fn all_zero_preshared_key_normalises_to_none() {
        let cfg = WgConfig::parse(&format!(
            "{MINIMAL}PresharedKey = {}\n",
            base64::engine::general_purpose::STANDARD.encode([0u8; 32])
        ))
        .unwrap();
        assert!(
            cfg.peers[0].preshared_key.is_none(),
            "wireproxy defaults PresharedKey to all-zero; boringtun wants None"
        );
    }

    #[test]
    fn real_preshared_key_is_kept() {
        let cfg = WgConfig::parse(&format!(
            "{MINIMAL}PresharedKey = {}\n",
            base64::engine::general_purpose::STANDARD.encode([7u8; 32])
        ))
        .unwrap();
        assert_eq!(cfg.peers[0].preshared_key.as_ref().map(|k| k.0), Some([7u8; 32]));
    }

    #[test]
    fn debug_never_leaks_key_material() {
        let cfg = WgConfig::parse(MINIMAL).unwrap();
        let dumped = format!("{cfg:?}");
        assert!(dumped.contains("<redacted>"));
        assert!(
            !dumped.contains("LAr1aNSNF9d0"),
            "config Debug must not print the private key: {dumped}"
        );
    }

    // ---- rejections -------------------------------------------------------

    #[test]
    fn rejects_missing_interface() {
        assert_eq!(
            WgConfig::parse("[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\n")
                .unwrap_err(),
            ConfigError::InterfaceCount { found: 0 }
        );
    }

    #[test]
    fn rejects_two_interfaces() {
        let text = format!("{MINIMAL}[Interface]\nPrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=\n");
        assert_eq!(
            WgConfig::parse(&text).unwrap_err(),
            ConfigError::InterfaceCount { found: 2 }
        );
    }

    #[test]
    fn rejects_no_peers() {
        assert_eq!(
            WgConfig::parse(
                "[Interface]\nPrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=\n"
            )
            .unwrap_err(),
            ConfigError::NoPeers
        );
    }

    #[test]
    fn rejects_missing_private_key() {
        assert_eq!(
            WgConfig::parse("[Interface]\nMTU = 1400\n[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\n")
                .unwrap_err(),
            ConfigError::MissingKey { section: "Interface", key: "PrivateKey" }
        );
    }

    #[test]
    fn rejects_short_key() {
        let short = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
        let err = WgConfig::parse(&format!("[Interface]\nPrivateKey = {short}\n[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\n"))
            .unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { key: "PrivateKey", .. }), "{err}");
    }

    #[test]
    fn rejects_non_base64_key() {
        let err = WgConfig::parse("[Interface]\nPrivateKey = not!base64\n[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\n")
            .unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { key: "PrivateKey", .. }), "{err}");
    }

    #[test]
    fn rejects_bad_address() {
        let err = WgConfig::parse(&MINIMAL.replace(
            "[Peer]",
            "Address = 999.1.1.1\n[Peer]",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { key: "Address", .. }), "{err}");
    }

    #[test]
    fn rejects_oversized_prefix() {
        let err = WgConfig::parse(&format!("{MINIMAL}AllowedIPs = 10.0.0.0/33\n")).unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { key: "AllowedIPs", .. }), "{err}");
    }

    #[test]
    fn rejects_mtu_above_the_buffer_safety_bound() {
        // An MTU over MAX_MTU would let smoltcp produce a packet that overflows
        // the encapsulate buffer, which is an abort, not an error.
        let err = WgConfig::parse(&MINIMAL.replace("[Peer]", "MTU = 9000\n[Peer]")).unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { key: "MTU", .. }), "{err}");
    }

    #[test]
    fn rejects_absurdly_small_mtu() {
        let err = WgConfig::parse(&MINIMAL.replace("[Peer]", "MTU = 68\n[Peer]")).unwrap_err();
        assert!(matches!(err, ConfigError::BadValue { key: "MTU", .. }), "{err}");
    }

    #[test]
    fn accepts_mtu_at_both_bounds() {
        for mtu in [MIN_MTU, MAX_MTU, DEFAULT_MTU] {
            let cfg = WgConfig::parse(&MINIMAL.replace("[Peer]", &format!("MTU = {mtu}\n[Peer]")))
                .unwrap_or_else(|e| panic!("MTU {mtu} should be accepted: {e}"));
            assert_eq!(cfg.mtu, mtu);
        }
    }

    #[test]
    fn rejects_line_without_equals() {
        let err = WgConfig::parse("[Interface]\ngarbage line\n").unwrap_err();
        assert!(matches!(err, ConfigError::Malformed { line: 2, .. }), "{err}");
    }

    #[test]
    fn rejects_key_before_any_section() {
        let err = WgConfig::parse("PrivateKey = x\n[Interface]\n").unwrap_err();
        assert!(matches!(err, ConfigError::OrphanKey { line: 1, .. }), "{err}");
    }

    #[test]
    fn empty_input_is_an_error_not_a_panic() {
        assert!(WgConfig::parse("").is_err());
        assert!(WgConfig::parse("\n\n   \n").is_err());
    }

    /// Never panic on hostile input — the extension builds with `panic = "abort"`.
    #[test]
    fn fuzz_ish_never_panics() {
        let fragments = [
            "[", "]", "[]", "[Interface", "Interface]", "=", "= =", "a=", "=b",
            "[Peer]", "PrivateKey =", "MTU = -1", "MTU = 99999999999",
            "Address = ,,,", "AllowedIPs = /", "ListenPort = abc", "\0", "\t=\t",
            "[Interface]", "PrivateKey = ====", "DNS = ::::",
        ];
        // Every 3-fragment permutation must return, not unwind.
        for a in fragments {
            for b in fragments {
                for c in fragments {
                    let _ = WgConfig::parse(&format!("{a}\n{b}\n{c}\n"));
                }
            }
        }
    }
}
