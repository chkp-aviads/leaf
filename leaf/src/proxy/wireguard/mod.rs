//! WireGuard outbound: sends a session's traffic through a userspace WireGuard
//! tunnel, replacing the Go wireproxy library.
//!
//! The tunnel itself lives in the `wg-netstack` crate, keyed by a `controlKey`
//! string from the outbound settings. The wg-quick config — and therefore the
//! private key — is supplied at runtime over the C API, never through the leaf
//! config, so it never lands in a config file or a log line.

#[cfg(feature = "outbound-wireguard")]
pub mod outbound;
