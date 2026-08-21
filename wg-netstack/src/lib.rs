//! Userspace WireGuard with a dial-capable TCP/IP stack.
//!
//! Replaces the Go wireproxy library. The external contract is the same — dial
//! TCP/UDP and resolve DNS from *inside* a WireGuard tunnel configured by a
//! wg-quick file — but the SOCKS5/HTTP front end is left to leaf, which already
//! implements it.
//!
//! This crate deliberately contains no leaf types so it can be tested standalone.

// The extension links with `panic = "abort"`, so an unwrap on hostile input is
// a crash of the whole network extension, not a failed request.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![deny(clippy::indexing_slicing)]

pub mod clock;
pub mod config;
pub mod registry;
pub mod resolve;
pub mod stack;

/// In-process WireGuard peer for tests. Never compiled into a shipped build.
#[cfg(feature = "test-harness")]
pub mod testpeer;
pub mod tunnel;

pub use config::{ConfigError, Key, PeerConfig, WgConfig};
pub use registry::{Live, SlotError, WgSlot};
pub use resolve::{HostRecord, ResolveError};
pub use stack::WgStack;
pub use tunnel::{TunnelError, TunnelState, TunnelStatus, WgDevice, WgTunnel};
