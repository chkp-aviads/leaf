//! Process-global map of `controlKey` -> WireGuard tunnel.
//!
//! This is the seam between the two callers that must agree on one tunnel:
//! leaf's `wireguard` outbound (which needs a stack to dial from) and the C API
//! (which sets the config and reads status). Keying on a string from the leaf
//! config keeps the wg-quick text — and therefore the private key — out of the
//! leaf JSON entirely; Picard supplies it at runtime via `px_wg_set_config`.
//!
//! Tunnels come up **lazily**, on first use. When policy says "no WireGuard"
//! the cost is a config struct and nothing else: no socket, no handshake, no
//! smoltcp buffers. That is the whole point of the exercise, and it also means
//! `set_config` needs no tokio runtime — the connect happens on leaf's runtime,
//! inside the outbound handler that asked for it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::{Mutex as SyncMutex, RwLock};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::config::WgConfig;
use crate::stack::WgStack;
use crate::tunnel::{TunnelError, TunnelState, TunnelStatus, WgTunnel};

/// A live tunnel and its stack. Dropping this aborts the tunnel's tasks and
/// stops the smoltcp reactor, releasing every buffer.
pub struct Live {
    pub tunnel: Arc<WgTunnel>,
    pub stack: WgStack,
    tasks: Vec<JoinHandle<()>>,
}

impl Drop for Live {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        debug!("wireguard tunnel torn down");
    }
}

pub struct WgSlot {
    key: String,
    /// `None` until `px_wg_set_config` supplies a config.
    config: SyncMutex<Option<Arc<WgConfig>>>,
    /// The live tunnel, behind a *sync* lock so status can be read from a
    /// thread with no tokio runtime -- which is exactly where the C API is
    /// called from. Connecting is serialised separately by `connecting`.
    live: RwLock<Option<Arc<Live>>>,
    /// Held across `connect().await` so two concurrent first-uses do not build
    /// two tunnels. Never held while touching `live` for a read.
    connecting: AsyncMutex<()>,
    /// Bumped on every config change, so a stale `Live` is discarded.
    generation: AtomicU64,
    /// The generation the current `Live` was built from.
    live_generation: AtomicU64,
    /// Captured when a tunnel goes live, so the C API can drive async work
    /// (DNS, teardown) from a thread that has no runtime of its own.
    runtime: SyncMutex<Option<tokio::runtime::Handle>>,
}

#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    #[error("no wireguard config has been set for key {0:?}")]
    NotConfigured(String),
    #[error(transparent)]
    Tunnel(#[from] TunnelError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl WgSlot {
    fn new(key: String) -> Self {
        Self {
            key,
            config: SyncMutex::new(None),
            live: RwLock::new(None),
            connecting: AsyncMutex::new(()),
            generation: AtomicU64::new(0),
            live_generation: AtomicU64::new(u64::MAX),
            runtime: SyncMutex::new(None),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// Install a config. Synchronous and validating, so a bad config is
    /// reported to the caller immediately rather than failing later on a
    /// background task. Any live tunnel is dropped; the next use reconnects.
    pub fn set_config(&self, cfg: WgConfig) {
        *self.config.lock() = Some(Arc::new(cfg));
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        info!(key = %self.key, generation, "wireguard config installed");
    }

    pub fn is_configured(&self) -> bool {
        self.config.lock().is_some()
    }

    /// Tear the tunnel down but keep the config, so a later use reconnects.
    /// Synchronous: dropping `Live` aborts its tasks and releases every buffer.
    pub fn stop(&self) {
        if self.live.write().take().is_some() {
            info!(key = %self.key, "wireguard tunnel stopped");
        }
    }

    /// Forget the config too.
    pub fn clear(&self) {
        self.stop();
        *self.config.lock() = None;
    }

    /// A runtime handle captured when the tunnel came up, for callers that have
    /// no runtime of their own (the C API).
    pub fn runtime(&self) -> Option<tokio::runtime::Handle> {
        self.runtime.lock().clone()
    }

    /// The live tunnel if there is one, without connecting. Sync and cheap.
    pub fn current(&self) -> Option<Arc<Live>> {
        let wanted = self.generation.load(Ordering::SeqCst);
        if self.live_generation.load(Ordering::SeqCst) != wanted {
            return None;
        }
        self.live.read().clone()
    }

    /// Get the live tunnel, connecting on first use.
    pub async fn live(&self) -> Result<Arc<Live>, SlotError> {
        let wanted = self.generation.load(Ordering::SeqCst);

        // Fast path: no lock contention for the common case.
        if let Some(live) = self.current() {
            return Ok(live);
        }

        // Slow path. Serialise connects so a burst of first-use requests
        // builds one tunnel rather than one each.
        let _connecting = self.connecting.lock().await;
        if let Some(live) = self.current() {
            return Ok(live);
        }
        // A superseded tunnel is dropped here, releasing its buffers before we
        // allocate the replacement.
        if self.live_generation.load(Ordering::SeqCst) != wanted {
            self.live.write().take();
        }

        let cfg = self
            .config
            .lock()
            .clone()
            .ok_or_else(|| SlotError::NotConfigured(self.key.clone()))?;

        let (tunnel, device, tasks) = WgTunnel::connect(&cfg).await?;
        let stack = WgStack::new(device, &tunnel)?;
        let live = Arc::new(Live {
            tunnel,
            stack,
            tasks,
        });
        *self.runtime.lock() = Some(tokio::runtime::Handle::current());
        self.live_generation.store(wanted, Ordering::SeqCst);
        *self.live.write() = Some(Arc::clone(&live));
        info!(key = %self.key, "wireguard tunnel up");
        Ok(live)
    }

    /// Status without forcing a connection, and without needing a runtime: a
    /// slot that has never been used reports `Down`, which is what
    /// `px_wg_get_status` should say.
    pub fn status(&self) -> TunnelStatus {
        match self.current() {
            Some(live) => live.tunnel.status(),
            None => TunnelStatus {
                state: TunnelState::Down,
                last_handshake: None,
                tx_bytes: 0,
                rx_bytes: 0,
                dropped_inbound: 0,
            },
        }
    }

    /// Called on device wake. boringtun 0.7.1 keeps its timers on `Instant`,
    /// which does not advance across suspend, so we do not trust its notion of
    /// handshake age — we force a fresh one.
    pub async fn wake(&self) {
        match self.current() {
            Some(live) => {
                debug!(key = %self.key, "forcing rekey after wake");
                live.tunnel.begin_handshake(true).await;
            }
            None => warn!(key = %self.key, "wake with no live tunnel; nothing to do"),
        }
    }
}

fn registry() -> &'static SyncMutex<HashMap<String, Arc<WgSlot>>> {
    static REGISTRY: std::sync::OnceLock<SyncMutex<HashMap<String, Arc<WgSlot>>>> =
        std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| SyncMutex::new(HashMap::new()))
}

/// Get or create the slot for `key`.
///
/// Creating on lookup is deliberate: leaf's outbound handler and the C API can
/// arrive in either order, and whichever gets there first should not fail.
pub fn slot(key: &str) -> Arc<WgSlot> {
    let mut map = registry().lock();
    Arc::clone(
        map.entry(key.to_owned())
            .or_insert_with(|| Arc::new(WgSlot::new(key.to_owned()))),
    )
}

/// An existing slot, without creating one.
pub fn existing(key: &str) -> Option<Arc<WgSlot>> {
    registry().lock().get(key).map(Arc::clone)
}

pub fn keys() -> Vec<String> {
    registry().lock().keys().cloned().collect()
}

/// Drop every tunnel but keep the configs. Used by `px_trim_memory` under
/// memory pressure: an idle tunnel's smoltcp buffers are the largest thing we
/// can hand back, and the next request transparently reconnects.
pub fn stop_all() {
    let slots: Vec<Arc<WgSlot>> = registry().lock().values().map(Arc::clone).collect();
    for slot in slots {
        slot.stop();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn slot_is_stable_per_key() {
        let a = slot("test-stable");
        let b = slot("test-stable");
        assert!(Arc::ptr_eq(&a, &b), "the same key must map to the same slot");
        assert_eq!(a.key(), "test-stable");
    }

    #[test]
    fn distinct_keys_are_distinct_slots() {
        let a = slot("test-a");
        let b = slot("test-b");
        assert!(!Arc::ptr_eq(&a, &b));
    }

    #[test]
    fn existing_does_not_create() {
        assert!(existing("test-never-created").is_none());
        let _ = slot("test-now-created");
        assert!(existing("test-now-created").is_some());
    }

    #[tokio::test]
    async fn unconfigured_slot_reports_down_and_refuses_to_connect() {
        let s = slot("test-unconfigured");
        assert!(!s.is_configured());
        assert_eq!(s.status().state, TunnelState::Down);
        match s.live().await {
            Err(SlotError::NotConfigured(k)) => assert_eq!(k, "test-unconfigured"),
            Err(e) => panic!("wrong error: {e}"),
            Ok(_) => panic!("an unconfigured slot must not connect"),
        }
    }

    #[tokio::test]
    async fn setting_a_config_bumps_the_generation() {
        let s = slot("test-generation");
        let cfg = WgConfig::parse(
            "[Interface]\nPrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=\n\
             Address = 10.0.0.2\n[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\n\
             Endpoint = 127.0.0.1:1\n",
        )
        .unwrap();
        assert_eq!(s.generation.load(Ordering::SeqCst), 0);
        s.set_config(cfg.clone());
        assert_eq!(s.generation.load(Ordering::SeqCst), 1);
        assert!(s.is_configured());
        s.set_config(cfg);
        assert_eq!(s.generation.load(Ordering::SeqCst), 2);
        s.clear();
        assert!(!s.is_configured());
    }

    #[tokio::test]
    async fn wake_without_a_tunnel_is_harmless() {
        slot("test-wake-noop").wake().await;
    }
}
