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
//! inside whichever caller asked for it.
//!
//! "First use" includes in-tunnel DNS from the C API, not just a proxied
//! connection. The C API has no runtime of its own, so leaf attaches its
//! runtime to the slot when it builds the `wireguard` outbound — at startup,
//! before any traffic. Work that arrives before that is queued, not refused.
//!
//! A tunnel belongs to the runtime that built it: its tasks die with that
//! runtime. So attaching a runtime invalidates any tunnel built on another one,
//! and a tunnel built on a runtime other than the attached one is never
//! published. Without that, a leaf restart (`px_shutdown` returns before the old
//! runtime has exited) could publish a tunnel whose tasks are about to die.

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

/// Work waiting for a runtime; see [`WgSlot::on_runtime`].
type RuntimeJob = Box<dyn FnOnce(tokio::runtime::Handle) + Send>;

#[derive(Default)]
struct RuntimeState {
    handle: Option<tokio::runtime::Handle>,
    /// Identifies the current attachment, so a stale [`RuntimeAttachment`]
    /// cannot detach a newer one. 0 means none.
    attachment: u64,
    next_attachment: u64,
    pending: Vec<RuntimeJob>,
}

/// Returned by [`WgSlot::attach_runtime`]. Dropping it detaches the runtime,
/// unless a newer attachment or a `clear` has replaced it since. Leaf keeps it
/// in the `wireguard` outbound handler, so an instance that fails to start, or
/// exits, does not leave its dead runtime behind for the C API to spawn onto.
#[must_use = "dropping the attachment detaches the runtime immediately"]
pub struct RuntimeAttachment {
    slot: Arc<WgSlot>,
    id: u64,
}

impl Drop for RuntimeAttachment {
    fn drop(&mut self) {
        self.slot.detach_runtime(self.id);
    }
}

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
    /// The runtime that owns this tunnel, so the C API can drive async work
    /// (DNS, wake) from a thread that has no runtime of its own. Attached by
    /// leaf at startup; detached by `clear` or when leaf's instance goes away,
    /// so nothing is spawned onto the runtime of an instance that has shut down.
    runtime: SyncMutex<RuntimeState>,
}

#[derive(Debug, thiserror::Error)]
pub enum SlotError {
    #[error("no wireguard config has been set for key {0:?}")]
    NotConfigured(String),
    #[error("wireguard config or lifecycle changed while connecting key {0:?}")]
    Superseded(String),
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
            runtime: SyncMutex::new(RuntimeState::default()),
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    /// Install a config. Synchronous and validating, so a bad config is
    /// reported to the caller immediately rather than failing later on a
    /// background task. Any live tunnel is dropped; the next use reconnects.
    pub fn set_config(&self, cfg: WgConfig) {
        let generation = {
            let mut config = self.config.lock();
            *config = Some(Arc::new(cfg));
            self.generation.fetch_add(1, Ordering::SeqCst) + 1
        };
        info!(key = %self.key, generation, "wireguard config installed");
    }

    pub fn is_configured(&self) -> bool {
        self.config.lock().is_some()
    }

    /// Tear the tunnel down but keep the config, so a later use reconnects.
    /// Synchronous: dropping `Live` aborts its tasks and releases every buffer.
    pub fn stop(&self) {
        let live = {
            let _config = self.config.lock();
            self.generation.fetch_add(1, Ordering::SeqCst);
            self.live.write().take()
        };
        if live.is_some() {
            info!(key = %self.key, "wireguard tunnel stopped");
        }
    }

    /// Forget the config too, and detach the runtime: `clear` is how the owner
    /// says this tunnel's leaf instance is going away. Queued work is dropped,
    /// which is how its owners learn it will never run.
    pub fn clear(&self) {
        let (pending, live) = {
            let mut runtime = self.runtime.lock();
            let mut config = self.config.lock();
            *config = None;
            self.generation.fetch_add(1, Ordering::SeqCst);
            let live = self.live.write().take();
            runtime.handle = None;
            runtime.attachment = 0;
            (std::mem::take(&mut runtime.pending), live)
        };
        drop(live);
        // Dropped outside the lock: a job's drop may call back into its owner.
        drop(pending);
    }

    /// The attached runtime, for callers that have none of their own (the C API).
    pub fn runtime(&self) -> Option<tokio::runtime::Handle> {
        self.runtime.lock().handle.clone()
    }

    /// Attach the runtime that owns this tunnel, and run any work that was
    /// waiting for one. Called by leaf when it builds the `wireguard` outbound;
    /// keep the returned attachment for as long as that runtime runs.
    ///
    /// Any tunnel built on a previous runtime is dropped: its tasks live on that
    /// runtime, so once a new owner takes over it is, or soon will be, dead.
    pub fn attach_runtime(self: &Arc<Self>, handle: tokio::runtime::Handle) -> RuntimeAttachment {
        let (id, pending, live) = {
            let mut runtime = self.runtime.lock();
            let _config = self.config.lock();
            runtime.next_attachment += 1;
            runtime.attachment = runtime.next_attachment;
            runtime.handle = Some(handle.clone());
            self.generation.fetch_add(1, Ordering::SeqCst);
            let live = self.live.write().take();
            (runtime.attachment, std::mem::take(&mut runtime.pending), live)
        };
        drop(live);
        if !pending.is_empty() {
            debug!(key = %self.key, queued = pending.len(), "runtime attached; running queued work");
        }
        for job in pending {
            job(handle.clone());
        }
        RuntimeAttachment {
            slot: Arc::clone(self),
            id,
        }
    }

    /// Undo attachment `id`, if it is still the current one. Its tunnel goes
    /// with it, for the same reason as in `attach_runtime`.
    fn detach_runtime(&self, id: u64) {
        let live = {
            let mut runtime = self.runtime.lock();
            if runtime.attachment != id {
                return;
            }
            let _config = self.config.lock();
            runtime.attachment = 0;
            runtime.handle = None;
            self.generation.fetch_add(1, Ordering::SeqCst);
            self.live.write().take()
        };
        drop(live);
        debug!(key = %self.key, "runtime detached");
    }

    /// Run `job` with the attached runtime, now if there is one, otherwise as
    /// soon as one is attached. This closes the gap between Picard installing a
    /// config and leaf's runtime existing: a request in that window waits for
    /// leaf instead of failing. Unconfigured work is dropped unrun, and so is
    /// queued work on `clear`; dropping it is how its owner learns it never ran.
    pub fn on_runtime(&self, job: impl FnOnce(tokio::runtime::Handle) + Send + 'static) {
        let mut runtime = self.runtime.lock();
        if !self.is_configured() {
            drop(runtime);
            drop(job);
            return;
        }
        match runtime.handle.clone() {
            Some(handle) => {
                drop(runtime);
                job(handle);
            }
            None => runtime.pending.push(Box::new(job)),
        }
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
        let (cfg, wanted) = {
            let config = self.config.lock();
            let cfg = config
                .clone()
                .ok_or_else(|| SlotError::NotConfigured(self.key.clone()))?;
            (cfg, self.generation.load(Ordering::SeqCst))
        };
        // A superseded tunnel is dropped here, releasing its buffers before we
        // allocate the replacement.
        if self.live_generation.load(Ordering::SeqCst) != wanted {
            self.live.write().take();
        }

        // The tunnel's tasks are spawned on whichever runtime we are on.
        let built_on = tokio::runtime::Handle::current().id();
        let (tunnel, device, tasks) = WgTunnel::connect(&cfg).await?;
        let stack = WgStack::with_limits(device, &tunnel, cfg.limits)?;
        let live = Arc::new(Live {
            tunnel,
            stack,
            tasks,
        });
        self.publish_live(wanted, built_on, live)
    }

    /// Publish `live` unless the config or lifecycle moved on while it was being
    /// built, or it was built on a runtime other than the attached one (the old
    /// leaf instance, still winding down after a restart). With no runtime
    /// attached -- standalone use, or the gap before the new instance attaches
    /// -- it is published, and the next `attach_runtime` drops it if stale.
    fn publish_live(
        &self,
        wanted: u64,
        built_on: tokio::runtime::Id,
        live: Arc<Live>,
    ) -> Result<Arc<Live>, SlotError> {
        {
            let runtime = self.runtime.lock();
            let config = self.config.lock();
            let foreign = runtime.handle.as_ref().is_some_and(|h| h.id() != built_on);
            if config.is_none() || self.generation.load(Ordering::SeqCst) != wanted || foreign {
                return Err(SlotError::Superseded(self.key.clone()));
            }
            self.live_generation.store(wanted, Ordering::SeqCst);
            *self.live.write() = Some(Arc::clone(&live));
        }
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

    fn config() -> WgConfig {
        WgConfig::parse(
            "[Interface]\nPrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=\n\
             Address = 10.0.0.2\n[Peer]\nPublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=\n\
             Endpoint = 127.0.0.1:1\n",
        )
        .unwrap()
    }

    #[test]
    fn slot_is_stable_per_key() {
        let a = slot("test-stable");
        let b = slot("test-stable");
        assert!(
            Arc::ptr_eq(&a, &b),
            "the same key must map to the same slot"
        );
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
        let cfg = config();
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
    async fn work_waits_for_a_runtime_and_clear_detaches_it() {
        use std::sync::atomic::AtomicUsize;
        let s = slot("test-runtime");
        s.set_config(config());
        let ran = Arc::new(AtomicUsize::new(0));
        let job = |ran: &Arc<AtomicUsize>| {
            let ran = Arc::clone(ran);
            move |_: tokio::runtime::Handle| {
                ran.fetch_add(1, Ordering::SeqCst);
            }
        };

        assert!(s.runtime().is_none());
        s.on_runtime(job(&ran));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            0,
            "no runtime yet: the job must wait"
        );

        let _attached = s.attach_runtime(tokio::runtime::Handle::current());
        assert_eq!(ran.load(Ordering::SeqCst), 1, "attaching runs queued work");
        s.on_runtime(job(&ran));
        assert_eq!(
            ran.load(Ordering::SeqCst),
            2,
            "with a runtime, work runs at once"
        );

        // `clear` means the owning leaf instance is going away: forget its
        // runtime, and drop queued work rather than ever running it.
        s.clear();
        assert!(s.runtime().is_none());
        s.set_config(config());
        s.on_runtime(job(&ran));
        let dropped = Arc::new(());
        let witness = Arc::clone(&dropped);
        s.on_runtime(move |_| drop(witness));
        s.clear();
        assert_eq!(
            Arc::strong_count(&dropped),
            1,
            "clear must drop queued work"
        );
        let _attached = s.attach_runtime(tokio::runtime::Handle::current());
        assert_eq!(
            ran.load(Ordering::SeqCst),
            2,
            "work dropped by clear never runs"
        );
        s.clear();
    }

    #[tokio::test]
    async fn work_submitted_after_clear_is_dropped() {
        let s = slot("test-runtime-after-clear");
        s.set_config(config());
        s.clear();
        let dropped = Arc::new(());
        let witness = Arc::clone(&dropped);
        s.on_runtime(move |_| drop(witness));
        assert_eq!(Arc::strong_count(&dropped), 1);
    }

    #[tokio::test]
    async fn stale_connect_cannot_restore_a_stopped_or_cleared_tunnel() {
        let s = slot("test-stale-connect");
        s.set_config(config());
        let live = s.live().await.unwrap();
        let generation = s.generation.load(Ordering::SeqCst);
        s.stop();
        assert!(matches!(
            s.publish_live(generation, tokio::runtime::Handle::current().id(), Arc::clone(&live)),
            Err(SlotError::Superseded(_))
        ));
        assert!(s.current().is_none());

        s.clear();
        assert!(matches!(
            s.publish_live(generation, tokio::runtime::Handle::current().id(), live),
            Err(SlotError::Superseded(_))
        ));
        assert!(s.current().is_none());
        assert!(s.runtime().is_none());
    }

    /// A leaf instance that exits, or fails to start, takes its runtime with it.
    /// Only the current attachment may detach: an older instance winding down
    /// after a restart must not detach its replacement.
    #[tokio::test]
    async fn only_the_current_attachment_detaches() {
        let s = slot("test-attachment");
        let first = s.attach_runtime(tokio::runtime::Handle::current());
        assert!(s.runtime().is_some());
        drop(first);
        assert!(s.runtime().is_none(), "dropping the attachment detaches");

        let old = s.attach_runtime(tokio::runtime::Handle::current());
        let new = s.attach_runtime(tokio::runtime::Handle::current());
        drop(old);
        assert!(s.runtime().is_some(), "a superseded attachment must not detach");

        s.clear();
        let after_clear = s.attach_runtime(tokio::runtime::Handle::current());
        drop(new);
        assert!(s.runtime().is_some(), "an attachment from before clear is stale");
        drop(after_clear);
        assert!(s.runtime().is_none());
    }

    /// A leaf restart: `px_shutdown` returns before the old runtime exits, so a
    /// connect can still run there after the new instance exists. Whichever
    /// order the old runtime's publish and the new runtime's attach happen in,
    /// a tunnel whose tasks live on the old runtime must not end up current.
    #[tokio::test]
    async fn a_tunnel_from_a_previous_runtime_never_ends_up_current() {
        let s = slot("test-foreign-runtime");
        s.set_config(config());
        // The replacement instance's runtime. Built and dropped off this one,
        // because tokio refuses to drop a runtime from async context.
        let other = std::thread::spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap()
        })
        .join()
        .unwrap();

        // New owner attached first: our connect is refused outright.
        let attached = s.attach_runtime(other.handle().clone());
        assert!(matches!(s.live().await, Err(SlotError::Superseded(_))));
        assert!(s.current().is_none());
        drop(attached);

        // Our connect published first (nothing attached): attaching drops it.
        let live = s.live().await.unwrap();
        assert!(s.current().is_some());
        let _attached = s.attach_runtime(other.handle().clone());
        assert!(
            s.current().is_none(),
            "a new owner must drop the previous runtime's tunnel"
        );
        drop(live);
        s.clear();
        std::thread::spawn(move || drop(other)).join().unwrap();
    }

    #[tokio::test]
    async fn wake_without_a_tunnel_is_harmless() {
        slot("test-wake-noop").wake().await;
    }
}
