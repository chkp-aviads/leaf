//! The C API Picard links against.
//!
//! Replaces the Go build's `wgProxyTurnOn` / `wgResolveDNS` / `wgSetLogger` /
//! `tunConnect` surface. Differences from that API, and why:
//!
//! * Tunnels are named by a `controlKey` string, not an `int32` handle. The
//!   Go side kept an unsynchronised `map[int32]tunnelHandle` with handle reuse
//!   and several functions that nil-dereferenced on a stale handle; there is no
//!   handle table here to get wrong.
//! * The wg-quick config is supplied here, at runtime, rather than embedded in
//!   a leaf config — so no private key is ever written to a config file.
//! * `px_wg_get_status` replaces the health-check HTTP server and the
//!   `CheckAlive` ICMP pings: handshake age and byte counters come free from
//!   the WireGuard state machine.
//!
//! ## Threading contract
//!
//! * `px_start` **blocks until shutdown**. Call it on a dedicated thread.
//! * `px_shutdown` must **not** be called from a thread running a tokio
//!   runtime (`leaf::shutdown` uses `blocking_send`, which panics there). A
//!   Swift thread is fine.
//! * Everything else is safe to call from any thread.
//!
//! Error codes are negative; 0 means success.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicI32, Ordering};

use leaf::config::json;

use crate::logger;

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const PX_OK: i32 = 0;
/// A required string argument was null or not valid UTF-8.
pub const PX_ERR_BAD_ARGUMENT: i32 = -1;
/// The leaf JSON config did not parse. The reason is logged.
pub const PX_ERR_BAD_CONFIG: i32 = -2;
/// The wg-quick config did not parse. The reason is logged.
pub const PX_ERR_BAD_WG_CONFIG: i32 = -3;
/// No wg-quick config has been installed for this key yet.
pub const PX_ERR_NOT_CONFIGURED: i32 = -4;
/// The tunnel is configured but not currently up.
pub const PX_ERR_NOT_RUNNING: i32 = -5;
/// leaf itself failed to start; see the log.
pub const PX_ERR_START_FAILED: i32 = -6;
/// A required output pointer was null.
pub const PX_ERR_NULL_OUT: i32 = -7;

fn cstr<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    // SAFETY: caller contract is a NUL-terminated string valid for this call.
    unsafe { CStr::from_ptr(p) }.to_str().ok()
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Register the log callback. Pass `None`/NULL to stop delivery.
///
/// The `msg` pointer is only valid for the duration of the call — copy it.
/// `min_level`: 0 trace, 1 debug, 2 info, 3 warn, 4 error, 5 off.
///
/// # Safety
/// `f` must be a valid C function pointer of the documented signature, or null.
#[no_mangle]
pub unsafe extern "C" fn px_set_logger(
    f: Option<extern "C" fn(level: c_int, msg: *const c_char)>,
    min_level: c_int,
) {
    logger::install();
    logger::set_callback(f, min_level);
    tracing::info!("logger installed at level {min_level}");
}

/// Change the level floor without re-registering the callback.
#[no_mangle]
pub extern "C" fn px_set_log_level(min_level: c_int) {
    logger::set_min_level(min_level);
}

// ---------------------------------------------------------------------------
// leaf lifecycle
// ---------------------------------------------------------------------------

/// Start a leaf instance from a JSON config. **Blocks until shutdown.**
///
/// # Safety
/// `json_config` must be a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn px_start(rt_id: u16, json_config: *const c_char) -> c_int {
    let Some(text) = cstr(json_config) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    logger::install();

    // Parse as JSON explicitly rather than via `leaf::config::from_string`,
    // which swallows the serde error and silently retries with the `.conf`
    // parser — so one typo in JSON surfaces as a nonsensical `.conf` syntax
    // error. This way the real diagnostic reaches the log.
    let mut config = match json::json_from_string(text) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("leaf config is not valid JSON: {e}");
            return PX_ERR_BAD_CONFIG;
        }
    };

    // Force leaf's own logger off. With `level: none` leaf installs no
    // subscriber at all (`app/logger.rs:193` returns early), leaving ours as
    // the only one — so it receives leaf's events too, with levels intact.
    // Doing it here rather than documenting it means a caller cannot get it
    // wrong, and two instances cannot fight over the global subscriber.
    config.log = Some(json::Log {
        level: Some("none".to_string()),
        output: None,
        format: None,
    });

    let internal = match json::to_internal(config) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("leaf config rejected: {e}");
            return PX_ERR_BAD_CONFIG;
        }
    };

    let opts = leaf::StartOptions {
        config: leaf::Config::Internal(internal),
        #[cfg(feature = "auto-reload")]
        auto_reload: false,
        runtime_opt: leaf::RuntimeOption::SingleThread,
    };
    tracing::info!("starting leaf instance {rt_id}");
    match leaf::start(rt_id, opts) {
        Ok(()) => {
            tracing::info!("leaf instance {rt_id} stopped");
            PX_OK
        }
        Err(e) => {
            tracing::error!("leaf instance {rt_id} failed: {e}");
            PX_ERR_START_FAILED
        }
    }
}

/// Ask a leaf instance to stop. Returns false if it was not running.
///
/// Must not be called from a thread with an active tokio runtime.
#[no_mangle]
pub extern "C" fn px_shutdown(rt_id: u16) -> bool {
    leaf::shutdown(rt_id)
}

#[no_mangle]
pub extern "C" fn px_is_running(rt_id: u16) -> bool {
    leaf::is_running(rt_id)
}

// ---------------------------------------------------------------------------
// WireGuard control
// ---------------------------------------------------------------------------

/// Install (or replace) the wg-quick config for `key`.
///
/// Validated synchronously, so a bad config is reported here rather than
/// failing later on a background task. The tunnel itself comes up lazily on
/// first use, so this allocates nothing beyond the parsed config: when policy
/// never routes anything to WireGuard, there is no socket and no handshake.
///
/// # Safety
/// Both arguments must be NUL-terminated UTF-8 strings.
#[no_mangle]
pub unsafe extern "C" fn px_wg_set_config(
    key: *const c_char,
    wg_quick_conf: *const c_char,
) -> c_int {
    let (Some(key), Some(conf)) = (cstr(key), cstr(wg_quick_conf)) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    match wg_netstack::WgConfig::parse(conf) {
        Ok(cfg) => {
            wg_netstack::registry::slot(key).set_config(cfg);
            PX_OK
        }
        Err(e) => {
            // Deliberately does not log the config text: it carries a private key.
            tracing::error!("wireguard config for {key} rejected: {e}");
            PX_ERR_BAD_WG_CONFIG
        }
    }
}

/// Tear the tunnel down, keeping the config so a later request reconnects.
///
/// # Safety
/// `key` must be a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn px_wg_stop(key: *const c_char) -> c_int {
    let Some(key) = cstr(key) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    match wg_netstack::registry::existing(key) {
        Some(slot) => {
            slot.stop();
            PX_OK
        }
        None => PX_ERR_NOT_CONFIGURED,
    }
}

/// Forget the tunnel and its config entirely.
///
/// # Safety
/// `key` must be a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn px_wg_clear(key: *const c_char) -> c_int {
    let Some(key) = cstr(key) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    match wg_netstack::registry::existing(key) {
        Some(slot) => {
            slot.clear();
            PX_OK
        }
        None => PX_ERR_NOT_CONFIGURED,
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PxWgStatus {
    /// Milliseconds since the last completed handshake, or -1 if never.
    pub last_handshake_ms_ago: i64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    /// Inbound packets dropped because the stack was behind. Non-zero here is
    /// the signal to raise the queue depth.
    pub dropped_inbound: u64,
    /// 0 down, 1 handshaking, 2 up.
    pub state: i32,
    /// True once a config has been installed, whether or not the tunnel is up.
    pub configured: bool,
}

/// Read tunnel status. Never blocks and needs no runtime.
///
/// # Safety
/// `key` must be a NUL-terminated UTF-8 string; `out` must be a valid,
/// writable `PxWgStatus`.
#[no_mangle]
pub unsafe extern "C" fn px_wg_get_status(key: *const c_char, out: *mut PxWgStatus) -> c_int {
    let Some(key) = cstr(key) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    if out.is_null() {
        return PX_ERR_NULL_OUT;
    }
    let Some(slot) = wg_netstack::registry::existing(key) else {
        return PX_ERR_NOT_CONFIGURED;
    };
    let status = slot.status();
    let value = PxWgStatus {
        last_handshake_ms_ago: status
            .last_handshake
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(-1),
        tx_bytes: status.tx_bytes,
        rx_bytes: status.rx_bytes,
        dropped_inbound: status.dropped_inbound,
        state: status.state as i32,
        configured: slot.is_configured(),
    };
    // SAFETY: `out` checked non-null above; caller guarantees it is writable.
    unsafe { out.write(value) };
    PX_OK
}

/// Device is going to sleep. Releases the tunnel's buffers; the next request
/// reconnects.
///
/// # Safety
/// `key` must be a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn px_wg_sleep(key: *const c_char) -> c_int {
    let Some(key) = cstr(key) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    match wg_netstack::registry::existing(key) {
        Some(slot) => {
            slot.stop();
            PX_OK
        }
        None => PX_ERR_NOT_CONFIGURED,
    }
}

/// Device woke up: force a fresh handshake.
///
/// boringtun 0.7.1 keeps its timers on `Instant`, which does not advance while
/// the device is suspended, so its idea of handshake age is wrong after a
/// resume. Rather than patch boringtun we simply re-key. Harmless if the tunnel
/// is already healthy, and a no-op if it is not up.
///
/// # Safety
/// `key` must be a NUL-terminated UTF-8 string.
#[no_mangle]
pub unsafe extern "C" fn px_wg_wake(key: *const c_char) -> c_int {
    let Some(key) = cstr(key) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    let Some(slot) = wg_netstack::registry::existing(key) else {
        return PX_ERR_NOT_CONFIGURED;
    };
    let Some(handle) = slot.runtime() else {
        return PX_ERR_NOT_RUNNING;
    };
    handle.spawn(async move { slot.wake().await });
    PX_OK
}

// ---------------------------------------------------------------------------
// DNS through the tunnel
// ---------------------------------------------------------------------------

/// Receives `[{"ip":"1.2.3.4","ttl":300}]`, or NULL on failure.
///
/// The string is freed as soon as the callback returns, so copy it. This is the
/// same contract as the Go build, whose callback string was freed by Go on
/// return — `HarmonySASEVPN.resolveDNS` already copies.
pub type DnsCallback = extern "C" fn(json: *const c_char, user_data: *mut c_void);

static NEXT_REQUEST_ID: AtomicI32 = AtomicI32::new(1);

/// A fresh request id, always > 0. Wrapping into 0 or negative would break the
/// contract the caller relies on to decide who releases `user_data`: a
/// non-positive return means "the callback will never fire".
fn next_request_id() -> i32 {
    NEXT_REQUEST_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
            Some(if id == i32::MAX { 1 } else { id + 1 })
        })
        .unwrap_or_else(|id| id)
}

/// Carries the caller's opaque `user_data` across a task boundary.
///
/// Declared at module scope with an accessor on purpose: with edition 2021's
/// disjoint closure capture, an async block that touches `wrapper.0` directly
/// captures the raw pointer rather than the wrapper, and the pointer is not
/// `Send`. Going through a method forces the whole struct to be captured.
struct UserData(*mut c_void);

// SAFETY: the pointer is opaque to us. We never dereference it, only hand it
// straight back to the caller's callback, which is what it was given for.
unsafe impl Send for UserData {}

impl UserData {
    fn raw(&self) -> *mut c_void {
        self.0
    }
}

/// One resolve, from `px_wg_resolve` until its callback fires.
///
/// The callback fires **exactly once**, whatever happens: with the answer, or
/// NULL on failure, on cancel, or when the request is dropped without running
/// (`px_wg_clear` before leaf attached a runtime, or a runtime that shut down
/// under it). The caller retains `user_data` for the callback to release, so a
/// callback that never fires is a leak and a caller left waiting on a timeout.
struct DnsRequest {
    id: i32,
    reply: parking_lot::Mutex<Option<(DnsCallback, UserData)>>,
    task: parking_lot::Mutex<Option<tokio::task::AbortHandle>>,
}

impl DnsRequest {
    /// Fire the callback, unless it already fired. Returns whether this call fired it.
    fn reply(&self, json: Option<CString>) -> bool {
        // Taken under the lock, called outside it: the callback is foreign code.
        let Some((cb, user_data)) = self.reply.lock().take() else {
            return false;
        };
        match json {
            Some(s) => cb(s.as_ptr(), user_data.raw()),
            // NULL on any failure, matching the Go behaviour Picard's
            // VPNDNSResolver already treats as "fall through to the next
            // resolver in the chain".
            None => cb(std::ptr::null(), user_data.raw()),
        }
        true
    }

    /// A request still queued for a runtime is left in the queue: it sees the
    /// reply is gone and does nothing when it runs, and `attach` or `clear`
    /// frees it either way.
    fn cancel(&self) -> bool {
        let replied = self.reply(None);
        if let Some(task) = self.task.lock().take() {
            task.abort();
        }
        replied
    }
}

impl Drop for DnsRequest {
    fn drop(&mut self) {
        request_table().lock().remove(&self.id);
        self.reply(None);
    }
}

/// Weak, so the table never keeps a request alive: the last strong reference
/// is the work itself, and dropping it is what fires a NULL callback.
fn request_table(
) -> &'static parking_lot::Mutex<std::collections::HashMap<i32, std::sync::Weak<DnsRequest>>> {
    static TABLE: std::sync::OnceLock<
        parking_lot::Mutex<std::collections::HashMap<i32, std::sync::Weak<DnsRequest>>>,
    > = std::sync::OnceLock::new();
    TABLE.get_or_init(Default::default)
}

async fn resolve_json(
    slot: &wg_netstack::registry::WgSlot,
    host: &str,
    ipv4: bool,
) -> Option<CString> {
    let live = match slot.live().await {
        Ok(live) => live,
        Err(e) => {
            tracing::debug!("in-tunnel DNS for {host} has no tunnel: {e}");
            return None;
        }
    };
    let servers = live.tunnel.dns_servers().to_vec();
    match wg_netstack::resolve::resolve(&live.stack, &servers, host, ipv4).await {
        Ok(records) => match CString::new(wg_netstack::resolve::records_to_json(&records)) {
            Ok(json) => Some(json),
            Err(e) => {
                tracing::error!("in-tunnel DNS for {host} produced invalid C JSON: {e}");
                None
            }
        },
        Err(e) => {
            tracing::debug!("in-tunnel DNS for {host} failed: {e}");
            None
        }
    }
}

/// Resolve `host` inside the tunnel. Returns a request id (>0), or a negative
/// error. A negative return never invokes the callback; a positive one invokes
/// it exactly once, with JSON or NULL. Where it runs:
///
/// * normally on leaf's runtime thread, when the lookup finishes;
/// * synchronously, on the calling thread, from `px_wg_resolve` itself when the
///   attached runtime has already shut down or the slot is cleared
///   concurrently, from `px_wg_resolve_cancel`, or from `px_wg_clear`;
/// * on leaf's thread during `px_shutdown`, as the runtime drops unfinished
///   lookups. That is inside a tokio context, so the callback must not block,
///   call `px_shutdown`, or call anything that blocks on a runtime.
///
/// Brings the tunnel up if it is not up yet: Picard asking for in-tunnel DNS is
/// the policy decision to use the tunnel, exactly as a proxied connection is.
/// A request made after `px_wg_set_config` but before the leaf instance has
/// started waits for it, rather than failing or leaking outside the tunnel.
///
/// `ipv4` selects A vs AAAA; there is no "both" mode, matching the Go
/// `wgResolveDNS` contract that `resolveDNSRecords(host:ipv4:)` is built on.
///
/// # Safety
/// `key` and `host` must be NUL-terminated UTF-8 strings. `cb` must be a valid
/// function pointer. `user_data` is passed back untouched and must remain valid
/// until the callback fires.
#[no_mangle]
pub unsafe extern "C" fn px_wg_resolve(
    key: *const c_char,
    host: *const c_char,
    ipv4: bool,
    cb: Option<extern "C" fn(json: *const c_char, user_data: *mut c_void)>,
    user_data: *mut c_void,
) -> c_int {
    let (Some(key), Some(host), Some(cb)) = (cstr(key), cstr(host), cb) else {
        return PX_ERR_BAD_ARGUMENT;
    };
    let Some(slot) = wg_netstack::registry::existing(key) else {
        return PX_ERR_NOT_CONFIGURED;
    };
    if !slot.is_configured() {
        return PX_ERR_NOT_CONFIGURED;
    }

    let id = next_request_id();
    let host = host.to_owned();
    let request = std::sync::Arc::new(DnsRequest {
        id,
        reply: parking_lot::Mutex::new(Some((cb, UserData(user_data)))),
        task: parking_lot::Mutex::new(None),
    });
    // Registered before any work can run, so the work's completion (which
    // drops the request and unregisters it) can never precede registration.
    request_table()
        .lock()
        .insert(id, std::sync::Arc::downgrade(&request));

    let queued_request = std::sync::Arc::clone(&request);
    let task_slot = std::sync::Arc::clone(&slot);
    slot.on_runtime(move |handle| {
        // Cancelled while queued.
        if queued_request.reply.lock().is_none() {
            return;
        }
        let task_request = std::sync::Arc::clone(&queued_request);
        let task = handle.spawn(async move {
            let json = resolve_json(&task_slot, &host, ipv4).await;
            task_request.reply(json);
        });
        *queued_request.task.lock() = Some(task.abort_handle());
        // Cancelled before the task existed: the reply already went, so just
        // stop the work.
        if queued_request.reply.lock().is_none() {
            task.abort();
        }
    });
    id
}

/// Cancel an in-flight resolve. Returns true if this call completed the request,
/// in which case the callback has already fired with NULL, on this thread.
/// False means the request had already finished: its callback has fired or is
/// firing. Either way the callback fires exactly once.
#[no_mangle]
pub extern "C" fn px_wg_resolve_cancel(request_id: c_int) -> bool {
    let request = request_table().lock().remove(&request_id);
    match request.and_then(|weak| weak.upgrade()) {
        Some(request) => request.cancel(),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Memory pressure
// ---------------------------------------------------------------------------

/// Called on memory pressure. Drops every idle WireGuard tunnel, keeping the
/// configs, so the next request transparently reconnects.
///
/// This is the Rust answer to `wgRunGC`. There is no garbage collector to run;
/// what we can actually hand back is the smoltcp socket buffers, which are the
/// largest thing the tunnel holds.
///
/// A tunnel with live connections is left alone: tearing it down mid-session
/// would break working traffic to reclaim memory the sessions are still using.
#[no_mangle]
pub extern "C" fn px_trim_memory() {
    let mut released = 0usize;
    for key in wg_netstack::registry::keys() {
        if let Some(slot) = wg_netstack::registry::existing(&key) {
            match slot.current() {
                // Only the registry itself holds it, so nothing is in flight.
                Some(live) if std::sync::Arc::strong_count(&live) <= 2 => {
                    drop(live);
                    slot.stop();
                    released += 1;
                }
                _ => {}
            }
        }
    }
    tracing::info!("memory trim released {released} idle wireguard tunnel(s)");
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#[path = "px_tests.rs"]
mod px_tests;
