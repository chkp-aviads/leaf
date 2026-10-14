//! Exercises the exported C API the way Swift will call it: real C function
//! pointers, real NUL-terminated strings, real opaque `user_data`.
//!
//! Covers the lifecycle hazards the Go build had, so a regression here is
//! caught rather than discovered on-device:
//!
//! - a bad handle/key must return an error, never panic (the Go version
//!   nil-dereferenced on a stale handle)
//! - the DNS callback must fire exactly once and never leak `user_data`
//! - repeated shutdown must be safe
//!
//! Lives inside the crate rather than in `tests/`: `leaf-ffi`'s lib target is
//! itself named `leaf` (`[lib] name = "leaf"`), so an integration test cannot
//! disambiguate it from the `leaf` crate it depends on.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use crate::px::{self, PxWgStatus};
use wg_netstack::testpeer::TestPeer;

const CLIENT_SECRET: [u8; 32] = [0x55; 32];
const PEER_SECRET: [u8; 32] = [0x66; 32];

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Poison-tolerant lock helper.
///
/// These callbacks are `extern "C"`, and a panic inside one is
/// "panic in a function that cannot unwind" -- an immediate abort, which takes
/// the whole test binary down and hides the original failure. So a callback
/// must never unwrap a lock that an earlier failing test may have poisoned.
/// The same rule applies to the real logging path in `logger::emit`.
fn lock<T>(m: &'static Mutex<T>) -> std::sync::MutexGuard<'static, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

static LOG_HITS: AtomicUsize = AtomicUsize::new(0);
static LAST_LEVEL: AtomicI32 = AtomicI32::new(-1);
static LAST_MSG: Mutex<String> = Mutex::new(String::new());

/// Only events carrying this marker are counted.
///
/// The callback is process-global, so every other test in the binary -- and
/// every background tunnel task they start -- logs into it too. Counting
/// everything made this test observe other people's levels and flake about 1
/// run in 4. Attributing by marker is robust regardless of what else is running.
const MARKER: &str = "px-logger-test-marker";

extern "C" fn log_callback(level: c_int, msg: *const c_char) {
    assert!(!msg.is_null(), "the log callback must never get a null message");
    // Swift copies the string here; the pointer is only valid for this call.
    let owned = unsafe { CStr::from_ptr(msg) }
        .to_str()
        .expect("log messages must be valid UTF-8")
        .to_owned();
    if !owned.contains(MARKER) {
        return;
    }
    *lock(&LAST_MSG) = owned;
    LAST_LEVEL.store(level, Ordering::SeqCst);
    LOG_HITS.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn logger_delivers_levels_and_can_be_unregistered() {
    let _guard = crate::logger::test_lock();
    unsafe { px::px_set_logger(Some(log_callback), 0) };

    LOG_HITS.store(0, Ordering::SeqCst);
    tracing::warn!("hello from the test {MARKER}");
    assert!(LOG_HITS.load(Ordering::SeqCst) >= 1, "callback never fired");
    assert_eq!(LAST_LEVEL.load(Ordering::SeqCst), 3, "WARN should map to 3");
    assert!(
        lock(&LAST_MSG).contains("hello from the test"),
        "message body lost: {:?}",
        lock(&LAST_MSG)
    );
    // The target is included so Swift can tell subsystems apart -- this is what
    // replaces the Go build's separate `context` argument.
    assert!(
        lock(&LAST_MSG).contains("px_tests"),
        "expected the target in the line: {:?}",
        lock(&LAST_MSG)
    );

    // Raising the floor suppresses lower levels.
    px::px_set_log_level(4);
    let before = LOG_HITS.load(Ordering::SeqCst);
    tracing::warn!("should be suppressed {MARKER}");
    assert_eq!(LOG_HITS.load(Ordering::SeqCst), before);

    // Unregistering stops delivery entirely.
    unsafe { px::px_set_logger(None, 0) };
    let before = LOG_HITS.load(Ordering::SeqCst);
    tracing::error!("dropped {MARKER}");
    assert_eq!(LOG_HITS.load(Ordering::SeqCst), before);
}

// ---------------------------------------------------------------------------
// Argument validation: nothing may panic
// ---------------------------------------------------------------------------

#[test]
fn null_and_unknown_arguments_return_errors_not_panics() {
    let key = c("px-test-missing");
    let conf = c("[Interface]\n");

    unsafe {
        assert_eq!(
            px::px_wg_set_config(std::ptr::null(), conf.as_ptr()),
            px::PX_ERR_BAD_ARGUMENT
        );
        assert_eq!(
            px::px_wg_set_config(key.as_ptr(), std::ptr::null()),
            px::PX_ERR_BAD_ARGUMENT
        );
        // Malformed wg-quick: rejected, and the reason is logged without the
        // config text (which holds a private key).
        assert_eq!(
            px::px_wg_set_config(key.as_ptr(), conf.as_ptr()),
            px::PX_ERR_BAD_WG_CONFIG
        );

        // An unknown key is an error on every entry point. The Go build
        // nil-dereferenced and killed the extension for several of these.
        let unknown = c("px-test-never-existed");
        assert_eq!(px::px_wg_stop(unknown.as_ptr()), px::PX_ERR_NOT_CONFIGURED);
        assert_eq!(px::px_wg_clear(unknown.as_ptr()), px::PX_ERR_NOT_CONFIGURED);
        assert_eq!(px::px_wg_wake(unknown.as_ptr()), px::PX_ERR_NOT_CONFIGURED);
        assert_eq!(px::px_wg_sleep(unknown.as_ptr()), px::PX_ERR_NOT_CONFIGURED);

        let mut status = std::mem::zeroed::<PxWgStatus>();
        assert_eq!(
            px::px_wg_get_status(unknown.as_ptr(), &mut status),
            px::PX_ERR_NOT_CONFIGURED
        );
        // A null out-pointer is caught, not written through.
        let known = c("px-test-status-null");
        let good = c(GOOD_CONF);
        assert_eq!(px::px_wg_set_config(known.as_ptr(), good.as_ptr()), px::PX_OK);
        assert_eq!(
            px::px_wg_get_status(known.as_ptr(), std::ptr::null_mut()),
            px::PX_ERR_NULL_OUT
        );
        px::px_wg_clear(known.as_ptr());

        assert_eq!(px::px_start(0, std::ptr::null()), px::PX_ERR_BAD_ARGUMENT);
        let bad_json = c("{ this is not json");
        assert_eq!(px::px_start(0, bad_json.as_ptr()), px::PX_ERR_BAD_CONFIG);
    }

    // Shutting down an instance that was never started is false, not a panic.
    assert!(!px::px_shutdown(9999));
    assert!(!px::px_is_running(9999));
    // Twice is also safe.
    assert!(!px::px_shutdown(9999));
}

const GOOD_CONF: &str = "\
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.9.0.2/24
DNS = 10.9.0.1
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
Endpoint = 127.0.0.1:51820
AllowedIPs = 0.0.0.0/0
";

// ---------------------------------------------------------------------------
// Status lifecycle
// ---------------------------------------------------------------------------

#[test]
fn status_reports_configured_but_down_before_first_use() {
    let key = c("px-test-status");
    let conf = c(GOOD_CONF);
    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
        let mut status = std::mem::zeroed::<PxWgStatus>();
        assert_eq!(px::px_wg_get_status(key.as_ptr(), &mut status), px::PX_OK);

        // Lazy by design: configuring costs a struct, not a socket.
        assert!(status.configured, "the config was installed");
        assert_eq!(status.state, 0, "state should be Down before first use");
        assert_eq!(status.last_handshake_ms_ago, -1, "never handshaked");
        assert_eq!(status.tx_bytes, 0);
        assert_eq!(status.rx_bytes, 0);

        // wake before anything is live is a clean error, not a crash.
        assert_eq!(px::px_wg_wake(key.as_ptr()), px::PX_ERR_NOT_RUNNING);
        px::px_wg_clear(key.as_ptr());
    }
}

// ---------------------------------------------------------------------------
// DNS: the callback contract
// ---------------------------------------------------------------------------

static DNS_HITS: AtomicUsize = AtomicUsize::new(0);
static DNS_JSON: Mutex<Option<String>> = Mutex::new(None);
/// The sentinel we hand out as `user_data`, to prove it round-trips untouched.
const SENTINEL: usize = 0xDEAD_BEEF;

extern "C" fn dns_callback(json: *const c_char, user_data: *mut c_void) {
    assert_eq!(
        user_data as usize, SENTINEL,
        "user_data must come back exactly as it was passed"
    );
    let value = if json.is_null() {
        None
    } else {
        Some(
            unsafe { CStr::from_ptr(json) }
                .to_str()
                .expect("DNS JSON must be valid UTF-8")
                .to_owned(),
        )
    };
    *lock(&DNS_JSON) = value;
    DNS_HITS.fetch_add(1, Ordering::SeqCst);
}

/// Per-test callback sink, passed as `user_data` so parallel tests never see
/// each other's callbacks. Also proves `user_data` round-trips untouched.
struct Probe(Mutex<Vec<Option<String>>>);

impl Probe {
    const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }
    fn user_data(&'static self) -> *mut c_void {
        self as *const Probe as *mut c_void
    }
    fn calls(&'static self) -> Vec<Option<String>> {
        lock(&self.0).clone()
    }
    /// Up to 15 s: long enough for a handshake plus one retried DNS query
    /// (wg-netstack's per-query timeout is 5 s).
    fn wait_for_calls(&'static self, n: usize) -> Vec<Option<String>> {
        for _ in 0..600 {
            if lock(&self.0).len() >= n {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        self.calls()
    }
}

extern "C" fn probe_callback(json: *const c_char, user_data: *mut c_void) {
    // SAFETY: every caller passes `Probe::user_data` of a `'static` probe.
    let probe = unsafe { &*(user_data as *const Probe) };
    let value = (!json.is_null()).then(|| {
        unsafe { CStr::from_ptr(json) }
            .to_str()
            .expect("DNS JSON must be valid UTF-8")
            .to_owned()
    });
    lock(&probe.0).push(value);
}

#[test]
fn dns_resolve_rejects_bad_arguments() {
    let key = c("px-test-dns-args");
    let conf = c(GOOD_CONF);
    let host = c("example.internal");
    static PROBE: Probe = Probe::new();

    unsafe {
        // No slot, and a slot with no config, are both "not configured".
        assert_eq!(
            px::px_wg_resolve(
                key.as_ptr(),
                host.as_ptr(),
                true,
                Some(probe_callback),
                PROBE.user_data()
            ),
            px::PX_ERR_NOT_CONFIGURED
        );
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
        px::px_wg_clear(key.as_ptr());
        assert_eq!(
            px::px_wg_resolve(
                key.as_ptr(),
                host.as_ptr(),
                true,
                Some(probe_callback),
                PROBE.user_data()
            ),
            px::PX_ERR_NOT_CONFIGURED
        );

        // A null callback is rejected before any work is queued.
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
        assert_eq!(
            px::px_wg_resolve(
                key.as_ptr(),
                host.as_ptr(),
                true,
                None,
                std::ptr::null_mut()
            ),
            px::PX_ERR_BAD_ARGUMENT
        );

        // Cancelling an id that never existed is false, not a panic.
        assert!(!px::px_wg_resolve_cancel(4242));
        px::px_wg_clear(key.as_ptr());
    }
    assert!(
        PROBE.calls().is_empty(),
        "a rejected request must never call back"
    );
}

/// Configured, but the leaf instance has not started yet: the request waits
/// for it instead of being refused. If the tunnel is cleared instead, the
/// callback still fires -- once, with NULL -- so the caller's retained
/// `user_data` is released and it is not left waiting on a timeout.
#[test]
fn dns_resolve_before_leaf_starts_is_queued_and_cleared_with_null() {
    let key = c("px-test-dns-queued");
    let conf = c(GOOD_CONF);
    let host = c("example.internal");
    static PROBE: Probe = Probe::new();

    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
        let id = px::px_wg_resolve(
            key.as_ptr(),
            host.as_ptr(),
            true,
            Some(probe_callback),
            PROBE.user_data(),
        );
        assert!(id > 0, "expected a request id, got {id}");
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            PROBE.calls().is_empty(),
            "nothing can run before leaf has a runtime"
        );

        px::px_wg_clear(key.as_ptr());
    }
    assert_eq!(
        PROBE.calls(),
        vec![None],
        "clear must fire the callback exactly once, with NULL"
    );
    assert!(
        !px::px_wg_resolve_cancel(1_000_000),
        "an unknown id is false"
    );
}

/// Cancel completes the request on the cancelling thread, with NULL, and the
/// work never calls back a second time -- including when leaf attaches its
/// runtime afterwards.
#[test]
fn dns_resolve_cancel_fires_null_exactly_once() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let key = c("px-test-dns-cancel");
    let conf = c(GOOD_CONF);
    let host = c("example.internal");
    static PROBE: Probe = Probe::new();

    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
        let id = px::px_wg_resolve(
            key.as_ptr(),
            host.as_ptr(),
            true,
            Some(probe_callback),
            PROBE.user_data(),
        );
        assert!(id > 0);
        let request = px::request_table().lock().get(&id).unwrap().clone();

        assert!(
            px::px_wg_resolve_cancel(id),
            "a pending request is cancellable"
        );
        assert_eq!(PROBE.calls(), vec![None], "cancel fires NULL synchronously");
        assert!(!px::px_wg_resolve_cancel(id), "a second cancel is a no-op");

        let slot = wg_netstack::registry::slot("px-test-dns-cancel");
        let _attached = slot.attach_runtime(rt.handle().clone());
        assert!(
            request.upgrade().is_none(),
            "attaching runs the cancelled job, which releases the request"
        );
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            slot.current().is_none(),
            "cancelled work must not start a tunnel"
        );
        px::px_wg_clear(key.as_ptr());
    }
    assert_eq!(
        PROBE.calls(),
        vec![None],
        "the callback must fire exactly once"
    );
}

#[test]
fn dns_resolve_cancel_before_task_poll_fires_null_once() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let key = c("px-test-dns-cancel-spawned");
    let conf = c(GOOD_CONF);
    let host = c("example.internal");
    static PROBE: Probe = Probe::new();
    let slot = wg_netstack::registry::slot("px-test-dns-cancel-spawned");

    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
    }
    let _attached = slot.attach_runtime(rt.handle().clone());
    let id = unsafe {
        px::px_wg_resolve(
            key.as_ptr(),
            host.as_ptr(),
            true,
            Some(probe_callback),
            PROBE.user_data(),
        )
    };
    assert!(id > 0);
    let request = px::request_table().lock().get(&id).unwrap().clone();
    assert!(px::px_wg_resolve_cancel(id));
    assert_eq!(PROBE.calls(), vec![None]);
    rt.block_on(async { tokio::task::yield_now().await });
    assert!(request.upgrade().is_none());
    assert!(slot.current().is_none());
    unsafe { px::px_wg_clear(key.as_ptr()) };
    assert_eq!(PROBE.calls(), vec![None]);
}

/// A runtime that shut down while still attached (an instance that died
/// without `px_wg_clear`): the resolve cannot run, and must say so with one NULL
/// rather than vanish. Picard runs leaf on a current-thread runtime, so test
/// that flavour as well as the default one.
fn stopped_runtime_fires_null_once(rt: tokio::runtime::Runtime, name: &str, probe: &'static Probe) {
    let key = c(name);
    let conf = c(GOOD_CONF);
    let host = c("example.internal");
    let slot = wg_netstack::registry::slot(name);

    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
    }
    let _attached = slot.attach_runtime(rt.handle().clone());
    drop(rt);
    let id = unsafe {
        px::px_wg_resolve(
            key.as_ptr(),
            host.as_ptr(),
            true,
            Some(probe_callback),
            probe.user_data(),
        )
    };
    assert!(id > 0);
    assert_eq!(probe.wait_for_calls(1), vec![None]);
    assert!(!px::px_wg_resolve_cancel(id));
    unsafe { px::px_wg_clear(key.as_ptr()) };
    assert_eq!(probe.calls(), vec![None]);
}

#[test]
fn dns_resolve_on_a_stopped_multi_thread_runtime_fires_null_once() {
    static PROBE: Probe = Probe::new();
    stopped_runtime_fires_null_once(
        tokio::runtime::Runtime::new().unwrap(),
        "px-test-dns-dead-mt",
        &PROBE,
    );
}

#[test]
fn dns_resolve_on_a_stopped_current_thread_runtime_fires_null_once() {
    static PROBE: Probe = Probe::new();
    stopped_runtime_fires_null_once(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap(),
        "px-test-dns-dead-ct",
        &PROBE,
    );
}

/// The `px_shutdown` teardown path: a lookup already spawned on leaf's
/// current-thread runtime, never finished, when that runtime is dropped. The
/// runtime drops the future, and that must fire the callback, once, with NULL.
#[test]
fn dns_resolve_in_flight_when_runtime_drops_fires_null_once() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let key = c("px-test-dns-teardown");
    let conf = c(GOOD_CONF);
    let host = c("example.internal");
    static PROBE: Probe = Probe::new();
    let slot = wg_netstack::registry::slot("px-test-dns-teardown");

    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
    }
    let _attached = slot.attach_runtime(rt.handle().clone());
    let id = unsafe {
        px::px_wg_resolve(
            key.as_ptr(),
            host.as_ptr(),
            true,
            Some(probe_callback),
            PROBE.user_data(),
        )
    };
    assert!(id > 0);
    // Nothing drives a current-thread runtime but `block_on`, so the task is
    // spawned and parked, exactly as leaf leaves it when told to shut down.
    assert!(PROBE.calls().is_empty());
    drop(rt);
    assert_eq!(PROBE.calls(), vec![None], "teardown fires NULL exactly once");
    assert!(!px::px_wg_resolve_cancel(id));
    unsafe { px::px_wg_clear(key.as_ptr()) };
    assert_eq!(PROBE.calls(), vec![None]);
}

/// The SASE split-tunnel regression: Picard asks for in-tunnel DNS before any
/// traffic has been proxied -- and here, before leaf has even started. Nothing
/// else brings the tunnel up; the resolve must, once leaf attaches its runtime.
#[test]
fn dns_resolve_before_any_traffic_brings_the_tunnel_up() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let key = c("px-test-dns-first-use");
    static PROBE: Probe = Probe::new();

    let peer = rt.block_on(async {
        let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
        peer.spawn_dns("first.internal", std::net::Ipv4Addr::new(10, 9, 0, 77), 60)
            .await;
        peer
    });
    let conf = c(&peer.client_config(CLIENT_SECRET));
    let host = c("first.internal");
    let slot = wg_netstack::registry::slot("px-test-dns-first-use");

    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
        let id = px::px_wg_resolve(
            key.as_ptr(),
            host.as_ptr(),
            true,
            Some(probe_callback),
            PROBE.user_data(),
        );
        assert!(id > 0, "expected a request id, got {id}");
    }
    assert_eq!(slot.status().state, wg_netstack::TunnelState::Down);

    // What leaf does when it builds the `wireguard` outbound at startup.
    let _attached = slot.attach_runtime(rt.handle().clone());

    assert_eq!(
        PROBE.wait_for_calls(1),
        vec![Some(r#"[{"ip":"10.9.0.77","ttl":60}]"#.to_string())],
        "the resolve must bring the tunnel up and answer exactly once"
    );
    assert!(
        slot.current().is_some(),
        "the resolve brought the tunnel up"
    );
    unsafe { px::px_wg_clear(key.as_ptr()) };
}

/// The full DNS path: a live tunnel, a real in-tunnel responder, and the JSON
/// contract `SASEVPNProtocol.resolveDNSRecords` consumes.
#[test]
fn dns_resolve_returns_json_through_a_live_tunnel() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let key = c("px-test-dns-live");

    let peer = rt.block_on(async {
        let peer = TestPeer::start(CLIENT_SECRET, PEER_SECRET).await;
        peer.spawn_dns("host.internal", std::net::Ipv4Addr::new(10, 9, 0, 99), 123)
            .await;
        peer
    });
    let conf = c(&peer.client_config(CLIENT_SECRET));
    unsafe {
        assert_eq!(px::px_wg_set_config(key.as_ptr(), conf.as_ptr()), px::PX_OK);
    }

    // What leaf does at startup; the C API spawns its lookups here.
    let _attached =
        wg_netstack::registry::slot("px-test-dns-live").attach_runtime(rt.handle().clone());
    rt.block_on(async {
        wg_netstack::registry::slot("px-test-dns-live")
            .live()
            .await
            .expect("tunnel should come up");
    });

    // Wait for the handshake: `live()` returns as soon as the tunnel object
    // exists, while the handshake completes asynchronously -- so a live tunnel
    // legitimately reads as Handshaking for a few milliseconds.
    for _ in 0..200 {
        if wg_netstack::registry::slot("px-test-dns-live")
            .status()
            .state
            == wg_netstack::TunnelState::Up
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    // Status must now report Up, with a handshake age.
    unsafe {
        let mut status = std::mem::zeroed::<PxWgStatus>();
        assert_eq!(px::px_wg_get_status(key.as_ptr(), &mut status), px::PX_OK);
        assert_eq!(status.state, 2, "tunnel should be Up");
        assert!(
            status.last_handshake_ms_ago >= 0,
            "should have a handshake age"
        );
    }

    DNS_HITS.store(0, Ordering::SeqCst);
    let host = c("host.internal");
    let id = unsafe {
        px::px_wg_resolve(
            key.as_ptr(),
            host.as_ptr(),
            true,
            Some(dns_callback),
            SENTINEL as *mut c_void,
        )
    };
    assert!(id > 0, "expected a request id, got {id}");

    // Wait for the callback.
    for _ in 0..200 {
        if DNS_HITS.load(Ordering::SeqCst) > 0 {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        DNS_HITS.load(Ordering::SeqCst),
        1,
        "the DNS callback must fire exactly once"
    );
    let json = lock(&DNS_JSON).clone().expect("expected JSON, got NULL");
    assert_eq!(
        json, r#"[{"ip":"10.9.0.99","ttl":123}]"#,
        "this is the exact shape SASEVPNProtocol.resolveDNSRecords parses"
    );

    // Give it a moment; the callback must not fire a second time.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(DNS_HITS.load(Ordering::SeqCst), 1);

    // px_trim_memory releases an idle tunnel and status drops back to Down.
    px::px_trim_memory();
    unsafe {
        let mut status = std::mem::zeroed::<PxWgStatus>();
        assert_eq!(px::px_wg_get_status(key.as_ptr(), &mut status), px::PX_OK);
        assert_eq!(status.state, 0, "trim should have released the idle tunnel");
        assert!(status.configured, "trim must keep the config");
        px::px_wg_clear(key.as_ptr());
    }
}
