//! Bridges `tracing` to a C callback, so Picard's swift-log / CocoaLumberjack
//! stack receives leaf's and wg-netstack's events with real levels.
//!
//! Why a subscriber of our own rather than leaf's built-in logger: leaf's
//! `CONSOLE` output on iOS goes through `mobile::logger::ConsoleWriter`, which
//! calls `asl_log(..., ASL_LEVEL_NOTICE, ...)` — every event, whatever its
//! level, arrives as NOTICE, and ASL is deprecated besides. Here the level
//! survives the trip.
//!
//! leaf installs nothing when its config says `level: none`
//! (`app/logger.rs:193` returns before touching the global subscriber), and
//! `px_start` forces that, so this is the only subscriber in the process. It
//! therefore captures leaf's events *and* wg-netstack's.

use std::ffi::{c_char, c_int, CString};
use std::fmt::Write as _;
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Levels as Swift sees them. Matches `CPNELogLevel`'s ordering closely enough
/// that `WireGuardFacade`'s existing mapping shape carries over.
pub const LEVEL_TRACE: i32 = 0;
pub const LEVEL_DEBUG: i32 = 1;
pub const LEVEL_INFO: i32 = 2;
pub const LEVEL_WARN: i32 = 3;
pub const LEVEL_ERROR: i32 = 4;
/// Above every real level: silences the callback without uninstalling it.
pub const LEVEL_OFF: i32 = 5;

pub type LogFn = extern "C" fn(level: c_int, msg: *const c_char);

/// The registered callback, or null. A C function pointer cannot capture, which
/// is why Swift needs a static shim on its side too.
static CALLBACK: AtomicPtr<()> = AtomicPtr::new(std::ptr::null_mut());
static MIN_LEVEL: AtomicI32 = AtomicI32::new(LEVEL_INFO);

pub fn set_callback(f: Option<LogFn>, min_level: i32) {
    let ptr = match f {
        Some(f) => f as *mut (),
        None => std::ptr::null_mut(),
    };
    MIN_LEVEL.store(min_level.clamp(LEVEL_TRACE, LEVEL_OFF), Ordering::Relaxed);
    CALLBACK.store(ptr, Ordering::Release);
}

pub fn set_min_level(min_level: i32) {
    MIN_LEVEL.store(min_level.clamp(LEVEL_TRACE, LEVEL_OFF), Ordering::Relaxed);
}

fn level_of(level: &Level) -> i32 {
    match *level {
        Level::TRACE => LEVEL_TRACE,
        Level::DEBUG => LEVEL_DEBUG,
        Level::INFO => LEVEL_INFO,
        Level::WARN => LEVEL_WARN,
        Level::ERROR => LEVEL_ERROR,
    }
}

fn emit(level: i32, message: &str) {
    if level < MIN_LEVEL.load(Ordering::Relaxed) {
        return;
    }
    let ptr = CALLBACK.load(Ordering::Acquire);
    if ptr.is_null() {
        return;
    }
    // SAFETY: only ever set from `set_callback` with a valid `LogFn`.
    let callback: LogFn = unsafe { std::mem::transmute::<*mut (), LogFn>(ptr) };

    // Interior NULs would truncate the message; replace rather than drop it.
    let owned = match CString::new(message) {
        Ok(s) => s,
        Err(_) => {
            let cleaned: String = message.chars().filter(|c| *c != '\0').collect();
            match CString::new(cleaned) {
                Ok(s) => s,
                Err(_) => return,
            }
        }
    };
    callback(level, owned.as_ptr());
    // `owned` is dropped here, so the callback must copy the string. Same
    // contract as the Go build's logger, where Go freed it on return.
}

/// Renders `message` plus any other fields as `key=value`, which keeps a log
/// line readable without pulling in a formatter.
struct FieldVisitor {
    message: String,
    extras: String,
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.extras, " {}={}", field.name(), value);
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.extras, " {}={:?}", field.name(), value);
        }
    }
}

pub struct CallbackLayer;

impl<S: Subscriber> Layer<S> for CallbackLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = level_of(metadata.level());
        // Cheap bail-out before doing any formatting work.
        if level < MIN_LEVEL.load(Ordering::Relaxed)
            || CALLBACK.load(Ordering::Acquire).is_null()
        {
            return;
        }

        let mut visitor = FieldVisitor {
            message: String::new(),
            extras: String::new(),
        };
        event.record(&mut visitor);

        // The target tells Swift which subsystem spoke, replacing the Go
        // build's separate `context` argument (which its own callback discarded
        // anyway).
        let line = format!(
            "[{}] {}{}",
            metadata.target(),
            visitor.message,
            visitor.extras
        );
        emit(level, &line);
    }
}

/// Install the subscriber. Idempotent: later calls are no-ops, so repeated
/// `px_set_logger` calls only swap the callback.
pub fn install() {
    use std::sync::Once;
    use tracing_subscriber::prelude::*;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        // TRACE at the subscriber, filtered at emit time, so `px_set_log_level`
        // can raise verbosity at runtime without reinstalling anything.
        let _ = tracing_subscriber::registry()
            .with(CallbackLayer.with_filter(tracing_subscriber::filter::LevelFilter::TRACE))
            .try_init();
    });
}

/// Serialises tests that install a callback.
///
/// The callback and level floor are process-global by necessity (a C function
/// pointer cannot carry context), so concurrent tests would otherwise observe
/// each other's events. Poison-tolerant: a panicking test must not wedge the
/// rest of the suite.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static HITS: AtomicUsize = AtomicUsize::new(0);
    static LAST_LEVEL: AtomicI32 = AtomicI32::new(-1);

    /// See the note in `px_tests`: the callback is process-global, so events
    /// from other tests and from background tasks arrive here too. Count only
    /// what this test emitted.
    const MARKER: &str = "logger-unit-test-marker";

    extern "C" fn counting_callback(level: c_int, msg: *const c_char) {
        assert!(!msg.is_null(), "callback must never receive a null message");
        // Must be readable as a C string.
        let s = unsafe { std::ffi::CStr::from_ptr(msg) };
        let Ok(text) = s.to_str() else {
            panic!("log message was not valid UTF-8");
        };
        if !text.contains(MARKER) {
            return;
        }
        HITS.fetch_add(1, Ordering::SeqCst);
        LAST_LEVEL.store(level, Ordering::SeqCst);
    }

    #[test]
    fn level_filtering_and_dispatch() {
        let _guard = test_lock();
        install();
        HITS.store(0, Ordering::SeqCst);
        set_callback(Some(counting_callback), LEVEL_WARN);

        tracing::info!("suppressed {MARKER}");
        assert_eq!(HITS.load(Ordering::SeqCst), 0, "info is below the WARN floor");

        tracing::warn!("surfaced {MARKER}");
        assert_eq!(HITS.load(Ordering::SeqCst), 1);
        assert_eq!(LAST_LEVEL.load(Ordering::SeqCst), LEVEL_WARN);

        tracing::error!("also surfaced {MARKER}");
        assert_eq!(LAST_LEVEL.load(Ordering::SeqCst), LEVEL_ERROR);

        // Lowering the floor at runtime takes effect immediately.
        set_min_level(LEVEL_TRACE);
        let before = HITS.load(Ordering::SeqCst);
        tracing::debug!("now visible {MARKER}");
        assert_eq!(HITS.load(Ordering::SeqCst), before + 1);

        // Unregistering stops delivery without uninstalling the subscriber.
        set_callback(None, LEVEL_TRACE);
        let before = HITS.load(Ordering::SeqCst);
        tracing::error!("dropped on the floor {MARKER}");
        assert_eq!(HITS.load(Ordering::SeqCst), before);
    }

    #[test]
    fn interior_nul_does_not_lose_the_message() {
        let _guard = test_lock();
        install();
        set_callback(Some(counting_callback), LEVEL_TRACE);
        let before = HITS.load(Ordering::SeqCst);
        emit(LEVEL_INFO, "before\0after logger-unit-test-marker");
        assert_eq!(
            HITS.load(Ordering::SeqCst),
            before + 1,
            "a NUL in the middle must be sanitised, not silently dropped"
        );
        set_callback(None, LEVEL_TRACE);
    }
}
