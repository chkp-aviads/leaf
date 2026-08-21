//! A clock that keeps counting while the device is asleep.
//!
//! WireGuard timers must treat suspended wall time as elapsed: a handshake that
//! is 10 minutes stale is stale regardless of whether the phone was awake for
//! those minutes. The Go build solves this by patching GOROOT
//! (`goruntime-boottime-over-monotonic.diff`) so the runtime uses
//! `mach_continuous_time` instead of `mach_absolute_time`.
//!
//! Rust's `Instant` has the same problem on Darwin, so our own timers use
//! `mach_continuous_time` directly. Note that boringtun 0.7.1 keeps its
//! internal timers on `Instant` and offers no way to inject a clock — we
//! compensate by forcing a rekey on wake rather than patching boringtun.

use std::time::Duration;

/// Monotonic, sleep-inclusive time since an arbitrary epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(u64);

impl Timestamp {
    pub fn saturating_since(self, earlier: Timestamp) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }
}

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub fn now() -> Timestamp {
    // CLOCK_MONOTONIC_RAW stops during sleep on Darwin; CLOCK_MONOTONIC_RAW_APPROX
    // likewise. CLOCK_UPTIME_RAW is awake-only. The continuous clock is what
    // `mach_continuous_time` reports, exposed to POSIX as CLOCK_MONOTONIC.
    //
    // ponytail: calling clock_gettime keeps this dependency-free. Switch to
    // mach_continuous_time + timebase scaling only if this shows up in a profile.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid, writable timespec for the duration of the call.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    debug_assert_eq!(rc, 0, "clock_gettime(CLOCK_MONOTONIC) must not fail");
    if rc != 0 {
        return Timestamp(0);
    }
    Timestamp((ts.tv_sec as u64).saturating_mul(1_000_000_000) + ts.tv_nsec as u64)
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
pub fn now() -> Timestamp {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let epoch = EPOCH.get_or_init(Instant::now);
    Timestamp(Instant::now().saturating_duration_since(*epoch).as_nanos() as u64)
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

    #[test]
    fn advances_monotonically() {
        let a = now();
        let b = now();
        assert!(b >= a, "clock went backwards: {a:?} -> {b:?}");
    }

    #[test]
    fn measures_elapsed_time() {
        let a = now();
        std::thread::sleep(Duration::from_millis(20));
        let elapsed = now().saturating_since(a);
        assert!(
            elapsed >= Duration::from_millis(15),
            "expected >=15ms, got {elapsed:?}"
        );
        assert!(elapsed < Duration::from_secs(5), "absurd elapsed {elapsed:?}");
    }

    #[test]
    fn reversed_operands_saturate_instead_of_panicking() {
        let a = now();
        std::thread::sleep(Duration::from_millis(5));
        let b = now();
        assert_eq!(a.saturating_since(b), Duration::ZERO);
    }
}
