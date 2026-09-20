//! Time types and clock abstraction.

use core::sync::atomic::{AtomicU64, Ordering};

/// A Unix timestamp in milliseconds.
///
/// Wrapping ms-valued wire fields in a newtype prevents accidental mixing
/// with the seconds-valued intervals in [`crate::constants`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Timestamp(pub u64);

impl Timestamp {
    /// Construct from milliseconds.
    pub const fn from_millis(ms: u64) -> Self {
        Timestamp(ms)
    }

    /// Construct from seconds.
    pub const fn from_secs(s: u64) -> Self {
        Timestamp(s * 1000)
    }

    /// Read as milliseconds.
    pub const fn as_millis(self) -> u64 {
        self.0
    }

    /// Read as whole seconds (truncating).
    pub const fn as_secs(self) -> u64 {
        self.0 / 1000
    }
}

/// A source of the current time.
///
/// Implementations return [`Timestamp`] in Unix milliseconds. The trait
/// exists so that callers — the transport driver, the BFT state machine,
/// TTL sweeps — do not depend on `std::time` directly and can be driven
/// by a deterministic clock in tests.
///
/// Callers that take `now: Timestamp` explicitly do not need this trait;
/// it is for the *edge* where a `Timestamp` first enters the system.
pub trait Clock {
    /// Current Unix time in milliseconds.
    fn now(&self) -> Timestamp;
}

impl<T: Clock + ?Sized> Clock for &T {
    fn now(&self) -> Timestamp {
        (**self).now()
    }
}

// -------------------------------------------------------------------------
// SystemClock — wall-clock, requires `std`
// -------------------------------------------------------------------------

/// The system wall clock.
///
/// `Clock::now` reads `SystemTime::now()` relative to `UNIX_EPOCH`. If the
/// system clock is before the epoch (misconfigured or hostile), it returns
/// `Timestamp(0)` rather than panicking: the protocol treats timestamps as
/// best-effort and enforces a replay window on receipt anyway.
#[cfg(feature = "std")]
#[derive(Copy, Clone, Debug, Default)]
pub struct SystemClock;

#[cfg(feature = "std")]
impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        use std::time::{SystemTime, UNIX_EPOCH};
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Timestamp::from_millis(ms)
    }
}

// -------------------------------------------------------------------------
// ManualClock — deterministic, no_std-compatible
// -------------------------------------------------------------------------

/// A clock whose time is set by the caller.
///
/// Backed by an `AtomicU64`, so it is `Sync` and can be shared across
/// threads. Advancing it is `&self`, not `&mut self`, which means it can
/// live behind an `Arc` and be driven from a test harness while the
/// system under test still holds a shared reference.
///
/// ```
/// use quip_core::time::{Clock, ManualClock, Timestamp};
///
/// let clock = ManualClock::new(Timestamp::from_millis(1_000));
/// assert_eq!(clock.now().as_millis(), 1_000);
/// clock.advance(500);
/// assert_eq!(clock.now().as_millis(), 1_500);
/// clock.set(Timestamp::from_millis(0));
/// assert_eq!(clock.now().as_millis(), 0);
/// ```
#[derive(Debug)]
pub struct ManualClock {
    now_ms: AtomicU64,
}

impl ManualClock {
    /// Create a clock frozen at `start`.
    pub const fn new(start: Timestamp) -> Self {
        Self {
            now_ms: AtomicU64::new(start.0),
        }
    }

    /// Create a clock frozen at `0`.
    pub const fn epoch() -> Self {
        Self::new(Timestamp(0))
    }

    /// Advance the clock by `delta_ms` milliseconds.
    pub fn advance(&self, delta_ms: u64) {
        // `fetch_add` on an AtomicU64 wraps on overflow in release; that
        // is acceptable for a test clock whose timestamps are bounded by
        // any realistic test duration. Use `set` if overflow matters.
        self.now_ms.fetch_add(delta_ms, Ordering::Relaxed);
    }

    /// Set the clock to an absolute time.
    pub fn set(&self, now: Timestamp) {
        self.now_ms.store(now.0, Ordering::Relaxed);
    }
}

impl Clock for ManualClock {
    fn now(&self) -> Timestamp {
        Timestamp::from_millis(self.now_ms.load(Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_conversions() {
        let t = Timestamp::from_secs(2);
        assert_eq!(t.as_millis(), 2_000);
        assert_eq!(t.as_secs(), 2);

        let t = Timestamp::from_millis(2_500);
        assert_eq!(t.as_secs(), 2, "truncates");
    }

    #[test]
    fn manual_clock_starts_frozen() {
        let c = ManualClock::new(Timestamp::from_millis(1_000));
        assert_eq!(c.now().as_millis(), 1_000);
        assert_eq!(c.now().as_millis(), 1_000, "does not tick on its own");
    }

    #[test]
    fn manual_clock_advances_and_sets() {
        let c = ManualClock::epoch();
        c.advance(100);
        c.advance(50);
        assert_eq!(c.now().as_millis(), 150);
        c.set(Timestamp::from_millis(9_000));
        assert_eq!(c.now().as_millis(), 9_000);
    }

    #[test]
    fn clock_is_usable_through_reference() {
        // The blanket `impl<T: Clock + ?Sized> Clock for &T` should let a
        // `&ManualClock` satisfy `&impl Clock`.
        fn read(c: &impl Clock) -> Timestamp {
            c.now()
        }
        let c = ManualClock::new(Timestamp::from_millis(42));
        assert_eq!(read(&c).as_millis(), 42);
        assert_eq!(read(&&c).as_millis(), 42, "reference-of-reference also works");
    }

    #[cfg(feature = "std")]
    #[test]
    fn system_clock_is_after_2020() {
        // 2020-01-01 is a reasonable lower bound: any host clock set
        // before then is misconfigured, and the trait is documented to
        // return `Timestamp(0)` on a pre-epoch clock, so a failure here
        // is a host problem, not a code problem.
        const JAN_2020_MS: u64 = 1_577_836_800_000;
        let t = SystemClock.now();
        assert!(
            t.as_millis() >= JAN_2020_MS,
            "system clock returned {ms} ms, before 2020-01-01",
            ms = t.as_millis(),
        );
    }
}