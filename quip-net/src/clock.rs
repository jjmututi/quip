//! Wall-clock helper.
//!
//! Thin wrapper around [`quip_core::time::SystemClock`], kept for source
//! compatibility. New code should depend on the [`Clock`] trait directly
//! so that tests can substitute a [`ManualClock`].
//!
//! [`Clock`]: quip_core::time::Clock
//! [`ManualClock`]: quip_core::time::ManualClock

use quip_core::time::Timestamp;

/// Current Unix time as a [`Timestamp`].
///
/// Under `std` this reads the system clock. Without `std` it returns
/// `Timestamp(0)`; `no_std` users should obtain time from a [`Clock`]
/// implementation instead of calling this.
///
/// [`Clock`]: quip_core::time::Clock
#[cfg(feature = "std")]
pub fn unix_now() -> Timestamp {
    use quip_core::time::{Clock, SystemClock};
    SystemClock.now()
}

/// No-std fallback: returns the epoch.
#[cfg(not(feature = "std"))]
pub fn unix_now() -> Timestamp {
    Timestamp::from_millis(0)
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn unix_now_is_after_2020() {
        // A correctly configured system clock is after 2020-01-01. If this
        // fails, the host clock is misconfigured (or is set to the epoch
        // because the platform has no wall clock). The wrapper itself
        // cannot return an earlier value, so a failure here is a host
        // problem, not a code problem.
        const JAN_2020_MS: u64 = 1_577_836_800_000;
        let t = unix_now();
        assert!(
            t.as_millis() >= JAN_2020_MS,
            "system clock returned {ms} ms, before 2020-01-01",
            ms = t.as_millis(),
        );
    }
}