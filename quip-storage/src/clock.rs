//! Wall-clock helper.
//!
//! Thin wrapper around [`quip_core::time::SystemClock`], kept for source
//! compatibility. New code should depend on the [`Clock`] trait directly.
//!
//! [`Clock`]: quip_core::time::Clock

use quip_core::time::Timestamp;

/// Current Unix time as a [`Timestamp`].
///
/// Only available with the `std` feature. `no_std` users supply a
/// [`Clock`](quip_core::time::Clock) implementation from their runtime.
#[cfg(feature = "std")]
pub fn unix_now() -> Timestamp {
    use quip_core::time::{Clock, SystemClock};
    SystemClock.now()
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn unix_now_is_after_2020() {
        // Same rationale as the `quip-net` variant: a broken host clock
        // is worth surfacing, a functioning one is not.
        const JAN_2020_MS: u64 = 1_577_836_800_000;
        let t = unix_now();
        assert!(
            t.as_millis() >= JAN_2020_MS,
            "system clock returned {ms} ms, before 2020-01-01",
            ms = t.as_millis(),
        );
    }
}