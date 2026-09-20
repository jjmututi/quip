//! Storage-layer constants.
//!
//! Spec-derived values live in [`quip_core::constants`] and are re-exported
//! here for source compatibility. Only implementation-choice capacities are
//! defined locally: the spec bounds Trusted CIDs and pins, but leaves cache
//! and derivative-link capacities to the implementation.

// ─── Re-exports from quip-core (spec-derived) ────────────────────────────

/// Default pin TTL, in seconds, selected when a `pin` carries `ttl = 0`.
///
/// Spec §14.2 and App. A.5. Canonical definition:
/// [`quip_core::constants::pin::DEFAULT_PIN_TTL_S`].
pub use quip_core::constants::DEFAULT_PIN_TTL_S;

/// TTL sentinel meaning "store indefinitely", in seconds.
///
/// Spec §14.2. Deliberately distinct from
/// [`quip_core::constants::dvv::INF`] even though both equal `0xFFFFFFFF`:
/// `INF` is the DVV pruning sentinel, this is the pin TTL sentinel, and they
/// should not move together. Canonical definition:
/// [`quip_core::constants::pin::INDEFINITE_TTL_S`].
pub use quip_core::constants::INDEFINITE_TTL_S;

/// Pin refresh threshold, as a whole percentage of the TTL.
///
/// Spec App. A.5: *"Peers SHOULD refresh pins before TTL expiry (at 80% of
/// TTL)."* Canonical definition:
/// [`quip_core::constants::pin::PIN_REFRESH_PERCENT`].
pub use quip_core::constants::PIN_REFRESH_PERCENT;

/// Maximum age of a `resource_announce` record, in seconds.
///
/// Spec §14.5. Canonical definition:
/// [`quip_core::constants::resource::MAX_ANNOUNCEMENT_AGE_S`].
pub use quip_core::constants::MAX_ANNOUNCEMENT_AGE_S;

// ─── Storage-layer implementation choices ────────────────────────────────

/// Default cap on cached resource announcements.
///
/// Implementation choice: the spec bounds pins and Trusted CIDs but leaves
/// the location cache to the implementation.
pub const DEFAULT_RESOURCE_CAPACITY: usize = 4_096;

/// Default cap on cached quarantine notices.
///
/// Implementation choice: the spec's 100-entry cap applies to Trusted CID
/// registrations, not to quarantine notices.
pub const DEFAULT_QUARANTINE_CAPACITY: usize = 256;

/// Default cap on derivative links per Trusted CID.
///
/// Implementation choice, in the same spirit as
/// [`quip_core::constants::MAX_RANGES`]: it bounds application-supplied
/// evidence, not a protocol rule.
pub const DERIVATIVE_LINK_CAPACITY: usize = 1_024;

// Compile-time invariants. Checked by rustc on every build: a regression
// that sets a capacity to zero fails compilation, not a test run.
const _: () = assert!(DEFAULT_RESOURCE_CAPACITY > 0);
const _: () = assert!(DEFAULT_QUARANTINE_CAPACITY > 0);
const _: () = assert!(DERIVATIVE_LINK_CAPACITY > 0);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indefinite_ttl_sentinel_matches_spec_value() {
        // Spec §14.2 pins this at 0xFFFFFFFF. The re-export is checked
        // here so a change to the canonical core value would surface as
        // a test failure in the storage crate too.
        assert_eq!(INDEFINITE_TTL_S, 0xFFFF_FFFF);
    }

    #[test]
    fn pin_default_is_seven_days() {
        assert_eq!(DEFAULT_PIN_TTL_S, 604_800);
    }
}