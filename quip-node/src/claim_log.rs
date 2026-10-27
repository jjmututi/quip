//! The first-seen claim log.
//!
//! [`ClaimLog`] records, per peer, the first time this node observed
//! that peer's `KeyClaim`. That single fact is consumed by two
//! subsystems that must not know about each other:
//!
//! - [`TrustPolicy`](crate::trust::TrustPolicy), for TOFU pinning.
//! - [`WitnessStore`](crate::witness::WitnessStore), for §5.3.3's
//!   6-hour first-seen rule.
//!
//! Keeping the fact in one place means they cannot disagree about it.
//! See §2.5 of `docs/M9.6a-design.md`.
//!
//! The log is in-memory. A node that restarts loses its first-seen
//! times and genuinely has not observed the claims that long; that is
//! correct behaviour, not a bug. Persistence belongs with M9.7's
//! store-persistence work.

use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Records the first time this node observed each peer's claim.
///
/// Clones share the underlying map, matching the other node-wide
/// handles (`DhtHandle`, `DiscoveryHandle`, `WitnessStore`).
#[derive(Clone, Default)]
pub struct ClaimLog {
    inner: std::sync::Arc<Mutex<BTreeMap<NodeId, Timestamp>>>,
}

impl ClaimLog {
    /// Build an empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer`'s claim was observed at `now`.
    ///
    /// Idempotent: the first observation wins. A later observation of
    /// the same peer does not move the timestamp, because the fact the
    /// log records is *first* seen.
    pub fn observe(&self, peer: NodeId, now: Timestamp) {
        let mut map = self.inner.lock().expect("claim log poisoned");
        map.entry(peer).or_insert(now);
    }

    /// The first time this node observed `peer`'s claim, if ever.
    pub fn first_seen(&self, peer: &NodeId) -> Option<Timestamp> {
        let map = self.inner.lock().expect("claim log poisoned");
        map.get(peer).copied()
    }

    /// The number of peers the log knows about.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("claim log poisoned").len()
    }

    /// True if the log is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn first_seen_is_none_for_an_unknown_peer() {
        let log = ClaimLog::new();
        assert_eq!(log.first_seen(&nid(1)), None);
        assert!(log.is_empty());
    }

    #[test]
    fn observe_records_the_first_timestamp() {
        let log = ClaimLog::new();
        log.observe(nid(1), t(100));
        assert_eq!(log.first_seen(&nid(1)), Some(t(100)));
        assert_eq!(log.len(), 1);
    }

    #[test]
    fn observe_is_idempotent_and_first_wins() {
        let log = ClaimLog::new();
        log.observe(nid(1), t(100));
        log.observe(nid(1), t(200));
        assert_eq!(
            log.first_seen(&nid(1)),
            Some(t(100)),
            "a later observation must not move the first-seen time",
        );
    }

    #[test]
    fn observe_is_per_peer() {
        let log = ClaimLog::new();
        log.observe(nid(1), t(100));
        log.observe(nid(2), t(200));
        assert_eq!(log.first_seen(&nid(1)), Some(t(100)));
        assert_eq!(log.first_seen(&nid(2)), Some(t(200)));
        assert_eq!(log.len(), 2);
    }

    #[test]
    fn clones_share_the_underlying_map() {
        let log = ClaimLog::new();
        let clone = log.clone();
        log.observe(nid(7), t(42));
        assert_eq!(clone.first_seen(&nid(7)), Some(t(42)));
        assert_eq!(log.first_seen(&nid(7)), Some(t(42)));
    }
}
