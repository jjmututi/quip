//! Coral DHT discovery state (spec §5.3, §13).
//!
//! This module holds the in-memory state for Coral DHT lookups: multi-path
//! queries, spillover, cross-path validation, and witness-ring caching. The
//! wire codecs for `coral_lookup`, `spillover`, and `cross_path_validation`
//! are not yet modeled; they will land alongside the CTRL-verb dispatcher.

use crate::error::{Error, Result};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;

// -------------------------------------------------------------------------
// Cluster level discriminants
// -------------------------------------------------------------------------

/// Level discriminant for the "local" (city/region) tier of the Coral
/// hierarchy.
///
/// The Coral hierarchy numbers levels by coverage, descending: `2` is
/// the innermost (local) tier, `1` is regional, `0` is the global tier.
/// This matches spec §13 and [`crate::cluster::ClusterLevel`].
pub const LOCAL_CLUSTER: u8 = 2;

/// Level discriminant for the "regional" (continent) tier.
///
/// See [`LOCAL_CLUSTER`] for the numbering rationale.
pub const REGIONAL_CLUSTER: u8 = 1;

/// Level discriminant for the "global" (planet-wide) tier.
///
/// See [`LOCAL_CLUSTER`] for the numbering rationale.
pub const GLOBAL_CLUSTER: u8 = 0;

/// Acceptance percentile for cluster admission (spec §3: 90).
pub const ACCEPTANCE_PERCENTILE: u8 = crate::constants::CLUSTER_ACCEPTANCE_PERCENTILE;

/// RTT class for cluster placement.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RttClass {
    /// Under 30ms.
    Local,
    /// Under 100ms.
    Regional,
    /// Anything slower.
    Global,
}

impl RttClass {
    /// Classify a measured RTT in milliseconds.
    pub fn classify(rtt_ms: u64) -> Self {
        if rtt_ms <= crate::constants::RTT_LOCAL_MS {
            Self::Local
        } else if rtt_ms <= crate::constants::RTT_REGIONAL_MS {
            Self::Regional
        } else {
            Self::Global
        }
    }
}

/// Per-path lookup state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupPathState {
    /// Query in flight.
    Pending,
    /// Path returned witnesses.
    Ok(Vec<NodeId>),
    /// Path failed.
    Failed,
}

/// Progress of a multi-path witness lookup.
///
/// This is the in-memory state for a lookup in flight; the wire form is
/// [`crate::coral::CoralLookup`]. The two types are deliberately
/// distinct: `CoralLookup` is what a peer sends, `LookupProgress` is
/// what a driver tracks while awaiting responses.
#[derive(Clone, Debug)]
pub struct LookupProgress {
    /// Target node whose ring is sought.
    pub target: NodeId,
    /// One entry per lookup path.
    pub paths: Vec<LookupPathState>,
    /// When the lookup started.
    pub started_at: Timestamp,
}

impl LookupProgress {
    /// Start a `LOOKUP_PATHS`-path lookup.
    pub fn start(target: NodeId, now: Timestamp) -> Self {
        Self {
            target,
            paths: alloc::vec![LookupPathState::Pending; crate::constants::LOOKUP_PATHS],
            started_at: now,
        }
    }

    /// Record a path result.
    pub fn answer(&mut self, path: usize, witnesses: Vec<NodeId>) -> Result<()> {
        let slot = self.paths.get_mut(path).ok_or(Error::Dht("bad path"))?;
        *slot = LookupPathState::Ok(witnesses);
        Ok(())
    }

    /// Record a path failure.
    pub fn fail(&mut self, path: usize) -> Result<()> {
        let slot = self.paths.get_mut(path).ok_or(Error::Dht("bad path"))?;
        *slot = LookupPathState::Failed;
        Ok(())
    }

    /// True when at least `SPILLOVER_THRESHOLD` paths agree.
    pub fn has_consensus(&self) -> bool {
        let oks = self
            .paths
            .iter()
            .filter(|p| matches!(p, LookupPathState::Ok(_)))
            .count();
        oks >= crate::constants::SPILLOVER_THRESHOLD
    }
}

/// Lookup lifecycle state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LookupState {
    /// In flight.
    Pending,
    /// Consensus reached.
    Complete,
    /// Failed (no consensus / no cluster).
    Failed,
}

/// Cross-path validation request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossPathCheck {
    /// Candidate ring under validation.
    pub ring: Vec<NodeId>,
    /// Paths that must sign off.
    pub paths: u8,
}

/// Coral DHT configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CoralConfig {
    /// Parallel lookup paths.
    pub lookup_paths: u8,
    /// Paths that must agree.
    pub spillover_threshold: u8,
    /// Max nodes per cluster.
    pub max_cluster: usize,
}

impl Default for CoralConfig {
    fn default() -> Self {
        Self {
            lookup_paths: crate::constants::LOOKUP_PATHS as u8,
            spillover_threshold: crate::constants::SPILLOVER_THRESHOLD as u8,
            max_cluster: crate::constants::MAX_CLUSTER_SIZE,
        }
    }
}

/// Cached witness rings learned via DHT.
#[derive(Clone, Debug, Default)]
pub struct WitnessRingCache {
    rings: BTreeMap<NodeId, (Vec<NodeId>, Timestamp)>,
}

impl WitnessRingCache {
    /// Create an empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a ring for `target`.
    pub fn insert(&mut self, target: NodeId, ring: Vec<NodeId>, now: Timestamp) {
        self.rings.insert(target, (ring, now));
    }

    /// Fetch a cached ring younger than `max_age_s`.
    pub fn get(&self, target: &NodeId, now: Timestamp, max_age_s: u64) -> Option<&[NodeId]> {
        let (ring, at) = self.rings.get(target)?;
        let age_ms = now.as_millis().saturating_sub(at.as_millis());
        if age_ms > max_age_s.saturating_mul(1_000) {
            return None;
        }
        Some(ring)
    }

    /// Number of cached rings.
    pub fn len(&self) -> usize {
        self.rings.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.rings.is_empty()
    }
}

// -------------------------------------------------------------------------
// Witness ring participation cap (§19.4)
// -------------------------------------------------------------------------

/// Default cap on concurrent witness rings a node joins.
///
/// §19.4: "Witness ring load: cap the number of rings a witness actively
/// participates in (MAX_CAPACITY = 10) to bound the cost of BFT
/// consensus participation."
pub const DEFAULT_MAX_RINGS: usize = 10;

/// A node's own witness-ring participation tracker.
///
/// Tracks how many rings this node is currently an active member of. A
/// node at capacity declines new ring invitations rather than silently
/// overflowing, so its BFT participation cost stays bounded.
#[derive(Clone, Debug)]
pub struct WitnessLoad {
    max_rings: usize,
    active: BTreeSet<[u8; 32]>,
}

impl WitnessLoad {
    /// A tracker with the §19.4 default of 10 rings.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_RINGS)
    }

    /// A tracker with an explicit cap.
    ///
    /// `max_rings` is clamped to at least 1.
    pub fn with_capacity(max_rings: usize) -> Self {
        Self {
            max_rings: max_rings.max(1),
            active: BTreeSet::new(),
        }
    }

    /// The configured cap.
    pub fn max_rings(&self) -> usize {
        self.max_rings
    }

    /// Number of rings currently joined.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// True when the tracker is at its cap.
    pub fn is_at_capacity(&self) -> bool {
        self.active.len() >= self.max_rings
    }

    /// True if `ring` is currently joined.
    pub fn contains(&self, ring: &[u8; 32]) -> bool {
        self.active.contains(ring)
    }

    /// The set of joined rings, for inspection.
    pub fn active(&self) -> &BTreeSet<[u8; 32]> {
        &self.active
    }

    /// Try to join `ring`.
    ///
    /// Returns `Ok(())` if the ring was joined (or was already joined),
    /// and [`Error::RateLimit`] if the tracker is at capacity.
    pub fn try_join(&mut self, ring: [u8; 32]) -> Result<()> {
        if self.active.contains(&ring) {
            return Ok(());
        }
        if self.is_at_capacity() {
            return Err(Error::RateLimit);
        }
        self.active.insert(ring);
        Ok(())
    }

    /// Leave `ring`. Returns true if it was joined.
    pub fn leave(&mut self, ring: &[u8; 32]) -> bool {
        self.active.remove(ring)
    }

    /// Forget every ring.
    pub fn clear(&mut self) {
        self.active.clear();
    }
}

impl Default for WitnessLoad {
    fn default() -> Self {
        Self::new()
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
    fn rtt_classification_uses_spec_thresholds() {
        assert_eq!(RttClass::classify(0), RttClass::Local);
        assert_eq!(RttClass::classify(30), RttClass::Local);
        assert_eq!(RttClass::classify(31), RttClass::Regional);
        assert_eq!(RttClass::classify(100), RttClass::Regional);
        assert_eq!(RttClass::classify(101), RttClass::Global);
    }

    #[test]
    fn lookup_starts_with_three_pending_paths() {
        let l = LookupProgress::start(nid(1), t(0));
        assert_eq!(l.paths.len(), crate::constants::LOOKUP_PATHS);
        assert!(l.paths.iter().all(|p| matches!(p, LookupPathState::Pending)));
        assert!(!l.has_consensus());
    }

    #[test]
    fn consensus_requires_threshold() {
        let mut l = LookupProgress::start(nid(1), t(0));
        l.answer(0, vec![nid(2), nid(3)]).unwrap();
        assert!(!l.has_consensus());
        l.answer(1, vec![nid(4), nid(5)]).unwrap();
        assert!(l.has_consensus());
    }

    #[test]
    fn cache_respects_age() {
        let mut c = WitnessRingCache::new();
        c.insert(nid(1), vec![nid(2)], t(0));
        assert!(c.get(&nid(1), t(500), 1).is_some());
        assert!(c.get(&nid(1), t(2_000), 1).is_none());
    }

    #[test]
    fn cluster_discriminants_match_spec() {
        assert_eq!(LOCAL_CLUSTER, 2);
        assert_eq!(REGIONAL_CLUSTER, 1);
        assert_eq!(GLOBAL_CLUSTER, 0);
    }

    #[test]
    fn cluster_discriminants_are_distinct() {
        assert_ne!(LOCAL_CLUSTER, REGIONAL_CLUSTER);
        assert_ne!(REGIONAL_CLUSTER, GLOBAL_CLUSTER);
        assert_ne!(LOCAL_CLUSTER, GLOBAL_CLUSTER);
    }

    // ---- witness load (§19.4) ----

    #[test]
    fn witness_load_starts_empty() {
        let w = WitnessLoad::new();
        assert_eq!(w.max_rings(), DEFAULT_MAX_RINGS);
        assert_eq!(w.active_count(), 0);
        assert!(!w.is_at_capacity());
        assert!(w.active().is_empty());
    }

    #[test]
    fn witness_load_accepts_up_to_the_cap() {
        let mut w = WitnessLoad::with_capacity(3);
        assert!(w.try_join([1; 32]).is_ok());
        assert!(w.try_join([2; 32]).is_ok());
        assert!(w.try_join([3; 32]).is_ok());
        assert!(w.is_at_capacity());
        assert!(matches!(w.try_join([4; 32]), Err(Error::RateLimit)));
        assert_eq!(w.active_count(), 3);
    }

    #[test]
    fn witness_load_join_is_idempotent() {
        let mut w = WitnessLoad::with_capacity(1);
        w.try_join([1; 32]).unwrap();
        assert!(w.try_join([1; 32]).is_ok());
        assert_eq!(w.active_count(), 1);
    }

    #[test]
    fn witness_load_leave_frees_a_slot() {
        let mut w = WitnessLoad::with_capacity(1);
        w.try_join([1; 32]).unwrap();
        assert!(w.try_join([2; 32]).is_err());
        assert!(w.leave(&[1; 32]));
        assert!(!w.leave(&[1; 32]));
        assert!(w.try_join([2; 32]).is_ok());
    }

    #[test]
    fn witness_load_contains_reports_membership() {
        let mut w = WitnessLoad::new();
        assert!(!w.contains(&[1; 32]));
        w.try_join([1; 32]).unwrap();
        assert!(w.contains(&[1; 32]));
    }

    #[test]
    fn witness_load_clear_empties_the_set() {
        let mut w = WitnessLoad::new();
        w.try_join([1; 32]).unwrap();
        w.try_join([2; 32]).unwrap();
        w.clear();
        assert_eq!(w.active_count(), 0);
        assert!(!w.is_at_capacity());
    }

    #[test]
    fn witness_load_cap_is_clamped() {
        let w = WitnessLoad::with_capacity(0);
        assert_eq!(w.max_rings(), 1);
    }

    #[test]
    fn witness_load_default_matches_new() {
        let w = WitnessLoad::default();
        assert_eq!(w.max_rings(), DEFAULT_MAX_RINGS);
    }
}