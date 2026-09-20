//! Coral DHT discovery state (spec §5.3, §13).
//!
//! This module holds the in-memory state for Coral DHT lookups: multi-path
//! queries, spillover, cross-path validation, and witness-ring caching. The
//! wire codecs for `coral_lookup`, `spillover`, and `cross_path_validation`
//! are not yet modeled; they will land alongside the CTRL-verb dispatcher.

use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
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
}