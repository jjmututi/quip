//! Coral cluster state machine (spec §13.2–§13.6).
//!
//! Pure state machine. No I/O, no async, no transport dependency. The
//! caller drives it: feeds in observations (RTT samples, heartbeat
//! ticks, peer reports) and reads out decisions (accept or reject a
//! cluster, merge to a neighbour, split, create new).
//!
//! # What it is
//!
//! `ClusterState` models the Coral self-organisation protocol from the
//! perspective of one member. It knows:
//!
//! - which level of the hierarchy it belongs to;
//! - whether it is still within the RTT threshold (§13.2);
//! - whether a neighbour is large enough to warrant a merge (§13.4);
//! - whether it has been over-threshold long enough to split (§13.5);
//! - which split branch to take — near, far, or new (§13.5).
//!
//! It does not own a routing table, does not send messages, and does not
//! know about DHT lookups. Those are `WitnessDiscovery`'s job.
//!
//! # Level numbering
//!
//! [`ClusterLevel`] uses the spec's numbering: Global is 0, Regional is
//! 1, Local is 2. This is the opposite of the `dht::LOCAL_CLUSTER` /
//! `dht::REGIONAL_CLUSTER` / `dht::GLOBAL_CLUSTER` constants, which were
//! declared before §13 was finalised. New code should prefer
//! [`ClusterLevel`].

use crate::constants::{
    CLUSTER_ACCEPTANCE_PERCENTILE, CLUSTER_HEARTBEAT_S, CLUSTER_LEVELS,
    COORDINATOR_INTERVAL_S, MAX_CLUSTER_SIZE, MAX_SPLIT_ATTEMPTS,
    MERGE_DELTA_INTERVAL_S, MIN_CLUSTER_SIZE, RTT_GLOBAL_MS, RTT_LOCAL_MS,
    RTT_REGIONAL_MS,
};
use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;

/// A 16-byte Coral cluster identifier (§13).
pub type ClusterId = [u8; 16];

/// Minimum number of RTT samples required for an acceptance test.
///
/// Spec §13.2: *"Obtain a random subset of at least 20 nodes."*
pub const ACCEPTANCE_MIN_SAMPLES: usize = 20;

// -------------------------------------------------------------------------
// Cluster level
// -------------------------------------------------------------------------

/// Level in the Coral hierarchy (§13).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ClusterLevel {
    /// Planet-wide. RTT threshold: unbounded.
    Global = 0,
    /// Continent-scale. RTT threshold: 100 ms.
    Regional = 1,
    /// City/region-scale. RTT threshold: 30 ms.
    Local = 2,
}

impl ClusterLevel {
    /// Default RTT threshold for this level, in milliseconds.
    pub const fn default_rtt_threshold_ms(self) -> u64 {
        match self {
            ClusterLevel::Local => RTT_LOCAL_MS,
            ClusterLevel::Regional => RTT_REGIONAL_MS,
            ClusterLevel::Global => RTT_GLOBAL_MS,
        }
    }

    /// All levels, in declaration order (global → local).
    pub const ALL: [ClusterLevel; CLUSTER_LEVELS] = [
        ClusterLevel::Global,
        ClusterLevel::Regional,
        ClusterLevel::Local,
    ];

    /// The next-more-specific level (towards local), or `None` for
    /// `Local`.
    pub const fn more_specific(self) -> Option<ClusterLevel> {
        match self {
            ClusterLevel::Global => Some(ClusterLevel::Regional),
            ClusterLevel::Regional => Some(ClusterLevel::Local),
            ClusterLevel::Local => None,
        }
    }

    /// The next-less-specific level (towards global), or `None` for
    /// `Global`.
    pub const fn less_specific(self) -> Option<ClusterLevel> {
        match self {
            ClusterLevel::Local => Some(ClusterLevel::Regional),
            ClusterLevel::Regional => Some(ClusterLevel::Global),
            ClusterLevel::Global => None,
        }
    }
}

// -------------------------------------------------------------------------
// Cluster info (peer reports)
// -------------------------------------------------------------------------

/// A peer's report about the cluster it belongs to (§13.4).
///
/// The wire form is a CBOR map with a signature field; M2b.1 operates on
/// the *value* after the signature has been verified by the caller. That
/// keeps this state machine independent of the `Verifier` trait and of
/// the `crypto` feature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterInfo {
    /// The cluster's identifier.
    pub id: ClusterId,
    /// The cluster's estimated size.
    pub size: u64,
    /// The cluster's creation time.
    pub ctime: Timestamp,
}

// -------------------------------------------------------------------------
// Merge decision (§13.4)
// -------------------------------------------------------------------------

/// Whether to leave the current cluster for a neighbour.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MergeDecision {
    /// Stay where you are.
    Stay,
    /// Migrate to the neighbour in the [`ClusterInfo`].
    Merge,
}

// -------------------------------------------------------------------------
// Split decision (§13.5)
// -------------------------------------------------------------------------

/// Which cluster to join when the current cluster is splitting.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SplitAction {
    /// Join the "near" split cluster `cid^N`.
    JoinNear,
    /// Join the "far" split cluster `cid^F`.
    JoinFar,
    /// Neither was acceptable; create a new cluster with a random ID.
    CreateNew,
}

// -------------------------------------------------------------------------
// Cluster configuration
// -------------------------------------------------------------------------

/// Per-level configuration for [`ClusterState`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClusterConfig {
    /// Which level of the hierarchy this cluster belongs to.
    pub level: ClusterLevel,
    /// RTT ceiling for cluster acceptance, in milliseconds.
    pub rtt_threshold_ms: u64,
    /// Latency percentile used in the acceptance test (§13.2).
    pub acceptance_percentile: u8,
    /// Maximum number of members before the cluster should split (§3.1).
    pub max_size: usize,
    /// Minimum number of members for viability (§3.1).
    pub min_size: usize,
    /// Heartbeat interval, in seconds (§3.1).
    pub heartbeat_s: u64,
    /// Coordinator rotation interval, in seconds (§3.1).
    pub coordinator_interval_s: u64,
    /// δ preference function interval, in seconds (§3.1).
    pub merge_delta_interval_s: u64,
    /// Maximum split attempts before creating a new cluster (§3.1).
    pub max_split_attempts: u32,
}

impl ClusterConfig {
    /// Protocol defaults for the given level.
    pub fn for_level(level: ClusterLevel) -> Self {
        Self {
            level,
            rtt_threshold_ms: level.default_rtt_threshold_ms(),
            acceptance_percentile: CLUSTER_ACCEPTANCE_PERCENTILE,
            max_size: MAX_CLUSTER_SIZE,
            min_size: MIN_CLUSTER_SIZE,
            heartbeat_s: CLUSTER_HEARTBEAT_S,
            coordinator_interval_s: COORDINATOR_INTERVAL_S,
            merge_delta_interval_s: MERGE_DELTA_INTERVAL_S,
            max_split_attempts: MAX_SPLIT_ATTEMPTS,
        }
    }
}

// -------------------------------------------------------------------------
// Cluster state
// -------------------------------------------------------------------------

/// One member's view of its cluster.
#[derive(Clone, Debug)]
pub struct ClusterState {
    /// The cluster's identifier.
    pub id: ClusterId,
    /// Which level of the hierarchy the cluster belongs to.
    pub level: ClusterLevel,
    /// Estimated number of members.
    pub size: u64,
    /// When the cluster was created.
    pub ctime: Timestamp,
    /// Current coordinator, if one has been elected.
    pub coordinator: Option<NodeId>,
    /// When the coordinator's term began.
    pub coordinator_since: Timestamp,
    /// Last heartbeat observed from any member.
    pub last_heartbeat: Timestamp,
    /// When the RTT threshold was first exceeded in the current run, or
    /// `None` if the cluster is currently within threshold.
    pub rtt_exceeded_since: Option<Timestamp>,
    /// Number of split attempts made so far in the current episode.
    pub split_attempts: u32,
}

impl ClusterState {
    /// Create a fresh cluster with the given ID and level.
    ///
    /// The caller is the first member; `size` starts at 1.
    pub fn new(id: ClusterId, level: ClusterLevel, now: Timestamp) -> Self {
        Self {
            id,
            level,
            size: 1,
            ctime: now,
            coordinator: None,
            coordinator_since: now,
            last_heartbeat: now,
            rtt_exceeded_since: None,
            split_attempts: 0,
        }
    }

    // ---------------------------------------------------------------------
    // Liveness
    // ---------------------------------------------------------------------

    /// Record a heartbeat from a peer.
    pub fn note_heartbeat(&mut self, now: Timestamp) {
        self.last_heartbeat = now;
    }

    /// True if the last heartbeat is older than `config.heartbeat_s`.
    pub fn heartbeat_expired(&self, now: Timestamp, config: &ClusterConfig) -> bool {
        let elapsed_s = now
            .as_secs()
            .saturating_sub(self.last_heartbeat.as_secs());
        elapsed_s > config.heartbeat_s
    }

    /// True if the coordinator's term has reached
    /// `config.coordinator_interval_s`.
    pub fn coordinator_rotation_due(&self, now: Timestamp, config: &ClusterConfig) -> bool {
        let elapsed_s = now
            .as_secs()
            .saturating_sub(self.coordinator_since.as_secs());
        elapsed_s >= config.coordinator_interval_s
    }

    /// Record a new coordinator and reset its term.
    pub fn elect_coordinator(&mut self, node: NodeId, now: Timestamp) {
        self.coordinator = Some(node);
        self.coordinator_since = now;
    }

    /// Replace the size estimate.
    pub fn update_size(&mut self, size: u64) {
        self.size = size.max(1);
    }

    // ---------------------------------------------------------------------
    // Acceptance (§13.2)
    // ---------------------------------------------------------------------

    /// Test whether this cluster is acceptable given measured RTTs to a
    /// sample of its members.
    ///
    /// Returns `false` if fewer than [`ACCEPTANCE_MIN_SAMPLES`] samples
    /// are provided.
    ///
    /// The criterion is: the `config.acceptance_percentile`-th percentile
    /// RTT is at or below `config.rtt_threshold_ms`.
    pub fn is_acceptable(&self, rtts_ms: &[u64], config: &ClusterConfig) -> bool {
        if rtts_ms.len() < ACCEPTANCE_MIN_SAMPLES {
            return false;
        }
        percentile_at_or_below(
            rtts_ms,
            config.acceptance_percentile,
            config.rtt_threshold_ms,
        )
    }

    // ---------------------------------------------------------------------
    // Merge decision (§13.4)
    // ---------------------------------------------------------------------

    /// Decide whether to merge into `other`.
    ///
    /// The preference function δ flips every
    /// `config.merge_delta_interval_s` seconds based on wall-clock time,
    /// so all nodes in the network see the same parity at the same
    /// moment. A node migrates to a strictly larger cluster only when
    /// `|log2(sizeA) - log2(sizeB)| > δ`. Otherwise the tie-break is
    /// "lower `cluster_id`".
    ///
    /// # Interpretation
    ///
    /// Spec §13.4 writes `δ(min(ageA, ageB))` where `age` is called
    /// "cluster creation time". Both readings — "current wall clock" and
    /// "older cluster's age" — produce the same value at any given
    /// moment for two clusters alive at the same time, so this
    /// implementation uses wall clock. If a future revision specifies a
    /// per-cluster derivation, the change is confined to `delta_for`.
    pub fn should_merge(
        &self,
        other: &ClusterInfo,
        now: Timestamp,
        config: &ClusterConfig,
    ) -> MergeDecision {
        if other.id == self.id {
            return MergeDecision::Stay;
        }
        let delta = delta_for(now, config);

        let other_is_larger = other.size > self.size;
        let ratio_exceeds_delta = log2_diff_exceeds(self.size, other.size, delta);

        if ratio_exceeds_delta {
            if other_is_larger {
                MergeDecision::Merge
            } else {
                MergeDecision::Stay
            }
        } else if other.id < self.id {
            // Deterministic tie-break: lower cluster_id wins.
            MergeDecision::Merge
        } else {
            MergeDecision::Stay
        }
    }

    // ---------------------------------------------------------------------
    // Split decision (§13.5)
    // ---------------------------------------------------------------------

    /// Record the current 90th-percentile RTT of the cluster.
    ///
    /// If the observation is within threshold, the "over-threshold since"
    /// timer is cleared. Otherwise, it is started on the first
    /// observation that crosses the threshold and left running.
    pub fn note_rtt_observation(
        &mut self,
        rtt_90_percentile_ms: u64,
        now: Timestamp,
        config: &ClusterConfig,
    ) {
        if rtt_90_percentile_ms <= config.rtt_threshold_ms {
            self.rtt_exceeded_since = None;
        } else if self.rtt_exceeded_since.is_none() {
            self.rtt_exceeded_since = Some(now);
        }
    }

    /// True if the cluster has been above its RTT threshold for longer
    /// than `config.heartbeat_s * 3` (§13.5).
    pub fn should_split(&self, now: Timestamp, config: &ClusterConfig) -> bool {
        let Some(since) = self.rtt_exceeded_since else {
            return false;
        };
        let elapsed_s = now.as_secs().saturating_sub(since.as_secs());
        elapsed_s > config.heartbeat_s.saturating_mul(3)
    }

    /// Choose which cluster to join when splitting (§13.5).
    ///
    /// The two `*_acceptable` arguments are the caller's verdicts on
    /// whether each candidate cluster passed its own acceptance test
    /// (§13.2). Combining both decisions in one call keeps this method
    /// pure.
    pub fn choose_split_target(
        &self,
        rtt_to_center_ms: u64,
        near_acceptable: bool,
        far_acceptable: bool,
        config: &ClusterConfig,
    ) -> SplitAction {
        if rtt_to_center_ms <= config.rtt_threshold_ms && near_acceptable {
            SplitAction::JoinNear
        } else if far_acceptable {
            SplitAction::JoinFar
        } else {
            SplitAction::CreateNew
        }
    }

    /// Record a split attempt.
    ///
    /// Returns `Err(Error::Dht(_))` if `config.max_split_attempts` has
    /// been exceeded; the caller should then create a new cluster with a
    /// random ID instead of retrying.
    pub fn record_split_attempt(&mut self, config: &ClusterConfig) -> Result<()> {
        self.split_attempts = self.split_attempts.saturating_add(1);
        if self.split_attempts > config.max_split_attempts {
            return Err(Error::Dht("split attempt limit exceeded"));
        }
        Ok(())
    }

    /// Reset the split-attempt counter; called when a split succeeds.
    pub fn clear_split_attempts(&mut self) {
        self.split_attempts = 0;
    }
}

// -------------------------------------------------------------------------
// Size estimation (§13.6)
// -------------------------------------------------------------------------

/// Estimate a cluster's size from the average routing-table size (§13.6).
///
/// The spec formula is `size = 2^(average_routing_table_size)`. This
/// implementation accepts an integer average and truncates fractional
/// input, which is adequate for merge decisions — those only care about
/// log2 of the sizes.
pub fn estimate_size_from_routing_table(avg_routing_table_size: u64) -> u64 {
    1u64
        .checked_shl(avg_routing_table_size as u32)
        .unwrap_or(u64::MAX)
}

// -------------------------------------------------------------------------
// Internal arithmetic
// -------------------------------------------------------------------------

/// Compute `δ(now)` for the merge preference function (§13.4).
///
/// Returns 0 or 2, alternating every `config.merge_delta_interval_s`.
fn delta_for(now: Timestamp, config: &ClusterConfig) -> u64 {
    let interval = config.merge_delta_interval_s.max(1);
    let intervals = now.as_secs() / interval;
    if intervals % 2 == 0 {
        0
    } else {
        2
    }
}

/// True if `|log2(a) - log2(b)| > delta`.
///
/// Equivalent to `max(a,b) > min(a,b) * 2^delta`. Uses integer
/// arithmetic only; overflow on the `* 2^delta` step is treated as "not
/// exceeding", since the sizes are bounded by network scale.
fn log2_diff_exceeds(a: u64, b: u64, delta: u64) -> bool {
    let a = a.max(1);
    let b = b.max(1);
    if a == b {
        return false;
    }
    let (larger, smaller) = if a > b { (a, b) } else { (b, a) };
    let factor = 1u64.checked_shl(delta as u32).unwrap_or(u64::MAX);
    match smaller.checked_mul(factor) {
        Some(threshold) => larger > threshold,
        None => false,
    }
}

/// True if the `percentile`-th percentile of `values` is at most
/// `max_value`.
///
/// Uses the nearest-rank method: sort ascending, then take the element
/// at index `ceil(percentile/100 * N) - 1`, clamped to `N - 1`.
fn percentile_at_or_below(values: &[u64], percentile: u8, max_value: u64) -> bool {
    if values.is_empty() {
        return false;
    }
    let n = values.len() as u64;
    let p = percentile.min(100) as u64;
    let idx = (p * n).div_ceil(100)
        .saturating_sub(1)
        .min(n - 1) as usize;
    let mut sorted: Vec<u64> = values.to_vec();
    sorted.sort_unstable();
    sorted[idx] <= max_value
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn cid(b: u8) -> ClusterId {
        [b; 16]
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn t(secs: u64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn local_config() -> ClusterConfig {
        ClusterConfig::for_level(ClusterLevel::Local)
    }

    fn info(id: u8, size: u64) -> ClusterInfo {
        ClusterInfo {
            id: cid(id),
            size,
            ctime: t(0),
        }
    }

    // ---- level ----

    #[test]
    fn level_discriminants_match_spec() {
        assert_eq!(ClusterLevel::Global as u8, 0);
        assert_eq!(ClusterLevel::Regional as u8, 1);
        assert_eq!(ClusterLevel::Local as u8, 2);
    }

    #[test]
    fn level_default_thresholds() {
        assert_eq!(ClusterLevel::Local.default_rtt_threshold_ms(), 30);
        assert_eq!(ClusterLevel::Regional.default_rtt_threshold_ms(), 100);
        assert_eq!(ClusterLevel::Global.default_rtt_threshold_ms(), u64::MAX);
    }

    #[test]
    fn level_transitions() {
        assert_eq!(
            ClusterLevel::Global.more_specific(),
            Some(ClusterLevel::Regional)
        );
        assert_eq!(
            ClusterLevel::Regional.more_specific(),
            Some(ClusterLevel::Local)
        );
        assert_eq!(ClusterLevel::Local.more_specific(), None);

        assert_eq!(ClusterLevel::Local.less_specific(), Some(ClusterLevel::Regional));
        assert_eq!(ClusterLevel::Global.less_specific(), None);
    }

    // ---- constructor ----

    #[test]
    fn new_cluster_starts_with_one_member() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(1000));
        assert_eq!(c.id, cid(1));
        assert_eq!(c.level, ClusterLevel::Local);
        assert_eq!(c.size, 1);
        assert_eq!(c.ctime, t(1000));
        assert_eq!(c.coordinator, None);
        assert_eq!(c.rtt_exceeded_since, None);
        assert_eq!(c.split_attempts, 0);
    }

    // ---- liveness ----

    #[test]
    fn heartbeat_expires_after_interval() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_heartbeat(t(0));
        assert!(!c.heartbeat_expired(t(60), &cfg), "at the interval, not yet");
        assert!(c.heartbeat_expired(t(61), &cfg), "past the interval, expired");

        c.note_heartbeat(t(100));
        assert!(!c.heartbeat_expired(t(150), &cfg));
    }

    #[test]
    fn coordinator_rotation_due_at_interval() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.elect_coordinator(nid(1), t(0));
        assert!(!c.coordinator_rotation_due(t(86_399), &cfg));
        assert!(c.coordinator_rotation_due(t(86_400), &cfg));
    }

    #[test]
    fn elect_coordinator_resets_term() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        c.elect_coordinator(nid(1), t(0));
        c.elect_coordinator(nid(2), t(50_000));
        assert_eq!(c.coordinator, Some(nid(2)));
        assert_eq!(c.coordinator_since, t(50_000));
    }

    // ---- acceptance ----

    #[test]
    fn acceptance_rejects_too_few_samples() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        let samples = vec![10u64; 19];
        assert!(!c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn acceptance_accepts_all_within_threshold() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        let samples = vec![20u64; 20];
        assert!(c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn acceptance_rejects_when_p90_above_threshold() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        // 20 samples: three above 30ms. The 90th percentile of 20
        // items is index 17 (0-based, nearest-rank), which is the 18th
        // item — the first of the three outliers.
        let mut samples = vec![10u64; 17];
        samples.extend_from_slice(&[100, 100, 100]);
        assert_eq!(samples.len(), 20);
        assert!(!c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn acceptance_accepts_when_only_far_outliers() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        // Two outliers at the top; the 90th percentile falls below them.
        let mut samples = vec![10u64; 18];
        samples.extend_from_slice(&[100, 100]);
        assert_eq!(samples.len(), 20);
        assert!(c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn percentile_math_20_samples() {
        // 20 items ascending 1..=20. p90 should be 18.
        let values: Vec<u64> = (1..=20).collect();
        assert!(percentile_at_or_below(&values, 90, 18));
        assert!(!percentile_at_or_below(&values, 90, 17));
    }

    #[test]
    fn percentile_math_100_samples() {
        // 100 items ascending 1..=100. p90 should be 90.
        let values: Vec<u64> = (1..=100).collect();
        assert!(percentile_at_or_below(&values, 90, 90));
        assert!(!percentile_at_or_below(&values, 90, 89));
    }

    // ---- merge ----

    #[test]
    fn merge_same_id_stays() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        let other = info(1, 100); // same id
        assert_eq!(c.should_merge(&other, t(0), &cfg), MergeDecision::Stay);
    }

    #[test]
    fn merge_to_larger_when_delta_zero() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(10);
        let cfg = local_config();
        // Pick `now` inside an even interval so δ = 0.
        let now = Timestamp::from_secs(0);
        let other = info(1, 100);
        // log2(100) - log2(10) ≈ 3.3 > 0, so merge to the larger.
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);
    }

    #[test]
    fn merge_stays_when_own_size_larger() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(100);
        let cfg = local_config();
        let now = Timestamp::from_secs(0);
        let other = info(1, 10);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Stay);
    }

    #[test]
    fn merge_tie_break_lower_cluster_id_wins() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(100);
        let cfg = local_config();
        // δ = 2 during odd intervals; use a time inside one.
        let now = Timestamp::from_secs(3600); // interval 1, δ = 2
        let other = info(1, 100); // same size, lower id
        // |log2(100) - log2(100)| = 0, not > 2; tie-break to lower id.
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);

        let other = info(99, 100); // same size, higher id
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Stay);
    }

    #[test]
    fn merge_delta_two_requires_size_ratio_greater_than_four() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(10);
        let cfg = local_config();
        let now = Timestamp::from_secs(3600); // δ = 2

        // Ratio 3:1 (below δ=2 threshold), other has higher id: the
        // ratio rule doesn't fire, and the tie-break (lower id wins)
        // says stay.
        let other = info(99, 30);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Stay);

        // Ratio 3:1, other has lower id: the tie-break fires and says
        // merge, even though the sizes are within δ.
        let other = info(1, 30);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);

        // Ratio 5:1 exceeds 2^δ = 4: the size rule fires and says
        // merge regardless of id.
        let other = info(99, 50);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);
    }

    #[test]
    fn delta_for_flips_every_interval() {
        let cfg = local_config();
        assert_eq!(delta_for(t(0), &cfg), 0);
        assert_eq!(delta_for(t(3599), &cfg), 0);
        assert_eq!(delta_for(t(3600), &cfg), 2);
        assert_eq!(delta_for(t(7199), &cfg), 2);
        assert_eq!(delta_for(t(7200), &cfg), 0);
    }

    // ---- split ----

    #[test]
    fn split_not_triggered_within_threshold() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(20, t(0), &cfg);
        assert!(c.rtt_exceeded_since.is_none());
        assert!(!c.should_split(t(10_000), &cfg));
    }

    #[test]
    fn split_not_triggered_after_two_heartbeats() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(100, t(0), &cfg);
        assert_eq!(c.rtt_exceeded_since, Some(t(0)));
        // 3 heartbeats = 180s; 120s < 180s.
        assert!(!c.should_split(t(120), &cfg));
    }

    #[test]
    fn split_triggered_after_three_heartbeats() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(100, t(0), &cfg);
        assert!(c.should_split(t(181), &cfg));
    }

    #[test]
    fn recovery_clears_over_threshold_timer() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(100, t(0), &cfg);
        c.note_rtt_observation(20, t(100), &cfg);
        assert!(c.rtt_exceeded_since.is_none());
        assert!(!c.should_split(t(1000), &cfg));
    }

    #[test]
    fn choose_split_target_prefers_near_when_rtt_ok() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        assert_eq!(
            c.choose_split_target(20, true, true, &cfg),
            SplitAction::JoinNear,
        );
    }

    #[test]
    fn choose_split_target_falls_back_to_far() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        // RTT to near center is above threshold; far is acceptable.
        assert_eq!(
            c.choose_split_target(200, true, true, &cfg),
            SplitAction::JoinFar,
        );
        // Near refuses on policy grounds even with good RTT.
        assert_eq!(
            c.choose_split_target(20, false, true, &cfg),
            SplitAction::JoinFar,
        );
    }

    #[test]
    fn choose_split_target_creates_new_when_both_reject() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        assert_eq!(
            c.choose_split_target(200, false, false, &cfg),
            SplitAction::CreateNew,
        );
    }

    #[test]
    fn record_split_attempt_errors_at_limit() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        assert!(c.record_split_attempt(&cfg).is_ok()); // 1
        assert!(c.record_split_attempt(&cfg).is_ok()); // 2
        assert!(c.record_split_attempt(&cfg).is_ok()); // 3
        assert!(c.record_split_attempt(&cfg).is_err()); // 4 > max
        c.clear_split_attempts();
        assert!(c.record_split_attempt(&cfg).is_ok());
    }

    // ---- size estimation ----

    #[test]
    fn estimate_size_from_routing_table_basic() {
        assert_eq!(estimate_size_from_routing_table(0), 1);
        assert_eq!(estimate_size_from_routing_table(1), 2);
        assert_eq!(estimate_size_from_routing_table(10), 1024);
    }

    #[test]
    fn estimate_size_from_routing_table_saturates() {
        assert_eq!(estimate_size_from_routing_table(64), u64::MAX);
        assert_eq!(estimate_size_from_routing_table(1000), u64::MAX);
    }
}