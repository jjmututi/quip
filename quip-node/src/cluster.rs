//! Node-level cluster membership (spec §13.2–§13.6).
//!
//! [`ClusterHandle`] wraps the pure [`quip_net::cluster::ClusterState`]
//! machine and derives the node's member set from the routing-eligible
//! subset of the DHT table, applying the §13.2 RTT acceptance test.
//!
//! # Membership
//!
//! Membership is a subset of routing-eligible peers (§4 of
//! `docs/M9.5b-design.md`). A peer is a member when its recorded RTT
//! is within the cluster's threshold; a peer with no RTT sample is not
//! a member and does not count toward the §13.2 sample minimum.

use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;
use quip_net::cluster::{
    estimate_size_from_routing_table, percentile, ClusterConfig, ClusterLevel, ClusterState,
};

use std::sync::{Arc, Mutex};

use crate::dht::DhtHandle;

/// A derived snapshot of this node's cluster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterView {
    /// This node's cluster id.
    pub id: [u8; 16],
    /// The hierarchy tier this node belongs to.
    pub level: ClusterLevel,
    /// Estimated member count (§13.6).
    pub size: u64,
    /// Member `NodeId`s — routing-eligible peers within the RTT
    /// threshold.
    pub members: Vec<NodeId>,
    /// Whether the §13.2 acceptance test passed on the last recompute.
    pub acceptable: bool,
    /// Whether the cluster has been over its RTT threshold long enough
    /// to split (§13.5).
    pub split_due: bool,
}

/// Shared state behind every [`ClusterHandle`] clone.
struct ClusterInner {
    state: Mutex<ClusterState>,
    config: ClusterConfig,
}

/// A shared handle to the node's cluster state.
///
/// Clones share the underlying [`ClusterState`], matching the
/// [`DhtHandle`] and trust-policy shapes elsewhere in the node.
#[derive(Clone)]
pub struct ClusterHandle {
    inner: Arc<ClusterInner>,
}

impl ClusterHandle {
    /// Build a cluster handle with a fresh cluster `id` at `level`.
    pub fn new(id: [u8; 16], level: ClusterLevel, now: Timestamp) -> Self {
        Self {
            inner: Arc::new(ClusterInner {
                state: Mutex::new(ClusterState::new(id, level, now)),
                config: ClusterConfig::for_level(level),
            }),
        }
    }

    /// The cluster's configured level.
    pub fn level(&self) -> ClusterLevel {
        self.inner.config.level
    }

    /// Recompute membership and advance the state machine, returning a
    /// snapshot.
    ///
    /// Reads the routing-eligible records from `dht`, collects the
    /// valid RTT samples, applies the §13.2 acceptance test, updates
    /// the size estimate, and feeds the RTT percentile into the split
    /// timer. Missing RTT samples are excluded and never counted
    /// toward the sample minimum.
    pub fn recompute(&self, dht: &DhtHandle, now: Timestamp) -> ClusterView {
        let records = dht.routing_eligible_records();

        let samples: Vec<u64> = records.iter().filter_map(|(_, r)| r.rtt_ms).collect();

        let members: Vec<NodeId> = records
            .iter()
            .filter(|(_, r)| {
                r.rtt_ms
                    .map(|ms| ms <= self.inner.config.rtt_threshold_ms)
                    .unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .collect();

        let mut state = self.inner.state.lock().expect("cluster lock poisoned");
        // §13.6 size estimate from this node's routing-table size.
        state.update_size(estimate_size_from_routing_table(records.len() as u64));

        if let Some(p) = percentile(&samples, self.inner.config.acceptance_percentile) {
            state.note_rtt_observation(p, now, &self.inner.config);
        }

        ClusterView {
            id: state.id,
            level: state.level,
            size: state.size,
            members,
            acceptable: state.is_acceptable(&samples, &self.inner.config),
            split_due: state.should_split(now, &self.inner.config),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::{PeerLifecycle, PeerSlot};

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn slot(b: u8, g: u64) -> PeerSlot {
        PeerSlot::new(nid(b), g)
    }

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    /// A handle with five routing-eligible peers, no RTT samples.
    fn eligible_handle() -> DhtHandle {
        let (h, _rx) = DhtHandle::new(nid(0));
        for i in 1..=5u8 {
            h.note_peer(nid(i), slot(i, 1), None, t(0));
            h.update_lifecycle(&nid(i), &slot(i, 1), PeerLifecycle::NatDirect);
        }
        h
    }

    /// A fresh cluster has no members and fails the §13.2 acceptance
    /// test (no samples at all).
    #[test]
    fn fresh_cluster_has_no_members_and_fails_acceptance() {
        let h = eligible_handle();
        let handle = ClusterHandle::new([0u8; 16], ClusterLevel::Local, t(0));
        let view = handle.recompute(&h, t(0));
        assert!(view.members.is_empty());
        assert!(!view.acceptable);
        assert!(!view.split_due);
    }

    /// Members are routing-eligible peers whose RTT is within the
    /// cluster's threshold; faster-than-threshold peers are members,
    /// slower ones are not.
    #[test]
    fn members_are_eligible_peers_within_threshold() {
        let h = eligible_handle();
        for i in 1..=3u8 {
            h.note_rtt(&nid(i), &slot(i, 1), 10);
        }
        h.note_rtt(&nid(4), &slot(4, 1), 50);
        h.note_rtt(&nid(5), &slot(5, 1), 200);

        let handle = ClusterHandle::new([0u8; 16], ClusterLevel::Local, t(0));
        let view = handle.recompute(&h, t(0));
        // Local threshold is 30 ms: peers 1–3 (10 ms) are members.
        assert_eq!(view.members, vec![nid(1), nid(2), nid(3)]);
    }

    /// A routing-eligible peer with no RTT sample is not a member and
    /// does not count toward the sample minimum.
    #[test]
    fn missing_rtt_samples_are_not_members() {
        let h = eligible_handle();
        h.note_rtt(&nid(1), &slot(1, 1), 10);

        let handle = ClusterHandle::new([0u8; 16], ClusterLevel::Local, t(0));
        let view = handle.recompute(&h, t(0));
        assert_eq!(view.members, vec![nid(1)]);
        // 5 routing-eligible peers, but only one valid sample.
        assert!(!view.acceptable);
    }
}
