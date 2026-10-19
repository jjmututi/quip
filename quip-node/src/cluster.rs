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
use quip_core::messages::Signer;
use quip_core::time::Timestamp;
use quip_net::cluster::{
    estimate_size_from_routing_table, percentile, ClusterConfig, ClusterInfo, ClusterInfoAnnounce,
    ClusterLevel, ClusterState,
};

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::dht::DhtHandle;

/// Upper bound on recorded neighbour tuples.
///
/// A node has one routing table, so the bound only guards against a peer
/// that announces from many identities. When the map is full, a *new*
/// identity is ignored; an existing one is still overwritten, so a
/// known peer can always correct itself.
pub const MAX_NEIGHBOUR_CLUSTERS: usize = 64;

/// How far ahead of the local clock an announced `ctime` may be.
///
/// §13.4's tuple has no freshness field beyond `ctime`, so a claim from
/// the future is either a skewed clock or a lie, and neither should be
/// allowed to steer a merge or a split. Five minutes is a conservative
/// allowance for ordinary NTP drift.
pub const MAX_CTIME_SKEW_MS: u64 = 5 * 60 * 1000;

/// What peers have told us about their clusters (§13.4).
///
/// Keyed by the *authenticated* sender id, never by the announced
/// cluster id: the record is a fact about what a peer said, and the id
/// filter in [`is_cluster_member`] decides whether that claim counts as
/// membership. Recording unconditionally is deliberate — see
/// `docs/M9.6b-design.md` §3, "Record is not member".
#[derive(Clone, Default)]
pub struct NeighbourClusters {
    inner: Arc<Mutex<BTreeMap<NodeId, ClusterInfo>>>,
}

impl NeighbourClusters {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record `info` as `peer`'s current view.
    ///
    /// Returns `false` when the tuple fails the cheap sanity bounds —
    /// `size == 0`, or a `ctime` more than [`MAX_CTIME_SKEW_MS`] ahead of
    /// `now`. The signature check is the caller's job and the main gate;
    /// this only rejects values that cannot be true.
    pub fn observe(&self, peer: NodeId, info: ClusterInfo, now: Timestamp) -> bool {
        if info.size == 0 {
            return false;
        }
        let limit = now.as_millis().saturating_add(MAX_CTIME_SKEW_MS);
        if info.ctime.as_millis() > limit {
            return false;
        }
        let Ok(mut map) = self.inner.lock() else {
            return false;
        };
        if !map.contains_key(&peer) && map.len() >= MAX_NEIGHBOUR_CLUSTERS {
            return false;
        }
        map.insert(peer, info);
        true
    }

    /// What `peer` last told us, if anything.
    pub fn get(&self, peer: &NodeId) -> Option<ClusterInfo> {
        self.inner.lock().ok()?.get(peer).cloned()
    }

    /// Recorded neighbours.
    pub fn len(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }

    /// True when nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Whether `peer` belongs to the cluster identified by `local_id`.
///
/// Routing-eligible **and** either silent or advertising our id. A peer
/// that has not announced is included on purpose: before the first
/// exchange every peer is unknown, and excluding unknowns would make a
/// fresh cluster empty and fail §13.2 forever. The optimistic rule is
/// also the safe one — a peer that has claimed a *different* cluster is
/// excluded immediately.
///
/// This is read-time filtering. Applying it at record time would hide
/// the announcement and require re-verifying the store after every
/// local-id change, which is the bug class the filter exists to prevent.
pub fn is_cluster_member(
    neighbours: &NeighbourClusters,
    peer: &NodeId,
    local_id: &[u8; 16],
) -> bool {
    match neighbours.get(peer) {
        None => true,
        Some(info) => info.id == *local_id,
    }
}

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
    /// What peers have told us about their clusters. Kept beside the
    /// state rather than inside it: the state machine is pure and wants
    /// decisions, not a peer table.
    neighbours: NeighbourClusters,
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
                neighbours: NeighbourClusters::new(),
            }),
        }
    }

    /// The neighbour tuple store, shared with every clone.
    pub fn neighbours(&self) -> NeighbourClusters {
        self.inner.neighbours.clone()
    }

    /// Record a verified announcement from `peer`.
    ///
    /// Verification happens at the call site: this only applies the
    /// cheap sanity bounds and stores the tuple. In particular it does
    /// **not** compare the announced id with ours — that is
    /// [`is_cluster_member`]'s job, at read time.
    pub fn observe_cluster_info(&self, peer: NodeId, info: ClusterInfo, now: Timestamp) -> bool {
        self.inner.neighbours.observe(peer, info, now)
    }

    /// This node's current tuple, as it would be announced.
    pub fn info(&self) -> ClusterInfo {
        let state = self.inner.state.lock().expect("cluster lock poisoned");
        ClusterInfo {
            id: state.id,
            size: state.size,
            ctime: state.ctime,
        }
    }

    /// This node's current tuple, signed for the wire.
    pub fn signed_info(&self, signer: &impl Signer) -> quip_net::Result<ClusterInfoAnnounce> {
        let mut announce = ClusterInfoAnnounce {
            info: self.info(),
            signature: [0u8; 64],
        };
        let payload = announce.signing_payload()?;
        announce.signature = signer.sign_ed25519(&payload);
        Ok(announce)
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

        // The id the filter compares against. Read before the member
        // set is built so a concurrent split cannot produce a member
        // list filtered against one id and a view reporting another.
        let local_id = {
            let state = self.inner.state.lock().expect("cluster lock poisoned");
            state.id
        };

        let samples: Vec<u64> = records.iter().filter_map(|(_, r)| r.rtt_ms).collect();

        let members: Vec<NodeId> = records
            .iter()
            .filter(|(_, r)| {
                r.rtt_ms
                    .map(|ms| ms <= self.inner.config.rtt_threshold_ms)
                    .unwrap_or(false)
            })
            .map(|(id, _)| *id)
            .filter(|id| is_cluster_member(&self.inner.neighbours, id, &local_id))
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

    // ---- id filter (§13.4) ----

    fn cinfo(id: u8, size: u64) -> ClusterInfo {
        ClusterInfo {
            id: [id; 16],
            size,
            ctime: t(0),
        }
    }

    /// A peer that has not announced is a member: a fresh cluster would
    /// otherwise be empty and fail §13.2 forever.
    #[test]
    fn unknown_peers_count_as_members() {
        let n = NeighbourClusters::new();
        assert!(is_cluster_member(&n, &nid(1), &[7u8; 16]));
    }

    /// The filter is a function of the *stored* record and the *current*
    /// local id, evaluated on read. The same record excludes against one
    /// id and admits against another — which is what makes a split
    /// observable without rewriting the store.
    #[test]
    fn the_same_record_flips_with_the_local_id() {
        let n = NeighbourClusters::new();
        assert!(n.observe(nid(1), cinfo(2, 3), t(0)));

        assert!(!is_cluster_member(&n, &nid(1), &[1u8; 16]));
        assert!(is_cluster_member(&n, &nid(1), &[2u8; 16]));
    }

    /// Recording does not drop a foreign id: the record is what was
    /// announced, and `recompute` is where it stops counting.
    #[test]
    fn a_foreign_id_is_recorded_and_filtered_not_dropped() {
        let h = eligible_handle();
        h.note_rtt(&nid(1), &slot(1, 1), 10);
        h.note_rtt(&nid(2), &slot(2, 1), 10);

        let handle = ClusterHandle::new([9u8; 16], ClusterLevel::Local, t(0));
        assert!(handle.observe_cluster_info(nid(2), cinfo(2, 2), t(0)));

        let view = handle.recompute(&h, t(0));
        assert_eq!(view.members, vec![nid(1)], "peer 2 left the cluster");
        assert_eq!(
            handle.neighbours().len(),
            1,
            "the record survives; only the member set is filtered"
        );
    }

    /// The tuple the heartbeat publishes carries this node's id and a
    /// signature that verifies against its own `NodeId`.
    #[test]
    fn signed_info_verifies_against_the_local_id() {
        use quip_core::messages::Signer as _;
        use quip_net::crypto::{Ed25519Signer, Ed25519Verifier};

        let signer = Ed25519Signer::from_seed(&[5u8; 32]);
        let handle = ClusterHandle::new([3u8; 16], ClusterLevel::Local, t(0));
        let announce = handle.signed_info(&signer).unwrap();

        assert_eq!(announce.info.id, [3u8; 16]);
        assert_eq!(announce.info.size, 1);
        assert!(announce
            .verify(&signer.public_key(), &Ed25519Verifier)
            .unwrap());
    }

    #[test]
    fn observe_rejects_impossible_tuples() {
        let n = NeighbourClusters::new();

        assert!(!n.observe(nid(1), cinfo(1, 0), t(0)), "size 0");

        let mut future = cinfo(1, 1);
        future.ctime = t(MAX_CTIME_SKEW_MS + 1);
        assert!(!n.observe(nid(2), future, t(0)), "ctime past the allowance");

        // At the boundary it is accepted: the allowance is inclusive.
        let mut edge = cinfo(1, 1);
        edge.ctime = t(MAX_CTIME_SKEW_MS);
        assert!(n.observe(nid(3), edge, t(0)));
        assert_eq!(n.len(), 1, "only the acceptable tuple was stored");
    }
}
