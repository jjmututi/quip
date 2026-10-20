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
    center_lookup_key, estimate_size_from_routing_table, far_cluster_id, fresh_cluster_id,
    near_cluster_id, percentile, ClusterConfig, ClusterInfo, ClusterInfoAnnounce, ClusterLevel,
    ClusterState, SplitAction,
};
use quip_net::MIN_CLUSTER_SIZE;

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

/// The outcome of one split evaluation (§13.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitPlan {
    /// The branch [`ClusterState::choose_split_target`] chose.
    pub action: SplitAction,
    /// The id this node moves to if the plan is applied.
    pub new_id: [u8; 16],
    /// The peer the center lookup picked, and its RTT sample. `None`
    /// when there is no routing-eligible peer to be the center.
    pub center: Option<(NodeId, u64)>,
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

    /// Evaluate the split decision without changing anything (§13.5).
    ///
    /// Returns `None` unless `split_due`. The plan is deterministic from
    /// local state: the same `now`, routing table and neighbour records
    /// always produce the same action and id.
    pub fn plan_split(&self, dht: &DhtHandle, now: Timestamp) -> Option<SplitPlan> {
        let view = self.recompute(dht, now);
        if !view.split_due {
            return None;
        }

        let cfg = self.inner.config;
        let cid = view.id;
        let near = near_cluster_id(&cid);
        let far = far_cluster_id(&cid);

        // §13.5's `get(hash(cid^N))`, served from connected peers: there
        // is no address book yet (M9.8), so the closest routing-eligible
        // peer stands in for the cluster center.
        let records = dht.routing_eligible_records();
        let center = dht
            .closest_to(&center_lookup_key(&cid), 1)
            .into_iter()
            .next()
            .map(|peer| {
                let rtt = records
                    .iter()
                    .find(|(id, _)| *id == peer)
                    .and_then(|(_, r)| r.rtt_ms)
                    .unwrap_or(u64::MAX);
                (peer, rtt)
            });
        let rtt_to_center = center.map(|(_, rtt)| rtt).unwrap_or(u64::MAX);

        let near_ok = self.candidate_acceptable(&near, &records);
        let far_ok = self.candidate_acceptable(&far, &records);

        let attempts = {
            let state = self.inner.state.lock().expect("cluster lock poisoned");
            state.split_attempts.saturating_add(1)
        };
        let action = if attempts > cfg.max_split_attempts {
            // §13.5: past the attempt limit, take a fresh cluster rather
            // than retry a branch that keeps failing acceptance.
            SplitAction::CreateNew
        } else {
            let state = self.inner.state.lock().expect("cluster lock poisoned");
            state.choose_split_target(rtt_to_center, near_ok, far_ok, &cfg)
        };

        let new_id = match action {
            SplitAction::JoinNear => near,
            SplitAction::JoinFar => far,
            SplitAction::CreateNew => fresh_cluster_id(&dht.local_id(), now, attempts),
        };

        Some(SplitPlan {
            action,
            new_id,
            center,
        })
    }

    /// Apply a plan: record the move and start a pending attempt.
    ///
    /// Nothing is counted here. §13.5 makes the attempt pending until
    /// the first eligible acceptance test after the migration, so
    /// `apply_split` neither increments nor clears the counter — the
    /// settlement check in `recompute` decides.
    pub fn apply_split(&self, plan: &SplitPlan, now: Timestamp) -> [u8; 16] {
        let mut state = self.inner.state.lock().expect("cluster lock poisoned");
        state.migrate(plan.new_id, now);
        plan.new_id
    }

    /// Decide the pending attempt (§13.5), if one is in flight.
    ///
    /// `recompute` calls this once the attempt has settled; tests call it
    /// directly. With no attempt in flight it is a no-op.
    pub fn note_split_outcome(&self, acceptable: bool) {
        let mut state = self.inner.state.lock().expect("cluster lock poisoned");
        state.note_split_outcome(acceptable, &self.inner.config);
    }

    /// Whether a split attempt is awaiting its first eligible verdict.
    pub fn split_attempt_pending(&self) -> bool {
        let state = self.inner.state.lock().expect("cluster lock poisoned");
        state.split_attempt_pending()
    }

    /// Consecutive split failures recorded so far.
    pub fn split_attempts(&self) -> u32 {
        let state = self.inner.state.lock().expect("cluster lock poisoned");
        state.split_attempts
    }

    /// Plan and apply a split if one is due.
    ///
    /// Returns the new cluster id when the node migrated. The move
    /// starts a *pending* attempt; the verdict comes from the first
    /// `recompute` taken at least `CLUSTER_HEARTBEAT` after it, not from
    /// the recompute performed here.
    pub fn split_if_due(&self, dht: &DhtHandle, now: Timestamp) -> Option<[u8; 16]> {
        let plan = self.plan_split(dht, now)?;
        let new_id = self.apply_split(&plan, now);
        // Refresh `size` and the member set against the new id. The RTT
        // timer restarts here if the samples are still over threshold,
        // which is correct: the new cluster gets its own episode.
        let _ = self.recompute(dht, now);
        Some(new_id)
    }

    /// Whether `candidate` is acceptable as a split target (§13.5).
    ///
    /// At least one routing-eligible peer must advertise exactly that
    /// cluster id, be within the RTT threshold, and report a cluster at
    /// least `MIN_CLUSTER_SIZE` large. The size check is the reason a
    /// split does not just bounce a node between two clusters too small
    /// to accept it back.
    fn candidate_acceptable(
        &self,
        candidate: &[u8; 16],
        records: &[(NodeId, crate::dht::PeerRecord)],
    ) -> bool {
        let threshold = self.inner.config.rtt_threshold_ms;
        records.iter().any(|(peer, record)| {
            let Some(info) = self.inner.neighbours.get(peer) else {
                return false;
            };
            info.id == *candidate
                && info.size >= MIN_CLUSTER_SIZE as u64
                && record
                    .rtt_ms
                    .map(|ms| ms <= threshold)
                    .unwrap_or(false)
        })
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

        let acceptable = state.is_acceptable(&samples, &self.inner.config);

        // §13.5: a split attempt is decided by the first acceptance test
        // taken after it has had `CLUSTER_HEARTBEAT` to settle. Deciding
        // at the move itself would call every attempt a failure: the
        // member set is empty until a peer has re-announced the new id.
        if state.split_attempt_pending() && state.pending_split_settled(now, &self.inner.config) {
            state.note_split_outcome(acceptable, &self.inner.config);
        }

        ClusterView {
            id: state.id,
            level: state.level,
            size: state.size,
            members,
            acceptable,
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

#[cfg(test)]
mod split_tests {
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

    /// Test peers are `[b; 32]`, so the first byte identifies the slot
    /// the peer was registered under.
    struct Mesh {
        dht: DhtHandle,
        cluster: ClusterHandle,
        local: NodeId,
    }

    const CID: [u8; 16] = [0x11; 16];

    /// Three routing-eligible peers and a cluster at the local tier.
    /// The RTT samples are left to each test: they are the input that
    /// decides both `split_due` and the branch, and nothing else varies.
    fn mesh() -> Mesh {
        let local = nid(0);
        let (dht, _rx) = DhtHandle::new(local);
        for i in 1..=3u8 {
            dht.note_peer(nid(i), slot(i, 1), None, t(0));
            dht.update_lifecycle(&nid(i), &slot(i, 1), PeerLifecycle::NatDirect);
        }
        let cluster = ClusterHandle::new(CID, ClusterLevel::Local, t(0));
        Mesh { dht, cluster, local }
    }

    fn set_rtt(m: &Mesh, peer: &NodeId, ms: u64) {
        m.dht.note_rtt(peer, &slot(peer[0], 1), ms);
    }

    /// Number of peers in a mesh wide enough to satisfy §13.2's
    /// 20-sample minimum.
    const WIDE: u8 = 25;

    /// A mesh wide enough for the acceptance test to be satisfiable, so
    /// a pending attempt can end in success rather than only in failure.
    fn wide_mesh() -> Mesh {
        let local = nid(0);
        let (dht, _rx) = DhtHandle::new(local);
        for i in 1..=WIDE {
            dht.note_peer(nid(i), slot(i, 1), None, t(0));
            dht.update_lifecycle(&nid(i), &slot(i, 1), PeerLifecycle::NatDirect);
        }
        let cluster = ClusterHandle::new(CID, ClusterLevel::Local, t(0));
        Mesh { dht, cluster, local }
    }

    fn announce(m: &Mesh, peer: NodeId, id: [u8; 16], size: u64) {
        assert!(m.cluster.observe_cluster_info(
            peer,
            ClusterInfo {
                id,
                size,
                ctime: t(0),
            },
            t(0),
        ));
    }

    /// 181 s after the first over-threshold observation, i.e. past
    /// `heartbeat * 3` for the local tier.
    fn split_due_at() -> Timestamp {
        t(181_000)
    }

    /// Start the over-threshold timer: three samples at 200 ms against a
    /// 30 ms threshold.
    fn prime_split_timer(m: &Mesh) {
        for i in 1..=3u8 {
            set_rtt(m, &nid(i), 200);
        }
        m.cluster.recompute(&m.dht, t(0));
    }

    #[test]
    fn no_split_before_the_timer_fires() {
        let m = mesh();
        prime_split_timer(&m);
        assert!(
            m.cluster.plan_split(&m.dht, t(60_000)).is_none(),
            "60 s of over-threshold RTT is not yet `heartbeat * 3`"
        );
    }

    /// The near branch: the center is close and some peer advertises
    /// `cid^N` at an acceptable size. The new id is asserted against the
    /// derivation, not merely as "different": if `hash` changed, this
    /// test fails rather than passing on an arbitrary id.
    #[test]
    fn split_joins_near_when_the_center_is_close_and_near_is_acceptable() {
        let m = mesh();
        prime_split_timer(&m);

        // The center is whichever peer is closest to hash(cid^N); give
        // that peer the close sample so `rtt_to_center` is within
        // threshold.
        let center = m.dht.closest_to(&center_lookup_key(&CID), 1)[0];
        set_rtt(&m, &center, 5);
        announce(&m, center, near_cluster_id(&CID), 40);

        let plan = m
            .cluster
            .plan_split(&m.dht, split_due_at())
            .expect("split due");

        assert_eq!(plan.action, SplitAction::JoinNear);
        assert_eq!(plan.new_id, near_cluster_id(&CID));
        assert_eq!(
            plan.center,
            Some((center, 5)),
            "the center is the close peer"
        );
    }

    /// The far branch: the center is too far, so `JoinNear` cannot be
    /// taken even though a peer is close to us; `cid^F` is acceptable.
    #[test]
    fn split_joins_far_when_the_center_is_distant() {
        let m = mesh();
        prime_split_timer(&m);

        let far = far_cluster_id(&CID);
        // One close peer advertising the far id. If that peer happens to
        // be the center, `rtt_to_center` is small but `near_acceptable`
        // is false, so the branch is still far.
        set_rtt(&m, &nid(2), 5);
        announce(&m, nid(2), far, 40);

        let plan = m
            .cluster
            .plan_split(&m.dht, split_due_at())
            .expect("split due");

        assert_eq!(plan.action, SplitAction::JoinFar);
        assert_eq!(plan.new_id, far_cluster_id(&CID));
        assert_ne!(plan.new_id, near_cluster_id(&CID));
    }

    /// Neither branch is acceptable: the node takes a fresh id, derived
    /// from its identity, the time and the attempt count.
    #[test]
    fn split_creates_a_new_cluster_when_neither_branch_is_acceptable() {
        let m = mesh();
        prime_split_timer(&m);

        let plan = m
            .cluster
            .plan_split(&m.dht, split_due_at())
            .expect("split due");

        assert_eq!(plan.action, SplitAction::CreateNew);
        assert_eq!(
            plan.new_id,
            fresh_cluster_id(&m.local, split_due_at(), 1),
            "the id is the documented derivation, not an arbitrary value"
        );
    }

    /// The milestone's purpose: peers that announce a different cluster
    /// id leave the member set when the local id moves, with no change
    /// to the transport and no peer disconnecting.
    #[test]
    fn a_split_partitions_the_member_set_through_the_exchanged_tuple() {
        let m = mesh();
        for i in 1..=3u8 {
            set_rtt(&m, &nid(i), 10); // within threshold: all three are members
        }
        // Peers 1 and 2 claim our cluster; peer 3 claims another.
        announce(&m, nid(1), CID, 40);
        announce(&m, nid(2), CID, 40);
        announce(&m, nid(3), [0xEE; 16], 40);

        let before = m.cluster.recompute(&m.dht, t(0));
        assert_eq!(before.members, vec![nid(1), nid(2)]);

        let table_before: Vec<NodeId> = m
            .dht
            .table_snapshot()
            .iter()
            .map(|(id, _)| *id)
            .collect();

        // Exactly what `split_if_due` does, minus the timer: the only
        // input that changes is the local id.
        let plan = SplitPlan {
            action: SplitAction::JoinNear,
            new_id: near_cluster_id(&CID),
            center: None,
        };
        m.cluster.apply_split(&plan, t(1_000));

        let after = m.cluster.recompute(&m.dht, t(1_000));
        assert_eq!(after.id, plan.new_id, "the node moved");
        assert!(
            after.members.is_empty(),
            "every peer still advertises the old id: {after:?}"
        );

        let table_after: Vec<NodeId> = m
            .dht
            .table_snapshot()
            .iter()
            .map(|(id, _)| *id)
            .collect();
        assert_eq!(
            table_after, table_before,
            "no peer left the routing table; the partition is the tuple's doing"
        );
    }

    /// `split_if_due` is the whole operation, not just the plan: it
    /// moves the node and returns the id the heartbeat will announce.
    #[test]
    fn split_if_due_migrates_and_reports_the_new_id() {
        let m = mesh();
        prime_split_timer(&m);
        assert!(m.cluster.plan_split(&m.dht, t(60_000)).is_none());

        let new_id = m
            .cluster
            .split_if_due(&m.dht, split_due_at())
            .expect("split due");
        assert_eq!(m.cluster.info().id, new_id);
        assert_eq!(
            new_id,
            fresh_cluster_id(&m.local, split_due_at(), 1),
            "with no acceptable branch the node takes a fresh id"
        );
    }

    // ---- §13.5 attempt episode ----

    /// §13.5 with Shape B: the migration starts a *pending* attempt, and
    /// only a recompute at least one heartbeat later decides it.
    #[test]
    fn a_failed_attempt_counts_only_after_the_settle_interval() {
        let m = mesh();
        prime_split_timer(&m); // three samples: below the §13.2 minimum of 20
        let before = m.cluster.info().id;

        let new_id = m
            .cluster
            .split_if_due(&m.dht, split_due_at())
            .expect("split due");

        assert_ne!(new_id, before, "the node moved");
        assert!(m.cluster.split_attempt_pending(), "the attempt is pending");
        assert_eq!(
            m.cluster.split_attempts(),
            0,
            "a pending attempt does not count"
        );

        let settled = m.cluster.recompute(&m.dht, t(181_000 + 60_000));
        assert!(
            !settled.acceptable,
            "three samples is below §13.2's minimum"
        );
        assert_eq!(
            m.cluster.split_attempts(),
            1,
            "the settled verdict counts the failure"
        );
        assert!(!m.cluster.split_attempt_pending());
    }

    #[test]
    fn note_split_outcome_clears_only_on_success() {
        let m = mesh();
        let plan = SplitPlan {
            action: SplitAction::JoinNear,
            new_id: near_cluster_id(&CID),
            center: None,
        };

        m.cluster.apply_split(&plan, t(1_000));
        m.cluster.note_split_outcome(false);
        assert_eq!(m.cluster.split_attempts(), 1);
        assert!(
            !m.cluster.split_attempt_pending(),
            "a verdict ends the attempt"
        );

        // A second verdict needs a second attempt: with none in flight,
        // `note_split_outcome` is a no-op.
        m.cluster.apply_split(&plan, t(2_000));
        m.cluster.note_split_outcome(true);
        assert_eq!(m.cluster.split_attempts(), 0, "success clears it");
    }

    /// Three consecutive failures with `MAX_SPLIT_ATTEMPTS = 3` force
    /// `CreateNew` on the next evaluation — even when a branch would
    /// otherwise be acceptable, which is what distinguishes the cap from
    /// "no branch was acceptable".
    #[test]
    fn the_cap_forces_a_new_cluster_even_when_a_branch_is_acceptable() {
        let m = mesh();
        prime_split_timer(&m);
        let mut now_ms = 181_000u64;

        for i in 1..=3u32 {
            // Keep the p90 over threshold so the split stays due, then
            // give the center a close sample so the near branch is
            // acceptable.
            for j in 1..=3u8 {
                set_rtt(&m, &nid(j), 200);
            }
            let cid = m.cluster.info().id;
            let center = m.dht.closest_to(&center_lookup_key(&cid), 1)[0];
            set_rtt(&m, &center, 5);
            announce(&m, center, near_cluster_id(&cid), 40);

            let plan = m.cluster.plan_split(&m.dht, t(now_ms)).expect("due");
            assert_eq!(
                plan.action,
                SplitAction::JoinNear,
                "a branch is acceptable on attempt {i}"
            );

            m.cluster.apply_split(&plan, t(now_ms));
            now_ms += 60_000; // settle: one CLUSTER_HEARTBEAT
            let view = m.cluster.recompute(&m.dht, t(now_ms));
            assert!(!view.acceptable, "three samples is below §13.2's minimum");
            assert_eq!(m.cluster.split_attempts(), i);
            now_ms += 181_000; // the new cluster's own split timer
        }

        for j in 1..=3u8 {
            set_rtt(&m, &nid(j), 200);
        }
        let cid = m.cluster.info().id;
        let center = m.dht.closest_to(&center_lookup_key(&cid), 1)[0];
        set_rtt(&m, &center, 5);
        announce(&m, center, near_cluster_id(&cid), 40);

        let plan = m.cluster.plan_split(&m.dht, t(now_ms)).expect("due");
        assert_eq!(
            plan.action,
            SplitAction::CreateNew,
            "MAX_SPLIT_ATTEMPTS consecutive failures force a new cluster"
        );
        assert_eq!(plan.new_id, fresh_cluster_id(&m.local, t(now_ms), 4));
    }

    // ---- Shape B: pending attempts and the settle interval ----

    #[test]
    fn pending_attempt_does_not_count_against_the_cap() {
        let m = mesh();
        prime_split_timer(&m);

        m.cluster
            .split_if_due(&m.dht, split_due_at())
            .expect("split due");

        assert!(m.cluster.split_attempt_pending());
        assert_eq!(
            m.cluster.split_attempts(),
            0,
            "the recompute at the migration is not eligible, so nothing is counted"
        );
    }

    #[test]
    fn create_new_begins_a_fresh_pending_attempt() {
        let m = mesh();
        prime_split_timer(&m);

        // One decided failure, so the counter is non-zero and the
        // CreateNew decision below has something it could wrongly add to.
        m.cluster
            .split_if_due(&m.dht, t(181_000))
            .expect("split due");
        let view = m.cluster.recompute(&m.dht, t(241_000));
        assert!(!view.acceptable);
        assert_eq!(m.cluster.split_attempts(), 1);

        // No acceptable branch exists in this mesh, so the next plan is
        // CreateNew. The decision is not an outcome.
        m.cluster
            .split_if_due(&m.dht, t(422_000))
            .expect("split due");

        assert_eq!(
            m.cluster.split_attempts(),
            1,
            "CreateNew neither increments nor decides the previous attempt"
        );
        assert!(
            m.cluster.split_attempt_pending(),
            "the new cluster starts a fresh pending attempt"
        );
    }

    #[test]
    fn the_cap_is_reachable_after_the_settle_interval() {
        let m = mesh();
        prime_split_timer(&m);
        let mut now_ms = 181_000u64;

        for i in 1..=3u32 {
            m.cluster
                .split_if_due(&m.dht, t(now_ms))
                .expect("split due");
            now_ms += 60_000;
            let view = m.cluster.recompute(&m.dht, t(now_ms));
            assert!(
                !view.acceptable,
                "three samples is below §13.2's minimum of 20"
            );
            assert_eq!(m.cluster.split_attempts(), i, "failure {i} is counted");
            now_ms += 181_000;
        }

        let plan = m.cluster.plan_split(&m.dht, t(now_ms)).expect("due");
        assert_eq!(
            plan.action,
            SplitAction::CreateNew,
            "three consecutive failures reach MAX_SPLIT_ATTEMPTS"
        );
    }

    #[test]
    fn a_pending_attempt_that_becomes_acceptable_clears_the_counter() {
        let m = wide_mesh();
        for i in 1..=WIDE {
            set_rtt(&m, &nid(i), 200);
        }
        m.cluster.recompute(&m.dht, t(0));

        // Two decided failures.
        let mut now_ms = 181_000u64;
        for i in 1..=2u32 {
            m.cluster
                .split_if_due(&m.dht, t(now_ms))
                .expect("split due");
            now_ms += 60_000;
            m.cluster.recompute(&m.dht, t(now_ms));
            assert_eq!(m.cluster.split_attempts(), i);
            now_ms += 181_000;
        }

        // The RTTs recover, and a new attempt's first eligible verdict
        // is acceptable.
        for i in 1..=WIDE {
            set_rtt(&m, &nid(i), 10);
        }
        let cid = m.cluster.info().id;
        let plan = SplitPlan {
            action: SplitAction::JoinNear,
            new_id: near_cluster_id(&cid),
            center: None,
        };
        m.cluster.apply_split(&plan, t(now_ms));
        assert!(m.cluster.split_attempt_pending());

        let view = m.cluster.recompute(&m.dht, t(now_ms + 60_000));
        assert!(view.acceptable, "25 samples at 10 ms is acceptable");
        assert_eq!(
            m.cluster.split_attempts(),
            0,
            "success clears the consecutive failures"
        );
        assert!(!m.cluster.split_attempt_pending());
    }
}

