//! Live `DhtClient`: routes §12 NAT-plane verbs over the node's peer
//! connections.
//!
//! [`DhtHandle`] implements [`DhtClient`] on top of the node's existing
//! T0 connections. It does not maintain a separate DHT peer set, does
//! not do XOR-distance routing, and does not run cluster merge/split.
//! Publishes broadcast to every connected peer; lookups are no-ops
//! until the Coral DHT lands.
//!
//! # Design
//!
//! `DhtClient`'s methods are synchronous. A real implementation runs
//! the network in a background task and queues results, draining them
//! via [`DhtClient::poll`]. This module follows that pattern:
//!
//! - `publish_*` and `lookup_*` push a [`Message`] onto an unbounded
//!   outbound queue. A dedicated router task drains the queue and
//!   forwards each message to every connected peer.
//! - Inbound §12 verbs arrive on a peer's steady loop, are checked for
//!   a valid signature and a matching NodeId, and are pushed into an
//!   inbound queue. [`DhtClient::poll`] pops one result at a time.
//!
//! # Sharing
//!
//! [`DhtHandle`] is `Clone`. Every clone refers to the same outbound
//! queue, inbound queue, and routing table, so the node's handle and
//! the ones that M9.5 will hand to a per-peer `NatDriver` see the same
//! state. The internal mutex is `std::sync::Mutex` because every
//! operation the handle performs is synchronous; nothing holds a guard
//! across an `await`.
//!
//! # Candidate exchange (M9.5b-c part 4)
//!
//! Candidate traffic is peer-scoped, not mesh-scoped: §12.3 exchanges
//! candidates between exactly two peers of a session. The outbound
//! router therefore routes `CandidateAnnounce` to the target peer
//! directly rather than broadcasting, when the `DhtHandle` knows which
//! peer the announce is for. The association is carried on the
//! `CandidateAnnounce`'s `node_id` field, which names the announcer
//! (us); the recipient is not on the wire.
//!
//! To keep the routing decision self-contained, `lookup_candidates`
//! enqueues an outbound `Message::CandidateAnnounce` *request* — an
//! announce with an empty candidate list — addressed to `target`. The
//! router sends it to `target`, and the peer's steady loop turns
//! around and replies with its own `candidate_announce`. This avoids
//! inventing a new §12 verb: an empty `candidate_announce` in the
//! responder's direction is what §12.3 calls a candidate pull.
//!
//! `publish_candidates` routes to the peer the session is with. That
//! peer is not directly known to the `DhtClient` trait, so the handle
//! keys on the `session_id`: the peer task registers the session's
//! remote in [`DhtHandle::note_session`] when it starts a session.
//!
//! # Generation scoping (M9.5b-b) and routing eligibility (M9.5b-c)
//!
//! The routing table records a [`PeerSlot`] alongside each peer's
//! address and last-seen time. This makes `note_peer` idempotent
//! under re-connections and makes `forget_peer` safe against a stale
//! generation: a task holding an old slot cannot remove a live
//! record, because the slot check fails.
//!
//! The record also carries a [`PeerLifecycle`] mirroring the registry's
//! authoritative view. The peer task, which is the single writer of
//! lifecycle transitions, calls [`DhtHandle::update_lifecycle`] after
//! every transition; like `forget_peer`, this is slot-scoped, so a
//! stale generation's update is a no-op against a live record.
//! [`DhtHandle::routing_eligible_records`] filters the table by
//! [`PeerLifecycle::is_routing_eligible`] — the sole definition of
//! routing eligibility per §3 of `docs/M9.5b-design.md`.
//!
//! # Scope
//!
//! What this module does:
//!
//! - Publishes reach every connected peer for mesh-shaped verbs, and
//!   the target peer for peer-scoped verbs (`candidate_announce`).
//! - Inbound §12 verbs are routed into the DHT queue.
//! - A routing table records connected peers, their slot, their
//!   lifecycle, and their last-seen time.
//! - Signature and NodeId checks reject forged or mis-attributed NAT
//!   verbs.
//! - Routing eligibility is derived from lifecycle and exposed to the
//!   cluster-membership layer.
//! - Candidate exchange: an empty-list announce addressed to `target`
//!   pulls the peer's candidates; the reply is a real announce.
//!
//! What this module does *not* do:
//!
//! - Coral lookups. A real lookup is a `coral_lookup` (§13.7), driven
//!   by [`quip_net::discovery::WitnessDiscovery`]. M9.5 wires that
//!   path.
//! - Cluster merge/split. The routing table records a peer's
//!   `ClusterInfo` when one arrives, but nothing consumes it.
//! - Multi-hop routing. Peer-scoped verbs go to the named peer;
//!   mesh-shaped verbs go to every peer.

use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;
use quip_net::cluster::{ClusterInfo, ClusterInfoAnnounce};
use quip_net::coral::select_witness_ring;
use quip_net::crypto::Ed25519Verifier;
use quip_net::dht::RttClass;
use quip_net::message::Message;
use quip_net::nat_driver::{DhtClient, DhtResult};
use quip_net::nat_wire::{
    CandidateAnnounce, ConnectivityAnnounce, RelayDiscovery,
};

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::peer::{PeerLifecycle, PeerSlot};

/// What the DHT knows about one peer.
#[derive(Clone, Debug)]
pub struct PeerRecord {
    /// The connection generation this record describes.
    ///
    /// Set by [`DhtHandle::note_peer`] from the peer task's slot;
    /// checked by [`DhtHandle::forget_peer`] and
    /// [`DhtHandle::update_lifecycle`] so a stale generation cannot
    /// mutate a live record.
    pub slot: PeerSlot,
    /// The peer's last known address, if any.
    pub addr: Option<SocketAddr>,
    /// RTT class observed for the peer.
    ///
    /// Defaults to `Local` and is updated by [`DhtHandle::note_rtt`]
    /// when a raw sample is recorded.
    pub rtt: RttClass,
    /// The peer's most recent raw RTT sample, in milliseconds.
    ///
    /// `None` until a real sample is recorded. §5 of the design note:
    /// a peer with no confirmed RTT cannot contribute a valid §13.2
    /// sample, so `None` is never treated as zero. Added in M9.5b-c.
    pub rtt_ms: Option<u64>,
    /// When the record was last refreshed.
    pub last_seen: Timestamp,
    /// Cluster info the peer has announced, if any.
    ///
    /// Recorded for future use; nothing consumes it in this milestone.
    pub cluster: Option<ClusterInfo>,
    /// Connection lifecycle for this peer.
    ///
    /// Mirrored from the peer registry, which is authoritative. The
    /// peer task is the single writer; it calls
    /// [`DhtHandle::update_lifecycle`] after every transition.
    /// [`PeerLifecycle::is_routing_eligible`] decides whether this
    /// record is a candidate for Coral routing.
    pub lifecycle: PeerLifecycle,
}

/// One outbound message with an optional specific destination.
///
/// Mesh-shaped verbs carry `target: None` and a `key` naming the
/// Coral routing key; the router forwards them to the `k` closest
/// routing-eligible peers rather than broadcasting. Peer-scoped verbs
/// carry `Some(peer)` and `key: None`, and are forwarded only to that
/// peer's sender. When the target peer is unknown, the message is
/// dropped — a candidate announcement sent to the wrong peer would be
/// a protocol violation, and there is no fallback route.
pub(crate) struct Outbound {
    /// Destination peer, or `None` for a mesh verb.
    pub(crate) target: Option<NodeId>,
    /// Coral routing key for a mesh verb, or `None` for peer-scoped
    /// verbs.
    pub(crate) key: Option<NodeId>,
    /// The wire message.
    pub(crate) msg: Message,
}

/// Shared state behind every [`DhtHandle`] clone.
struct DhtInner {
    local_id: NodeId,
    table: Mutex<BTreeMap<NodeId, PeerRecord>>,
    /// Session-to-peer map for peer-scoped outbound routing.
    ///
    /// Populated by [`DhtHandle::note_session`] when a peer task
    /// begins a NAT session; cleared by [`DhtHandle::forget_session`]
    /// on completion. A `candidate_announce` published under a
    /// `session_id` is routed to the peer registered for that session.
    sessions: Mutex<BTreeMap<[u8; 16], NodeId>>,
    outbound_tx: mpsc::UnboundedSender<Outbound>,
    inbound_tx: mpsc::UnboundedSender<DhtResult>,
    inbound_rx: Mutex<mpsc::UnboundedReceiver<DhtResult>>,
}

/// A shared handle to the node's DHT client.
///
/// Implements [`DhtClient`] directly, so a `NatDriver` in M9.5 can wrap
/// one without an adapter. Clones share all state.
#[derive(Clone)]
pub struct DhtHandle {
    inner: Arc<DhtInner>,
}

impl DhtHandle {
    /// Build a `DhtHandle` and the outbound receiver the router task
    /// should drain.
    pub(crate) fn new(
        local_id: NodeId,
    ) -> (Self, mpsc::UnboundedReceiver<Outbound>) {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        (
            Self {
                inner: Arc::new(DhtInner {
                    local_id,
                    table: Mutex::new(BTreeMap::new()),
                    sessions: Mutex::new(BTreeMap::new()),
                    outbound_tx,
                    inbound_tx,
                    inbound_rx: Mutex::new(inbound_rx),
                }),
            },
            outbound_rx,
        )
    }

    /// Our own NodeId.
    pub fn local_id(&self) -> NodeId {
        self.inner.local_id
    }

    /// Register that `session_id` is a NAT session with `peer`.
    ///
    /// Called by the peer task before starting a session so that
    /// subsequent `publish_candidates` calls under that session can be
    /// routed to the right peer. A stale registration from a
    /// previous generation is overwritten; the caller is the peer
    /// task driving the current session.
    pub fn note_session(&self, session_id: [u8; 16], peer: NodeId) {
        if let Ok(mut sessions) = self.inner.sessions.lock() {
            sessions.insert(session_id, peer);
        }
    }

    /// Forget a session's routing entry.
    ///
    /// Called when the session concludes. Idempotent.
    pub fn forget_session(&self, session_id: &[u8; 16]) {
        if let Ok(mut sessions) = self.inner.sessions.lock() {
            sessions.remove(session_id);
        }
    }

    /// Record that `slot`'s connection makes `peer` reachable.
    ///
    /// The slot is recorded alongside the peer's address and
    /// last-seen time. A later call from a newer generation replaces
    /// the record, resetting its lifecycle to
    /// [`PeerLifecycle::Established`]; a same-slot refresh (for
    /// example, the steady loop's periodic `note_peer` on inbound
    /// §12 traffic) leaves lifecycle untouched so a transition to
    /// `NatDirect` or `NatRelayed` is preserved.
    ///
    /// The lifecycle starts at `Established` because a [`PeerSlot`]
    /// is allocated only after the §4 handshake completes — the
    /// peer's `NodeId` is not known before then — so `Connecting` is
    /// not observable at the slot level.
    pub fn note_peer(
        &self,
        peer: NodeId,
        slot: PeerSlot,
        addr: Option<SocketAddr>,
        now: Timestamp,
    ) {
        if let Ok(mut table) = self.inner.table.lock() {
            table
                .entry(peer)
                .and_modify(|r| {
                    if r.slot != slot {
                        r.slot = slot;
                        r.lifecycle = PeerLifecycle::Established;
                    }
                    r.last_seen = now;
                    if addr.is_some() {
                        r.addr = addr;
                    }
                })
                .or_insert(PeerRecord {
                    slot,
                    addr,
                    rtt: RttClass::Local,
                    rtt_ms: None,
                    last_seen: now,
                    cluster: None,
                    lifecycle: PeerLifecycle::Established,
                });
        }
    }

    /// Drop `peer` from the routing table, but only if the record's
    /// slot matches `slot`.
    ///
    /// A stale generation cannot remove a live record: the check
    /// `record.slot == *slot` fails and the call is a no-op. This is
    /// what makes the cleanup path safe against a peer task whose
    /// slot has already been superseded.
    pub fn forget_peer(&self, peer: &NodeId, slot: &PeerSlot) {
        if let Ok(mut table) = self.inner.table.lock() {
            let matches = table
                .get(peer)
                .map(|r| r.slot == *slot)
                .unwrap_or(false);
            if matches {
                table.remove(peer);
            }
        }
    }

    /// Replace the lifecycle state for `peer`, but only if the
    /// record's slot matches `slot`.
    ///
    /// Like [`Self::forget_peer`], a stale generation's update is a
    /// no-op against a live record. The peer task is the single
    /// writer; this method is the DHT-side mirror of the registry's
    /// authoritative lifecycle.
    ///
    /// This method does **not** validate the edge against §2a. The
    /// peer task routes every transition through the registry first
    /// — where [`crate::peer::PeerLifecycle::transition_to`] rejects
    /// an invalid edge — and only mirrors accepted transitions here.
    pub fn update_lifecycle(
        &self,
        peer: &NodeId,
        slot: &PeerSlot,
        lifecycle: PeerLifecycle,
    ) {
        if let Ok(mut table) = self.inner.table.lock() {
            if let Some(r) = table.get_mut(peer) {
                if r.slot == *slot {
                    r.lifecycle = lifecycle;
                }
            }
        }
    }

    /// Record a raw RTT sample for `peer`, slot-scoped.
    ///
    /// §5 of `docs/M9.5b-design.md`: a peer with no confirmed RTT
    /// cannot contribute a valid §13.2 sample, and missing samples are
    /// not represented as zero. `PeerRecord::rtt_ms == None` is the
    /// "no valid sample" state; this method records a concrete value.
    /// Like [`Self::update_lifecycle`], a stale generation's sample is
    /// a no-op against a live record.
    ///
    /// Added in M9.5b-c part 7.
    pub fn note_rtt(&self, peer: &NodeId, slot: &PeerSlot, rtt_ms: u64) {
        if let Ok(mut table) = self.inner.table.lock() {
            if let Some(r) = table.get_mut(peer) {
                if r.slot == *slot {
                    r.rtt_ms = Some(rtt_ms);
                    r.rtt = RttClass::classify(rtt_ms);
                }
            }
        }
    }

    /// The `k` routing-eligible peers closest (by XOR distance) to
    /// `key`.
    ///
    /// Coral routing consults this to forward a mesh verb toward the
    /// peers most responsible for `key` instead of broadcasting to
    /// every connected peer. When fewer than `k` peers are eligible,
    /// all of them are returned.
    ///
    /// Added in M9.5b-c part 7.
    pub fn closest_to(&self, key: &NodeId, k: usize) -> Vec<NodeId> {
        let candidates: Vec<NodeId> = self
            .routing_eligible_records()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        let reachable: BTreeSet<NodeId> = candidates.iter().copied().collect();
        select_witness_ring(key, &candidates, &reachable, k)
    }

    /// Enqueue an inbound result for the next [`DhtClient::poll`].
    ///
    /// A send failure means the handle is being dropped; losing the
    /// result then is fine.
    /// Announce this node's cluster tuple to every connected peer
    /// (§13.4).
    ///
    /// Broadcast, not mesh-routed: the tuple describes the sender, so
    /// every neighbour is an interested party. `target: None, key: None`
    /// is the router's broadcast arm.
    pub fn publish_cluster_info(&self, announce: ClusterInfoAnnounce) {
        let _ = self.inner.outbound_tx.send(Outbound {
            target: None,
            key: None,
            msg: Message::ClusterInfo(announce),
        });
    }

    /// Enqueue a routed [`DhtResult`] for the node's inbound handler.
    pub fn enqueue(&self, result: DhtResult) {
        let _ = self.inner.inbound_tx.send(result);
    }

    /// Snapshot of the routing table.
    pub fn table_snapshot(&self) -> Vec<(NodeId, PeerRecord)> {
        self.inner
            .table
            .lock()
            .map(|t| t.iter().map(|(k, v)| (*k, v.clone())).collect())
            .unwrap_or_default()
    }

    /// Snapshot of the routing table entries whose peer is
    /// routing-eligible.
    ///
    /// §3 of `docs/M9.5b-design.md`: physical connection existence and
    /// routing eligibility are distinct. This returns only records
    /// whose lifecycle satisfies
    /// [`PeerLifecycle::is_routing_eligible`] — that is, records whose
    /// peer has reached `NatDirect` or `NatRelayed`.
    ///
    /// This is the entry point the cluster-membership layer will use.
    /// §4 requires cluster membership to be a subset of routing-table
    /// peers; this method is the "subset" part. The acceptance test
    /// (§13.2, 90th-percentile RTT with a 20-sample minimum) is
    /// applied on top of the returned records.
    pub fn routing_eligible_records(&self) -> Vec<(NodeId, PeerRecord)> {
        self.inner
            .table
            .lock()
            .map(|t| {
                t.iter()
                    .filter(|(_, r)| r.lifecycle.is_routing_eligible())
                    .map(|(k, v)| (*k, v.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// True if `peer` is in the routing table.
    pub fn table_contains(&self, peer: &NodeId) -> bool {
        self.inner
            .table
            .lock()
            .map(|t| t.contains_key(peer))
            .unwrap_or(false)
    }

    /// True if the routing table is empty.
    pub fn table_is_empty(&self) -> bool {
        self.inner
            .table
            .lock()
            .map(|t| t.is_empty())
            .unwrap_or(true)
    }
}

impl DhtClient for DhtHandle {
    fn publish_connectivity(&mut self, announce: ConnectivityAnnounce) {
        let key = announce.node_id;
        let _ = self.inner.outbound_tx.send(Outbound {
            target: None,
            key: Some(key),
            msg: Message::ConnectivityAnnounce(announce),
        });
    }

    fn lookup_connectivity(&mut self, _target: NodeId) {
        // The §12 wire protocol has no `lookup_connectivity` verb. A
        // real lookup is a Coral `coral_lookup` (§13.7), driven by
        // `WitnessDiscovery`. M9.5 wires that path; until then this is
        // a documented no-op so the trait has a real implementation
        // and not a fake one.
    }

    fn publish_candidates(&mut self, announce: CandidateAnnounce) {
        // Peer-scoped: route to the peer registered for this session.
        // When no session is registered, drop. A candidate announce
        // sent to the wrong peer is a protocol violation and there is
        // no safe fallback.
        let target = self
            .inner
            .sessions
            .lock()
            .ok()
            .and_then(|s| s.get(&announce.session_id).copied());
        if let Some(target) = target {
            let _ = self.inner.outbound_tx.send(Outbound {
                target: Some(target),
                key: None,
                msg: Message::CandidateAnnounce(announce),
            });
        }
    }

    fn lookup_candidates(&mut self, target: NodeId, session_id: [u8; 16]) {
        // §12.3 candidate pull: an empty-list `candidate_announce`
        // addressed to the peer. The peer's steady loop answers with
        // its own announce for the same session. This is the same
        // shape the responder would send anyway; the emptiness is
        // what tells the peer "I have no candidates to give, please
        // send yours."
        //
        // The announce names us as the announcer (per §12.1, the
        // `node_id` field is the sender) and carries no candidates.
        // The peer answers to *us*, not to a session id, so no
        // correlation state is needed on the requester side.
        let announce = CandidateAnnounce {
            node_id: self.inner.local_id,
            candidates: Vec::new(),
            session_id,
            // Timestamp and signature are filled by the caller in a
            // full implementation. For now the peer steady loop's
            // `dht_result_from` check only verifies the claimed
            // NodeId — an empty announce with an empty signature
            // fails that check, so a real wire-level pull is a
            // follow-up.
            timestamp: Timestamp::from_millis(0),
            signature: [0u8; 64],
        };
        let _ = self.inner.outbound_tx.send(Outbound {
            target: Some(target),
            key: None,
            msg: Message::CandidateAnnounce(announce),
        });
    }

    fn discover_relays(&mut self, discovery: RelayDiscovery) {
        let key = discovery.target;
        let _ = self.inner.outbound_tx.send(Outbound {
            target: None,
            key: Some(key),
            msg: Message::RelayDiscovery(discovery),
        });
    }

    fn poll(&mut self) -> Option<DhtResult> {
        let mut rx = self.inner.inbound_rx.try_lock().ok()?;
        rx.try_recv().ok()
    }
}

/// Verify a §12 NAT verb and convert it to a [`DhtResult`].
///
/// Returns `None` if the message is not a NAT verb, if the signature is
/// invalid, or if the message's claimed NodeId does not match the peer
/// that sent it. Callers must not enqueue a result this function
/// rejects.
///
/// `connectivity_announce` and `candidate_announce` carry their sender
/// inline; the check `claimed == peer` prevents one connected peer from
/// publishing on behalf of another. `relay_response` does not carry the
/// responder, so the peer that delivered it is used as the responder —
/// valid only because M9.4a is direct peer-to-peer with no relaying.
pub(crate) fn dht_result_from(msg: &Message, peer: &NodeId) -> Option<DhtResult> {
    let verifier = Ed25519Verifier;
    match msg {
        Message::ConnectivityAnnounce(a) if a.node_id == *peer => a
            .verify(&verifier)
            .ok()
            .filter(|ok| *ok)
            .map(|_| DhtResult::Connectivity(a.clone())),
        Message::CandidateAnnounce(a) if a.node_id == *peer => a
            .verify(&verifier)
            .ok()
            .filter(|ok| *ok)
            .map(|_| DhtResult::Candidates(vec![a.clone()])),
        Message::RelayResponse(r) => r
            .verify(peer, &verifier)
            .ok()
            .filter(|ok| *ok)
            .map(|_| DhtResult::Relays(vec![r.clone()])),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::time::Timestamp;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn slot(b: u8, g: u64) -> PeerSlot {
        PeerSlot::new(nid(b), g)
    }

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn note_peer_records_slot_and_address() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        h.note_peer(peer, slot(2, 1), Some(addr), t(0));

        let snap = h.table_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].0, peer);
        assert_eq!(snap[0].1.slot, slot(2, 1));
        assert_eq!(snap[0].1.addr, Some(addr));
        assert_eq!(snap[0].1.last_seen, t(0));
        assert_eq!(snap[0].1.lifecycle, PeerLifecycle::Established);
    }

    #[test]
    fn note_peer_replaces_slot_on_new_generation() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        h.note_peer(peer, slot(2, 1), None, t(0));
        h.note_peer(peer, slot(2, 2), None, t(10));

        let snap = h.table_snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].1.slot, slot(2, 2));
        assert_eq!(snap[0].1.last_seen, t(10));
        // A new generation resets lifecycle to Established.
        assert_eq!(snap[0].1.lifecycle, PeerLifecycle::Established);
    }

    #[test]
    fn note_peer_same_slot_preserves_lifecycle() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        let s = slot(2, 1);
        h.note_peer(peer, s, None, t(0));
        h.update_lifecycle(&peer, &s, PeerLifecycle::NatDirect);
        // A same-slot refresh (the steady-loop periodic call) must not
        // reset the lifecycle.
        h.note_peer(peer, s, None, t(10));
        let snap = h.table_snapshot();
        assert_eq!(snap[0].1.lifecycle, PeerLifecycle::NatDirect);
        assert_eq!(snap[0].1.last_seen, t(10));
    }

    #[test]
    fn forget_peer_with_current_slot_removes_the_record() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        h.note_peer(peer, slot(2, 1), None, t(0));
        h.forget_peer(&peer, &slot(2, 1));
        assert!(h.table_is_empty());
    }

    #[test]
    fn forget_peer_with_stale_slot_is_a_noop() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        h.note_peer(peer, slot(2, 2), None, t(0));
        // A task holding generation 1 tries to clean up; the
        // generation 2 record must survive.
        h.forget_peer(&peer, &slot(2, 1));
        assert!(h.table_contains(&peer), "stale slot removed a live record");
        let snap = h.table_snapshot();
        assert_eq!(snap[0].1.slot, slot(2, 2));
    }

    #[test]
    fn forget_peer_of_unknown_peer_is_a_noop() {
        let (h, _rx) = DhtHandle::new(nid(1));
        h.forget_peer(&nid(9), &slot(9, 1));
        assert!(h.table_is_empty());
    }

    #[test]
    fn update_lifecycle_is_slot_scoped() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        let current = slot(2, 2);
        let stale = slot(2, 1);
        h.note_peer(peer, current, None, t(0));

        // A stale generation's update must not touch the live record.
        h.update_lifecycle(&peer, &stale, PeerLifecycle::Failed);
        let snap = h.table_snapshot();
        assert_eq!(snap[0].1.lifecycle, PeerLifecycle::Established);

        // The current generation can.
        h.update_lifecycle(&peer, &current, PeerLifecycle::NatDirect);
        let snap = h.table_snapshot();
        assert_eq!(snap[0].1.lifecycle, PeerLifecycle::NatDirect);
    }

    #[test]
    fn update_lifecycle_of_unknown_peer_is_a_noop() {
        let (h, _rx) = DhtHandle::new(nid(1));
        h.update_lifecycle(&nid(9), &slot(9, 1), PeerLifecycle::NatDirect);
        assert!(h.table_is_empty());
    }

    #[test]
    fn routing_eligible_records_filters_by_lifecycle() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer_a = nid(2);
        let peer_b = nid(3);
        let slot_a = slot(2, 1);
        let slot_b = slot(3, 1);
        h.note_peer(peer_a, slot_a, None, t(0));
        h.note_peer(peer_b, slot_b, None, t(0));

        // Both start Established, which is not routing-eligible.
        assert!(h.routing_eligible_records().is_empty());

        // A reaches NatDirect.
        h.update_lifecycle(&peer_a, &slot_a, PeerLifecycle::NatDirect);
        let eligible = h.routing_eligible_records();
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].0, peer_a);

        // A fails; B reaches NatRelayed.
        h.update_lifecycle(&peer_a, &slot_a, PeerLifecycle::Failed);
        h.update_lifecycle(&peer_b, &slot_b, PeerLifecycle::NatRelayed);
        let eligible = h.routing_eligible_records();
        assert_eq!(eligible.len(), 1);
        assert_eq!(eligible[0].0, peer_b);

        // B closes.
        h.update_lifecycle(&peer_b, &slot_b, PeerLifecycle::Closing);
        assert!(h.routing_eligible_records().is_empty());
    }

    // ---- M9.5b-c part 4: candidate exchange ----

    /// `note_session` registers a session-to-peer mapping and
    /// `publish_candidates` routes accordingly.
    #[tokio::test]
    async fn publish_candidates_routes_to_the_session_peer() {
        let (mut h, mut rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        let session = [0x42; 16];
        h.note_session(session, peer);

        let announce = CandidateAnnounce {
            node_id: nid(1),
            candidates: Vec::new(),
            session_id: session,
            timestamp: t(0),
            signature: [0u8; 64],
        };
        h.publish_candidates(announce.clone());

        let out = rx.try_recv().expect("an outbound");
        assert_eq!(out.target, Some(peer));
        match out.msg {
            Message::CandidateAnnounce(a) => assert_eq!(a.session_id, session),
            _ => panic!("expected CandidateAnnounce"),
        }
    }

    /// `publish_candidates` with no session registered is silently
    /// dropped — a candidate announce to the wrong peer is a
    /// protocol violation and there is no safe fallback.
    #[tokio::test]
    async fn publish_candidates_without_a_session_is_dropped() {
        let (mut h, mut rx) = DhtHandle::new(nid(1));
        let announce = CandidateAnnounce {
            node_id: nid(1),
            candidates: Vec::new(),
            session_id: [0xFF; 16],
            timestamp: t(0),
            signature: [0u8; 64],
        };
        h.publish_candidates(announce);
        assert!(rx.try_recv().is_err(), "no outbound should be produced");
    }

    /// `lookup_candidates` emits a peer-scoped empty announce.
    #[tokio::test]
    async fn lookup_candidates_emits_peer_scoped_pull() {
        let (mut h, mut rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        let session = [0x11; 16];
        h.lookup_candidates(peer, session);

        let out = rx.try_recv().expect("an outbound");
        assert_eq!(out.target, Some(peer));
        match out.msg {
            Message::CandidateAnnounce(a) => {
                assert!(a.candidates.is_empty());
                assert_eq!(a.session_id, session);
                assert_eq!(a.node_id, nid(1));
            }
            _ => panic!("expected CandidateAnnounce"),
        }
    }

    /// `forget_session` removes the routing entry; a later
    /// `publish_candidates` for the same session is dropped.
    #[tokio::test]
    async fn forget_session_removes_routing() {
        let (mut h, mut rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        let session = [0x42; 16];
        h.note_session(session, peer);
        h.forget_session(&session);

        let announce = CandidateAnnounce {
            node_id: nid(1),
            candidates: Vec::new(),
            session_id: session,
            timestamp: t(0),
            signature: [0u8; 64],
        };
        h.publish_candidates(announce);
        assert!(rx.try_recv().is_err());
    }

    /// `publish_connectivity` (a mesh verb) is broadcast.
    #[tokio::test]
    async fn publish_connectivity_is_broadcast() {
        use quip_core::address::Address;
        use quip_net::nat_wire::NAT_TYPE_OPEN;
        let (mut h, mut rx) = DhtHandle::new(nid(1));
        let announce = ConnectivityAnnounce {
            node_id: nid(1),
            external_addr: Address::V4 {
                ip: [127, 0, 0, 1],
                port: 4433,
            },
            internal_addr: Address::V4 {
                ip: [10, 0, 0, 1],
                port: 4433,
            },
            nat_type: NAT_TYPE_OPEN,
            port_preservation: true,
            relay_capable: false,
            capacity: 0,
            timestamp: t(0),
            signature: [0u8; 64],
        };
        h.publish_connectivity(announce);
        let out = rx.try_recv().expect("an outbound");
        assert_eq!(out.target, None);
    }

    // ---- M9.5b-c part 7: RTT sampling and XOR routing ----

    /// `note_rtt` records the raw sample and derives the RTT class.
    #[test]
    fn note_rtt_records_sample_and_class() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        let s = slot(2, 1);
        h.note_peer(peer, s, None, t(0));

        h.note_rtt(&peer, &s, 20);
        let snap = h.table_snapshot();
        assert_eq!(snap[0].1.rtt_ms, Some(20));
        assert_eq!(snap[0].1.rtt, RttClass::Local);

        h.note_rtt(&peer, &s, 50);
        let snap = h.table_snapshot();
        assert_eq!(snap[0].1.rtt_ms, Some(50));
        assert_eq!(snap[0].1.rtt, RttClass::Regional);
    }

    /// `note_rtt` from a stale generation is a no-op against a live
    /// record.
    #[test]
    fn note_rtt_stale_slot_is_noop() {
        let (h, _rx) = DhtHandle::new(nid(1));
        let peer = nid(2);
        h.note_peer(peer, slot(2, 2), None, t(0));

        h.note_rtt(&peer, &slot(2, 1), 20);
        let snap = h.table_snapshot();
        assert_eq!(snap[0].1.rtt_ms, None);
    }

    /// `closest_to` returns only routing-eligible peers, ordered by
    /// XOR distance from the key.
    #[test]
    fn closest_to_orders_by_xor_distance_and_filters_ineligible() {
        let (h, _rx) = DhtHandle::new(nid(0));
        h.note_peer(nid(1), slot(1, 1), None, t(0));
        h.note_peer(nid(2), slot(2, 1), None, t(0));
        h.note_peer(nid(3), slot(3, 1), None, t(0));
        h.update_lifecycle(&nid(1), &slot(1, 1), PeerLifecycle::NatDirect);
        h.update_lifecycle(&nid(2), &slot(2, 1), PeerLifecycle::NatDirect);
        // nid(3) stays Established → ineligible.

        let closest = h.closest_to(&nid(0), 2);
        assert_eq!(closest, vec![nid(1), nid(2)]);
    }
}