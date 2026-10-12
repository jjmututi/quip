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
//! - Publishes reach every connected peer.
//! - Inbound §12 verbs are routed into the DHT queue.
//! - A routing table records connected peers, their slot, their
//!   lifecycle, and their last-seen time.
//! - Signature and NodeId checks reject forged or mis-attributed NAT
//!   verbs.
//! - Routing eligibility is derived from lifecycle and exposed to the
//!   cluster-membership layer.
//!
//! What this module does *not* do:
//!
//! - Lookups. The §12 wire protocol has no `lookup_connectivity` verb;
//!   a real lookup is a Coral `coral_lookup` (§13.7), driven by
//!   [`quip_net::discovery::WitnessDiscovery`]. M9.5
//!   wires that path.
//! - Cluster merge/split. The routing table records a peer's
//!   `ClusterInfo` when one arrives, but nothing consumes it.
//! - Relay-response generation. A node that receives a `relay_discovery`
//!   request does not answer it yet.
//! - Multi-hop routing. Every message goes to every connected peer.

use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;
use quip_net::cluster::ClusterInfo;
use quip_net::crypto::Ed25519Verifier;
use quip_net::dht::RttClass;
use quip_net::message::Message;
use quip_net::nat_driver::{DhtClient, DhtResult};
use quip_net::nat_wire::{
    CandidateAnnounce, ConnectivityAnnounce, RelayDiscovery,
};

use std::collections::BTreeMap;
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
    /// Defaults to `Local` and is not updated until M9.5 measures RTTs;
    /// recorded here so the shape is stable across milestones.
    pub rtt: RttClass,
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

/// Shared state behind every [`DhtHandle`] clone.
struct DhtInner {
    local_id: NodeId,
    table: Mutex<BTreeMap<NodeId, PeerRecord>>,
    outbound_tx: mpsc::UnboundedSender<Message>,
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
    ) -> (Self, mpsc::UnboundedReceiver<Message>) {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        (
            Self {
                inner: Arc::new(DhtInner {
                    local_id,
                    table: Mutex::new(BTreeMap::new()),
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

    /// Enqueue an inbound result for the next [`DhtClient::poll`].
    ///
    /// A send failure means the handle is being dropped; losing the
    /// result then is fine.
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
        let _ = self
            .inner
            .outbound_tx
            .send(Message::ConnectivityAnnounce(announce));
    }

    fn lookup_connectivity(&mut self, _target: NodeId) {
        // The §12 wire protocol has no `lookup_connectivity` verb. A
        // real lookup is a Coral `coral_lookup` (§13.7), driven by
        // `WitnessDiscovery`. M9.5 wires that path; until then this is
        // a documented no-op so the trait has a real implementation
        // and not a fake one.
    }

    fn publish_candidates(&mut self, announce: CandidateAnnounce) {
        let _ = self
            .inner
            .outbound_tx
            .send(Message::CandidateAnnounce(announce));
    }

    fn lookup_candidates(&mut self, _target: NodeId, _session_id: [u8; 16]) {
        // See `lookup_connectivity`.
    }

    fn discover_relays(&mut self, discovery: RelayDiscovery) {
        let _ = self
            .inner
            .outbound_tx
            .send(Message::RelayDiscovery(discovery));
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
}