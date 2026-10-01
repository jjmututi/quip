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
//! # Scope
//!
//! What this module does:
//!
//! - Publishes reach every connected peer.
//! - Inbound §12 verbs are routed into the DHT queue.
//! - A routing table records connected peers and their last-seen time.
//! - Signature and NodeId checks reject forged or mis-attributed NAT
//!   verbs.
//!
//! What this module does *not* do:
//!
//! - Lookups. The §12 wire protocol has no `lookup_connectivity` verb;
//!   a real lookup is a Coral `coral_lookup` (§13.7), driven by
//!   [`WitnessDiscovery`](quip_net::discovery::WitnessDiscovery). M9.5
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

/// What the DHT knows about one peer.
#[derive(Clone, Debug)]
pub struct PeerRecord {
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

    /// Record that `peer` is reachable, updating an existing record.
    pub fn note_peer(
        &self,
        peer: NodeId,
        addr: Option<SocketAddr>,
        now: Timestamp,
    ) {
        if let Ok(mut table) = self.inner.table.lock() {
            table
                .entry(peer)
                .and_modify(|r| {
                    r.last_seen = now;
                    if addr.is_some() {
                        r.addr = addr;
                    }
                })
                .or_insert(PeerRecord {
                    addr,
                    rtt: RttClass::Local,
                    last_seen: now,
                    cluster: None,
                });
        }
    }

    /// Drop `peer` from the routing table.
    pub fn forget_peer(&self, peer: &NodeId) {
        if let Ok(mut table) = self.inner.table.lock() {
            table.remove(peer);
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