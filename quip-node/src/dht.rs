//! Live `DhtClient`: routes §12 NAT-plane verbs over the node's peer
//! connections.
//!
//! [`LiveDht`] implements
//! [`DhtClient`] on top of the node's
//! existing T0 connections. It does not maintain a separate DHT peer
//! set, does not do XOR-distance routing, and does not run cluster
//! merge/split. Publishes broadcast to every connected peer; lookups
//! are no-ops until the Coral DHT lands.
//!
//! # Design
//!
//! `DhtClient`'s methods are synchronous. The trait docs say a real
//! implementation "runs the network in a background task and queues
//! results, draining them via `poll`". This module follows that
//! pattern:
//!
//! - `publish_*` and `lookup_*` push a [`Message`] onto an unbounded
//!   outbound queue. A dedicated router task drains the queue and
//!   forwards each message to every connected peer.
//! - Inbound §12 verbs arrive on a peer's steady loop, are checked for
//!   a valid signature and a matching NodeId, and are pushed into an
//!   inbound queue. [`LiveDht::poll`] pops one result at a time.
//!
//! # Scope
//!
//! What this milestone does:
//!
//! - Publishes reach every connected peer.
//! - Inbound §12 verbs are routed into the DHT queue.
//! - A routing table records connected peers and their last-seen time.
//! - Signature and NodeId checks reject forged or mis-attributed NAT
//!   verbs.
//!
//! What this milestone does *not* do:
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
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, MutexGuard};

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

/// A live `DhtClient` implementation.
pub struct LiveDht {
    local_id: NodeId,
    table: BTreeMap<NodeId, PeerRecord>,
    outbound_tx: mpsc::UnboundedSender<Message>,
    inbound_rx: mpsc::UnboundedReceiver<DhtResult>,
}

impl LiveDht {
    /// Build a `LiveDht` and the two channel ends the caller wires up.
    ///
    /// The returned outbound receiver goes to a router task that
    /// forwards each message to the connected peers. The returned
    /// inbound sender is cloned into every peer task, which uses it to
    /// enqueue results that [`DhtClient::poll`] drains.
    pub(crate) fn new(
        local_id: NodeId,
    ) -> (
        Self,
        mpsc::UnboundedReceiver<Message>,
        mpsc::UnboundedSender<DhtResult>,
    ) {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        (
            Self {
                local_id,
                table: BTreeMap::new(),
                outbound_tx,
                inbound_rx,
            },
            outbound_rx,
            inbound_tx,
        )
    }

    /// Our own NodeId.
    pub fn local_id(&self) -> NodeId {
        self.local_id
    }

    /// Read the routing table.
    pub fn table(&self) -> &BTreeMap<NodeId, PeerRecord> {
        &self.table
    }

    /// Record that `peer` is reachable, updating an existing record.
    pub fn note_peer(
        &mut self,
        peer: NodeId,
        addr: Option<SocketAddr>,
        now: Timestamp,
    ) {
        self.table
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

    /// Drop `peer` from the routing table.
    pub fn forget_peer(&mut self, peer: &NodeId) {
        self.table.remove(peer);
    }

    /// Push `msg` onto the outbound queue.
    ///
    /// A send failure means the router task has exited, which only
    /// happens when `Node` is being dropped; losing the message then is
    /// fine.
    fn broadcast(&mut self, msg: Message) {
        let _ = self.outbound_tx.send(msg);
    }
}

impl DhtClient for LiveDht {
    fn publish_connectivity(&mut self, announce: ConnectivityAnnounce) {
        self.broadcast(Message::ConnectivityAnnounce(announce));
    }

    fn lookup_connectivity(&mut self, _target: NodeId) {
        // The §12 wire protocol has no `lookup_connectivity` verb. A
        // real lookup is a Coral `coral_lookup` (§13.7), driven by
        // `WitnessDiscovery`. M9.5 wires that path; until then this is
        // a documented no-op so the trait has a real implementation and
        // not a fake one.
    }

    fn publish_candidates(&mut self, announce: CandidateAnnounce) {
        self.broadcast(Message::CandidateAnnounce(announce));
    }

    fn lookup_candidates(&mut self, _target: NodeId, _session_id: [u8; 16]) {
        // See `lookup_connectivity`.
    }

    fn discover_relays(&mut self, discovery: RelayDiscovery) {
        self.broadcast(Message::RelayDiscovery(discovery));
    }

    fn poll(&mut self) -> Option<DhtResult> {
        self.inbound_rx.try_recv().ok()
    }
}

/// The node-owned handle to the DHT.
///
/// Bundles the shared [`LiveDht`] with a clone of the inbound sender so
/// a peer task can note a peer and enqueue a result without holding
/// two handles.
#[derive(Clone)]
pub(crate) struct DhtHandle {
    client: Arc<Mutex<LiveDht>>,
    inbound_tx: mpsc::UnboundedSender<DhtResult>,
}

impl DhtHandle {
    /// Build the handle and return the outbound receiver the router
    /// task should drain.
    pub(crate) fn new(
        local_id: NodeId,
    ) -> (Self, mpsc::UnboundedReceiver<Message>) {
        let (client, outbound_rx, inbound_tx) = LiveDht::new(local_id);
        (
            Self {
                client: Arc::new(Mutex::new(client)),
                inbound_tx,
            },
            outbound_rx,
        )
    }

    /// Lock the underlying `LiveDht`.
    ///
    /// Used by the M9.4b integration and by tests; production code goes
    /// through the `DhtClient` trait.
    pub(crate) async fn lock(&self) -> MutexGuard<'_, LiveDht> {
        self.client.lock().await
    }

    /// Record that `peer` is reachable.
    pub(crate) async fn note_peer(
        &self,
        peer: NodeId,
        addr: Option<SocketAddr>,
        now: Timestamp,
    ) {
        self.client.lock().await.note_peer(peer, addr, now);
    }

    /// Drop `peer` from the routing table.
    pub(crate) async fn forget_peer(&self, peer: &NodeId) {
        self.client.lock().await.forget_peer(peer);
    }

    /// Enqueue an inbound result for the next `poll`.
    pub(crate) fn enqueue(&self, result: DhtResult) {
        let _ = self.inbound_tx.send(result);
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