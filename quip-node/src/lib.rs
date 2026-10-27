//! A running QUIP node.
//!
//! [`Node`] binds a QUIC endpoint, accepts inbound connections, dials
//! outbound ones, and surfaces a single event stream keyed by peer
//! NodeId. It owns a [`QuipStore`] and uses it to auto-serve the
//! storage-plane verbs that have a 1:1 wire mapping, a
//! [`DhtHandle`] that carries §12 NAT-plane verbs over
//! the same connections, a
//! [`DiscoveryHandle`] that runs Coral
//! witness discovery for each peer and answers the peer's own
//! lookups, and a [`TrustPolicy`] that decides how each peer's Key
//! Claim maps to a trust level.
//!
//! # Scope
//!
//! This is the eleventh cut. It does:
//!
//! - Bind a server endpoint with a self-signed cert (rcgen).
//! - Accept inbound connections; drive the §4/§16 handshake to
//!   completion in a background task.
//! - Dial outbound connections; drive the handshake inline.
//! - Run a [`ConnectionFlow`](quip_net::establishment::ConnectionFlow) per peer, sequencing §16 establishment
//!   from the point the transport's inline handshake leaves off.
//! - Drive a per-peer [`NatDriver`](quip_net::nat_driver::NatDriver) during the flow's NAT phase, so
//!   the phase concludes from a `NatEvent` rather than from a
//!   hardcoded reading of the transport.
//! - Run Coral witness discovery for each peer during the flow's
//!   witness phase, answering the peer's own lookups.
//! - Record every peer's Key Claim and expose an explicit trust
//!   policy: a first-seen peer is `Unknown` until the application
//!   calls [`Node::trust_peer`] with `Trusted`.
//! - Expose `send_to(peer, msg)` and `poll() -> Vec<NodeEvent>`.
//! - Track a `NodeId -> outbound sender` table.
//! - Track every peer task it spawns and abort them all on `Drop`.
//! - Own a `QuipStore<B>`, shared across peer tasks behind a mutex.
//! - Auto-serve `pin`, `unpin`, and `query_pins` from that store
//!   when [`NodeConfig::auto_serve_pins`] is set.
//! - Expose direct store helpers: `put_content`, `get_content`,
//!   `pin`, `unpin`, `query_pins`, and a raw `store()` accessor.
//! - Read the wall clock through a [`Clock`](quip_core::time::Clock), so tests can inject a
//!   deterministic time source.
//! - **M9.5b-b:** allocate a [`PeerSlot`] for every connection,
//!   abort the previous generation's task on reconnect, and scope
//!   the DHT routing table to the current generation.
//! - **M9.5b-c (gates 5 and 6):** track [`PeerLifecycle`] per slot,
//!   derive routing eligibility from it, and expose the derived set
//!   through [`Node::routing_eligible_peers`]. The registry is the
//!   authoritative owner; the DHT routing table mirrors the state so
//!   routing decisions can consult it directly.
//! - **M9.5b-c (part 3):** drive a `NatDriver` per peer during the
//!   §16 NAT phase. The peer's current transport address is fed in as
//!   a host candidate and reported as a successful probe; the driver
//!   turns that into `NatEvent::DirectPathEstablished`, which the
//!   flow loop translates into `PeerLifecycle::NatDirect`.
//! - **M9.5b-c (part 5):** sign outbound §12 verbs with the node's
//!   key and probe candidate addresses by dialing them.
//! - **M9.5b-c (part 6):** route inbound §12 verbs through
//!   `dht_result_from` during the NAT phase, answer an inbound
//!   `relay_discovery` with a signed `relay_response` when
//!   [`NodeConfig::relay_capable`] is set, and provide
//!   [`NodeConfig::force_relay`] to put a node's sessions onto the
//!   relay branch by policy. `PeerLifecycle::NatRelayed` is now
//!   reachable end-to-end.
//!
//! It does not (yet):
//!
//! - Exchange candidates over the DHT via Coral lookup. The
//!   `DhtHandle`'s `lookup_candidates` emits a peer-scoped empty
//!   announce, not a `coral_lookup`.
//! - Prevent a `probe_candidate` connection from being registered as
//!   a peer on the receiving side. A probe carries no identity (per
//!   §12.3, path validation does not authenticate the prober), but
//!   the receiving node's accept loop cannot tell a probe from a
//!   real connection. The probe uses a fresh per-call seed so it is
//!   not a fixed identity, but the accept loop still allocates a
//!   slot for it. Marking probe connections and skipping the peer
//!   task for them is a later milestone.
//! - Run cluster merge/split or XOR-distance routing. The routing
//!   eligibility set is defined and exposed; the consumer is
//!   M9.5b-c's cluster integration.
//! - Accumulate `WitnessStatement`s. The discovery client runs, but
//!   the responder answers with no witnesses, so `Ready(Verified)`
//!   is unreachable in a network smaller than five independent
//!   peers. A later milestone wires witness accumulation and the
//!   responder returns real rings.
//! - Auto-serve `register_tcid`, `delegation`, `derivative_link`,
//!   `resource_announce`, or `query_resource`. Those carry signatures
//!   the peer task cannot verify, or require a wire-to-storage type
//!   conversion that has not been written.
//! - Auto-serve `get`, `set`, `sync`, or `rbsr_sync`: they are
//!   DVV-shaped and need DVV state that `Node` does not own yet.
//! - Run a `BftDriver`.
//!
//! # Peer generation (M9.5b-b)
//!
//! Every connection gets a [`PeerSlot`]: the peer's logical `NodeId`
//! plus a per-node generation counter that increments on each new
//! connection for that `NodeId`. The counter is persistent — it is
//! never reset when a peer disconnects — so slot values are never
//! reused.
//!
//! When a second connection arrives for an already-connected peer,
//! the newer slot wins. The node:
//!
//! 1. Allocates the new slot under the peer-registry lock.
//! 2. Aborts the previous task's `JoinHandle` (taken from the task
//!    map).
//! 3. Spawns the new peer task with the new slot.
//!
//! The aborted task cannot emit further events, so the application
//! never observes two live generations for the same `NodeId`
//! simultaneously. The task's own cleanup path (`unregister_peer`)
//! only removes the DHT record and the task-map entry if the slot is
//! still current, so a stale task cannot clobber its successor.
//!
//! # Peer lifecycle and routing eligibility (M9.5b-c gates 5 and 6)
//!
//! Every `PeerHandle` in the registry carries a [`PeerLifecycle`].
//! The peer task is the single writer: it starts the handle at
//! `Established` (a slot is only allocated after the §4 handshake,
//! so `Connecting` is not observable), transitions to `NatDirect` or
//! `NatRelayed` when the flow's NAT phase concludes, transitions to
//! `Failed` on any establishment failure, and transitions to
//! `Closing` when the steady loop exits.
//!
//! Every transition flows through `set_peer_lifecycle`, which
//! updates both the registry (authoritative) and the DHT routing
//! table (mirror). Both updates are slot-scoped: a stale generation's
//! transition is a no-op against a live record.
//!
//! Routing eligibility is defined by
//! [`PeerLifecycle::is_routing_eligible`]: a peer is a routing
//! candidate iff it has reached `NatDirect` or `NatRelayed`. §3 of
//! `docs/M9.5b-design.md` requires physical connection existence and
//! routing eligibility to be distinct, and this is how the
//! distinction is encoded — a peer in `Established` has a live
//! connection but is not yet a routing candidate. [`Node::routing_eligible_peers`]
//! and [`DhtHandle::routing_eligible_records`] expose the derived set.
//!
//! # NAT phase (M9.5b-c parts 3, 5, and 6)
//!
//! The §16 NAT phase is driven by a per-peer [`NatDriver`](quip_net::nat_driver::NatDriver). The peer
//! task seeds the driver with the peer's current transport address,
//! reports a successful probe for it — the live QUIC connection is
//! proof the address is reachable — and reads the terminal
//! `NatEvent` the driver produces: `DirectPathEstablished`,
//! `RelayedPathEstablished`, or `SessionFailed`. The first two
//! conclude the phase with `PeerLifecycle::NatDirect` and
//! `PeerLifecycle::NatRelayed` respectively; the third fails
//! establishment.
//!
//! Part 5 signs every outbound §12 verb with the node's key, so a
//! peer's `dht_result_from` accepts our candidate announces rather
//! than rejecting them for a zero signature. Part 6 does the same on
//! the receiving side: inbound §12 verbs during the NAT phase are
//! verified by `dht_result_from` before they reach the state machine,
//! and a node with `relay_capable` set answers an inbound
//! `relay_discovery` with a signed `relay_response`.
//!
//! # Relay path (M9.5b-c part 6)
//!
//! On loopback the direct candidates always succeed, so the driver
//! never emits `RelayDiscoveryRequested` and `NatRelayed` is
//! unreachable by probe failure alone. Two `NodeConfig` knobs make
//! the relay branch reachable:
//!
//! - [`NodeConfig::force_relay`] tells the node to put every session
//!   it starts onto the relay branch by policy, skipping the direct
//!   probe ladder entirely. A node behind a symmetric NAT knows a
//!   priori that its direct candidates will fail; this is the honest
//!   way to express that, and it is what makes the relay path
//!   reachable end-to-end in a test.
//! - [`NodeConfig::relay_capable`] makes the node answer an inbound
//!   `relay_discovery` with a signed `relay_response` naming itself
//!   as the relay. Default is `false`: a node that has not opted in
//!   does not relay.
//!
//! Both are legitimate production knobs. `relay_capable` is what
//! M9.7's headless deployment will set on a VPS that acts as a
//! rendezvous point.
//!
//! # Establishment
//!
//! After the §4 handshake and §16 Key Claim exchange — both performed
//! inline by `ConnectionDriver` — each peer task runs a
//! [`ConnectionFlow`](quip_net::establishment::ConnectionFlow) resumed at `NatTraversal` via
//! [`ConnectionFlow::resume_from_key_claim`](quip_net::establishment::ConnectionFlow::resume_from_key_claim). The NAT phase runs
//! through the per-peer `NatDriver` described above. The witness phase
//! runs a real
//! [`WitnessDiscovery`](quip_net::discovery::WitnessDiscovery) against
//! the peer: the flow sends a `coral_lookup`, ingests the response,
//! and either completes with `Ready(KtStatus)` or falls back to
//! `Ready(Pending)` when the discovery fails.
//!
//! # Trust policy
//!
//! Two independent axes determine whether a peer is usable:
//!
//! - **Policy trust** (`Unknown` / `Trusted` / `Untrusted` /
//!   `Revoked`) is decided by [`TrustPolicy`] from the local store
//!   and the application's explicit [`Node::trust_peer`] calls. A
//!   first-seen peer is `Unknown`; nothing auto-escalates.
//! - **Flow status** (`Pending` / `Verified`) is decided by the §16
//!   witness-discovery phase and reflects 4+ independent witnesses.
//!
//! `Verified` is never set by the application — only the flow can
//! promote a peer from `Trusted` to `Verified`. The combined
//! [`PeerTrust`] returned on peer events reflects both axes.
//!
//! # Coral roles
//!
//! A running node is both a Coral *client* and a Coral *server*:
//!
//! - Client: it starts a `WitnessDiscovery` for each peer during §16
//!   establishment, sending a signed `coral_lookup` on T0.
//! - Server: it answers inbound `coral_lookup` and `spillover` with
//!   signed responses. M9.5a answers with no witnesses and no
//!   consensus, which is honest — the node holds no
//!   `WitnessStatement`s yet.
//!
//! Both roles share one [`DiscoveryHandle`], so the ring and
//! spillover caches are unified across the node.
//!
//! # DHT routing
//!
//! §12 NAT verbs (`connectivity_announce`, `candidate_announce`,
//! `relay_discovery`, `relay_response`) arriving on T0 are verified,
//! matched against the sending peer, and enqueued into the node's
//! [`DhtHandle`]. Outgoing publishes are broadcast to
//! every connected peer. There is no separate DHT peer set and no
//! XOR-distance routing yet; a later milestone replaces the broadcast.
//!
//! # Auto-served verbs
//!
//! With `auto_serve_pins` on (default), an inbound `pin`, `unpin`, or
//! `query_pins` is applied to the node's [`QuipStore`] and is **not**
//! surfaced as a [`NodeEvent::Message`]. `query_pins` replies with a
//! `pin_list` on the same tier.
//!
//! Everything else surfaces normally. An application that wants to
//! handle pins itself sets `auto_serve_pins = false` and takes over
//! the dispatch in its event loop.
//!
//! # Pin auto-serve
//!
//! The auto-serve path calls [`QuipStore::query_pins`] with whatever
//! filters arrived on the wire. `PinTable::query` requires at least
//! one filter — a `QueryPins` with both `resource_id` and `cid`
//! absent is well-formed on the wire but yields an empty `pin_list`,
//! not a full listing. Applications that want a full listing must
//! page through resource_ids or add a store-level enumeration helper.
//!
//! The wire message is still accepted; the reply is simply empty.
//!
//! # Clock
//!
//! Peer tasks read the current time through [`NodeConfig::clock`] —
//! a shared `Arc<dyn Clock + Send + Sync>`, defaulting to
//! [`SystemClock`](quip_core::time::SystemClock). Tests inject a
//! [`ManualClock`](quip_core::time::ManualClock) so that pin and
//! query timestamps match by construction. The clock is also what an
//! application should read via [`Node::clock`] when it wants a
//! timestamp consistent with what the node's own peer tasks are
//! using.
//!
//! One exception: the establishment-time discovery wait uses a
//! wall-clock deadline (`std::time::Instant`), not the injected
//! clock. The injected clock can be frozen — a stub discovery phase
//! must not block forever on it. The NAT-phase loop uses the same
//! wall-clock discipline.
//!
//! # Signer
//!
//! The node signs wire messages — §16 Key Claims, §13 Coral lookups
//! and responses, §12 NAT verbs — with the [`Ed25519Signer`](quip_net::crypto::Ed25519Signer) held in
//! [`NodeConfig::signer`]. It is `Arc<Ed25519Signer>` rather than
//! `Arc<dyn Signer>`: every verifier in the workspace is
//! `Ed25519Verifier`, so a `dyn` would be strictly less safe with no
//! gain.
//!
//! # Store locking
//!
//! The store is behind a single `tokio::sync::Mutex`, shared by the
//! `Node` handle and every peer task. A slow store operation
//! (e.g. `put_content` against a file-backed `FileBlobStore`) will
//! hold the lock across the `await`, blocking other peers' auto-served
//! verbs for that duration. For a first cut this is acceptable; a
//! longer-term design would shard the store or move it to a dedicated
//! task.
//!
//! # Example
//!
//! ```no_run
//! use quip_core::cid::HashAlgo;
//! use quip_core::time::{Clock, SystemClock};
//! use quip_net::crypto::{Ed25519Signer, Sha256Hasher};
//! use quip_node::{Node, NodeConfig, NodeEvent};
//! use quip_storage::{CidTagging, QuipStore};
//! use std::net::SocketAddr;
//! use std::sync::Arc;
//!
//! # async fn example() -> quip_net::Result<()> {
//! let signer = Ed25519Signer::from_seed(&[0x42; 32]);
//! let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
//! let now = SystemClock.now();
//! let config = NodeConfig::new(bind, Arc::new(signer), now)?;
//! let mut node = Node::bind_with_store(config, QuipStore::new()).await?;
//!
//! // Store and pin content locally.
//! let hasher = Sha256Hasher;
//! let cid = node
//!     .put_content(b"hello".to_vec(), HashAlgo::Sha256, CidTagging::V1, &hasher, now)
//!     .await?;
//! node.pin(b"greeting", &cid, 0, now).await;
//!
//! // React to peers.
//! for event in node.poll().await? {
//!     match event {
//!         NodeEvent::Ready { peer, kt_status, trust } => {
//!             println!("ready: {peer:?} ({kt_status:?}, {trust:?})");
//!         }
//!         NodeEvent::Message { peer, msg, .. } => {
//!             println!("{} from {:?}", msg.verb(), peer);
//!         }
//!         _ => {}
//!     }
//! }
//! # Ok(())
//! # }
//! ```

pub mod claim_log;
pub mod cluster;
pub mod config;
pub mod dht;
pub mod discovery;
pub mod event;
pub mod peer;
mod registry;
mod tasks;
pub mod trust;
pub mod witness;

use quip_core::cid::{CidOrV1, HashAlgo};
use quip_core::dvv::NodeId;
use quip_core::messages::{KeyClaim, PinEntry};
use quip_core::time::Timestamp;
use quip_net::cluster::ClusterLevel;
use quip_net::message::Message;
use quip_net::transport::{ClientConfig, Endpoint, ServerConfig};
use quip_net::{Error, Result};
use quip_storage::blob::{BlobStore, BlobStoreMut};
use quip_storage::{CidTagging, ContentHasher, MemoryBlobStore, QuipStore};

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, MutexGuard};
use tokio::task::JoinHandle;

use claim_log::ClaimLog;
use dht::DhtHandle;
use discovery::DiscoveryHandle;
use witness::WitnessStore;
// M9.5b-b: peer-slot and lifecycle vocabulary.
// M9.5b-c: `PeerLifecycle::is_routing_eligible` is the sole routing-
// eligibility predicate.
pub use config::{make_key_claim, NodeConfig, SharedClock, SharedSigner};
pub use event::NodeEvent;
pub use peer::{PeerLifecycle, PeerSlot};
// M10.3: the trust policy and the trust level that peer events carry.
use trust::{PeerTrust, TrustPolicy};
// M9.5b-c part 7: cluster membership over the routing-eligible set.
use cluster::{ClusterHandle, ClusterView};
use registry::{register_peer, unregister_peer, PeerRegistry, Registry, TaskMap};
use tasks::{accept_loop, dht_router_task, drive_handshake, peer_run};

/// Capacity of the node's event channel.
const EVENT_CHANNEL_CAPACITY: usize = 128;

/// Capacity of each peer's outbound queue.
pub(crate) const OUTBOUND_CAPACITY: usize = 64;

/// How long [`Node::poll`] waits for a first event before returning.
pub(crate) const POLL_TIMEOUT_MS: u64 = 50;

/// How long the establishment-time discovery phase waits for a
/// resolution before falling back to `Ready(Pending)`.
///
/// Wall-clock, not the injected `Clock`: the injected clock can be
/// frozen (tests) or advanced manually, and a stub discovery phase
/// must not block forever on a frozen clock. Two-node tests on
/// loopback resolve in well under 100 ms; the deadline is only hit
/// when a peer is unresponsive.
pub(crate) const DISCOVERY_WAIT_MS: u64 = 5_000;

/// Wall-clock bound on the NAT phase.
///
/// The flow's own NAT timeout is [`FlowConfig::nat_timeout_ms`]
/// (30 s by default); this bounds the driver loop independently so a
/// driver that never produces a terminal event cannot spin forever.
pub(crate) const NAT_PHASE_TIMEOUT_MS: u64 = 30_000;

/// Priority assigned to the node's own host candidate.
pub(crate) const LOCAL_CANDIDATE_PRIORITY: u64 = 1000;

// M10.3: shared handle around the trust policy, same shape as the
// store and the DHT handle.
pub(crate) type SharedTrust = Arc<Mutex<TrustPolicy>>;

/// Apply a lifecycle transition to both the registry and the DHT
/// routing table.
///
/// The registry is the authoritative view: it validates the edge
/// against §2a and rejects a transition from a stale slot. The DHT
/// mirror is updated only if the registry accepted the transition, so
/// the two cannot diverge. Both updates are slot-scoped, so a
/// superseded generation cannot mutate the live record.
///
/// The peer task is the single writer of lifecycle transitions; this
/// helper is the only path that mutates them.
pub(crate) async fn set_peer_lifecycle(
    peers: &PeerRegistry,
    dht: &DhtHandle,
    slot: &PeerSlot,
    to: PeerLifecycle,
) {
    let applied = {
        let mut reg = peers.lock().await;
        reg.set_lifecycle(slot, to)
    };
    if applied {
        dht.update_lifecycle(&slot.node_id, slot, to);
    }
}

// -------------------------------------------------------------------------
// Node
// -------------------------------------------------------------------------

/// A running QUIP node.
///
/// The blob backend `B` defaults to [`MemoryBlobStore`]. Use
/// [`Node::bind_with_store`] with a `QuipStore<FileBlobStore>` for
/// file-backed persistence.
pub struct Node<B = MemoryBlobStore> {
    endpoint: Arc<Endpoint>,
    local_claim: KeyClaim,
    /// The node's signer.
    ///
    /// Cloned into every peer task so §12 NAT verbs the peer sends —
    /// candidate announces, relay discoveries, relay responses —
    /// carry real signatures.
    signer: SharedSigner,
    peers: PeerRegistry,
    /// Peer tasks spawned by `connect` or the accept loop, keyed by
    /// peer NodeId. Aborted on `Drop`, so a dropped `Node` cannot leak
    /// tasks into the runtime.
    peer_tasks: TaskMap,
    /// The node's store, shared with every peer task for auto-serving.
    store: Arc<Mutex<QuipStore<B>>>,
    /// Whether peer tasks auto-serve pin/unpin/query_pins.
    auto_serve_pins: bool,
    /// Whether peer tasks answer inbound `relay_discovery`.
    relay_capable: bool,
    /// Whether every NAT session is forced onto the relay branch.
    force_relay: bool,
    /// Time source handed to peer tasks.
    clock: SharedClock,
    events_rx: Option<mpsc::Receiver<NodeEvent>>,
    events_tx: mpsc::Sender<NodeEvent>,
    accept_task: Option<JoinHandle<()>>,
    /// The node's DHT client, shared with every peer task.
    dht: DhtHandle,
    /// The DHT router task, draining the DHT's outbound queue and
    /// forwarding each message to connected peers. Aborted on `Drop`.
    dht_task: Option<JoinHandle<()>>,
    /// The cluster heartbeat task, announcing this node's `cluster_info`
    /// when its tuple changes (§13.4). Aborted on `Drop`: it would
    /// otherwise keep publishing into a DHT whose router has gone.
    heartbeat_task: Option<JoinHandle<()>>,
    /// The node's shared Coral discovery client.
    discovery: DiscoveryHandle,
    /// The node's trust policy. Shared with every peer task and with
    /// the application through [`Node::trust_peer`].
    trust: SharedTrust,
    /// The node-wide first-seen claim log. Shared with the trust policy
    /// (its writer) and the witness store's 6-hour rule (its reader).
    claim_log: ClaimLog,
    /// The node-wide witness store: corroboration the Coral responder
    /// answers from and the peer tasks accumulate into.
    witness: WitnessStore,
    /// The node's cluster state, driving membership derivation and
    /// the §13.2 acceptance test over the routing-eligible set.
    cluster: ClusterHandle,
}

impl Node<MemoryBlobStore> {
    /// Bind a server endpoint with an empty in-memory store.
    ///
    /// Equivalent to [`Self::bind_with_store`] with a fresh
    /// [`QuipStore::new`].
    pub async fn bind(config: NodeConfig) -> Result<Self> {
        Self::bind_with_store(config, QuipStore::new()).await
    }
}

impl<B> Node<B>
where
    B: BlobStore + Send + Sync + 'static,
{
    /// Bind a server endpoint with an explicit store.
    ///
    /// The store is moved into the node and shared across all peers.
    /// Use [`Self::store`] to access it directly.
    pub async fn bind_with_store(config: NodeConfig, store: QuipStore<B>) -> Result<Self> {
        let (cert_der, key_der) = generate_self_signed_cert()?;
        let server_config = ServerConfig {
            bind: config.bind,
            cert_der,
            key_der,
            key_claim: config.key_claim.clone(),
            capabilities: config.capabilities,
        };
        let endpoint = Arc::new(Endpoint::server(server_config)?);

        let (events_tx, events_rx) = mpsc::channel(EVENT_CHANNEL_CAPACITY);
        let peers: PeerRegistry = Arc::new(Mutex::new(Registry::new()));
        let peer_tasks: TaskMap = Arc::new(Mutex::new(BTreeMap::new()));
        let store = Arc::new(Mutex::new(store));
        let clock = Arc::clone(&config.clock);
        let signer = Arc::clone(&config.signer);
        // M9.6a: one claim log, written by the trust policy and read by
        // the witness store; one witness store, shared by every peer
        // task and the Coral responder.
        let claim_log = ClaimLog::new();
        let witness = WitnessStore::new();
        // M10.3: initialize the trust policy.
        let trust: SharedTrust =
            Arc::new(Mutex::new(TrustPolicy::with_claim_log(claim_log.clone())));

        let local_id = config.key_claim.node_id;
        let (dht, dht_outbound_rx) = DhtHandle::new(local_id);
        let dht_task = tokio::spawn(dht_router_task(
            dht_outbound_rx,
            Arc::clone(&peers),
            dht.clone(),
        ));

        let discovery = DiscoveryHandle::new(
            Arc::clone(&config.signer),
            witness.clone(),
            claim_log.clone(),
        );

        // A fresh node is its own cluster: the cluster id is derived
        // from its own NodeId, at the innermost (Local) tier. Merging
        // and splitting move it up and down the hierarchy as RTT
        // observations accumulate.
        let mut cluster_id = [0u8; 16];
        cluster_id.copy_from_slice(&local_id[..16]);
        let cluster = ClusterHandle::new(cluster_id, ClusterLevel::Local, clock.now());

        // The heartbeat task needs the cluster handle, so it is spawned
        // here rather than beside the DHT router above.
        let heartbeat_task = tokio::spawn(tasks::cluster_task(
            cluster.clone(),
            dht.clone(),
            Arc::clone(&clock),
            Arc::clone(&signer),
        ));

        let accept_endpoint = Arc::clone(&endpoint);
        let accept_peers = Arc::clone(&peers);
        let accept_tasks = Arc::clone(&peer_tasks);
        let accept_store = Arc::clone(&store);
        let accept_clock = Arc::clone(&clock);
        let accept_tx = events_tx.clone();
        let accept_dht = dht.clone();
        let accept_discovery = discovery.clone();
        let accept_trust = Arc::clone(&trust);
        let accept_witness = witness.clone();
        let accept_signer = Arc::clone(&signer);
        let accept_cluster = cluster.clone();
        let auto_serve = config.auto_serve_pins;
        let relay_capable = config.relay_capable;
        let force_relay = config.force_relay;
        let accept_task = tokio::spawn(async move {
            accept_loop(
                accept_endpoint,
                accept_peers,
                accept_tasks,
                accept_store,
                accept_clock,
                auto_serve,
                relay_capable,
                force_relay,
                accept_tx,
                accept_dht,
                accept_discovery,
                accept_trust,
                accept_witness,
                accept_signer,
                accept_cluster,
            )
            .await;
        });

        Ok(Self {
            endpoint,
            local_claim: config.key_claim,
            signer,
            peers,
            peer_tasks,
            store,
            auto_serve_pins: config.auto_serve_pins,
            relay_capable: config.relay_capable,
            force_relay: config.force_relay,
            clock,
            events_rx: Some(events_rx),
            events_tx,
            accept_task: Some(accept_task),
            dht,
            dht_task: Some(dht_task),
            heartbeat_task: Some(heartbeat_task),
            discovery,
            trust,
            claim_log,
            witness,
            cluster,
        })
    }

    /// Dial a remote node.
    ///
    /// Drives the handshake inline so the returned `NodeId` is the
    /// peer as identified by the §16 Key Claim exchange. The claim's
    /// signature is not verified by the driver; the caller is
    /// responsible for applying its own TOFU / rotation policy, same
    /// as for [`NodeEvent::Connected`].
    ///
    /// The returned `NodeId` is available as soon as the transport
    /// handshake completes. `NodeEvent::Ready` fires later, after the
    /// establishment flow completes.
    ///
    /// If a connection to the same peer is already registered, the
    /// previous task is aborted and this connection becomes the
    /// current generation. See the module docs under "Peer
    /// generation."
    pub async fn connect(&mut self, addr: SocketAddr, server_name: &str) -> Result<NodeId> {
        let client_config = ClientConfig {
            bind: "0.0.0.0:0".parse().expect("valid bind"),
            key_claim: self.local_claim.clone(),
            capabilities: self.endpoint.config().capabilities,
        };
        let client_endpoint = Endpoint::client(client_config)?;
        let mut driver = client_endpoint.connect(addr, server_name).await?;

        let clock = Arc::clone(&self.clock);
        let peer = drive_handshake(
            &mut driver,
            &clock,
            &self.discovery,
            &self.witness,
            self.store.as_ref(),
            &self.signer,
            &self.cluster,
        )
        .await?;

        let (out_tx, out_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        let slot = register_peer(&self.peers, &self.peer_tasks, peer, out_tx).await;
        self.dht.note_peer(peer, slot, Some(addr), clock.now());

        // M10.3: record the peer's claim before emitting Connected.
        // A first-seen peer lands as `Unknown`; a reconnect to a peer
        // already in the store reports its stored trust.
        let peer_claim = match driver.peer_key_claim().cloned() {
            Some(c) => c,
            None => {
                unregister_peer(&self.peers, &self.peer_tasks, &peer, &slot).await;
                self.dht.forget_peer(&peer, &slot);
                return Err(Error::Transport(
                    "peer claim missing after handshake".into(),
                ));
            }
        };
        let trust_level = {
            let mut policy = self.trust.lock().await;
            policy.observe_claim(peer_claim, clock.now())
        };
        let _ = self
            .events_tx
            .send(NodeEvent::Connected {
                peer,
                trust: trust_level,
            })
            .await;

        let events_tx = self.events_tx.clone();
        let peers = Arc::clone(&self.peers);
        let peer_tasks = Arc::clone(&self.peer_tasks);
        let store = Arc::clone(&self.store);
        let auto_serve = self.auto_serve_pins;
        let relay_capable = self.relay_capable;
        let force_relay = self.force_relay;
        let dht = self.dht.clone();
        let discovery = self.discovery.clone();
        let trust = Arc::clone(&self.trust);
        let witness = self.witness.clone();
        let task_peers = Arc::clone(&peers);
        let signer = Arc::clone(&self.signer);
        let cluster = self.cluster.clone();
        let local_id = self.local_claim.node_id;
        let handle = tokio::spawn(async move {
            // The client endpoint must outlive the connection, so it
            // is moved into the peer task and dropped when the loop
            // exits.
            let _keep_endpoint = client_endpoint;
            peer_run(
                driver,
                peer,
                slot,
                local_id,
                store,
                clock,
                auto_serve,
                relay_capable,
                force_relay,
                events_tx,
                out_rx,
                dht.clone(),
                discovery,
                trust,
                witness,
                task_peers,
                signer,
                cluster,
            )
            .await;
            unregister_peer(&peers, &peer_tasks, &peer, &slot).await;
            dht.forget_peer(&peer, &slot);
        });
        self.peer_tasks.lock().await.insert(peer, (slot, handle));

        Ok(peer)
    }

    /// Drain whatever events are ready, waiting briefly for the first.
    ///
    /// Returns an error if [`Self::take_events`] has been called: the
    /// receiver is gone, and the caller is responsible for draining
    /// it.
    pub async fn poll(&mut self) -> Result<Vec<NodeEvent>> {
        let rx = match self.events_rx.as_mut() {
            Some(rx) => rx,
            None => {
                return Err(Error::Transport(
                    "event receiver was taken by take_events()".into(),
                ))
            }
        };
        let mut events = Vec::new();
        match tokio::time::timeout(Duration::from_millis(POLL_TIMEOUT_MS), rx.recv()).await {
            Ok(Some(e)) => events.push(e),
            Ok(None) => return Err(Error::Transport("event channel closed".into())),
            Err(_) => return Ok(events),
        }
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        Ok(events)
    }

    /// Take the event receiver out of the node.
    ///
    /// After this call [`Self::poll`] returns an error; the caller
    /// owns the receiver and is responsible for draining it. The FFI
    /// layer uses this to hand events to Dart without competing with
    /// `poll`.
    ///
    /// Calling it twice returns `None` the second time.
    pub fn take_events(&mut self) -> Option<mpsc::Receiver<NodeEvent>> {
        self.events_rx.take()
    }

    /// Send `msg` to `peer`.
    ///
    /// Returns an error if the peer is unknown or its queue is closed.
    /// Capability violations surface as `NodeEvent::Error` from the
    /// peer's task; the caller observes them through `poll`.
    pub async fn send_to(&self, peer: &NodeId, msg: Message) -> Result<()> {
        let tx = {
            let reg = self.peers.lock().await;
            reg.outbound_of(peer)
                .ok_or_else(|| Error::Transport(format!("unknown peer {peer:?}")))?
        };
        tx.send(msg)
            .await
            .map_err(|_| Error::Transport("peer queue closed".into()))
    }

    /// Our own NodeId.
    pub fn local_node_id(&self) -> NodeId {
        self.local_claim.node_id
    }

    /// Our own Key Claim.
    pub fn local_claim(&self) -> &KeyClaim {
        &self.local_claim
    }

    /// The address the endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Snapshot of currently connected peers.
    pub async fn peers(&self) -> Vec<NodeId> {
        self.peers.lock().await.peer_ids()
    }

    /// Slots of peers that are currently routing-eligible.
    ///
    /// §3 of `docs/M9.5b-design.md`: physical connection existence and
    /// routing eligibility are distinct. A peer becomes routing-
    /// eligible only after the §16 NAT phase reaches `NatDirect` or
    /// `NatRelayed`, and loses eligibility on `Failed` or `Closing`.
    /// The predicate is [`PeerLifecycle::is_routing_eligible`].
    ///
    /// The returned slots are the identity the cluster-membership
    /// layer keys on: a peer that reconnects gets a new slot, so a
    /// cluster record keyed by an old slot is stale by construction.
    /// This is the "routing-table subset" part of §4; the §13.2
    /// acceptance test is applied on top of it.
    pub async fn routing_eligible_peers(&self) -> Vec<PeerSlot> {
        self.peers.lock().await.routing_eligible_slots()
    }

    /// The current connection generation for `peer`, if it is
    /// connected.
    ///
    /// Useful to applications that cache per-peer state and need to
    /// invalidate it when the peer reconnects. Two calls that return
    /// different slots for the same `NodeId` mean a reconnect happened
    /// in between.
    pub async fn peer_slot(&self, peer: &NodeId) -> Option<PeerSlot> {
        self.peers.lock().await.peer_slot(peer)
    }

    /// The current lifecycle state for `peer`, if it is connected.
    ///
    /// Read-only. The peer task is the single writer.
    pub async fn peer_lifecycle(&self, peer: &NodeId) -> Option<PeerLifecycle> {
        self.peers.lock().await.peer_lifecycle(peer)
    }

    /// Initiate a graceful close of the endpoint.
    ///
    /// In-flight peer tasks exit on their next poll; the accept loop
    /// returns. `Drop` additionally aborts every task, so calling
    /// `shutdown` is optional.
    pub fn shutdown(&self) {
        self.endpoint.close();
    }

    /// Read the clock peer tasks use.
    ///
    /// Prefer this over reading `SystemClock` directly in an
    /// application so that the timestamps it computes match what the
    /// node's own peer tasks see.
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }

    /// Convenience: the clock's current time.
    pub fn now(&self) -> Timestamp {
        self.clock.now()
    }

    /// Lock and access the node's store.
    ///
    /// The guard holds the store's mutex for its lifetime. Anything
    /// that touches the store while the guard is alive blocks
    /// auto-served verbs from peers, so callers should drop the guard
    /// promptly.
    pub async fn store(&self) -> MutexGuard<'_, QuipStore<B>> {
        self.store.lock().await
    }

    /// A clone of the node's DHT handle.
    ///
    /// Clones share the routing table and the inbound and outbound
    /// queues. Used by the peer tasks and by applications that want
    /// to inspect or drive the DHT.
    pub fn dht(&self) -> DhtHandle {
        self.dht.clone()
    }

    /// A clone of the node's cluster handle.
    ///
    /// Clones share the underlying cluster state. The application
    /// derives a fresh membership snapshot with [`Node::cluster_view`],
    /// or recomputes manually via `cluster.recompute(&node.dht(), now)`.
    pub fn cluster(&self) -> ClusterHandle {
        self.cluster.clone()
    }

    /// Derive and return the node's current cluster membership.
    ///
    /// Reads the routing-eligible set and RTT samples from the DHT
    /// table, advances the cluster state machine, and returns the
    /// resulting snapshot. `pending_merge` in the snapshot mirrors the
    /// state's outstanding merge proposal, the same way `split_due`
    /// mirrors the split timer.
    pub fn cluster_view(&self) -> ClusterView {
        self.cluster.recompute(&self.dht, self.clock.now())
    }

    /// A clone of the node's Coral discovery handle.
    ///
    /// Clones share the ring and spillover caches and the in-flight
    /// discovery state. Used by the peer tasks and by applications
    /// that want to start a lookup directly.
    pub fn discovery(&self) -> DiscoveryHandle {
        self.discovery.clone()
    }

    /// The node-wide witness store.
    ///
    /// Clones share the underlying map, so a caller observes the same
    /// accumulation the peer tasks and the Coral responder see.
    pub fn witness_store(&self) -> WitnessStore {
        self.witness.clone()
    }

    /// The node-wide first-seen claim log.
    ///
    /// Clones share the underlying map. The trust policy is the writer;
    /// the witness store's 6-hour rule is the reader.
    pub fn claim_log(&self) -> ClaimLog {
        self.claim_log.clone()
    }

    /// Record the node's trust decision for `peer`.
    ///
    /// The node records every peer's Key Claim on first contact but
    /// does not decide trust by default: a first-seen peer stays
    /// `Unknown` until the application calls this method with
    /// [`PeerTrust::Trusted`]. `Trusted`, `Untrusted`, and `Revoked`
    /// are accepted; `Unknown` and `Verified` are not — see
    /// [`TrustPolicy::record_decision`] for the reasoning.
    ///
    /// Returns `true` if the decision was recorded. On a successful
    /// change, a [`NodeEvent::PeerTrustChanged`] fires on the event
    /// stream.
    pub async fn trust_peer(&self, peer: &NodeId, decision: PeerTrust) -> bool {
        let now = self.clock.now();
        let (accepted, changed, resulting) = {
            let mut policy = self.trust.lock().await;
            let before = policy.trust_of(peer);
            let accepted = policy.record_decision(peer, decision, now);
            let resulting = policy.trust_of(peer);
            (accepted, before != resulting, resulting)
        };
        if accepted && changed {
            let _ = self
                .events_tx
                .send(NodeEvent::PeerTrustChanged {
                    peer: *peer,
                    trust: resulting,
                })
                .await;
        }
        accepted
    }

    /// Current trust level for `peer`.
    pub async fn peer_trust(&self, peer: &NodeId) -> PeerTrust {
        self.trust.lock().await.trust_of(peer)
    }

    /// Snapshot of the trust store.
    pub async fn trust_snapshot(&self) -> Vec<(NodeId, trust::StoredClaim)> {
        self.trust.lock().await.snapshot()
    }

    // ---- Direct store helpers ----

    /// Pin `cid` for `resource_id` locally.
    ///
    /// This updates only the local store; the pin is not propagated to
    /// peers. Propagation is an application concern (see `pin_announce`
    /// on T3 for the gossip mechanism).
    pub async fn pin(&self, resource_id: &[u8], cid: &CidOrV1, ttl_seconds: u64, now: Timestamp) {
        let mut s = self.store.lock().await;
        let _ = s.pin(resource_id, cid, ttl_seconds, now);
    }

    /// Drop a pin.
    pub async fn unpin(&self, resource_id: &[u8], cid: Option<&CidOrV1>) -> usize {
        let mut s = self.store.lock().await;
        s.unpin(resource_id, cid)
    }

    /// Query local pins.
    pub async fn query_pins(
        &self,
        resource_id: Option<&[u8]>,
        cid: Option<&CidOrV1>,
        now: Timestamp,
    ) -> Vec<PinEntry> {
        let s = self.store.lock().await;
        s.query_pins(resource_id, cid, now)
    }

    /// Fetch and verify content by CID.
    pub async fn get_content(
        &self,
        cid: &CidOrV1,
        negotiated: HashAlgo,
        hasher: &impl ContentHasher,
        now: Timestamp,
    ) -> Result<Vec<u8>> {
        let s = self.store.lock().await;
        s.get_content(cid, negotiated, hasher, now)
            .map_err(|e| Error::Transport(format!("store: {e}")))
    }
}

impl<B> Node<B>
where
    B: BlobStoreMut + Send + Sync + 'static,
{
    /// Store raw payload bytes after verifying their digest.
    ///
    /// Returns the CID. See [`QuipStore::put_content`] for the exact
    /// semantics of `algo` and `tagging`.
    pub async fn put_content(
        &self,
        payload: Vec<u8>,
        algo: HashAlgo,
        tagging: CidTagging,
        hasher: &impl ContentHasher,
        now: Timestamp,
    ) -> Result<CidOrV1> {
        let mut s = self.store.lock().await;
        s.put_content(payload, algo, tagging, hasher, now)
            .map_err(|e| Error::Transport(format!("store: {e}")))
    }
}

impl<B> Drop for Node<B> {
    fn drop(&mut self) {
        self.endpoint.close();
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
        if let Some(task) = self.dht_task.take() {
            task.abort();
        }
        if let Some(task) = self.heartbeat_task.take() {
            task.abort();
        }
        // Abort peer tasks. `try_lock` is safe inside a Drop that may
        // run on a tokio worker; `blocking_lock` would panic. If a
        // task holds the lock, we skip the abort — the endpoint close
        // above already caused every peer task to exit at its next
        // poll, so the tasks terminate regardless.
        if let Ok(mut tasks) = self.peer_tasks.try_lock() {
            while let Some((_, (_, handle))) = tasks.pop_first() {
                handle.abort();
            }
        }
    }
}

// -------------------------------------------------------------------------
// Certificates
// -------------------------------------------------------------------------

/// Generate a self-signed certificate for the endpoint's TLS layer.
///
/// QUIP has no WebPKI (§5); the certificate provides confidentiality
/// only, and identity is established by the §16 Key Claim exchange.
fn generate_self_signed_cert() -> Result<(Vec<u8>, Vec<u8>)> {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| Error::Transport(format!("cert generation: {e}")))?;
    Ok((cert.der().to_vec(), key_pair.serialize_der()))
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::make_lookup_paths;
    use crate::witness::{WITNESS_FIRST_SEEN_SECONDS, WITNESS_REISSUE_INTERVAL_SECONDS};
    use quip_core::address::Address;
    use quip_core::cid::Cid;
    use quip_core::dvv::Dvv;
    use quip_core::messages::Signer;
    use quip_core::time::{Clock, ManualClock};
    use quip_net::crypto::{Ed25519Signer, Sha256Hasher};
    use quip_net::establishment::KtStatus;
    use quip_net::nat_driver::DhtClient;
    use quip_net::nat_wire::{ConnectivityAnnounce, NAT_TYPE_OPEN};
    use quip_net::sync::{GetRequest, QueryPins};
    use quip_net::GATEWAY_ROUTER_COUNT;
    use quip_storage::CidTagging;
    use std::collections::BTreeSet;

    fn seed(b: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = b;
        s
    }

    /// Start time for the frozen test clock. Any value works; the
    /// tests never compare against wall-clock time.
    const T0_MS: u64 = 1_700_000_000_000;

    fn frozen_clock() -> Arc<ManualClock> {
        Arc::new(ManualClock::new(Timestamp::from_millis(T0_MS)))
    }

    fn addr_zero() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// Build a node with a frozen clock.
    ///
    /// Returns `(node, clock)` so tests can read the same time the
    /// peer tasks use.
    async fn make_node_with_clock(seed_byte: u8) -> (Node, Arc<ManualClock>) {
        let signer = Ed25519Signer::from_seed(&seed(seed_byte));
        let clock = frozen_clock();
        let config = NodeConfig::new(addr_zero(), Arc::new(signer), clock.now())
            .unwrap()
            .with_clock(Arc::clone(&clock) as SharedClock);
        let node = Node::bind(config).await.unwrap();
        (node, clock)
    }

    /// Build a node with a frozen clock, discarding the clock handle.
    async fn make_node(seed_byte: u8) -> Node {
        make_node_with_clock(seed_byte).await.0
    }

    /// Build a node whose every NAT session is forced onto the relay
    /// branch.
    ///
    /// Used by `relay_path_produces_nat_relayed` for the *requesting*
    /// side: A skips the direct probe ladder and sends a signed
    /// `relay_discovery`. A does not need `relay_capable` — it is the
    /// requester, not the relay.
    async fn make_forced_relay_node(seed_byte: u8) -> (Node, Arc<ManualClock>) {
        let signer = Ed25519Signer::from_seed(&seed(seed_byte));
        let clock = frozen_clock();
        let config = NodeConfig::new(addr_zero(), Arc::new(signer), clock.now())
            .unwrap()
            .with_clock(Arc::clone(&clock) as SharedClock)
            .with_force_relay(true);
        let node = Node::bind(config).await.unwrap();
        (node, clock)
    }

    /// Build a node that answers inbound `relay_discovery`.
    ///
    /// Used by `relay_path_produces_nat_relayed` for the *responding*
    /// side: B replies to A's discovery with a signed
    /// `relay_response` naming itself. B is not forced onto the relay
    /// branch — it takes the direct path and reaches `NatDirect`.
    async fn make_relay_capable_node(seed_byte: u8) -> (Node, Arc<ManualClock>) {
        let signer = Ed25519Signer::from_seed(&seed(seed_byte));
        let clock = frozen_clock();
        let config = NodeConfig::new(addr_zero(), Arc::new(signer), clock.now())
            .unwrap()
            .with_clock(Arc::clone(&clock) as SharedClock)
            .with_relay_capable(true);
        let node = Node::bind(config).await.unwrap();
        (node, clock)
    }

    /// Wait for `node` to emit a `Connected` event for `expected`, up
    /// to `timeout_ms`.
    async fn wait_for_connected(
        node: &mut Node,
        expected: NodeId,
        timeout_ms: u64,
    ) -> Option<PeerTrust> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if let Ok(events) = node.poll().await {
                for e in events {
                    if let NodeEvent::Connected { peer, trust } = e {
                        if peer == expected {
                            return Some(trust);
                        }
                    }
                }
            }
        }
        None
    }

    /// Wait for `node` to emit a `Ready` event for `expected` and
    /// return the KT status and the trust level.
    async fn wait_for_ready(
        node: &mut Node,
        expected: NodeId,
        timeout_ms: u64,
    ) -> Option<(KtStatus, PeerTrust)> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if let Ok(events) = node.poll().await {
                for e in events {
                    if let NodeEvent::Ready {
                        peer,
                        kt_status,
                        trust,
                    } = e
                    {
                        if peer == expected {
                            return Some((kt_status, trust));
                        }
                    }
                }
            }
        }
        None
    }

    /// Wait for `node` to see a `pin_list` from `expected` and return
    /// it.
    async fn wait_for_pin_list(
        node: &mut Node,
        expected: NodeId,
        timeout_ms: u64,
    ) -> Option<Vec<PinEntry>> {
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if let Ok(events) = node.poll().await {
                for e in events {
                    if let NodeEvent::Message { peer, msg, .. } = e {
                        if peer == expected {
                            if let Message::PinList(list) = msg {
                                return Some(list.pins);
                            }
                        }
                    }
                }
            }
        }
        None
    }

    /// Sign a `ConnectivityAnnounce` with the signer for `seed_byte`.
    fn signed_connectivity(seed_byte: u8, now: Timestamp) -> ConnectivityAnnounce {
        let signer = Ed25519Signer::from_seed(&seed(seed_byte));
        let unsigned = ConnectivityAnnounce {
            node_id: signer.public_key(),
            external_addr: Address::V4 {
                ip: [127, 0, 0, 1],
                port: 9999,
            },
            internal_addr: Address::V4 {
                ip: [10, 0, 0, 1],
                port: 9999,
            },
            nat_type: NAT_TYPE_OPEN,
            port_preservation: true,
            relay_capable: false,
            capacity: 0,
            timestamp: now,
            signature: [0u8; 64],
        };
        let payload = unsigned.signing_payload().unwrap();
        let signature = signer.sign_ed25519(&payload);
        ConnectivityAnnounce {
            signature,
            ..unsigned
        }
    }

    // All tests use the default single-threaded #[tokio::test]
    // runtime. The node's peer tasks are cooperative; a
    // multi-threaded runtime with several workers per test
    // oversubscribes small CI machines and can starve the accept
    // loop. The tests are I/O-bound, so a single thread is sufficient.

    #[tokio::test]
    async fn two_nodes_connect() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        let peer = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer, b_node_id, "A dials B and learns B's NodeId");

        assert_eq!(
            wait_for_connected(&mut b, a_node_id, 5_000).await,
            Some(PeerTrust::Unknown),
            "B should see the inbound connection from A as Unknown"
        );
    }

    #[tokio::test]
    async fn ready_fires_after_connect() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);

        // The discovery runs end to end. In a two-node network
        // neither side holds witnesses, so both peers surface
        // `Ready(Pending)`.
        let (status, trust) = wait_for_ready(&mut a, b_node_id, 10_000)
            .await
            .expect("A should reach Ready");
        assert_eq!(status, KtStatus::Pending);
        assert_eq!(trust, PeerTrust::Unknown);
    }

    #[tokio::test]
    async fn trust_escalates_after_explicit_call() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);

        // First-seen peer is Unknown.
        assert_eq!(a.peer_trust(&b_node_id).await, PeerTrust::Unknown);

        // The application accepts it.
        assert!(a.trust_peer(&b_node_id, PeerTrust::Trusted).await);
        assert_eq!(a.peer_trust(&b_node_id).await, PeerTrust::Trusted);

        // Verified cannot be set directly.
        assert!(!a.trust_peer(&b_node_id, PeerTrust::Verified).await);
        assert_eq!(a.peer_trust(&b_node_id).await, PeerTrust::Trusted);
    }

    #[tokio::test]
    async fn two_nodes_exchange_messages() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);

        assert!(
            wait_for_connected(&mut b, a_node_id, 5_000).await.is_some(),
            "B should see A connect"
        );

        // Wait for the flow to complete on both sides before
        // exchanging application messages: during establishment the
        // peer loop hasn't started yet.
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        // A sends a `get` to B on T1. (`get` is not auto-served, so it
        // surfaces as a `Message` event on B.)
        a.send_to(
            &peer_b,
            Message::Get(GetRequest {
                resource_id: b"hello".to_vec(),
                their_dvv: Dvv::from_write(a_node_id, 0),
            }),
        )
        .await
        .unwrap();

        let deadline = std::time::Instant::now() + Duration::from_millis(5_000);
        let mut received = false;
        while std::time::Instant::now() < deadline && !received {
            if let Ok(events) = b.poll().await {
                for e in events {
                    if let NodeEvent::Message { peer, msg, .. } = e {
                        if peer == a_node_id && msg.verb() == "get" {
                            received = true;
                            break;
                        }
                    }
                }
            }
        }
        assert!(received, "B did not receive the `get` from A");
    }

    #[tokio::test]
    async fn send_to_unknown_peer_errors() {
        let a = make_node(1).await;
        let unknown: NodeId = [0xee; 32];
        let err = a
            .send_to(
                &unknown,
                Message::Emit(quip_net::event::EmitEvent {
                    event_type: "ping".into(),
                    payload: quip_core::cbor::CborValue::Null,
                }),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Transport(_)));
    }

    #[tokio::test]
    async fn local_addr_is_bound() {
        let a = make_node(1).await;
        let addr = a.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn peers_snapshot_grows_after_connect() {
        let (mut a, _) = make_node_with_clock(1).await;
        let b = make_node(2).await;
        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        assert!(a.peers().await.is_empty());
        a.connect(b_addr, "localhost").await.unwrap();
        let peers = a.peers().await;
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0], b_node_id);
    }

    #[tokio::test]
    async fn drop_releases_peer_tasks() {
        // Two nodes, connect, then drop both. The test's runtime will
        // hang if either node leaks a task that outlives it.
        let (mut a, _) = make_node_with_clock(1).await;
        let b = make_node(2).await;
        let b_addr = b.local_addr().unwrap();

        a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(a.peers().await.len(), 1);

        drop(a);
        drop(b);
        // If we got here without a timeout, the drop impls worked.
    }

    #[tokio::test]
    async fn put_and_get_content_round_trip() {
        let (node, clock) = make_node_with_clock(1).await;
        let hasher = Sha256Hasher;

        let payload = b"hello quip".to_vec();
        let cid = node
            .put_content(
                payload.clone(),
                HashAlgo::Sha256,
                CidTagging::V1,
                &hasher,
                clock.now(),
            )
            .await
            .unwrap();

        let fetched = node
            .get_content(&cid, HashAlgo::Sha256, &hasher, clock.now())
            .await
            .unwrap();
        assert_eq!(fetched, payload);
    }

    #[tokio::test]
    async fn peer_query_pins_is_auto_served() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, b_clock) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await.is_some());
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        // B's peer tasks read `b_clock.now()`, so pinning at the same
        // time means the pin is fresh when the query arrives.
        let cid = CidOrV1::Raw(Cid([0xAA; 32]));
        b.pin(b"some-resource", &cid, 0, b_clock.now()).await;

        assert_eq!(
            b.query_pins(Some(b"some-resource"), None, b_clock.now())
                .await
                .len(),
            1,
        );

        a.send_to(
            &peer_b,
            Message::QueryPins(QueryPins {
                resource_id: Some(b"some-resource".to_vec()),
                cid: None,
            }),
        )
        .await
        .unwrap();

        let pins = wait_for_pin_list(&mut a, b_node_id, 5_000).await;
        let pins = pins.expect("A did not receive a pin_list from B");
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].cid, cid);
    }

    #[tokio::test]
    async fn peer_pin_is_applied_to_store() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, b_clock) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await.is_some());
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        // A pins a resource on B by sending a `pin` verb.
        let cid = CidOrV1::Raw(Cid([0xBB; 32]));
        a.send_to(
            &peer_b,
            Message::Pin(quip_net::sync::PinQuery {
                resource_id: b"remote-pinned".to_vec(),
                cid: Some(cid),
                ttl_seconds: 0,
                witness_ring: vec![],
            }),
        )
        .await
        .unwrap();

        // Poll B a few times to let the peer task process the pin.
        let deadline = std::time::Instant::now() + Duration::from_millis(5_000);
        let mut found = false;
        while std::time::Instant::now() < deadline && !found {
            let _ = b.poll().await;
            let pins = b
                .query_pins(Some(b"remote-pinned"), None, b_clock.now())
                .await;
            if pins.len() == 1 {
                found = true;
            }
        }
        assert!(found, "B's store did not receive the pin");
    }

    // ---- M9.4a: live DhtClient ----

    #[tokio::test]
    async fn dht_publish_connectivity_reaches_peer() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await.is_some());
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        let announce = signed_connectivity(1, a.now());
        let mut a_dht = a.dht();
        a_dht.publish_connectivity(announce.clone());

        let mut b_dht = b.dht();
        let deadline = std::time::Instant::now() + Duration::from_millis(5_000);
        let mut received: Option<ConnectivityAnnounce> = None;
        while std::time::Instant::now() < deadline && received.is_none() {
            if let Some(quip_net::nat_driver::DhtResult::Connectivity(got)) = b_dht.poll() {
                received = Some(got);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let received = received.expect("B did not receive the connectivity_announce");
        assert_eq!(received.node_id, a_node_id);
        assert_eq!(received.signature, announce.signature);
    }

    #[tokio::test]
    async fn dht_routing_table_lists_peers() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        // Before connecting, the tables are empty.
        assert!(a.dht().table_is_empty());
        assert!(b.dht().table_is_empty());

        let _ = a.connect(b_addr, "localhost").await.unwrap();
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await.is_some());
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        // A recorded B on the outbound side, B recorded A on the
        // accept side.
        assert!(a.dht().table_contains(&b_node_id));
        assert!(b.dht().table_contains(&a_node_id));
    }

    #[tokio::test]
    async fn dht_handle_clone_shares_routing_table() {
        let a = make_node(1).await;
        let h1 = a.dht();
        let h2 = a.dht();
        let peer: NodeId = [0x42; 32];
        let slot = PeerSlot::new(peer, 1);
        h1.note_peer(peer, slot, None, a.now());
        assert!(h2.table_contains(&peer));
    }

    #[tokio::test]
    async fn dht_publish_with_no_peers_is_a_noop() {
        let a = make_node(1).await;
        let announce = signed_connectivity(1, a.now());
        let mut h = a.dht();
        h.publish_connectivity(announce);
        assert!(h.poll().is_none());
        assert!(a.dht().table_is_empty());
    }

    #[tokio::test]
    async fn dht_forged_connectivity_is_dropped() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await.is_some());
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        // A publishes an announcement signed by A but attributed to B.
        // The peer-loop check rejects it on the attribution: the
        // delivered message claims `node_id = B`, but the sending peer
        // is A, so `dht_result_from` returns `None` and nothing is
        // enqueued.
        //
        // The NAT phase sends a *legitimate* `candidate_announce` from
        // A to B with `node_id = A`; that one passes the attribution
        // check and lands in B's DHT queue. This test must not treat
        // the legitimate result as a forged leak, so it drains the
        // queue and asserts no `Connectivity` result carrying B's
        // `node_id` ever appears.
        let mut announce = signed_connectivity(1, a.now());
        announce.node_id = b_node_id;
        let mut a_dht = a.dht();
        a_dht.publish_connectivity(announce);

        let mut b_dht = b.dht();
        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            while let Some(result) = b_dht.poll() {
                if let quip_net::nat_driver::DhtResult::Connectivity(a) = result {
                    assert_ne!(
                        a.node_id, b_node_id,
                        "forged announce leaked: attributed to B but \
                         delivered by A",
                    );
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    // ---- M9.5a: shared Coral discovery ----

    /// Two nodes reach `Ready` on both sides via the shared discovery
    /// handle. In a two-node network the responder holds no
    /// witnesses, so both sides conclude `Pending`.
    #[tokio::test]
    async fn ready_via_shared_discovery_on_both_sides() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        let peer_b = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(peer_b, b_node_id);

        let a_ready = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let b_ready = wait_for_ready(&mut b, a_node_id, 10_000).await;
        assert_eq!(a_ready.map(|(s, _)| s), Some(KtStatus::Pending));
        assert_eq!(b_ready.map(|(s, _)| s), Some(KtStatus::Pending));
    }

    /// The node's shared discovery handle exposes the same NodeId as
    /// its local claim, so the responder signs as itself.
    #[tokio::test]
    async fn discovery_local_node_id_matches_node() {
        let a = make_node(1).await;
        assert_eq!(a.discovery().local_node_id(), a.local_node_id());
    }

    /// Two clones of the node's discovery handle share one state.
    #[tokio::test]
    async fn discovery_clones_share_state() {
        let a = make_node(1).await;
        let h1 = a.discovery();
        let h2 = a.discovery();
        let target: NodeId = [0x77; 32];
        // Starting through one handle makes the other see the
        // in-flight discovery.
        let paths = make_lookup_paths(target, a.now());
        let _ = h1.start(target, paths, a.now()).unwrap();
        assert!(h2.status(&target).is_some());
    }

    // ---- M10.3: trust policy ----

    /// A peer stays `Unknown` until the application decides.
    #[tokio::test]
    async fn peer_stays_unknown_until_decided() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        let _ = a.connect(b_addr, "localhost").await.unwrap();
        assert_eq!(a.peer_trust(&b_node_id).await, PeerTrust::Unknown);

        // The store holds the claim.
        let snapshot = a.trust_snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].0, b_node_id);
        assert_eq!(snapshot[0].1.trust, PeerTrust::Unknown);

        // The application accepts.
        assert!(a.trust_peer(&b_node_id, PeerTrust::Trusted).await);
        assert_eq!(a.peer_trust(&b_node_id).await, PeerTrust::Trusted);
    }

    /// `trust_peer` emits a `PeerTrustChanged` event.
    #[tokio::test]
    async fn trust_change_emits_event() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        let _ = a.connect(b_addr, "localhost").await.unwrap();
        let _ = a.trust_peer(&b_node_id, PeerTrust::Trusted).await;

        // Poll until we see the event.
        let deadline = std::time::Instant::now() + Duration::from_millis(2_000);
        let mut saw = false;
        while std::time::Instant::now() < deadline && !saw {
            if let Ok(events) = a.poll().await {
                for e in events {
                    if let NodeEvent::PeerTrustChanged { peer, trust } = e {
                        if peer == b_node_id && trust == PeerTrust::Trusted {
                            saw = true;
                            break;
                        }
                    }
                }
            }
        }
        assert!(saw, "PeerTrustChanged event did not fire");
    }

    /// Revocation is terminal and fires a change event.
    #[tokio::test]
    async fn revocation_is_terminal() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        let _ = a.connect(b_addr, "localhost").await.unwrap();
        let _ = a.trust_peer(&b_node_id, PeerTrust::Trusted).await;
        assert!(a.trust_peer(&b_node_id, PeerTrust::Revoked).await);
        assert_eq!(a.peer_trust(&b_node_id).await, PeerTrust::Revoked);

        // Attempting to re-trust does not lift revocation.
        assert!(a.trust_peer(&b_node_id, PeerTrust::Trusted).await);
        assert_eq!(a.peer_trust(&b_node_id).await, PeerTrust::Revoked);
    }

    // ---- M9.5b-b: peer slots ----

    /// A `NodeId` gets a monotonically-increasing slot across
    /// reconnects, and `Node::peer_slot` reports the live one.
    #[tokio::test]
    async fn peer_slot_increments_across_reconnects() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;
        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        // No connection yet.
        assert!(a.peer_slot(&b_node_id).await.is_none());

        // First connection: generation 1.
        a.connect(b_addr, "localhost").await.unwrap();
        let first = a.peer_slot(&b_node_id).await.expect("connected");
        assert_eq!(first.node_id, b_node_id);
        assert_eq!(first.generation, 1);

        // Second connection to the same peer: generation 2, and the
        // first task has been aborted.
        a.connect(b_addr, "localhost").await.unwrap();
        let second = a.peer_slot(&b_node_id).await.expect("reconnected");
        assert_eq!(second.node_id, b_node_id);
        assert_eq!(second.generation, 2);
        assert_ne!(first, second);
    }

    /// `DhtHandle::forget_peer` refuses to remove a record whose slot
    /// does not match. This is the invariant M9.5b-c relies on for
    /// routing eligibility cleanup.
    #[tokio::test]
    async fn dht_forget_peer_is_slot_scoped() {
        let a = make_node(1).await;
        let dht = a.dht();
        let peer: NodeId = [0x99; 32];
        let current = PeerSlot::new(peer, 2);
        let stale = PeerSlot::new(peer, 1);

        dht.note_peer(peer, current, None, a.now());
        // A stale generation tries to clean up.
        dht.forget_peer(&peer, &stale);
        assert!(
            dht.table_contains(&peer),
            "stale slot must not remove a live record"
        );
        // The current generation can.
        dht.forget_peer(&peer, &current);
        assert!(!dht.table_contains(&peer));
    }

    // ---- M9.5b-c (gates 5 and 6): routing eligibility ----

    /// A freshly-bound node has no routing-eligible peers.
    #[tokio::test]
    async fn routing_eligible_peers_starts_empty() {
        let a = make_node(1).await;
        assert!(a.routing_eligible_peers().await.is_empty());
    }

    /// A peer that has reached `Ready` is routing-eligible. The NAT
    /// phase concludes before the `Ready` event fires, so by the time
    /// the event surfaces the state should already be visible.
    #[tokio::test]
    async fn peer_becomes_routing_eligible_after_establishment() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        a.connect(b_addr, "localhost").await.unwrap();
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;

        let eligible = a.routing_eligible_peers().await;
        assert!(
            eligible.iter().any(|s| s.node_id == b_node_id),
            "peer {b_node_id:?} should be routing-eligible after establishment; \
             got {eligible:?}",
        );

        // The peer's lifecycle should be `NatDirect`.
        assert_eq!(
            a.peer_lifecycle(&b_node_id).await,
            Some(PeerLifecycle::NatDirect),
        );
    }

    /// The DHT routing table mirrors the registry's lifecycle. After
    /// establishment, the peer record for `b_node_id` is eligible.
    #[tokio::test]
    async fn dht_mirrors_routing_eligibility() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let b_node_id = b.local_node_id();

        a.connect(b_addr, "localhost").await.unwrap();
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;

        let eligible = a.dht().routing_eligible_records();
        assert!(
            eligible.iter().any(|(id, _)| *id == b_node_id),
            "DHT should record {b_node_id:?} as routing-eligible; \
             got {eligible:?}",
        );
    }

    /// Two nodes exchange candidates during the NAT phase. Both reach
    /// `NatDirect`, which requires the peer's signed
    /// `candidate_announce` to have been accepted by `dht_result_from`.
    #[tokio::test]
    async fn nat_phase_exchanges_signed_candidates() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        a.connect(b_addr, "localhost").await.unwrap();
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        assert_eq!(
            a.peer_lifecycle(&b_node_id).await,
            Some(PeerLifecycle::NatDirect),
        );
        assert_eq!(
            b.peer_lifecycle(&a_node_id).await,
            Some(PeerLifecycle::NatDirect),
        );
    }

    // ---- M9.5b-c (part 6): relay path ----

    /// A node configured with `force_relay` puts every NAT session
    /// onto the relay branch and reaches `NatRelayed` end-to-end when
    /// the peer is `relay_capable`.
    ///
    /// On loopback the direct probe always succeeds, so `NatRelayed`
    /// is unreachable by probe failure alone. `force_relay` is the
    /// policy knob that a node behind a symmetric NAT would set; this
    /// test exercises it against a `relay_capable` responder and
    /// verifies both the lifecycle transition and the
    /// routing-eligibility consequence.
    #[tokio::test]
    async fn relay_path_produces_nat_relayed() {
        let (mut a, _) = make_forced_relay_node(1).await;
        let (mut b, _) = make_relay_capable_node(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        a.connect(b_addr, "localhost").await.unwrap();

        // A takes the relay branch by policy. The full ladder runs:
        // forced session → RequestRelays → signed relay_discovery →
        // B's signed relay_response → A's on_relay_result → lifecycle.
        let a_ready = wait_for_ready(&mut a, b_node_id, 20_000).await;
        assert!(
            a_ready.is_some(),
            "A should reach Ready via the relay branch",
        );

        // B still takes the direct branch: A's real candidate is
        // reachable from B.
        let _ = wait_for_ready(&mut b, a_node_id, 20_000).await;

        assert_eq!(
            a.peer_lifecycle(&b_node_id).await,
            Some(PeerLifecycle::NatRelayed),
            "A's peer lifecycle should be NatRelayed",
        );
        assert_eq!(
            b.peer_lifecycle(&a_node_id).await,
            Some(PeerLifecycle::NatDirect),
            "B's peer lifecycle should be NatDirect",
        );

        // A's routing-eligible set includes B: `NatRelayed` is
        // routing-eligible (§3 of the design note).
        let eligible = a.routing_eligible_peers().await;
        assert!(
            eligible.iter().any(|s| s.node_id == b_node_id),
            "B should be routing-eligible for A after a relayed path; \
             got {eligible:?}",
        );
    }

    // ---- M9.5b-c (part 7): cluster membership and XOR routing ----

    /// A node's cluster starts as its own `Local` cluster, id derived
    /// from its NodeId; after a peer becomes routing-eligible, XOR
    /// routing can reach it.
    #[tokio::test]
    async fn cluster_starts_local_and_routes_to_eligible_peer() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (b, _) = make_node_with_clock(2).await;

        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();
        let b_addr = b.local_addr().unwrap();

        let view = a.cluster_view();
        assert_eq!(view.level, ClusterLevel::Local);
        assert_eq!(&view.id[..], &a_node_id[..16]);
        assert!(view.members.is_empty());

        a.connect(b_addr, "localhost").await.unwrap();
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;

        // B is routing-eligible, so XOR routing can find it.
        let closest = a.dht().closest_to(&b_node_id, GATEWAY_ROUTER_COUNT);
        assert!(
            closest.contains(&b_node_id),
            "XOR routing should reach B: {closest:?}",
        );
    }

    // ------------------------------------------------------------------
    // Multi-node test harness.
    // ------------------------------------------------------------------

    /// The largest mesh [`MeshHarness`] supports.
    ///
    /// `connect_all` dials a complete graph — n×(n−1) connections, each
    /// spawning a peer task — so the cost is O(n²). Six is the largest
    /// mesh the §8 acceptance tests are expected to need; a
    /// sparse-connection mode can grow this later.
    const MESH_MAX_NODES: usize = 6;

    // Multi-node test harness. Exists for M9.6a (witness accumulation,
    // which needs four independent witnesses plus a subject) and §8's
    // multi-node acceptance tests. Not part of any milestone's public
    // surface.
    /// A loopback mesh of nodes for multi-node tests.
    ///
    /// Owns the nodes and their frozen clocks together, so a test can
    /// poll a specific node — or all of them — without holding a borrow
    /// across the whole polling loop. Dropped nodes abort their peer
    /// tasks, so the mesh tears down with the harness.
    struct MeshHarness {
        nodes: Vec<(Node, Arc<ManualClock>)>,
        /// Distinct peers each node has reported `Ready` for, keyed by
        /// node index and accumulated across polls.
        ready: Vec<BTreeSet<NodeId>>,
    }

    impl MeshHarness {
        /// Build `n` nodes with distinct Ed25519 seeds and frozen
        /// clocks, bound on loopback but not yet connected.
        async fn new(n: usize) -> MeshHarness {
            assert!(
                n <= MESH_MAX_NODES,
                "MeshHarness capped at {MESH_MAX_NODES} nodes; got {n}",
            );
            let mut nodes = Vec::with_capacity(n);
            for i in 0..n {
                nodes.push(make_node_with_clock((i + 1) as u8).await);
            }
            MeshHarness {
                nodes,
                ready: vec![BTreeSet::new(); n],
            }
        }

        /// Every node's `NodeId`, in index order.
        fn node_ids(&self) -> Vec<NodeId> {
            self.nodes
                .iter()
                .map(|(node, _)| node.local_node_id())
                .collect()
        }

        /// The distinct peers node `idx` has reported `Ready` for,
        /// sorted.
        fn ready_peers(&self, idx: usize) -> Vec<NodeId> {
            self.ready[idx].iter().copied().collect()
        }

        /// Dial every node from every other node, forming a complete
        /// connection graph.
        ///
        /// Each pair is dialled once — node `i` dials every `j > i`.
        /// Dialling both directions would form two connections per pair,
        /// and the second would abort the first through
        /// `register_peer`, churning the mesh while it settles.
        ///
        /// The `NodeId` each `connect` returns is discarded — the
        /// harness already has it via [`Self::node_ids`] — but the dial
        /// has to happen for the mesh to exist.
        async fn connect_all(&mut self) {
            let addrs: Vec<SocketAddr> = self
                .nodes
                .iter()
                .map(|(node, _)| node.local_addr().expect("node is bound"))
                .collect();
            let n = self.nodes.len();
            for i in 0..n {
                for &addr in addrs.iter().skip(i + 1) {
                    let _ = self.nodes[i].0.connect(addr, "localhost").await;
                }
            }
        }

        /// Poll node `idx` once, recording any `Ready` peers it reports.
        async fn poll_ready(&mut self, idx: usize) {
            if let Ok(events) = self.nodes[idx].0.poll().await {
                for event in events {
                    if let NodeEvent::Ready { peer, .. } = event {
                        self.ready[idx].insert(peer);
                    }
                }
            }
        }

        /// Wait until every node has emitted a `Ready` event for every
        /// other node, up to `timeout_ms`. Returns `true` when the full
        /// mesh is ready.
        async fn wait_all_ready(&mut self, timeout_ms: u64) -> bool {
            let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
            let n = self.nodes.len();
            let ids = self.node_ids();
            loop {
                for i in 0..n {
                    self.poll_ready(i).await;
                }
                let ready = &self.ready;
                let all = (0..n).all(|i| (0..n).all(|j| i == j || ready[i].contains(&ids[j])));
                if all {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    return false;
                }
            }
        }

        /// Advance every node's clock by `delta_ms`.
        fn advance_all(&self, delta_ms: u64) {
            for (_, clock) in &self.nodes {
                clock.advance(delta_ms);
            }
        }

        /// Poll node `idx` until it reports `Ready` for `peer`, and
        /// return the KT status that `Ready` carried.
        ///
        /// Unlike [`Self::poll_ready`], this keeps the status, which is
        /// what M9.6a's acceptance tests assert on.
        async fn wait_ready_status(
            &mut self,
            idx: usize,
            peer: NodeId,
            timeout_ms: u64,
        ) -> Option<KtStatus> {
            let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
            while std::time::Instant::now() < deadline {
                if let Ok(events) = self.nodes[idx].0.poll().await {
                    for event in events {
                        if let NodeEvent::Ready {
                            peer: reported,
                            kt_status,
                            ..
                        } = event
                        {
                            if reported == peer {
                                return Some(kt_status);
                            }
                        }
                    }
                }
            }
            None
        }

        /// Wait until node `idx` holds at least `n` witness statements.
        async fn wait_witnesses(&mut self, idx: usize, n: usize, timeout_ms: u64) -> bool {
            let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
            while std::time::Instant::now() < deadline {
                if self.nodes[idx].0.witness_store().len() >= n {
                    return true;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            false
        }
    }

    /// A three-node mesh reaches full readiness through the harness:
    /// each node reports `Ready` for exactly the other two, by their
    /// real `NodeId`s.
    #[tokio::test]
    async fn mesh_harness_three_nodes_all_ready() {
        let mut h = MeshHarness::new(3).await;
        h.connect_all().await;
        assert!(
            h.wait_all_ready(15_000).await,
            "a three-node mesh should reach full readiness",
        );

        let ids = h.node_ids();
        for i in 0..3 {
            let peers = h.ready_peers(i);
            assert_eq!(peers.len(), 2, "node {i} should report Ready for 2 peers");
            for (j, &id) in ids.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    peers.contains(&id),
                    "node {i} should report Ready for node {j} ({id:?})",
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // M9.6a: witness accumulation and issuance.
    // ------------------------------------------------------------------

    /// The six-node shape M9.6a's acceptance tests need.
    ///
    /// Indices are 0-based: node 1 (index 0) is the peer being verified,
    /// node 2 (index 1) is the verifier, and nodes 3..=6 (indices 2..=5)
    /// are the four independent witnesses. With the verifier and the
    /// peer excluded, four is the most an N=6 mesh can offer, which is
    /// exactly `MIN_WITNESSES`.
    async fn six_node_mesh() -> MeshHarness {
        let mut h = MeshHarness::new(6).await;
        h.connect_all().await;
        assert!(
            h.wait_all_ready(30_000).await,
            "the six-node mesh should reach full readiness",
        );
        h
    }

    /// Have the four witnesses accept the peer, then move every clock
    /// forward by `advance_ms`.
    async fn trust_and_advance(h: &mut MeshHarness, advance_ms: u64) -> (NodeId, NodeId) {
        let ids = h.node_ids();
        let peer = ids[0];
        let subject = ids[1];
        for i in 2..6 {
            assert!(
                h.nodes[i].0.trust_peer(&peer, PeerTrust::Trusted).await,
                "node {i} should accept node 1",
            );
        }
        h.advance_all(advance_ms);
        (peer, subject)
    }

    /// A verifier computes `Verified` once four independent witnesses
    /// have been first-seen for §5.3.3's six hours and their statements
    /// reach its flow.
    #[tokio::test]
    async fn six_nodes_reach_verified_after_first_seen_window() {
        let mut h = six_node_mesh().await;
        // Past the first-seen window and one re-issuance interval.
        let advance_ms = (WITNESS_FIRST_SEEN_SECONDS + WITNESS_REISSUE_INTERVAL_SECONDS) * 1_000;
        let (peer, subject) = trust_and_advance(&mut h, advance_ms).await;

        assert!(
            h.wait_witnesses(0, 4, 10_000).await,
            "node 1 should accumulate the four statements about itself",
        );
        assert!(
            h.wait_witnesses(1, 4, 10_000).await,
            "node 2 should accumulate the four statements about node 1",
        );

        // `Ready` fired once, before the clocks moved, and the flow was
        // not advanced afterwards. A fresh flow is the only way to
        // compute the status again; the discovery phase re-queries the
        // responder, whose store now holds four matured statements.
        let addr = h.nodes[0].0.local_addr().expect("node 1 is bound");
        h.nodes[1]
            .0
            .connect(addr, "localhost")
            .await
            .expect("reconnect");
        let status = h.wait_ready_status(1, peer, 30_000).await;
        assert_eq!(
            status,
            Some(KtStatus::Verified),
            "subject {subject:?} should compute Verified for {peer:?}",
        );
    }

    /// The control: the statements are held, but before the six-hour
    /// window closes the responder's query-time rule filters them out,
    /// so the verifier stays `Pending`.
    #[tokio::test]
    async fn six_nodes_stay_pending_before_first_seen_window() {
        let mut h = six_node_mesh().await;
        // One second short of the first-seen window.
        let advance_ms = (WITNESS_FIRST_SEEN_SECONDS - 1) * 1_000;
        let (peer, subject) = trust_and_advance(&mut h, advance_ms).await;

        assert!(
            h.wait_witnesses(0, 4, 10_000).await,
            "node 1 should still hold the statements",
        );

        let addr = h.nodes[0].0.local_addr().expect("node 1 is bound");
        h.nodes[1]
            .0
            .connect(addr, "localhost")
            .await
            .expect("reconnect");
        let status = h.wait_ready_status(1, peer, 30_000).await;
        assert_eq!(
            status,
            Some(KtStatus::Pending),
            "subject {subject:?} must not verify {peer:?} before six hours",
        );
    }
}
