//! A running QUIP node.
//!
//! # Changelog
//!
//! Milestone tags in the source (`M9.1`, `M10.1`, …) cite entries in
//! the [changelog].
//!
//! [changelog]: https://github.com/jjmututi/quip/blob/main/CHANGELOG.md
//!
//! [`Node`] binds a QUIC endpoint, accepts inbound connections, dials
//! outbound ones, and surfaces a single event stream keyed by peer
//! NodeId. It owns a [`QuipStore`] and uses it to auto-serve the
//! storage-plane verbs that have a 1:1 wire mapping, a
//! [`DhtHandle`] that carries §12 NAT-plane verbs over
//! the same connections, and a
//! [`DiscoveryHandle`] that runs Coral
//! witness discovery for each peer and answers the peer's own
//! lookups.
//!
//! # Scope
//!
//! This is the sixth cut. It does:
//!
//! - Bind a server endpoint with a self-signed cert (rcgen).
//! - Accept inbound connections; drive the §4/§16 handshake to
//!   completion in a background task.
//! - Dial outbound connections; drive the handshake inline.
//! - Run a [`ConnectionFlow`] per peer, sequencing §16 establishment
//!   from the point the transport's inline handshake leaves off.
//! - Run Coral witness discovery for each peer during the flow's
//!   witness phase, answering the peer's own lookups.
//! - Expose `send_to(peer, msg)` and `poll() -> Vec<NodeEvent>`.
//! - Track a `NodeId -> outbound sender` table.
//! - Track every peer task it spawns and abort them all on `Drop`.
//! - Own a `QuipStore<B>`, shared across peer tasks behind a mutex.
//! - Auto-serve `pin`, `unpin`, and `query_pins` from that store
//!   when [`NodeConfig::auto_serve_pins`] is set.
//! - Expose direct store helpers: `put_content`, `get_content`,
//!   `pin`, `unpin`, `query_pins`, and a raw `store()` accessor.
//! - Read the wall clock through a [`Clock`], so tests can inject a
//!   deterministic time source.
//!
//! It does not (yet):
//!
//! - Drive a real `NatDriver`. The flow's NAT phase still concludes
//!   from the live transport; M9.5b replaces that with a real driver
//!   per peer.
//! - Accumulate `WitnessStatement`s. The discovery client runs, but
//!   the responder answers with no witnesses, so `Ready(Verified)`
//!   is unreachable in a two-node network. A later milestone wires
//!   witness accumulation and the responder returns real rings.
//! - Run cluster merge/split. The DHT's routing table records
//!   observed `ClusterInfo` but nothing consumes it.
//! - Auto-serve `register_tcid`, `delegation`, `derivative_link`,
//!   `resource_announce`, or `query_resource`. Those carry signatures
//!   the peer task cannot verify, or require a wire-to-storage type
//!   conversion that has not been written.
//! - Auto-serve `get`, `set`, `sync`, or `rbsr_sync`: they are
//!   DVV-shaped and need DVV state that `Node` does not own yet.
//! - Run a `BftDriver`.
//!
//! # Establishment
//!
//! After the §4 handshake and §16 Key Claim exchange — both performed
//! inline by `ConnectionDriver` — each peer task runs a
//! [`ConnectionFlow`] resumed at `NatTraversal` via
//! [`ConnectionFlow::resume_from_key_claim`]. The NAT phase concludes
//! from the transport being up: direct connectivity is already proven
//! by the handshake. The witness phase runs a real
//! [`WitnessDiscovery`](quip_net::discovery::WitnessDiscovery) against
//! the peer: the flow sends a `coral_lookup`, ingests the response,
//! and either completes with `Ready(KtStatus)` or falls back to
//! `Ready(Pending)` when the discovery fails.
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
//! Both roles share one
//! [`DiscoveryHandle`], so the ring and
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
//! [`SystemClock`]. Tests inject a
//! [`ManualClock`](quip_core::time::ManualClock) so that pin and
//! query timestamps match by construction. The clock is also what an
//! application should read via [`Node::clock`] when it wants a
//! timestamp consistent with what the node's own peer tasks are
//! using.
//!
//! One exception: the establishment-time discovery wait uses a
//! wall-clock deadline (`std::time::Instant`), not the injected
//! clock. The injected clock can be frozen — a stub discovery phase
//! must not block forever on it.
//!
//! # Signer
//!
//! The node signs wire messages — §16 Key Claims, §13 Coral lookups
//! and responses — with the [`Ed25519Signer`] held in
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
//!         NodeEvent::Ready { peer, kt_status } => {
//!             println!("ready: {peer:?} ({kt_status:?})");
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

pub mod dht;
pub mod discovery;

use quip_core::cid::{CidOrV1, HashAlgo};
use quip_core::dvv::NodeId;
use quip_core::messages::{KeyClaim, PinEntry, Signer};
use quip_core::time::{Clock, SystemClock, Timestamp};
use quip_net::coral::LookupPath;
use quip_net::crypto::Ed25519Signer;
use quip_net::discovery::{
    DiscoveryPhaseKind, Outbound as DiscoveryOutbound, StartOutcome,
};
use quip_net::establishment::{
    ConnectionFlow, FlowAction, FlowConfig, FlowFailure, FlowPhase, KtStatus,
};
use quip_net::frame::Tier;
use quip_net::handshake::Capabilities;
use quip_net::message::{self, Message};
use quip_net::transport::{
    ClientConfig, ConnectionDriver, Endpoint, Event, ServerConfig,
};
use quip_net::{Error, Result};
use quip_storage::blob::{BlobStore, BlobStoreMut};
use quip_storage::{CidTagging, ContentHasher, MemoryBlobStore, QuipStore};

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, MutexGuard};
use tokio::task::JoinHandle;

use dht::DhtHandle;
use discovery::DiscoveryHandle;

/// Capacity of the node's event channel.
const EVENT_CHANNEL_CAPACITY: usize = 128;

/// Capacity of each peer's outbound queue.
const OUTBOUND_CAPACITY: usize = 64;

/// How long [`Node::poll`] waits for a first event before returning.
const POLL_TIMEOUT_MS: u64 = 50;

/// How long the establishment-time discovery phase waits for a
/// resolution before falling back to `Ready(Pending)`.
///
/// Wall-clock, not the injected `Clock`: the injected clock can be
/// frozen (tests) or advanced manually, and a stub discovery phase
/// must not block forever on a frozen clock. Two-node tests on
/// loopback resolve in well under 100 ms; the deadline is only hit
/// when a peer is unresponsive.
const DISCOVERY_WAIT_MS: u64 = 5_000;

/// A time source that can be moved across threads and shared.
///
/// `quip_core::time::Clock` does not itself require `Send + Sync`,
/// because the trait is also used in single-threaded contexts. The
/// node moves clocks into `tokio::spawn`ed tasks, so it needs the
/// stronger bound. Every implementation in the workspace
/// (`SystemClock`, `ManualClock`) satisfies it already.
type SharedClock = Arc<dyn Clock + Send + Sync + 'static>;

/// The node's Ed25519 signer.
///
/// Concrete `Ed25519Signer`, not `dyn Signer`: every verifier in the
/// workspace is `Ed25519Verifier`, so a `dyn` would be strictly less
/// safe with no gain.
pub type SharedSigner = Arc<Ed25519Signer>;

// -------------------------------------------------------------------------
// Config
// -------------------------------------------------------------------------

/// Configuration for a [`Node`].
#[derive(Clone)]
pub struct NodeConfig {
    /// UDP address to bind for inbound connections.
    pub bind: SocketAddr,
    /// Capabilities to advertise and accept.
    pub capabilities: Capabilities,
    /// Our self-signed identity claim, derived from `signer`.
    pub key_claim: KeyClaim,
    /// When true (default), the node auto-handles inbound `pin`,
    /// `unpin`, and `query_pins` from its store. When false, those
    /// messages surface as [`NodeEvent::Message`] and the application
    /// is responsible for handling them.
    pub auto_serve_pins: bool,
    /// Time source used by peer tasks. Defaults to [`SystemClock`];
    /// tests inject a [`ManualClock`](quip_core::time::ManualClock).
    pub clock: SharedClock,
    /// The node's signer. Shared with the DHT and the discovery
    /// client, so every signature the node produces traces to one
    /// key.
    pub signer: SharedSigner,
}

impl core::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("bind", &self.bind)
            .field("capabilities", &self.capabilities)
            .field("key_claim", &self.key_claim)
            .field("auto_serve_pins", &self.auto_serve_pins)
            .field("clock", &"<dyn Clock>")
            .field("signer", &"<Ed25519Signer>")
            .finish()
    }
}

impl NodeConfig {
    /// Build a config with baseline capabilities plus NAT traversal
    /// and DHT discovery, a claim derived from `signer`, auto-serving
    /// enabled, and the system clock.
    ///
    /// `NAT_TRAVERSAL` is what allows a peer to send and receive §12
    /// verbs; without it the transport's capability gate rejects them.
    /// `DHT_DISCOVERY` is what allows the Coral verbs of §13. Neither
    /// is in the baseline set (which is transport-level), so both are
    /// added explicitly here.
    pub fn new(
        bind: SocketAddr,
        signer: SharedSigner,
        now: Timestamp,
    ) -> Result<Self> {
        Ok(Self {
            bind,
            capabilities: Capabilities::baseline()
                | Capabilities(Capabilities::NAT_TRAVERSAL)
                | Capabilities(Capabilities::DHT_DISCOVERY),
            key_claim: make_key_claim(signer.as_ref(), now)?,
            auto_serve_pins: true,
            clock: Arc::new(SystemClock),
            signer,
        })
    }

    /// Replace the capability set.
    pub fn with_capabilities(mut self, caps: Capabilities) -> Self {
        self.capabilities = caps;
        self
    }

    /// Enable or disable pin auto-serving.
    pub fn with_auto_serve_pins(mut self, on: bool) -> Self {
        self.auto_serve_pins = on;
        self
    }

    /// Replace the time source.
    ///
    /// The clock is read once per peer task iteration, so a frozen or
    /// slowly-advancing
    /// [`ManualClock`](quip_core::time::ManualClock) makes the node
    /// deterministic.
    pub fn with_clock(mut self, clock: SharedClock) -> Self {
        self.clock = clock;
        self
    }
}

/// Build a signed `KeyClaim` for `signer`.
pub fn make_key_claim(signer: &impl Signer, now: Timestamp) -> Result<KeyClaim> {
    let node_id = signer.public_key();
    let unsigned = KeyClaim {
        node_id,
        timestamp: now,
        dht_id: node_id,
        signature: [0u8; 64],
    };
    let payload = unsigned.signing_payload()?;
    let signature = signer.sign_ed25519(&payload);
    Ok(KeyClaim {
        signature,
        ..unsigned
    })
}

// -------------------------------------------------------------------------
// Events
// -------------------------------------------------------------------------

/// An event surfaced to the application.
#[derive(Debug)]
pub enum NodeEvent {
    /// A peer completed the §4 handshake and §16 Key Claim exchange.
    ///
    /// The peer is reachable from `send_to` at this point; the
    /// establishment flow still has to run before T2/T3 traffic is
    /// appropriate. That completion is signalled by
    /// [`NodeEvent::Ready`].
    Connected {
        /// The peer's NodeId, as claimed. The application is
        /// responsible for verifying the claim's signature and
        /// applying its own TOFU / rotation policy.
        peer: NodeId,
    },
    /// The establishment flow reached `Ready`.
    ///
    /// `kt_status` is the trust level the flow computed from the
    /// witness discovery. In a two-node network the responder holds
    /// no witnesses, so this is [`KtStatus::Pending`]; a larger
    /// network can produce [`KtStatus::Verified`] once 4+ independent
    /// witness statements are collected.
    Ready {
        /// The peer.
        peer: NodeId,
        /// KT status at the moment the flow completed.
        kt_status: KtStatus,
    },
    /// The establishment flow failed before reaching `Ready`.
    ///
    /// The peer task terminates and [`NodeEvent::Disconnected`]
    /// follows. The transport connection is closed.
    EstablishmentFailed {
        /// The peer.
        peer: NodeId,
        /// Why the flow failed.
        failure: FlowFailure,
    },
    /// A peer disconnected.
    Disconnected {
        /// The peer's NodeId.
        peer: NodeId,
    },
    /// A framed message arrived from `peer` on `tier`.
    ///
    /// Verbs covered by [`NodeConfig::auto_serve_pins`] do not surface
    /// here. §12 NAT verbs do not surface here either; they are routed
    /// into the node's DHT client.
    Message {
        /// The peer that sent it.
        peer: NodeId,
        /// Tier the message arrived on.
        tier: Tier,
        /// Decoded message.
        msg: Message,
    },
    /// A T3 datagram arrived from `peer`.
    Datagram {
        /// The peer that sent it.
        peer: NodeId,
        /// Decoded message.
        msg: Message,
    },
    /// An error occurred on a peer connection, or globally.
    Error {
        /// Peer the error is associated with, if any.
        peer: Option<NodeId>,
        /// The error.
        error: Error,
    },
}

// -------------------------------------------------------------------------
// Node
// -------------------------------------------------------------------------

/// Peer table entry: outbound sender for one connected peer.
struct PeerHandle {
    outbound: mpsc::Sender<Message>,
}

/// Shared maps. Both are behind an `Arc<Mutex<…>>` because the accept
/// loop, the connect path, and the per-peer tasks all need to update
/// them.
type PeerMap = Arc<Mutex<BTreeMap<NodeId, PeerHandle>>>;
type TaskMap = Arc<Mutex<BTreeMap<NodeId, JoinHandle<()>>>>;

/// A running QUIP node.
///
/// The blob backend `B` defaults to [`MemoryBlobStore`]. Use
/// [`Node::bind_with_store`] with a `QuipStore<FileBlobStore>` for
/// file-backed persistence.
pub struct Node<B = MemoryBlobStore> {
    endpoint: Arc<Endpoint>,
    local_claim: KeyClaim,
    peers: PeerMap,
    /// Peer tasks spawned by `connect` or the accept loop, keyed by
    /// peer NodeId. Aborted on `Drop`, so a dropped `Node` cannot leak
    /// tasks into the runtime.
    peer_tasks: TaskMap,
    /// The node's store, shared with every peer task for auto-serving.
    store: Arc<Mutex<QuipStore<B>>>,
    /// Whether peer tasks auto-serve pin/unpin/query_pins.
    auto_serve_pins: bool,
    /// Time source handed to peer tasks.
    clock: SharedClock,
    events_rx: mpsc::Receiver<NodeEvent>,
    events_tx: mpsc::Sender<NodeEvent>,
    accept_task: Option<JoinHandle<()>>,
    /// The node's DHT client, shared with every peer task.
    dht: DhtHandle,
    /// The DHT router task, draining the DHT's outbound queue and
    /// forwarding each message to connected peers. Aborted on `Drop`.
    dht_task: Option<JoinHandle<()>>,
    /// The node's shared Coral discovery client.
    discovery: DiscoveryHandle,
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
    pub async fn bind_with_store(
        config: NodeConfig,
        store: QuipStore<B>,
    ) -> Result<Self> {
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
        let peers: PeerMap = Arc::new(Mutex::new(BTreeMap::new()));
        let peer_tasks: TaskMap = Arc::new(Mutex::new(BTreeMap::new()));
        let store = Arc::new(Mutex::new(store));
        let clock = Arc::clone(&config.clock);

        let local_id = config.key_claim.node_id;
        let (dht, dht_outbound_rx) = DhtHandle::new(local_id);
        let dht_task = tokio::spawn(dht_router_task(
            dht_outbound_rx,
            Arc::clone(&peers),
        ));

        let discovery = DiscoveryHandle::new(Arc::clone(&config.signer));

        let accept_endpoint = Arc::clone(&endpoint);
        let accept_peers = Arc::clone(&peers);
        let accept_tasks = Arc::clone(&peer_tasks);
        let accept_store = Arc::clone(&store);
        let accept_clock = Arc::clone(&clock);
        let accept_tx = events_tx.clone();
        let accept_dht = dht.clone();
        let accept_discovery = discovery.clone();
        let auto_serve = config.auto_serve_pins;
        let accept_task = tokio::spawn(async move {
            accept_loop(
                accept_endpoint,
                accept_peers,
                accept_tasks,
                accept_store,
                accept_clock,
                auto_serve,
                accept_tx,
                accept_dht,
                accept_discovery,
            )
            .await;
        });

        Ok(Self {
            endpoint,
            local_claim: config.key_claim,
            peers,
            peer_tasks,
            store,
            auto_serve_pins: config.auto_serve_pins,
            clock,
            events_rx,
            events_tx,
            accept_task: Some(accept_task),
            dht,
            dht_task: Some(dht_task),
            discovery,
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
    pub async fn connect(
        &mut self,
        addr: SocketAddr,
        server_name: &str,
    ) -> Result<NodeId> {
        let client_config = ClientConfig {
            bind: "0.0.0.0:0".parse().expect("valid bind"),
            key_claim: self.local_claim.clone(),
            capabilities: self.endpoint.config().capabilities,
        };
        let client_endpoint = Endpoint::client(client_config)?;
        let mut driver = client_endpoint.connect(addr, server_name).await?;

        let clock = Arc::clone(&self.clock);
        let peer = drive_handshake(&mut driver, &clock).await?;

        let (out_tx, out_rx) = mpsc::channel(OUTBOUND_CAPACITY);
        self.peers
            .lock()
            .await
            .insert(peer, PeerHandle { outbound: out_tx });
        self.dht.note_peer(peer, Some(addr), clock.now());
        let _ = self.events_tx.send(NodeEvent::Connected { peer }).await;

        let events_tx = self.events_tx.clone();
        let peers = Arc::clone(&self.peers);
        let peer_tasks = Arc::clone(&self.peer_tasks);
        let store = Arc::clone(&self.store);
        let auto_serve = self.auto_serve_pins;
        let dht = self.dht.clone();
        let discovery = self.discovery.clone();
        let handle = tokio::spawn(async move {
            // The client endpoint must outlive the connection, so it
            // is moved into the peer task and dropped when the loop
            // exits.
            let _keep_endpoint = client_endpoint;
            peer_run(
                driver, peer, store, clock, auto_serve, events_tx, out_rx, dht,
                discovery,
            )
            .await;
            peers.lock().await.remove(&peer);
            peer_tasks.lock().await.remove(&peer);
        });
        self.peer_tasks.lock().await.insert(peer, handle);

        Ok(peer)
    }

    /// Drain whatever events are ready, waiting briefly for the first.
    pub async fn poll(&mut self) -> Result<Vec<NodeEvent>> {
        let mut events = Vec::new();
        match tokio::time::timeout(
            Duration::from_millis(POLL_TIMEOUT_MS),
            self.events_rx.recv(),
        )
        .await
        {
            Ok(Some(e)) => events.push(e),
            Ok(None) => {
                return Err(Error::Transport("event channel closed".into()))
            }
            Err(_) => return Ok(events),
        }
        while let Ok(e) = self.events_rx.try_recv() {
            events.push(e);
        }
        Ok(events)
    }

    /// Send `msg` to `peer`.
    ///
    /// Returns an error if the peer is unknown or its queue is closed.
    /// Capability violations surface as `NodeEvent::Error` from the
    /// peer's task; the caller observes them through `poll`.
    pub async fn send_to(&self, peer: &NodeId, msg: Message) -> Result<()> {
        let tx = {
            let peers = self.peers.lock().await;
            peers
                .get(peer)
                .map(|h| h.outbound.clone())
                .ok_or_else(|| {
                    Error::Transport(format!("unknown peer {peer:?}"))
                })?
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
        self.peers.lock().await.keys().copied().collect()
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

    /// A clone of the node's Coral discovery handle.
    ///
    /// Clones share the ring and spillover caches and the in-flight
    /// discovery state. Used by the peer tasks and by applications
    /// that want to start a lookup directly.
    pub fn discovery(&self) -> DiscoveryHandle {
        self.discovery.clone()
    }

    // ---- Direct store helpers ----

    /// Pin `cid` for `resource_id` locally.
    ///
    /// This updates only the local store; the pin is not propagated to
    /// peers. Propagation is an application concern (see `pin_announce`
    /// on T3 for the gossip mechanism).
    pub async fn pin(
        &self,
        resource_id: &[u8],
        cid: &CidOrV1,
        ttl_seconds: u64,
        now: Timestamp,
    ) {
        let mut s = self.store.lock().await;
        let _ = s.pin(resource_id, cid, ttl_seconds, now);
    }

    /// Drop a pin.
    pub async fn unpin(
        &self,
        resource_id: &[u8],
        cid: Option<&CidOrV1>,
    ) -> usize {
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
        // Abort peer tasks. `try_lock` is safe inside a Drop that may
        // run on a tokio worker; `blocking_lock` would panic. If a
        // task holds the lock, we skip the abort — the endpoint close
        // above already caused every peer task to exit at its next
        // poll, so the tasks terminate regardless.
        if let Ok(mut tasks) = self.peer_tasks.try_lock() {
            while let Some((_, handle)) = tasks.pop_first() {
                handle.abort();
            }
        }
    }
}

// -------------------------------------------------------------------------
// Background tasks
// -------------------------------------------------------------------------

/// Drain the DHT's outbound queue and forward each message to every
/// connected peer.
///
/// A later milestone replaces this with XOR-distance routing over a
/// real DHT peer set. For now the network is small enough that
/// broadcast is correct and cheap.
async fn dht_router_task(
    mut rx: mpsc::UnboundedReceiver<Message>,
    peers: PeerMap,
) {
    while let Some(msg) = rx.recv().await {
        // Copy the senders out of the map before awaiting on any of
        // them, so a slow or stalled peer cannot hold the peer-map lock.
        let senders: Vec<mpsc::Sender<Message>> = {
            let map = peers.lock().await;
            map.values().map(|h| h.outbound.clone()).collect()
        };
        for tx in senders {
            let _ = tx.send(msg.clone()).await;
        }
    }
}

/// Accept inbound connections, drive each handshake, spawn a peer loop.
#[allow(clippy::too_many_arguments)]
async fn accept_loop<B>(
    endpoint: Arc<Endpoint>,
    peers: PeerMap,
    peer_tasks: TaskMap,
    store: Arc<Mutex<QuipStore<B>>>,
    clock: SharedClock,
    auto_serve_pins: bool,
    events_tx: mpsc::Sender<NodeEvent>,
    dht: DhtHandle,
    discovery: DiscoveryHandle,
) where
    B: BlobStore + Send + Sync + 'static,
{
    loop {
        let mut driver = match endpoint.accept().await {
            Ok(Some(d)) => d,
            Ok(None) => return,
            Err(e) => {
                let _ = events_tx
                    .send(NodeEvent::Error { peer: None, error: e })
                    .await;
                return;
            }
        };
        let peers = Arc::clone(&peers);
        let peer_tasks = Arc::clone(&peer_tasks);
        let store = Arc::clone(&store);
        let clock = Arc::clone(&clock);
        let events_tx = events_tx.clone();
        let dht = dht.clone();
        let discovery = discovery.clone();

        // The accept loop cannot know the peer's NodeId until the
        // handshake completes, so the peer task registers itself under
        // its own NodeId once `drive_handshake` returns. This means the
        // task cannot be aborted by Node::drop between spawn and
        // registration — a narrow window, but real. The endpoint close
        // in Drop still causes it to exit.
        tokio::spawn(async move {
            let peer = match drive_handshake(&mut driver, &clock).await {
                Ok(p) => p,
                Err(e) => {
                    let _ = events_tx
                        .send(NodeEvent::Error { peer: None, error: e })
                        .await;
                    return;
                }
            };
            let (out_tx, out_rx) = mpsc::channel(OUTBOUND_CAPACITY);
            peers
                .lock()
                .await
                .insert(peer, PeerHandle { outbound: out_tx });
            dht.note_peer(peer, None, clock.now());
            let _ = events_tx.send(NodeEvent::Connected { peer }).await;

            peer_run(
                driver,
                peer,
                store,
                clock,
                auto_serve_pins,
                events_tx,
                out_rx,
                dht.clone(),
                discovery,
            )
            .await;
            peers.lock().await.remove(&peer);
            peer_tasks.lock().await.remove(&peer);
            dht.forget_peer(&peer);
        });
    }
}

/// Drive a `ConnectionDriver` until the §4/§16 exchanges complete.
///
/// Returns the peer's NodeId. The driver is left in
/// `DriverPhase::Established`.
async fn drive_handshake(
    driver: &mut ConnectionDriver,
    clock: &SharedClock,
) -> Result<NodeId> {
    loop {
        let now = clock.now();
        let events = driver.poll(now).await?;
        for e in events {
            if matches!(e, Event::ControlConnected { .. }) {
                if let Some(peer) = driver.peer_node_id() {
                    return Ok(peer);
                }
            }
        }
    }
}

/// Derive a session identifier from the two NodeIds of a connection.
///
/// Symmetric, so both sides compute the same value without exchanging
/// one on the wire. The low 16 bytes of the two NodeIds, XORed. A
/// collision requires two distinct NodeId pairs to agree on their low
/// halves, which is 2^-128 for uniformly-distributed NodeIds — well
/// below any practical threshold.
fn derive_session_id(local: &NodeId, remote: &NodeId) -> [u8; 16] {
    let mut id = [0u8; 16];
    for i in 0..16 {
        id[i] = local[i] ^ remote[i];
    }
    id
}

/// Compute the lookup paths for a discovery against `target`.
///
/// M9.5a uses the target itself as a one-hop DHT node for each path:
/// the two-node network has no other candidates, and the routing table
/// only holds direct peers. The three `path_id`s are distinct so the
/// discovery state machine can tell the paths apart; when a later
/// milestone consults the routing table for real candidates, the node
/// sets diverge.
fn make_lookup_paths(target: NodeId, _now: Timestamp) -> Vec<LookupPath> {
    let n = quip_core::constants::LOOKUP_PATHS;
    (0..n)
        .map(|i| {
            let mut path_id = [0u8; 16];
            path_id[0] = i as u8;
            LookupPath {
                path_id,
                nodes: vec![target],
                value_hash: [0u8; 32],
                ttl: 60,
            }
        })
        .collect()
}

/// Convert a discovery `Outbound` to a wire `Message`.
fn outbound_to_message(out: DiscoveryOutbound) -> Option<Message> {
    match out {
        DiscoveryOutbound::CoralLookup(m) => Some(Message::CoralLookup(m)),
        DiscoveryOutbound::Spillover(m) => Some(Message::Spillover(m)),
    }
}

/// True for the §13 Coral verbs that the discovery client handles.
fn is_coral_verb(m: &Message) -> bool {
    matches!(
        m,
        Message::CoralLookup(_)
            | Message::CoralLookupResponse(_)
            | Message::Spillover(_)
            | Message::SpilloverResponse(_)
    )
}

/// Route one decoded Coral message into the shared discovery handle.
///
/// The node plays both roles here: responses feed the state machine
/// (client), and inbound `coral_lookup` / `spillover` requests are
/// answered (server). The reply is sent on the same connection the
/// request arrived on.
async fn handle_discovery_event(
    driver: &mut ConnectionDriver,
    clock: &SharedClock,
    discovery: &DiscoveryHandle,
    msg: Message,
) {
    let now = clock.now();
    match msg {
        Message::CoralLookupResponse(resp) => {
            if let Ok(outbound) = discovery.ingest_lookup_response(resp, now) {
                for out in outbound {
                    if let Some(m) = outbound_to_message(out) {
                        let _ = driver.send(&m, clock.now()).await;
                    }
                }
            }
        }
        Message::SpilloverResponse(resp) => {
            let _ = discovery.ingest_spillover_response(resp, now);
        }
        Message::CoralLookup(req) => {
            let resp = discovery.respond_to_lookup(&req, now);
            let _ = driver
                .send(&Message::CoralLookupResponse(resp), clock.now())
                .await;
        }
        Message::Spillover(req) => {
            let resp = discovery.respond_to_spillover(&req, now);
            let _ = driver
                .send(&Message::SpilloverResponse(resp), clock.now())
                .await;
        }
        _ => {}
    }
}

/// Run the flow's witness-discovery phase to completion.
///
/// On entry the flow is in [`FlowPhase::WitnessDiscovery`]. On exit it
/// is in [`FlowPhase::Ready`] with a `KtStatus` reflecting what the
/// discovery found (`Verified` for 4+ witnesses, `Pending` otherwise).
///
/// The state machine is shared across peer tasks; the peer we are
/// establishing with is the target.
async fn run_discovery_phase(
    driver: &mut ConnectionDriver,
    peer: NodeId,
    clock: &SharedClock,
    discovery: &DiscoveryHandle,
    flow: &mut ConnectionFlow,
) {
    let now = clock.now();
    let paths = make_lookup_paths(peer, now);

    // Start the discovery. A cached ring short-circuits the whole
    // phase; an error falls back to `Ready(Pending)`.
    let started = match discovery.start(peer, paths, now) {
        Ok(StartOutcome::Cached(ring)) => {
            let _ = flow.on_discovery_complete(ring, now);
            return;
        }
        Ok(StartOutcome::Started(outbound)) => outbound,
        Err(_) => {
            let _ = flow.on_discovery_failed();
            return;
        }
    };

    // Send the initial CoralLookup. `start` normally returns exactly
    // one outbound message; the loop handles a hypothetical batch.
    for out in started {
        if let Some(msg) = outbound_to_message(out) {
            if driver.send(&msg, clock.now()).await.is_err() {
                let _ = flow.on_discovery_failed();
                return;
            }
        }
    }

    // Wait for a resolution, bounded by a real-time deadline.
    let deadline =
        std::time::Instant::now() + Duration::from_millis(DISCOVERY_WAIT_MS);

    loop {
        let now = clock.now();

        // Resolution already available?
        if let Some(ring) = discovery.take_ring(&peer) {
            let _ = flow.on_discovery_complete(ring, now);
            return;
        }
        if let Some(status) = discovery.status(&peer) {
            if matches!(status.phase, DiscoveryPhaseKind::Failed(_)) {
                let _ = flow.on_discovery_failed();
                return;
            }
        }

        // Timed out?
        if std::time::Instant::now() >= deadline {
            discovery.forget(&peer);
            let _ = flow.on_discovery_failed();
            return;
        }

        // Poll for events. `driver.poll` blocks up to POLL_TIMEOUT_MS
        // internally, so this loop yields to the runtime on every
        // iteration.
        let events = match driver.poll(now).await {
            Ok(e) => e,
            Err(_) => {
                let _ = flow.on_discovery_failed();
                return;
            }
        };
        for event in events {
            if let Event::Frame { tier, msg, .. } = event {
                if let Ok(m) = message::dispatch(&msg.raw, tier) {
                    handle_discovery_event(driver, clock, discovery, m).await;
                }
            }
            // Other event variants (Datagram, BulkStreamOpened, ...)
            // do not occur during discovery in practice; the
            // steady-state loop handles them once the flow reaches
            // `Ready`.
        }
    }
}

/// Drive the §16 connection flow to completion.
///
/// Returns `true` on `Ready`. On any failure the `EstablishmentFailed`
/// event has already been emitted and the return is `false`. The
/// caller should then emit `Disconnected` and stop.
///
/// # Scope
///
/// The NAT phase concludes from the live transport: `ConnectionDriver`
/// has already exchanged the §4 handshake and §16 Key Claims, which
/// proves direct connectivity, so declaring `on_nat_complete(true)` is
/// the truth, not a stub. The witness phase runs a real
/// [`WitnessDiscovery`](quip_net::discovery::WitnessDiscovery) against
/// the peer; a later milestone replaces the NAT phase with a real
/// `NatDriver`.
#[allow(clippy::too_many_arguments)]
async fn run_establishment(
    driver: &mut ConnectionDriver,
    local_claim: &KeyClaim,
    peer_claim: &KeyClaim,
    peer: NodeId,
    clock: &SharedClock,
    events_tx: &mpsc::Sender<NodeEvent>,
    discovery: &DiscoveryHandle,
) -> bool {
    let session_id = derive_session_id(&local_claim.node_id, &peer);
    let mut flow = ConnectionFlow::resume_from_key_claim(
        local_claim.clone(),
        peer_claim.clone(),
        session_id,
        FlowConfig::default(),
        clock.now(),
    );

    loop {
        let now = clock.now();

        // Check for phase timeouts before driving the phase. An
        // overdue phase fails here rather than being advanced.
        for action in flow.poll(now) {
            if let FlowAction::Failed(failure) = action {
                let _ = events_tx
                    .send(NodeEvent::EstablishmentFailed { peer, failure })
                    .await;
                return false;
            }
        }

        match flow.phase() {
            FlowPhase::NatTraversal => {
                // The transport is up; direct connectivity is proven.
                // A later milestone replaces this with a real
                // `NatDriver` waiting for
                // `NatEvent::DirectPathEstablished`.
                let _ = flow.on_nat_complete(true, now);
            }
            FlowPhase::WitnessDiscovery => {
                run_discovery_phase(driver, peer, clock, discovery, &mut flow)
                    .await;
            }
            FlowPhase::Ready(status) => {
                let kt_status = *status;
                let _ = events_tx
                    .send(NodeEvent::Ready { peer, kt_status })
                    .await;
                return true;
            }
            FlowPhase::Failed(failure) => {
                let failure = *failure;
                let _ = events_tx
                    .send(NodeEvent::EstablishmentFailed { peer, failure })
                    .await;
                return false;
            }
            FlowPhase::AwaitHandshake | FlowPhase::AwaitKeyClaim => {
                // `resume_from_key_claim` starts the flow at
                // `NatTraversal`, so reaching these phases here is a
                // bug, not a runtime condition. Emit a protocol error
                // and give up.
                let error = Error::Transport(
                    "establishment flow in a pre-NAT phase".into(),
                );
                let _ = events_tx
                    .send(NodeEvent::Error {
                        peer: Some(peer),
                        error,
                    })
                    .await;
                return false;
            }
        }
    }
}

/// Run the establishment flow, then hand off to the steady-state loop.
///
/// Shared by the accept loop and `Node::connect`.
#[allow(clippy::too_many_arguments)]
async fn peer_run<B>(
    mut driver: ConnectionDriver,
    peer: NodeId,
    store: Arc<Mutex<QuipStore<B>>>,
    clock: SharedClock,
    auto_serve_pins: bool,
    events_tx: mpsc::Sender<NodeEvent>,
    mut outbound_rx: mpsc::Receiver<Message>,
    dht: DhtHandle,
    discovery: DiscoveryHandle,
) where
    B: BlobStore + Send + Sync + 'static,
{
    // `drive_handshake` returns only after the §16 Key Claim exchange,
    // so both claims are populated. Clone them out before the flow
    // borrows anything; the driver then goes to the steady loop.
    let local_claim = driver.local_key_claim().clone();
    let peer_claim = match driver.peer_key_claim().cloned() {
        Some(c) => c,
        None => {
            // Unreachable in practice; guard defensively in case the
            // transport's guarantees change.
            let failure = FlowFailure::KeyClaimTimeout;
            let _ = events_tx
                .send(NodeEvent::EstablishmentFailed { peer, failure })
                .await;
            let _ = events_tx.send(NodeEvent::Disconnected { peer }).await;
            return;
        }
    };

    let ready = run_establishment(
        &mut driver,
        &local_claim,
        &peer_claim,
        peer,
        &clock,
        &events_tx,
        &discovery,
    )
    .await;

    if !ready {
        let _ = events_tx.send(NodeEvent::Disconnected { peer }).await;
        return;
    }

    run_peer_loop(
        &mut driver,
        peer,
        &store,
        &clock,
        auto_serve_pins,
        &events_tx,
        &mut outbound_rx,
        &dht,
        &discovery,
    )
    .await;
    let _ = events_tx.send(NodeEvent::Disconnected { peer }).await;
}

#[allow(clippy::too_many_arguments)]
async fn run_peer_loop<B>(
    driver: &mut ConnectionDriver,
    peer: NodeId,
    store: &Mutex<QuipStore<B>>,
    clock: &SharedClock,
    auto_serve_pins: bool,
    events_tx: &mpsc::Sender<NodeEvent>,
    outbound_rx: &mut mpsc::Receiver<Message>,
    dht: &DhtHandle,
    discovery: &DiscoveryHandle,
) where
    B: BlobStore + Send + Sync + 'static,
{
    loop {
        // Non-blocking drain of the outbound queue.
        loop {
            match outbound_rx.try_recv() {
                Ok(msg) => {
                    let now = clock.now();
                    if let Err(e) = driver.send(&msg, now).await {
                        let _ = events_tx
                            .send(NodeEvent::Error {
                                peer: Some(peer),
                                error: e,
                            })
                            .await;
                    }
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => return,
            }
        }

        // Poll inbound; `driver.poll` blocks up to POLL_TIMEOUT_MS
        // internally, which yields this task to the runtime on every
        // iteration.
        let now = clock.now();
        let events = match driver.poll(now).await {
            Ok(events) => events,
            Err(e) => {
                let _ = events_tx
                    .send(NodeEvent::Error {
                        peer: Some(peer),
                        error: e,
                    })
                    .await;
                return;
            }
        };

        for e in events {
            let node_event = match e {
                Event::Frame { tier, msg, .. } => {
                    match message::dispatch(&msg.raw, tier) {
                        Ok(m) => {
                            // §12 NAT verbs route into the DHT client
                            // and never surface as a `Message` event.
                            // `dht_result_from` verifies the signature
                            // and the claimed NodeId before returning
                            // a result.
                            if let Some(result) = dht::dht_result_from(&m, &peer) {
                                dht.note_peer(peer, None, now);
                                dht.enqueue(result);
                                continue;
                            }
                            // §13 Coral verbs route into the shared
                            // discovery handle: as a client, ingest
                            // responses; as a server, answer the
                            // peer's own lookups.
                            if is_coral_verb(&m) {
                                handle_discovery_event(
                                    driver,
                                    clock,
                                    discovery,
                                    m,
                                )
                                .await;
                                continue;
                            }
                            // Auto-serve eligible verbs from the store.
                            if auto_serve_pins {
                                if let Some(reply) =
                                    try_auto_serve_pins(store, &m, now).await
                                {
                                    if let Some(reply) = reply {
                                        if let Err(e) =
                                            driver.send(&reply, now).await
                                        {
                                            let _ = events_tx
                                                .send(NodeEvent::Error {
                                                    peer: Some(peer),
                                                    error: e,
                                                })
                                                .await;
                                        }
                                    }
                                    continue;
                                }
                            }
                            NodeEvent::Message { peer, tier, msg: m }
                        }
                        Err(err) => NodeEvent::Error {
                            peer: Some(peer),
                            error: err,
                        },
                    }
                }
                Event::Datagram { msg } => {
                    match message::dispatch(&msg.raw, Tier::Event) {
                        Ok(m) => NodeEvent::Datagram { peer, msg: m },
                        Err(err) => NodeEvent::Error {
                            peer: Some(peer),
                            error: err,
                        },
                    }
                }
                // Bulk streams are not surfaced by the first cut; a
                // future iteration will hand them to a `BulkReceiver`.
                Event::BulkStreamOpened { .. }
                | Event::ControlConnected { .. } => continue,
                Event::Error { error, .. } => NodeEvent::Error {
                    peer: Some(peer),
                    error,
                },
            };
            if events_tx.send(node_event).await.is_err() {
                return;
            }
        }
    }
}

/// Apply an auto-served verb to the store.
///
/// Returns:
/// - `None` if `msg` is not auto-served; the caller emits it as an
///   event.
/// - `Some(None)` if `msg` was served and no reply is needed.
/// - `Some(Some(reply))` if `msg` was served and `reply` should be
///   sent back on the same tier.
///
/// The current auto-served set is `pin`, `unpin`, `query_pins`.
/// Governance verbs (`register_tcid`, `delegation`,
/// `derivative_link`) are deliberately excluded: they carry signatures
/// the peer task cannot verify, so the application handles them.
async fn try_auto_serve_pins<B>(
    store: &Mutex<QuipStore<B>>,
    msg: &Message,
    now: Timestamp,
) -> Option<Option<Message>>
where
    B: BlobStore + Send + Sync + 'static,
{
    let reply = match msg {
        Message::Pin(p) => {
            if let Some(cid) = p.cid.as_ref() {
                let mut s = store.lock().await;
                let _ = s.pin(&p.resource_id, cid, p.ttl_seconds, now);
            }
            None
        }
        Message::Unpin(u) => {
            let mut s = store.lock().await;
            let _ = s.unpin(&u.resource_id, u.cid.as_ref());
            None
        }
        Message::QueryPins(q) => {
            let s = store.lock().await;
            let pins =
                s.query_pins(q.resource_id.as_deref(), q.cid.as_ref(), now);
            Some(Message::PinList(quip_net::sync::PinList { pins }))
        }
        _ => return None,
    };
    Some(reply)
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
    use quip_core::address::Address;
    use quip_core::cid::Cid;
    use quip_core::dvv::Dvv;
    use quip_core::time::ManualClock;
    use quip_net::crypto::{Ed25519Signer, Sha256Hasher};
    use quip_net::nat_driver::DhtClient;
    use quip_net::nat_wire::{ConnectivityAnnounce, NAT_TYPE_OPEN};
    use quip_net::sync::{GetRequest, QueryPins};
    use quip_storage::CidTagging;

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

    /// Wait for `node` to emit a `Connected` event for `expected`, up
    /// to `timeout_ms`.
    async fn wait_for_connected(
        node: &mut Node,
        expected: NodeId,
        timeout_ms: u64,
    ) -> bool {
        let deadline =
            std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if let Ok(events) = node.poll().await {
                for e in events {
                    if let NodeEvent::Connected { peer } = e {
                        if peer == expected {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Wait for `node` to emit a `Ready` event for `expected` and
    /// return the KT status.
    async fn wait_for_ready(
        node: &mut Node,
        expected: NodeId,
        timeout_ms: u64,
    ) -> Option<KtStatus> {
        let deadline =
            std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if let Ok(events) = node.poll().await {
                for e in events {
                    if let NodeEvent::Ready { peer, kt_status } = e {
                        if peer == expected {
                            return Some(kt_status);
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
        let deadline =
            std::time::Instant::now() + Duration::from_millis(timeout_ms);
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
    fn signed_connectivity(
        seed_byte: u8,
        now: Timestamp,
    ) -> ConnectivityAnnounce {
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

        assert!(
            wait_for_connected(&mut b, a_node_id, 5_000).await,
            "B should see the inbound connection from A"
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
        let a_status = wait_for_ready(&mut a, b_node_id, 10_000)
            .await
            .expect("A should reach Ready");
        assert_eq!(a_status, KtStatus::Pending);
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
            wait_for_connected(&mut b, a_node_id, 5_000).await,
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

        let deadline =
            std::time::Instant::now() + Duration::from_millis(5_000);
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
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await);
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
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await);
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
        let deadline =
            std::time::Instant::now() + Duration::from_millis(5_000);
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
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await);
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        let announce = signed_connectivity(1, a.now());
        let mut a_dht = a.dht();
        a_dht.publish_connectivity(announce.clone());

        let mut b_dht = b.dht();
        let deadline =
            std::time::Instant::now() + Duration::from_millis(5_000);
        let mut received: Option<ConnectivityAnnounce> = None;
        while std::time::Instant::now() < deadline && received.is_none() {
            if let Some(quip_net::nat_driver::DhtResult::Connectivity(got)) =
                b_dht.poll()
            {
                received = Some(got);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let received =
            received.expect("B did not receive the connectivity_announce");
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
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await);
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
        h1.note_peer(peer, None, a.now());
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
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await);
        let _ = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let _ = wait_for_ready(&mut b, a_node_id, 10_000).await;

        // A publishes an announcement signed by A but attributed to B.
        // The peer-loop check rejects it on the attribution.
        let mut announce = signed_connectivity(1, a.now());
        announce.node_id = b_node_id;
        let mut a_dht = a.dht();
        a_dht.publish_connectivity(announce);

        let mut b_dht = b.dht();
        let deadline =
            std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            assert!(b_dht.poll().is_none(), "forged announce leaked");
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

        let a_status = wait_for_ready(&mut a, b_node_id, 10_000).await;
        let b_status = wait_for_ready(&mut b, a_node_id, 10_000).await;
        assert_eq!(a_status, Some(KtStatus::Pending));
        assert_eq!(b_status, Some(KtStatus::Pending));
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
}