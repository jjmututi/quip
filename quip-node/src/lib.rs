//! A running QUIP node.
//!
//! [`Node`] binds a QUIC endpoint, accepts inbound connections, dials
//! outbound ones, and surfaces a single event stream keyed by peer
//! NodeId. It owns a [`QuipStore`] and uses it to auto-serve the
//! storage-plane verbs that have a 1:1 wire mapping, and a
//! [`LiveDht`](dht::LiveDht) that carries §12 NAT-plane verbs over the
//! same connections.
//!
//! # Scope
//!
//! This is the fourth cut. It does:
//!
//! - Bind a server endpoint with a self-signed cert (rcgen).
//! - Accept inbound connections; drive the §4/§16 handshake to
//!   completion in a background task.
//! - Dial outbound connections; drive the handshake inline.
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
//! - Own a `LiveDht` implementing `DhtClient`. §12 NAT verbs sent and
//!   received through the node's peer connections are routed through
//!   it; publishes broadcast to all connected peers.
//!
//! It does not (yet):
//!
//! - Run a
//!   [`ConnectionFlow`](quip_net::establishment::ConnectionFlow)
//!   per peer, and therefore emits no `Ready` event. The flow, the
//!   live witness-discovery path, and `NodeEvent::Ready` /
//!   `NodeEvent::EstablishmentFailed` land in M9.4b.
//! - Route DHT lookups. `DhtClient::lookup_*` are no-ops; §12 has no
//!   lookup verb and a real lookup is a Coral `coral_lookup`, which is
//!   M9.5.
//! - Run cluster merge/split. The DHT's routing table records observed
//!   `ClusterInfo` but nothing consumes it.
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
//! A peer goes straight from the §4 handshake and §16 Key Claim
//! exchange — both performed inline by `ConnectionDriver` — into
//! steady-state operation. There is no `ConnectionFlow` at the node
//! layer yet; M9.4b introduces it on top of the DHT client.
//!
//! # DHT routing
//!
//! §12 NAT verbs (`connectivity_announce`, `candidate_announce`,
//! `relay_discovery`, `relay_response`) arriving on T0 are verified,
//! matched against the sending peer, and enqueued into the node's
//! [`LiveDht`](dht::LiveDht). Outgoing publishes are broadcast to every
//! connected peer. There is no separate DHT peer set and no
//! XOR-distance routing yet; M9.5 replaces the broadcast.
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
//!
//! # async fn example() -> quip_net::Result<()> {
//! let signer = Ed25519Signer::from_seed(&[0x42; 32]);
//! let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
//! let now = SystemClock.now();
//! let config = NodeConfig::new(bind, &signer, now)?;
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

use quip_core::cid::{CidOrV1, HashAlgo};
use quip_core::dvv::NodeId;
use quip_core::messages::{KeyClaim, PinEntry, Signer};
use quip_core::time::{Clock, SystemClock, Timestamp};
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

/// Capacity of the node's event channel.
const EVENT_CHANNEL_CAPACITY: usize = 128;

/// Capacity of each peer's outbound queue.
const OUTBOUND_CAPACITY: usize = 64;

/// How long [`Node::poll`] waits for a first event before returning.
const POLL_TIMEOUT_MS: u64 = 50;

/// A time source that can be moved across threads and shared.
///
/// `quip_core::time::Clock` does not itself require `Send + Sync`,
/// because the trait is also used in single-threaded contexts. The
/// node moves clocks into `tokio::spawn`ed tasks, so it needs the
/// stronger bound. Every implementation in the workspace
/// (`SystemClock`, `ManualClock`) satisfies it already.
type SharedClock = Arc<dyn Clock + Send + Sync + 'static>;

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
    /// Our self-signed identity claim.
    pub key_claim: KeyClaim,
    /// When true (default), the node auto-handles inbound `pin`,
    /// `unpin`, and `query_pins` from its store. When false, those
    /// messages surface as [`NodeEvent::Message`] and the application
    /// is responsible for handling them.
    pub auto_serve_pins: bool,
    /// Time source used by peer tasks. Defaults to [`SystemClock`];
    /// tests inject a [`ManualClock`](quip_core::time::ManualClock).
    pub clock: SharedClock,
}

impl core::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("bind", &self.bind)
            .field("capabilities", &self.capabilities)
            .field("key_claim", &self.key_claim)
            .field("auto_serve_pins", &self.auto_serve_pins)
            .field("clock", &"<dyn Clock>")
            .finish()
    }
}

impl NodeConfig {
    /// Build a config with baseline capabilities plus NAT traversal and
    /// DHT discovery, a claim derived from `signer`, auto-serving
    /// enabled, and the system clock.
    ///
    /// `NAT_TRAVERSAL` is what allows a peer to send and receive §12
    /// verbs; without it the transport's capability gate rejects them.
    /// `DHT_DISCOVERY` is what allows the Coral verbs of §13. Neither
    /// is in the baseline set (which is transport-level), so both are
    /// added explicitly here.
    pub fn new(
        bind: SocketAddr,
        signer: &impl Signer,
        now: Timestamp,
    ) -> Result<Self> {
        Ok(Self {
            bind,
            capabilities: Capabilities::baseline()
                | Capabilities(Capabilities::NAT_TRAVERSAL)
                | Capabilities(Capabilities::DHT_DISCOVERY),
            key_claim: make_key_claim(signer, now)?,
            auto_serve_pins: true,
            clock: Arc::new(SystemClock),
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
    /// The peer is reachable from `send_to` at this point. M9.4b will
    /// add a `Ready` event that marks the end of §16 establishment.
    Connected {
        /// The peer's NodeId, as claimed. The application is
        /// responsible for verifying the claim's signature and
        /// applying its own TOFU / rotation policy.
        peer: NodeId,
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

        let accept_endpoint = Arc::clone(&endpoint);
        let accept_peers = Arc::clone(&peers);
        let accept_tasks = Arc::clone(&peer_tasks);
        let accept_store = Arc::clone(&store);
        let accept_clock = Arc::clone(&clock);
        let accept_tx = events_tx.clone();
        let accept_dht = dht.clone();
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
    /// handshake completes. M9.4b will add a `Ready` event that fires
    /// later, after the §16 connection flow completes.
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
        self.dht.note_peer(peer, Some(addr), clock.now()).await;
        let _ = self.events_tx.send(NodeEvent::Connected { peer }).await;

        let events_tx = self.events_tx.clone();
        let peers = Arc::clone(&self.peers);
        let peer_tasks = Arc::clone(&self.peer_tasks);
        let store = Arc::clone(&self.store);
        let auto_serve = self.auto_serve_pins;
        let dht = self.dht.clone();
        let handle = tokio::spawn(async move {
            // The client endpoint must outlive the connection, so it
            // is moved into the peer task and dropped when the loop
            // exits.
            let _keep_endpoint = client_endpoint;
            peer_steady_loop(
                driver, peer, store, clock, auto_serve, events_tx, out_rx, dht,
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


    /// Lock and access the node's DHT client.
    ///
    /// Applications can use this to inspect the routing table or drive
    /// the DHT directly; the M9.4b flow drives it automatically and
    /// does not require the application to reach in.
    pub async fn dht(&self) -> MutexGuard<'_, dht::LiveDht> {
        self.dht.lock().await
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
/// M9.5 replaces this with XOR-distance routing over a real DHT peer
/// set. For now the network is small enough that broadcast is correct
/// and cheap.
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
            dht.note_peer(peer, None, clock.now()).await;
            let _ = events_tx.send(NodeEvent::Connected { peer }).await;

            peer_steady_loop(
                driver,
                peer,
                store,
                clock,
                auto_serve_pins,
                events_tx,
                out_rx,
                dht.clone(),
            )
            .await;
            peers.lock().await.remove(&peer);
            peer_tasks.lock().await.remove(&peer);
            dht.forget_peer(&peer).await;
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

/// Steady-state loop for one established peer.
#[allow(clippy::too_many_arguments)]
async fn peer_steady_loop<B>(
    mut driver: ConnectionDriver,
    peer: NodeId,
    store: Arc<Mutex<QuipStore<B>>>,
    clock: SharedClock,
    auto_serve_pins: bool,
    events_tx: mpsc::Sender<NodeEvent>,
    mut outbound_rx: mpsc::Receiver<Message>,
    dht: DhtHandle,
) where
    B: BlobStore + Send + Sync + 'static,
{
    run_peer_loop(
        &mut driver,
        peer,
        &store,
        &clock,
        auto_serve_pins,
        &events_tx,
        &mut outbound_rx,
        &dht,
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
                                dht.note_peer(peer, None, now).await;
                                dht.enqueue(result);
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
        let config = NodeConfig::new(addr_zero(), &signer, clock.now())
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

    /// A `connectivity_announce` published on A is delivered to B's
    /// DHT client, signature and all, without surfacing as a
    /// `NodeEvent::Message`.
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

        let announce = signed_connectivity(1, a.now());
        a.dht().await.publish_connectivity(announce.clone());

        // B's DHT client should receive the announcement.
        let deadline =
            std::time::Instant::now() + Duration::from_millis(5_000);
        let mut received: Option<ConnectivityAnnounce> = None;
        while std::time::Instant::now() < deadline && received.is_none() {
            if let Some(DhtResult::Connectivity(got)) = b.dht().await.poll() {
                received = Some(got);
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let received =
            received.expect("B did not receive the connectivity_announce");
        assert_eq!(received.node_id, a_node_id);
        assert_eq!(received.signature, announce.signature);
    }

    /// The DHT routing table records directly-connected peers.
    #[tokio::test]
    async fn dht_routing_table_lists_peers() {
        let (mut a, _) = make_node_with_clock(1).await;
        let (mut b, _) = make_node_with_clock(2).await;

        let b_addr = b.local_addr().unwrap();
        let a_node_id = a.local_node_id();
        let b_node_id = b.local_node_id();

        // Before connecting, the tables are empty.
        assert!(a.dht().await.table().is_empty());
        assert!(b.dht().await.table().is_empty());

        let _ = a.connect(b_addr, "localhost").await.unwrap();
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await);

        // A recorded B on the outbound side, B recorded A on the
        // accept side.
        assert!(a.dht().await.table().contains_key(&b_node_id));
        assert!(b.dht().await.table().contains_key(&a_node_id));
    }

    /// A fresh node's DHT client returns `None` from `poll` and does
    /// not panic when publishing with no peers.
    #[tokio::test]
    async fn dht_publish_with_no_peers_is_a_noop() {
        let a = make_node(1).await;
        let announce = signed_connectivity(1, a.now());
        a.dht().await.publish_connectivity(announce);
        assert!(a.dht().await.poll().is_none());
        assert!(a.dht().await.table().is_empty());
    }

    /// A forged `connectivity_announce` (wrong attribution) is dropped
    /// by `dht_result_from` and never reaches the DHT client.
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

        // A publishes an announcement signed by A but attributed to B.
        // The signature is valid for A's NodeId but the message claims
        // B's; the peer-loop check rejects it on the attribution.
        let mut announce = signed_connectivity(1, a.now());
        announce.node_id = b_node_id;
        a.dht().await.publish_connectivity(announce);

        // Give B a moment; nothing should arrive.
        let deadline =
            std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            assert!(b.dht().await.poll().is_none(), "forged announce leaked");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}