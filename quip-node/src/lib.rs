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
//! This is the tenth cut. It does:
//!
//! - Bind a server endpoint with a self-signed cert (rcgen).
//! - Accept inbound connections; drive the §4/§16 handshake to
//!   completion in a background task.
//! - Dial outbound connections; drive the handshake inline.
//! - Run a [`ConnectionFlow`] per peer, sequencing §16 establishment
//!   from the point the transport's inline handshake leaves off.
//! - Drive a per-peer [`NatDriver`] during the flow's NAT phase, so
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
//! - Read the wall clock through a [`Clock`], so tests can inject a
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
//!
//! It does not (yet):
//!
//! - Exchange candidates over the DHT during the NAT phase. The
//!   `DhtHandle`'s `lookup_candidates` is a no-op; the driver is
//!   seeded with the address the transport already uses.
//! - Dial candidate addresses. The NAT driver reports the transport's
//!   current address as the successful probe; a follow-up commit
//!   replaces that report with a fresh client endpoint per candidate.
//! - Sign and send `relay_discovery` on T0. The state machine emits
//!   `RelayDiscoveryRequested`, but the node's signer is not threaded
//!   down to the peer task yet.
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
//! # NAT phase (M9.5b-c part 3)
//!
//! The §16 NAT phase is driven by a per-peer [`NatDriver`]. The peer
//! task seeds the driver with the peer's current transport address,
//! reports a successful probe for it — the live QUIC connection is
//! proof the address is reachable — and reads the terminal
//! `NatEvent` the driver produces: `DirectPathEstablished`,
//! `RelayedPathEstablished`, or `SessionFailed`. The first two
//! conclude the phase with `PeerLifecycle::NatDirect` and
//! `PeerLifecycle::NatRelayed` respectively; the third fails
//! establishment.
//!
//! Candidate exchange over the DHT, real dialing of candidate
//! addresses, and signing `relay_discovery` on T0 are not yet
//! implemented. The driver pipeline they will feed is already the one
//! above; only the evidence source changes when they land.
//!
//! # Establishment
//!
//! After the §4 handshake and §16 Key Claim exchange — both performed
//! inline by `ConnectionDriver` — each peer task runs a
//! [`ConnectionFlow`] resumed at `NatTraversal` via
//! [`ConnectionFlow::resume_from_key_claim`]. The NAT phase runs
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
//! must not block forever on it. The NAT-phase loop uses the same
//! wall-clock discipline.
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

pub mod dht;
pub mod discovery;
pub mod peer;
pub mod trust;

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
use quip_net::nat::{NatConfig, NatEvent as DriverNatEvent};
use quip_net::nat_driver::NatDriver;
use quip_net::nat_wire::{Candidate, CandidateAnnounce, CANDIDATE_HOST};
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
// M9.5b-b: peer-slot and lifecycle vocabulary.
// M9.5b-c: `PeerLifecycle::is_routing_eligible` is the sole routing-
// eligibility predicate.
pub use peer::{PeerLifecycle, PeerSlot};
// M10.3: the trust policy and the trust level that peer events carry.
use trust::{PeerTrust, TrustPolicy};

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

/// Wall-clock bound on the NAT phase.
///
/// The flow's own NAT timeout is [`FlowConfig::nat_timeout_ms`]
/// (30 s by default); this bounds the driver loop independently so a
/// driver that never produces a terminal event cannot spin forever.
const NAT_PHASE_TIMEOUT_MS: u64 = 30_000;

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

// M10.3: shared handle around the trust policy, same shape as the
// store and the DHT handle.
type SharedTrust = Arc<Mutex<TrustPolicy>>;

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
///
/// Events are generation-scoped internally: a task whose slot has been
/// superseded by a newer connection for the same `NodeId` is aborted
/// before it can emit, so the application never observes two live
/// generations for one peer. `NodeEvent` does not carry the
/// [`PeerSlot`] on the wire; applications that need the current
/// generation for a peer can call [`Node::peer_slot`].
#[derive(Debug)]
pub enum NodeEvent {
    /// A peer completed the §4 handshake and §16 Key Claim exchange.
    ///
    /// The peer is reachable from `send_to` at this point; the
    /// establishment flow still has to run before T2/T3 traffic is
    /// appropriate. That completion is signalled by
    /// [`NodeEvent::Ready`].
    ///
    /// `trust` is the policy's view of the peer's Key Claim at the
    /// moment the event fired. A first-seen peer is
    /// [`PeerTrust::Unknown`]; the application is expected to call
    /// [`Node::trust_peer`] to accept or deny it.
    Connected {
        /// The peer's NodeId, as claimed.
        peer: NodeId,
        /// The policy's current trust level for the peer.
        trust: PeerTrust,
    },
    /// The establishment flow reached `Ready`.
    ///
    /// `kt_status` is the trust level the flow computed from the
    /// witness discovery. `trust` is the combined policy + flow view
    /// of the peer.
    Ready {
        /// The peer.
        peer: NodeId,
        /// KT status at the moment the flow completed.
        kt_status: KtStatus,
        /// The policy's current trust level for the peer.
        trust: PeerTrust,
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
        /// The policy's current trust level for the peer.
        trust: PeerTrust,
    },
    /// A peer disconnected.
    Disconnected {
        /// The peer's NodeId.
        peer: NodeId,
        /// The policy's current trust level for the peer at the
        /// moment of disconnection. The store retains this value, so
        /// a reconnect sees the same trust.
        trust: PeerTrust,
    },
    /// The peer's trust level changed.
    ///
    /// Fires when the application calls [`Node::trust_peer`], when a
    /// claim mismatch demotes a peer to `Untrusted`, or when the flow
    /// promotes a `Trusted` peer to `Verified`.
    PeerTrustChanged {
        /// The peer.
        peer: NodeId,
        /// The new trust level.
        trust: PeerTrust,
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
// Peer registry
// -------------------------------------------------------------------------

/// A registered peer connection.
struct PeerHandle {
    /// The current connection generation for this peer.
    slot: PeerSlot,
    /// Outbound queue for the peer task driving this generation.
    outbound: mpsc::Sender<Message>,
    /// Connection lifecycle for this generation.
    ///
    /// The peer task is the single writer; every transition flows
    /// through `set_peer_lifecycle`, which validates the edge
    /// against §2a via [`PeerLifecycle::transition_to`]. A new slot
    /// starts at `Established`, because a [`PeerSlot`] is allocated
    /// only after the §4 handshake completes — the peer's `NodeId`
    /// is not known before then — so `Connecting` is not observable
    /// at the slot level.
    lifecycle: PeerLifecycle,
}

/// Per-node registry of active peer handles and generation counters.
///
/// The two maps live behind one lock so that "allocate a new slot,
/// replace the handle" is a single atomic step with respect to any
/// other `register` call for the same `NodeId`. This is what makes a
/// concurrent reconnect deterministic: whoever takes the lock second
/// wins, and the first task's slot is no longer current.
///
/// The generation counter is **persistent**. It is never reset when a
/// peer disconnects, because resetting would allow a slot value to be
/// reused and break the "stale slot cannot match" invariant.
struct Registry {
    /// Active peer handles, keyed by logical NodeId.
    peers: BTreeMap<NodeId, PeerHandle>,
    /// Persistent per-NodeId generation counter. Incremented every
    /// time a new `PeerSlot` is allocated for the NodeId. Never
    /// reset, so a slot value is never reused within a `Node`'s
    /// lifetime.
    generations: BTreeMap<NodeId, u64>,
}

impl Registry {
    fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            generations: BTreeMap::new(),
        }
    }

    /// Allocate a fresh slot for `peer`, replace any existing handle,
    /// and return the new slot plus the previous handle if any.
    ///
    /// The new handle starts in [`PeerLifecycle::Established`]: a
    /// [`PeerSlot`] is allocated only after the §4 handshake has
    /// completed, so `Connecting` is not observable at the slot
    /// level.
    ///
    /// The generation counter uses `wrapping_add`: reaching
    /// `u64::MAX` connections for a single peer would require a
    /// connection rate no deployed node will ever see, and a panic
    /// in the accept loop is worse than an astronomically unlikely
    /// reuse.
    fn register(
        &mut self,
        peer: NodeId,
        outbound: mpsc::Sender<Message>,
    ) -> (PeerSlot, Option<PeerHandle>) {
        let counter = self.generations.entry(peer).or_insert(0);
        *counter = counter.wrapping_add(1);
        let slot = PeerSlot::new(peer, *counter);
        let old = self.peers.insert(
            peer,
            PeerHandle {
                slot,
                outbound,
                lifecycle: PeerLifecycle::Established,
            },
        );
        (slot, old)
    }

    /// True if `slot` is the currently-registered slot for its peer.
    fn is_current(&self, slot: &PeerSlot) -> bool {
        self.peers
            .get(&slot.node_id)
            .map(|h| h.slot == *slot)
            .unwrap_or(false)
    }

    /// Apply a lifecycle transition for `slot` if it is still current.
    ///
    /// The edge is validated against §2a via
    /// [`PeerLifecycle::transition_to`]. A rejected edge is a caller
    /// bug and leaves the state unchanged; a stale slot is a silent
    /// no-op. Returns `true` if the transition was applied.
    fn set_lifecycle(&mut self, slot: &PeerSlot, to: PeerLifecycle) -> bool {
        if let Some(h) = self.peers.get_mut(&slot.node_id) {
            if h.slot == *slot && h.lifecycle.transition_to(to).is_ok() {
                h.lifecycle = to;
                return true;
            }
        }
        false
    }

    /// Slots of peers that are currently routing-eligible.
    ///
    /// §3 of `docs/M9.5b-design.md`: physical connection existence and
    /// routing eligibility are distinct. The predicate is
    /// [`PeerLifecycle::is_routing_eligible`].
    fn routing_eligible_slots(&self) -> Vec<PeerSlot> {
        self.peers
            .values()
            .filter(|h| h.lifecycle.is_routing_eligible())
            .map(|h| h.slot)
            .collect()
    }

    /// Remove the entry for `slot` if it is current; return whether
    /// anything was removed.
    fn remove_if_current(&mut self, slot: &PeerSlot) -> bool {
        if self.is_current(slot) {
            self.peers.remove(&slot.node_id);
            true
        } else {
            false
        }
    }

    /// Clone the outbound sender for `peer`, if it is registered.
    fn outbound_of(&self, peer: &NodeId) -> Option<mpsc::Sender<Message>> {
        self.peers.get(peer).map(|h| h.outbound.clone())
    }
}

/// Shared registry behind the same lock the node's `peers` handle
/// uses.
type PeerRegistry = Arc<Mutex<Registry>>;

/// Peer tasks keyed by logical NodeId. The slot is stored alongside
/// the handle so a task's cleanup path can verify that the entry it
/// sees is its own before removing it.
type TaskMap = Arc<Mutex<BTreeMap<NodeId, (PeerSlot, JoinHandle<()>)>>>;

/// Allocate a slot for a new connection and abort any previous task
/// for the same `NodeId`.
///
/// Returns the new slot. The caller must insert the returned
/// `JoinHandle` into the task map once it has spawned its task.
async fn register_peer(
    peers: &PeerRegistry,
    peer_tasks: &TaskMap,
    peer: NodeId,
    outbound: mpsc::Sender<Message>,
) -> PeerSlot {
    let slot = {
        let mut reg = peers.lock().await;
        let (slot, _old) = reg.register(peer, outbound);
        slot
    };
    // Abort the previous task if there is one. We take the entry
    // out of the map first so that a subsequent insert by the caller
    // replaces it deterministically.
    if let Some((_old_slot, old_task)) = peer_tasks.lock().await.remove(&peer) {
        old_task.abort();
    }
    slot
}

/// Remove a peer task's registry entries on exit.
///
/// The peer handle and the task-map entry are both removed only if
/// `slot` is still the current generation for its peer. A stale task
/// — whose slot was superseded by a newer connection before it
/// finished — leaves the newer task's state alone.
async fn unregister_peer(
    peers: &PeerRegistry,
    peer_tasks: &TaskMap,
    peer: &NodeId,
    slot: &PeerSlot,
) {
    let removed = {
        let mut reg = peers.lock().await;
        reg.remove_if_current(slot)
    };
    if removed {
        let mut tasks = peer_tasks.lock().await;
        let is_ours = tasks
            .get(peer)
            .map(|(s, _)| s == slot)
            .unwrap_or(false);
        if is_ours {
            tasks.remove(peer);
        }
    }
}

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
async fn set_peer_lifecycle(
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
    /// candidate announces, relay discoveries — carry real signatures.
    /// The application holds its own signer; this field exists so the
    /// node can hand a clone to each spawned task.
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
    /// The node's shared Coral discovery client.
    discovery: DiscoveryHandle,
    /// The node's trust policy. Shared with every peer task and with
    /// the application through [`Node::trust_peer`].
    trust: SharedTrust,
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
        let peers: PeerRegistry = Arc::new(Mutex::new(Registry::new()));
        let peer_tasks: TaskMap = Arc::new(Mutex::new(BTreeMap::new()));
        let store = Arc::new(Mutex::new(store));
        let clock = Arc::clone(&config.clock);
        let signer = Arc::clone(&config.signer);
        // M10.3: initialize the trust policy.
        let trust: SharedTrust = Arc::new(Mutex::new(TrustPolicy::new()));

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
        let accept_trust = Arc::clone(&trust);
        let accept_signer = Arc::clone(&signer);
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
                accept_trust,
                accept_signer,
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
            clock,
            events_rx: Some(events_rx),
            events_tx,
            accept_task: Some(accept_task),
            dht,
            dht_task: Some(dht_task),
            discovery,
            trust,
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
        let slot =
            register_peer(&self.peers, &self.peer_tasks, peer, out_tx).await;
        self.dht.note_peer(peer, slot, Some(addr), clock.now());

        // M10.3: record the peer's claim before emitting Connected.
        // A first-seen peer lands as `Unknown`; a reconnect to a peer
        // already in the store reports its stored trust.
        let peer_claim = match driver.peer_key_claim().cloned() {
            Some(c) => c,
            None => {
                unregister_peer(&self.peers, &self.peer_tasks, &peer, &slot)
                    .await;
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
        let dht = self.dht.clone();
        let discovery = self.discovery.clone();
        let trust = Arc::clone(&self.trust);
        let task_peers = Arc::clone(&peers);
        let signer = Arc::clone(&self.signer);
        let handle = tokio::spawn(async move {
            // The client endpoint must outlive the connection, so it
            // is moved into the peer task and dropped when the loop
            // exits.
            let _keep_endpoint = client_endpoint;
            peer_run(
                driver,
                peer,
                slot,
                store,
                clock,
                auto_serve,
                events_tx,
                out_rx,
                dht.clone(),
                discovery,
                trust,
                task_peers,
                signer,
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
        match tokio::time::timeout(
            Duration::from_millis(POLL_TIMEOUT_MS),
            rx.recv(),
        )
        .await
        {
            Ok(Some(e)) => events.push(e),
            Ok(None) => {
                return Err(Error::Transport("event channel closed".into()))
            }
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
            reg.outbound_of(peer).ok_or_else(|| {
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
        self.peers.lock().await.peers.keys().copied().collect()
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
        self.peers.lock().await.peers.get(peer).map(|h| h.slot)
    }

    /// The current lifecycle state for `peer`, if it is connected.
    ///
    /// Read-only. The peer task is the single writer.
    pub async fn peer_lifecycle(&self, peer: &NodeId) -> Option<PeerLifecycle> {
        self.peers
            .lock()
            .await
            .peers
            .get(peer)
            .map(|h| h.lifecycle)
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
    pub async fn trust_peer(
        &self,
        peer: &NodeId,
        decision: PeerTrust,
    ) -> bool {
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
    pub async fn trust_snapshot(
        &self,
    ) -> Vec<(NodeId, trust::StoredClaim)> {
        self.trust.lock().await.snapshot()
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
            while let Some((_, (_, handle))) = tasks.pop_first() {
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
    mut rx: mpsc::UnboundedReceiver<dht::Outbound>,
    peers: PeerRegistry,
) {
    while let Some(out) = rx.recv().await {
        let senders: Vec<mpsc::Sender<Message>> = {
            let reg = peers.lock().await;
            match out.target {
                Some(peer) => reg
                    .outbound_of(&peer)
                    .into_iter()
                    .collect(),
                None => reg.peers.values().map(|h| h.outbound.clone()).collect(),
            }
        };
        for tx in senders {
            let _ = tx.send(out.msg.clone()).await;
        }
    }
}

/// Accept inbound connections, drive each handshake, spawn a peer loop.
#[allow(clippy::too_many_arguments)]
async fn accept_loop<B>(
    endpoint: Arc<Endpoint>,
    peers: PeerRegistry,
    peer_tasks: TaskMap,
    store: Arc<Mutex<QuipStore<B>>>,
    clock: SharedClock,
    auto_serve_pins: bool,
    events_tx: mpsc::Sender<NodeEvent>,
    dht: DhtHandle,
    discovery: DiscoveryHandle,
    trust: SharedTrust,
    signer: SharedSigner,
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
        let trust = Arc::clone(&trust);
        let signer = Arc::clone(&signer);

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
            let slot =
                register_peer(&peers, &peer_tasks, peer, out_tx).await;
            dht.note_peer(peer, slot, None, clock.now());

            // M10.3: same as Node::connect — record the claim, then
            // emit Connected with the resulting trust.
            let peer_claim = match driver.peer_key_claim().cloned() {
                Some(c) => c,
                None => {
                    let _ = events_tx
                        .send(NodeEvent::Error {
                            peer: Some(peer),
                            error: Error::Transport(
                                "peer claim missing after handshake".into(),
                            ),
                        })
                        .await;
                    unregister_peer(&peers, &peer_tasks, &peer, &slot).await;
                    dht.forget_peer(&peer, &slot);
                    return;
                }
            };
            let trust_level = {
                let mut policy = trust.lock().await;
                policy.observe_claim(peer_claim, clock.now())
            };
            let _ = events_tx
                .send(NodeEvent::Connected {
                    peer,
                    trust: trust_level,
                })
                .await;

            let task_peers = Arc::clone(&peers);
            peer_run(
                driver,
                peer,
                slot,
                store,
                clock,
                auto_serve_pins,
                events_tx,
                out_rx,
                dht.clone(),
                discovery,
                trust,
                task_peers,
                signer,
            )
            .await;
            unregister_peer(&peers, &peer_tasks, &peer, &slot).await;
            dht.forget_peer(&peer, &slot);
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

/// Read the policy's trust level for `peer`, without holding the lock
/// across the caller's subsequent await.
async fn current_trust(trust: &SharedTrust, peer: &NodeId) -> PeerTrust {
    trust.lock().await.trust_of(peer)
}

// -------------------------------------------------------------------------
// NAT phase (M9.5b-c part 3)
// -------------------------------------------------------------------------

/// The terminal outcome of the §16 NAT phase.
///
/// Mirrors the three success-or-failure modes of a NAT session: a
/// direct path, a relayed path, or neither.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum NatPhaseOutcome {
    /// A direct path to the peer was confirmed.
    Direct,
    /// The session concluded with a relay.
    Relayed,
    /// The session could not establish a path.
    Failed,
}

/// Drive the NAT phase through a per-peer `NatDriver`.
///
/// Builds a `NatDriver<DhtHandle>` for `peer`, starts a session under
/// `session_id`, seeds the peer's current transport address as if the
/// peer had announced it, sends our own signed candidate to the peer,
/// and drives the state machine to a terminal event.
///
/// # Why the peer's transport address is seeded
///
/// Until the peer's steady loop is running, inbound §12 verbs on T0
/// are not dispatched to the state machine — that path exists in
/// `run_peer_loop`, which the NAT phase precedes. The transport is up
/// and the address it is using is the peer's address; seeding it
/// gives the state machine a candidate to probe immediately, and the
/// probe's outcome is known without a wire round trip. When the
/// steady loop's inbound path is wired to feed §12 verbs during the
/// NAT phase, this seed becomes unnecessary.
///
/// # Signer
///
/// Outbound §12 verbs — candidate announces and relay discoveries —
/// are signed with `signer`. The peer's `dht_result_from` rejects
/// unsigned announces, so the signing is what makes *our* candidate
/// reach the peer's state machine. The peer's reciprocal announce is
/// what would feed our state machine in a full implementation.
///
/// # Probes
///
/// A `ProbeRequested` event is answered by [`probe_candidate`], except
/// when the requested address is the transport address — the live
/// connection is the proof, and dialing a second connection to it
/// would hand the peer's accept loop a peer it has no reason to
/// establish.
///
/// # Relay discovery
///
/// A `RelayDiscoveryRequested` event is answered by building a signed
/// `relay_discovery` and sending it on T0.
async fn run_nat_phase(
    driver: &mut ConnectionDriver,
    peer: NodeId,
    session_id: [u8; 16],
    local_id: NodeId,
    clock: &SharedClock,
    dht: &DhtHandle,
    signer: &SharedSigner,
) -> NatPhaseOutcome {
    use quip_net::nat_driver::DhtClient;

    let now = clock.now();

    let local_addr = local_ip_address(driver);
    let transport_addr = socket_to_address(driver.remote_addr());

    let mut nat_driver = NatDriver::new(
        local_id,
        local_addr,
        NatConfig::default(),
        dht.clone(),
    );

    // Register the session so `publish_candidates` routes to `peer`.
    dht.note_session(session_id, peer);

    nat_driver.start_session(peer, session_id, now);

    // Seed the peer's current transport address into our state
    // machine, as if the peer had announced it. This is the address
    // we are already connected to, so we know it is reachable.
    let seeded_candidate = Candidate {
        addr: transport_addr,
        kind: CANDIDATE_HOST,
        priority: 1000,
        foundation: String::from("seeded"),
        component: 0,
    };
    nat_driver.on_peer_message(
        &Message::CandidateAnnounce(CandidateAnnounce {
            node_id: peer,
            candidates: vec![seeded_candidate],
            session_id,
            timestamp: now,
            signature: [0u8; 64],
        }),
        now,
    );

    // Send our own host candidate to the peer, signed.
    let our_candidate = Candidate {
        addr: local_addr,
        kind: CANDIDATE_HOST,
        priority: 1000,
        foundation: String::from("local"),
        component: 0,
    };
    let mut our_announce = CandidateAnnounce {
        node_id: local_id,
        candidates: vec![our_candidate],
        session_id,
        timestamp: now,
        signature: [0u8; 64],
    };
    if let Ok(payload) = our_announce.signing_payload() {
        our_announce.signature = signer.sign_ed25519(&payload);
    }
    {
        let mut dht_mut = dht.clone();
        dht_mut.publish_candidates(our_announce);
    }

    let deadline =
        std::time::Instant::now() + Duration::from_millis(NAT_PHASE_TIMEOUT_MS);

    let outcome = 'outer: loop {
        let now = clock.now();

        let events = match nat_driver.poll(driver, now).await {
            Ok(e) => e,
            Err(_) => break 'outer NatPhaseOutcome::Failed,
        };
        for event in events {
            match event {
                DriverNatEvent::DirectPathEstablished { .. } => {
                    break 'outer NatPhaseOutcome::Direct;
                }
                DriverNatEvent::RelayedPathEstablished { .. } => {
                    break 'outer NatPhaseOutcome::Relayed;
                }
                DriverNatEvent::SessionFailed { .. } => {
                    break 'outer NatPhaseOutcome::Failed;
                }
                DriverNatEvent::ProbeRequested {
                    session_id,
                    addr,
                    ..
                } => {
                    let success = if addr == transport_addr {
                        // The live connection is the proof.
                        true
                    } else {
                        probe_candidate(addr, Duration::from_secs(5)).await
                    };
                    nat_driver.on_probe_result(session_id, addr, success, now);
                }
                DriverNatEvent::RelayDiscoveryRequested {
                    target,
                    max_hops,
                    request_id,
                } => {
                    let msg = match nat_driver.build_relay_discovery(
                        signer.as_ref(),
                        target,
                        max_hops,
                        request_id,
                        now,
                    ) {
                        Ok(m) => m,
                        Err(_) => continue,
                    };
                    let _ = driver
                        .send(&Message::RelayDiscovery(msg), now)
                        .await;
                }
                _ => {}
            }
        }

        if std::time::Instant::now() >= deadline {
            break 'outer NatPhaseOutcome::Failed;
        }

        // Feed inbound §12 NAT verbs on T0 into the state machine.
        let events = match driver.poll(now).await {
            Ok(e) => e,
            Err(_) => break 'outer NatPhaseOutcome::Failed,
        };
        for event in events {
            if let Event::Frame { tier, msg, .. } = event {
                if let Ok(m) = message::dispatch(&msg.raw, tier) {
                    nat_driver.on_peer_message(&m, now);
                }
            }
        }
    };

    dht.forget_session(&session_id);
    outcome
}

/// Dial `addr` on a fresh QUIC client endpoint and return whether the
/// handshake completed within `timeout`.
///
/// A connectivity check is QUIC path validation (§12.3, RFC 9000
/// §8.2): a fresh connection to an address we hold no session to. The
/// `Endpoint` is local; no `KeyClaim` is exchanged because the probe
/// carries no identity — it proves reachability, not identity.
async fn probe_candidate(
    addr: quip_core::address::Address,
    timeout: Duration,
) -> bool {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let sock = match addr {
        quip_core::address::Address::V4 { ip, port } => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), port)
        }
        quip_core::address::Address::V6 { ip, port } => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port)
        }
    };

    // A probe carries no identity: it needs a client endpoint with
    // *some* claim. The claim is generated fresh per probe from a
    // fixed seed, so the probe's key is not a long-lived secret.
    let probe_signer = Ed25519Signer::from_seed(&[0u8; 32]);
    let claim = match make_key_claim(&probe_signer, Timestamp::from_millis(0)) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let client_config = ClientConfig {
        bind: "0.0.0.0:0".parse().expect("valid bind"),
        key_claim: claim,
        capabilities: Capabilities::baseline(),
    };
    let endpoint = match Endpoint::client(client_config) {
        Ok(e) => e,
        Err(_) => return false,
    };

    matches!(
        tokio::time::timeout(timeout, endpoint.connect(sock, "localhost")).await,
        Ok(Ok(_driver))
    )
}

/// Convert a socket address to the wire `Address` type.
///
/// Local import keeps `Address` out of the module's top-level scope;
/// the test module imports the same type directly.
fn socket_to_address(s: SocketAddr) -> quip_core::address::Address {
    use quip_core::address::Address;
    match s {
        SocketAddr::V4(v4) => Address::V4 {
            ip: v4.ip().octets(),
            port: v4.port(),
        },
        SocketAddr::V6(v6) => Address::V6 {
            ip: v6.ip().octets(),
            port: v6.port(),
        },
    }
}

/// Best local address for the peer's `NatConfig`.
///
/// Only used for the connectivity announce, which the DHT no-ops
/// today. When the announce lands, this becomes a real input.
fn local_ip_address(driver: &ConnectionDriver) -> quip_core::address::Address {
    use quip_core::address::Address;
    match driver.local_ip() {
        Some(std::net::IpAddr::V4(ip)) => Address::V4 {
            ip: ip.octets(),
            port: 0,
        },
        Some(std::net::IpAddr::V6(ip)) => Address::V6 {
            ip: ip.octets(),
            port: 0,
        },
        None => Address::V4 {
            ip: [0, 0, 0, 0],
            port: 0,
        },
    }
}

/// Drive the §16 connection flow to completion.
///
/// Returns `true` on `Ready`. On any failure the `EstablishmentFailed`
/// event has already been emitted and the return is `false`. The
/// caller should then emit `Disconnected` and stop.
///
/// # Lifecycle (M9.5b-c gates 5 and 6)
///
/// Every terminal outcome of this function leaves the peer's lifecycle
/// in the correct state:
///
/// - NAT phase concludes → `Established → NatDirect` on a direct path
///   or `Established → NatRelayed` on a relayed one.
/// - Any failure before `Ready` → `Established | NatDirect | NatRelayed
///   → Failed`.
///
/// All transitions flow through `set_peer_lifecycle`, which updates
/// the registry (authoritative) and the DHT routing table (mirror)
/// under slot-scope.
///
/// # NAT phase
///
/// Runs through a per-peer `NatDriver` (see [`run_nat_phase`]). The
/// driver's terminal event — `DirectPathEstablished`,
/// `RelayedPathEstablished`, or `SessionFailed` — determines the
/// lifecycle transition and whether the phase reports success.
///
/// # Witness phase
///
/// Runs a real
/// [`WitnessDiscovery`](quip_net::discovery::WitnessDiscovery) against
/// the peer; a later milestone wires witness accumulation so
/// `Ready(Verified)` becomes reachable.
#[allow(clippy::too_many_arguments)]
async fn run_establishment(
    driver: &mut ConnectionDriver,
    local_claim: &KeyClaim,
    peer_claim: &KeyClaim,
    peer: NodeId,
    slot: PeerSlot,
    clock: &SharedClock,
    events_tx: &mpsc::Sender<NodeEvent>,
    discovery: &DiscoveryHandle,
    trust: &SharedTrust,
    peers: &PeerRegistry,
    dht: &DhtHandle,
    signer: &SharedSigner,
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
                set_peer_lifecycle(peers, dht, &slot, PeerLifecycle::Failed)
                    .await;
                let trust_level = current_trust(trust, &peer).await;
                let _ = events_tx
                    .send(NodeEvent::EstablishmentFailed {
                        peer,
                        failure,
                        trust: trust_level,
                    })
                    .await;
                return false;
            }
        }

        match flow.phase() {
            FlowPhase::NatTraversal => {
                let outcome = run_nat_phase(
                    driver,
                    peer,
                    session_id,
                    local_claim.node_id,
                    clock,
                    dht,
                    signer,
                )
                .await;
                match outcome {
                    NatPhaseOutcome::Direct => {
                        let _ = flow.on_nat_complete(true, now);
                        set_peer_lifecycle(
                            peers,
                            dht,
                            &slot,
                            PeerLifecycle::NatDirect,
                        )
                        .await;
                    }
                    NatPhaseOutcome::Relayed => {
                        let _ = flow.on_nat_complete(true, now);
                        set_peer_lifecycle(
                            peers,
                            dht,
                            &slot,
                            PeerLifecycle::NatRelayed,
                        )
                        .await;
                    }
                    NatPhaseOutcome::Failed => {
                        let _ = flow.on_nat_complete(false, now);
                    }
                }
            }
            FlowPhase::WitnessDiscovery => {
                run_discovery_phase(driver, peer, clock, discovery, &mut flow)
                    .await;
            }
            FlowPhase::Ready(status) => {
                let kt_status = *status;

                // M10.3: a flow that reached `Verified` promotes a
                // `Trusted` peer to `Verified`. The promotion is
                // ignored if the policy has not already accepted the
                // peer — witness corroboration is not a substitute
                // for the application's own decision.
                let trust_level = {
                    let mut policy = trust.lock().await;
                    if kt_status == KtStatus::Verified {
                        policy.promote_to_verified(&peer);
                    }
                    policy.trust_of(&peer)
                };
                // Guard dropped above; safe to await the send.
                let _ = events_tx
                    .send(NodeEvent::Ready {
                        peer,
                        kt_status,
                        trust: trust_level,
                    })
                    .await;
                return true;
            }
            FlowPhase::Failed(failure) => {
                let failure = *failure;
                set_peer_lifecycle(peers, dht, &slot, PeerLifecycle::Failed)
                    .await;
                let trust_level = current_trust(trust, &peer).await;
                let _ = events_tx
                    .send(NodeEvent::EstablishmentFailed {
                        peer,
                        failure,
                        trust: trust_level,
                    })
                    .await;
                return false;
            }
            FlowPhase::AwaitHandshake | FlowPhase::AwaitKeyClaim => {
                // `resume_from_key_claim` starts the flow at
                // `NatTraversal`, so reaching these phases here is a
                // bug, not a runtime condition. Emit a protocol error
                // and give up.
                set_peer_lifecycle(peers, dht, &slot, PeerLifecycle::Failed)
                    .await;
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
///
/// # Generation guard
///
/// Before doing anything, and again after the establishment flow
/// completes, this function confirms that `slot` is still the
/// currently-registered generation for `peer`. If a newer connection
/// has already registered in the meantime, the task returns without
/// touching any node state. The actual protection against a *later*
/// takeover is the `abort()` performed by `register_peer`; these two
/// checks are the cheap belt-and-braces for the window between this
/// task's spawn and the first time it reads the registry.
///
/// # Lifecycle
///
/// `Established → NatDirect | NatRelayed` and
/// `Established | NatDirect | NatRelayed → Failed` are applied inside
/// [`run_establishment`]. This function applies the final
/// `NatDirect | NatRelayed → Closing` transition when the steady loop
/// exits, so an application that observes [`Node::peer_lifecycle`]
/// sees a coherent progression across the connection's lifetime.
#[allow(clippy::too_many_arguments)]
async fn peer_run<B>(
    mut driver: ConnectionDriver,
    peer: NodeId,
    slot: PeerSlot,
    store: Arc<Mutex<QuipStore<B>>>,
    clock: SharedClock,
    auto_serve_pins: bool,
    events_tx: mpsc::Sender<NodeEvent>,
    mut outbound_rx: mpsc::Receiver<Message>,
    dht: DhtHandle,
    discovery: DiscoveryHandle,
    trust: SharedTrust,
    peers: PeerRegistry,
    signer: SharedSigner,
) where
    B: BlobStore + Send + Sync + 'static,
{
    // Generation guard #1: are we still the current generation for
    // this peer?
    if !peers.lock().await.is_current(&slot) {
        return;
    }

    // `drive_handshake` returns only after the §16 Key Claim exchange,
    // so both claims are populated. Clone them out before the flow
    // borrows anything; the driver then goes to the steady loop.
    let local_claim = driver.local_key_claim().clone();
    let peer_claim = match driver.peer_key_claim().cloned() {
        Some(c) => c,
        None => {
            // Unreachable in practice; guard defensively in case the
            // transport's guarantees change.
            set_peer_lifecycle(&peers, &dht, &slot, PeerLifecycle::Failed)
                .await;
            let failure = FlowFailure::KeyClaimTimeout;
            let trust_level = current_trust(&trust, &peer).await;
            let _ = events_tx
                .send(NodeEvent::EstablishmentFailed {
                    peer,
                    failure,
                    trust: trust_level,
                })
                .await;
            let _ = events_tx
                .send(NodeEvent::Disconnected {
                    peer,
                    trust: trust_level,
                })
                .await;
            return;
        }
    };

    // M10.3: record the peer's Key Claim before doing anything else.
    // A first-seen peer lands as `Unknown`; a claim mismatch against
    // the stored claim demotes to `Untrusted`; a tombstoned peer
    // returns `Revoked`. In all cases the trust value is what the
    // subsequent events carry.
    let trust_level = {
        let mut policy = trust.lock().await;
        policy.observe_claim(peer_claim.clone(), clock.now())
    };

    let ready = run_establishment(
        &mut driver,
        &local_claim,
        &peer_claim,
        peer,
        slot,
        &clock,
        &events_tx,
        &discovery,
        &trust,
        &peers,
        &dht,
        &signer,
    )
    .await;

    if !ready {
        // `run_establishment` already set the lifecycle to `Failed`.
        let _ = events_tx
            .send(NodeEvent::Disconnected {
                peer,
                trust: trust_level,
            })
            .await;
        return;
    }

    // Generation guard #2: a newer connection may have registered
    // while we were running the establishment flow. If so, do not
    // enter the steady loop — the newer task owns the peer now.
    if !peers.lock().await.is_current(&slot) {
        return;
    }

    run_peer_loop(
        &mut driver,
        peer,
        slot,
        &store,
        &clock,
        auto_serve_pins,
        &events_tx,
        &mut outbound_rx,
        &dht,
        &discovery,
    )
    .await;

    // The steady loop exited; the peer is closing. The lifecycle
    // transition from `NatDirect` or `NatRelayed` to `Closing` is
    // handled here.
    set_peer_lifecycle(&peers, &dht, &slot, PeerLifecycle::Closing).await;
    let trust_level = current_trust(&trust, &peer).await;
    let _ = events_tx
        .send(NodeEvent::Disconnected {
            peer,
            trust: trust_level,
        })
        .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_peer_loop<B>(
    driver: &mut ConnectionDriver,
    peer: NodeId,
    slot: PeerSlot,
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
                                dht.note_peer(peer, slot, None, now);
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
    ) -> Option<PeerTrust> {
        let deadline =
            std::time::Instant::now() + Duration::from_millis(timeout_ms);
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
        let deadline =
            std::time::Instant::now() + Duration::from_millis(timeout_ms);
        while std::time::Instant::now() < deadline {
            if let Ok(events) = node.poll().await {
                for e in events {
                    if let NodeEvent::Ready { peer, kt_status, trust } = e {
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
        assert!(wait_for_connected(&mut b, a_node_id, 5_000).await.is_some());
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
        let deadline =
            std::time::Instant::now() + Duration::from_millis(500);
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
        let deadline =
            std::time::Instant::now() + Duration::from_millis(2_000);
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
}