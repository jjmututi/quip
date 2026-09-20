//! NAT traversal state (spec §12).
//!
//! This module holds the in-memory state machines for NAT traversal:
//! hole-punch sessions, relay tables, connectivity state, address
//! discovery, and per-session candidate tracking. The wire codecs for
//! `connectivity_announce`, `candidate_announce`, `relay_discovery`, and
//! `relay_response` live in [`crate::nat_wire`]; the async driver that
//! feeds this state machine lives in `crate::nat_driver` (behind the
//! `quic` feature).
//!
//! # Legacy types removed in M3a
//!
//! `Candidate`, `CandidateKind`, `ConnectivityAnnounce`,
//! `RelayDiscovery`, and `RelayResponse` used to live here as in-memory
//! shapes that predated the spec being finalised. They had `Vec<u8>`
//! addresses and were missing several fields. They are now defined once,
//! with the correct shape, in `nat_wire.rs`.

use crate::constants::{CANDIDATE_TTL_S, CONNECTIVITY_TTL_S, RELAY_CAPACITY, RELAY_HOP_LIMIT};
use crate::error::{Error, Result};
use crate::message::Message;
use crate::nat_wire::{
    Candidate, CandidateAnnounce, ConnectivityAnnounce, RelayDiscovery, RelayEntry, RelayResponse,
};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use quip_core::address::Address;
use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;

// -------------------------------------------------------------------------
// NAT flavour and hole punching (M3a)
// -------------------------------------------------------------------------

/// NAT flavour of a peer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NatKind {
    /// Directly reachable.
    None,
    /// Full-cone NAT.
    FullCone,
    /// Restricted cone.
    Restricted,
    /// Symmetric NAT (relay required).
    Symmetric,
}

/// Role in a hole-punching session.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HolePunchRole {
    /// Initiator sends first.
    Initiator,
    /// Responder listens first.
    Responder,
}

/// Hole-punch session state machine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HolePunchSession {
    /// Remote peer.
    pub remote: NodeId,
    /// Local role.
    pub role: HolePunchRole,
    /// Attempts so far.
    pub attempts: u32,
    /// True once bidirectional packets flowed.
    pub established: bool,
}

impl HolePunchSession {
    /// Start a session.
    pub fn start(remote: NodeId, role: HolePunchRole) -> Self {
        Self {
            remote,
            role,
            attempts: 0,
            established: false,
        }
    }

    /// Record one punch attempt; fails after 5 tries.
    pub fn punch(&mut self) -> Result<()> {
        if self.established {
            return Ok(());
        }
        self.attempts += 1;
        if self.attempts > 5 {
            return Err(Error::NatUnreachable);
        }
        Ok(())
    }

    /// Mark the session established.
    pub fn on_packet(&mut self) {
        self.established = true;
    }
}

/// Connectivity state for one remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectivityState {
    /// Direct QUIC path works.
    Direct,
    /// Hole punching in progress.
    Punching(HolePunchSession),
    /// Relayed via `NodeId`.
    Relayed(NodeId),
    /// Unreachable.
    Unreachable,
}

// -------------------------------------------------------------------------
// Relay table (§12.2)
// -------------------------------------------------------------------------

/// A known relay and its track record.
#[derive(Clone, Debug)]
pub struct RelayRecord {
    /// The relay's advertised entry.
    pub entry: RelayEntry,
    /// Targets this relay has claimed to reach.
    pub targets: alloc::collections::BTreeSet<NodeId>,
    /// Successful relay sessions.
    pub successes: u32,
    /// Failed relay sessions.
    pub failures: u32,
    /// Monotonic insertion sequence, used for LRU eviction.
    pub seq: u64,
}

impl RelayRecord {
    /// Total attempts observed.
    pub fn attempts(&self) -> u32 {
        self.successes.saturating_add(self.failures)
    }

    /// Success ratio in [0, 1000]. Returns 500 when no attempts have
    /// been made, so an untested relay sits mid-pack.
    pub fn reliability_permille(&self) -> u32 {
        let attempts = self.attempts();
        if attempts == 0 {
            return 500;
        }
        (self.successes as u64 * 1000 / attempts as u64) as u32
    }
}

/// Relay table with capacity bound and scoring (§12.2).
///
/// Selection uses the §12.2 priority order: XOR distance to the target,
/// available capacity, cost, then reliability. Geographic proximity is
/// not modeled — the state machine does not carry cluster info.
#[derive(Clone, Debug)]
pub struct RelayManager {
    relays: BTreeMap<NodeId, RelayRecord>,
    capacity: usize,
    next_seq: u64,
}

impl Default for RelayManager {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayManager {
    /// Create with default `RELAY_CAPACITY`.
    pub fn new() -> Self {
        Self {
            relays: BTreeMap::new(),
            capacity: RELAY_CAPACITY,
            next_seq: 0,
        }
    }

    /// Register or update a relay. `target` is `Some` when the caller
    /// learned the relay from a `relay_response` that named a target,
    /// and `None` when it came from a bare `connectivity_announce`.
    ///
    /// Evicts the least-recently-inserted relay when at capacity.
    pub fn offer(&mut self, entry: RelayEntry, target: Option<NodeId>) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);

        match self.relays.get_mut(&entry.relay_id) {
            Some(record) => {
                record.entry = entry;
                record.seq = seq;
                if let Some(t) = target {
                    record.targets.insert(t);
                }
            }
            None => {
                let mut targets = alloc::collections::BTreeSet::new();
                if let Some(t) = target {
                    targets.insert(t);
                }
                self.relays.insert(
                    entry.relay_id,
                    RelayRecord {
                        entry,
                        targets,
                        successes: 0,
                        failures: 0,
                        seq,
                    },
                );
                while self.relays.len() > self.capacity {
                    let lru = self
                        .relays
                        .iter()
                        .min_by_key(|(_, r)| r.seq)
                        .map(|(id, _)| *id);
                    match lru {
                        Some(id) => {
                            self.relays.remove(&id);
                        }
                        None => break,
                    }
                }
            }
        }
    }

    /// All relays that claim to reach `target`, unordered.
    pub fn find(&self, target: &NodeId) -> Vec<RelayEntry> {
        self.relays
            .values()
            .filter(|r| r.targets.contains(target))
            .map(|r| r.entry.clone())
            .collect()
    }

    /// The best relay for `target`, per the §12.2 selection order.
    pub fn best_for(&self, target: &NodeId) -> Option<RelayEntry> {
        self.relays
            .values()
            .filter(|r| r.targets.contains(target))
            .filter(|r| r.entry.available() > 0)
            .min_by(|a, b| {
                let da = xor_distance(&a.entry.relay_id, target);
                let db = xor_distance(&b.entry.relay_id, target);
                da.cmp(&db)
                    .then_with(|| {
                        // Higher available capacity wins → reverse compare.
                        b.entry.available().cmp(&a.entry.available())
                    })
                    .then_with(|| a.entry.cost.cmp(&b.entry.cost))
                    .then_with(|| {
                        b.reliability_permille()
                            .cmp(&a.reliability_permille())
                    })
            })
            .map(|r| r.entry.clone())
    }

    /// Record a successful relay session.
    pub fn record_success(&mut self, relay_id: &NodeId) {
        if let Some(r) = self.relays.get_mut(relay_id) {
            r.successes = r.successes.saturating_add(1);
        }
    }

    /// Record a failed relay session.
    pub fn record_failure(&mut self, relay_id: &NodeId) {
        if let Some(r) = self.relays.get_mut(relay_id) {
            r.failures = r.failures.saturating_add(1);
        }
    }

    /// Read-only view of a relay record.
    pub fn get(&self, relay_id: &NodeId) -> Option<&RelayRecord> {
        self.relays.get(relay_id)
    }

    /// Validate a relay path length.
    pub fn check_hops(hops: u8) -> Result<()> {
        if hops > RELAY_HOP_LIMIT {
            return Err(Error::NatUnreachable);
        }
        Ok(())
    }

    /// Number of relay entries.
    pub fn len(&self) -> usize {
        self.relays.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.relays.is_empty()
    }
}

/// XOR distance between two NodeIds, as a byte array for lexicographic
/// comparison.
fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 32] {
    let mut d = [0u8; 32];
    for i in 0..32 {
        d[i] = a[i] ^ b[i];
    }
    d
}

// -------------------------------------------------------------------------
// Relay chaining (§12.2)
// -------------------------------------------------------------------------

/// One hop in a relay chain.
///
/// The spec writes `encrypted_key: bytes` — "encrypted with the next
/// hop's public key" — but does not name the encryption scheme. The
/// field is carried opaquely here; a deployment that uses chaining MUST
/// define its own scheme (ECDH+X25519+AEAD is the natural choice) and
/// fill the bytes. One-hop chains do not use this field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayHop {
    /// The relay at this hop.
    pub relay_id: NodeId,
    /// The address to send to next.
    pub next_hop: Address,
    /// Opaque per-hop key material, if the chain uses more than one hop.
    pub encrypted_key: Vec<u8>,
}

/// A chain of relays between us and `target`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayChain {
    /// Ordered hops, first to last.
    pub hops: Vec<RelayHop>,
    /// The eventual target.
    pub target: NodeId,
    /// Time-to-live for the chain, in seconds.
    pub ttl: u64,
}

impl RelayChain {
    /// A chain is valid when it has between 1 and `RELAY_HOP_LIMIT`
    /// hops.
    pub fn is_valid(&self) -> bool {
        !self.hops.is_empty() && self.hops.len() <= RELAY_HOP_LIMIT as usize
    }
}

// -------------------------------------------------------------------------
// Configuration (M3b.1)
// -------------------------------------------------------------------------

/// Tunables for [`NatTraversal`]. Defaults match §12.1 and §12.3.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NatConfig {
    /// `CONNECTIVITY_TTL` — validity window for a `connectivity_announce`.
    pub connectivity_ttl_s: u64,
    /// Re-announce at this percentage of the TTL. §12.1 recommends 80.
    pub reannounce_percent: u64,
    /// `CANDIDATE_TTL` — how long an unverified candidate survives.
    pub candidate_ttl_s: u64,
    /// Maximum observations retained across all observers.
    pub max_observations: usize,
    /// Maximum candidates retained per session.
    pub max_candidates_per_session: usize,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
}

impl Default for NatConfig {
    fn default() -> Self {
        Self {
            connectivity_ttl_s: CONNECTIVITY_TTL_S,
            reannounce_percent: 80,
            candidate_ttl_s: CANDIDATE_TTL_S,
            max_observations: 32,
            max_candidates_per_session: 32,
            max_sessions: 32,
        }
    }
}

impl NatConfig {
    /// Re-announce interval in milliseconds, derived from the TTL and
    /// the configured percentage.
    pub fn reannounce_interval_ms(&self) -> u64 {
        self.connectivity_ttl_s
            .saturating_mul(1000)
            .saturating_mul(self.reannounce_percent)
            / 100
    }
}

// -------------------------------------------------------------------------
// Address discovery (§12.1) (M3b.1)
// -------------------------------------------------------------------------

/// Tracks our own external address as observed by DHT peers.
///
/// The state machine feeds observations in via [`Self::observe`]; the
/// best external address is the one most observers agree on, with ties
/// broken by the encoded byte order so the result is deterministic.
#[derive(Clone, Debug, Default)]
pub struct AddressState {
    /// Latest observation per observer. Newer observations replace
    /// older ones.
    observations: BTreeMap<NodeId, Address>,
    /// Current best external address, if any.
    external: Option<Address>,
    /// Inferred NAT type (one of the `nat_wire::NAT_TYPE_*` values).
    nat_type: u64,
}

impl AddressState {
    /// Empty state with `nat_type = NAT_TYPE_UNKNOWN`.
    pub fn new() -> Self {
        Self {
            observations: BTreeMap::new(),
            external: None,
            nat_type: crate::nat_wire::NAT_TYPE_UNKNOWN,
        }
    }

    /// Record an observation and recompute the derived fields.
    pub fn observe(&mut self, observer: NodeId, observed: Address) {
        self.observations.insert(observer, observed);
        self.recompute();
    }

    /// Drop an observer's contribution (e.g. on disconnect).
    pub fn forget(&mut self, observer: &NodeId) {
        if self.observations.remove(observer).is_some() {
            self.recompute();
        }
    }

    /// Current best external address.
    pub fn external(&self) -> Option<Address> {
        self.external
    }

    /// Current inferred NAT type.
    pub fn nat_type(&self) -> u64 {
        self.nat_type
    }

    /// Number of live observations.
    pub fn observations(&self) -> usize {
        self.observations.len()
    }

    fn recompute(&mut self) {
        // Vote by observed address; ties broken by encoding order.
        let mut votes: BTreeMap<Vec<u8>, (u64, Address)> = BTreeMap::new();
        for addr in self.observations.values() {
            let key = encode_addr(addr);
            let entry = votes.entry(key).or_insert((0, *addr));
            entry.0 += 1;
        }
        self.external = votes
            .into_iter()
            .max_by(|a, b| a.1 .0.cmp(&b.1 .0).then_with(|| b.0.cmp(&a.0)))
            .map(|(_, (_, addr))| addr);

        self.nat_type = infer_nat_type(&self.observations);
    }
}

/// Canonical byte form of an address, for use as a BTreeMap key.
fn encode_addr(a: &Address) -> Vec<u8> {
    quip_core::cbor::encode(&a.to_cbor()).unwrap_or_default()
}

/// Infer the NAT type from a set of observations, per §12.1.
fn infer_nat_type(observations: &BTreeMap<NodeId, Address>) -> u64 {
    use crate::nat_wire::{
        NAT_TYPE_OPEN, NAT_TYPE_RESTRICTED, NAT_TYPE_SYMMETRIC,
        NAT_TYPE_UNKNOWN,
    };

    if observations.is_empty() {
        return NAT_TYPE_UNKNOWN;
    }

    let mut ips: BTreeMap<Vec<u8>, ()> = BTreeMap::new();
    let mut ports: BTreeMap<u16, ()> = BTreeMap::new();
    for addr in observations.values() {
        ips.insert(addr_ip_bytes(addr), ());
        ports.insert(addr_port(addr), ());
    }

    match (ips.len(), ports.len()) {
        (1, 1) => NAT_TYPE_OPEN,
        (1, _) => NAT_TYPE_RESTRICTED,
        _ => NAT_TYPE_SYMMETRIC,
    }
}

fn addr_ip_bytes(a: &Address) -> Vec<u8> {
    match a {
        Address::V4 { ip, .. } => ip.to_vec(),
        Address::V6 { ip, .. } => ip.to_vec(),
    }
}

fn addr_port(a: &Address) -> u16 {
    match a {
        Address::V4 { port, .. } => *port,
        Address::V6 { port, .. } => *port,
    }
}

// -------------------------------------------------------------------------
// Candidate table (§12.3) (M3b.1)
// -------------------------------------------------------------------------

/// Per-session candidate tracking.
///
/// Candidates from the remote peer are stamped on arrival and pruned
/// once older than `candidate_ttl_s`. Probe results are recorded
/// separately so a candidate that succeeds once is not re-probed.
#[derive(Clone, Debug)]
pub struct CandidateTable {
    peer: NodeId,
    session_id: [u8; 16],
    local: Vec<Candidate>,
    remote: Vec<(Candidate, Timestamp)>,
    probes: BTreeMap<Vec<u8>, bool>,
    established: Option<Address>,
}

impl CandidateTable {
    /// Empty table for one session.
    pub fn new(peer: NodeId, session_id: [u8; 16]) -> Self {
        Self {
            peer,
            session_id,
            local: Vec::new(),
            remote: Vec::new(),
            probes: BTreeMap::new(),
            established: None,
        }
    }

    /// The peer this table tracks.
    pub fn peer(&self) -> &NodeId {
        &self.peer
    }

    /// The session identifier.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Our own candidates for this session.
    pub fn local(&self) -> &[Candidate] {
        &self.local
    }

    /// Remote candidates received so far, cloned into a fresh `Vec`.
    pub fn remote(&self) -> Vec<Candidate> {
        self.remote.iter().map(|(c, _)| c.clone()).collect()
    }

    /// Number of remote candidates held.
    pub fn remote_len(&self) -> usize {
        self.remote.len()
    }

    /// The address of the established path, if any.
    pub fn established(&self) -> Option<Address> {
        self.established
    }

    /// Add one of our own candidates.
    pub fn add_local(&mut self, c: Candidate, cap: usize) {
        if self.local.len() < cap && !self.local.contains(&c) {
            self.local.push(c);
        }
    }

    /// Record a remote candidate, ignoring duplicates.
    pub fn add_remote(&mut self, c: Candidate, now: Timestamp, cap: usize) {
        if self.remote.iter().any(|(existing, _)| existing == &c) {
            return;
        }
        if self.remote.len() >= cap {
            // Drop the oldest.
            self.remote.sort_by_key(|(_, at)| *at);
            self.remote.remove(0);
        }
        self.remote.push((c, now));
    }

    /// Drop candidates older than `ttl_s`. Returns how many were
    /// dropped.
    pub fn prune(&mut self, now: Timestamp, ttl_s: u64) -> usize {
        let cutoff = now.as_millis().saturating_sub(ttl_s.saturating_mul(1000));
        let before = self.remote.len();
        self.remote.retain(|(_, at)| at.as_millis() >= cutoff);
        before - self.remote.len()
    }

    /// The next candidate that has not yet been probed, in preference
    /// order (host → server-reflexive → peer-reflexive → relayed, then
    /// by descending priority within a class).
    pub fn next_to_probe(&self, now: Timestamp, ttl_s: u64) -> Option<Candidate> {
        let cutoff = now.as_millis().saturating_sub(ttl_s.saturating_mul(1000));
        let mut live: Vec<Candidate> = self
            .remote
            .iter()
            .filter(|(_, at)| at.as_millis() >= cutoff)
            .map(|(c, _)| c.clone())
            .filter(|c| !self.probes.contains_key(&encode_addr(&c.addr)))
            .collect();
        live.sort_by_key(|c| (c.priority_class(), core::cmp::Reverse(c.priority)));
        live.into_iter().next()
    }

    /// Record a probe result.
    pub fn record_probe(&mut self, addr: Address, success: bool) {
        self.probes.insert(encode_addr(&addr), success);
        if success && self.established.is_none() {
            self.established = Some(addr);
        }
    }

    /// How many remote candidates are still unprobed.
    pub fn pending_probes(&self) -> usize {
        self.remote
            .iter()
            .filter(|(c, _)| !self.probes.contains_key(&encode_addr(&c.addr)))
            .count()
    }
}

// -------------------------------------------------------------------------
// Sessions and driver-facing types (M3b.1)
// -------------------------------------------------------------------------

/// Per-session state held by [`NatTraversal`].
#[derive(Clone, Debug)]
pub struct SessionState {
    /// The remote peer.
    pub peer: NodeId,
    /// Session identifier.
    pub session_id: [u8; 16],
    /// Candidates and probe results.
    pub candidates: CandidateTable,
    /// When the session began.
    pub started_at: Timestamp,
}

/// A request the driver should fulfil.
#[derive(Clone, Debug)]
pub enum Outbound {
    /// Publish our connectivity to the DHT.
    PublishConnectivity(ConnectivityAnnounce),
    /// Ask the DHT for a peer's connectivity.
    LookupConnectivity(NodeId),
    /// Publish our candidates for a session.
    PublishCandidates(CandidateAnnounce),
    /// Ask the DHT for a peer's candidates in a session.
    LookupCandidates {
        /// Peer whose candidates we want.
        target: NodeId,
        /// Session binding.
        session_id: [u8; 16],
    },
    /// Ask the DHT for relays to a target.
    DiscoverRelays(RelayDiscovery),
    /// Send a NAT message to a peer over T0.
    SendToPeer {
        /// Peer to send to.
        target: NodeId,
        /// Message to send.
        msg: Message,
    },
    /// Ask the driver to probe one candidate.
    ProbeCandidate {
        /// Session the candidate belongs to.
        session_id: [u8; 16],
        /// The peer on the other side.
        peer: NodeId,
        /// The candidate to probe.
        candidate: Candidate,
    },
    /// Ask the DHT for relays to `target`.
    ///
    /// Distinguished from `DiscoverRelays` above in that the state
    /// machine emits this one when it wants a `RelayDiscovery` sent;
    /// the driver decides whether to actually send it.
    RequestRelays {
        /// The target we want to reach.
        target: NodeId,
        /// Maximum hops we'll accept.
        max_hops: u8,
    },
}

/// Something the application should know about.
#[derive(Clone, Debug)]
pub enum NatEvent {
    /// Our external address or inferred NAT type changed.
    ExternalAddressUpdated {
        /// Best external address.
        addr: Address,
        /// Inferred NAT type.
        nat_type: u64,
    },
    /// A new session began.
    SessionStarted {
        /// Peer.
        peer: NodeId,
        /// Session identifier.
        session_id: [u8; 16],
    },
    /// Remote candidates arrived for a session.
    CandidatesReceived {
        /// Session identifier.
        session_id: [u8; 16],
        /// Number of candidates received.
        count: usize,
    },
    /// A probe succeeded.
    CandidateReachable {
        /// Session identifier.
        session_id: [u8; 16],
        /// Address that answered.
        addr: Address,
    },
    /// A direct path was established.
    DirectPathEstablished {
        /// Peer.
        peer: NodeId,
        /// Address of the working path.
        addr: Address,
    },
    /// A session exhausted all candidates.
    SessionFailed {
        /// Peer.
        peer: NodeId,
        /// Session identifier.
        session_id: [u8; 16],
    },
    /// The application must dial a candidate address (§12.3).
    ///
    /// A connectivity check is QUIC path validation (RFC 9000 §8.2)
    /// against an address we may hold no connection to, so it needs the
    /// application's `Endpoint` — which the driver does not own. The
    /// caller dials the candidate with the 5 s timeout from App. A.5 and
    /// reports the outcome through `on_probe_result`.
    ProbeRequested {
        /// Session the candidate belongs to.
        session_id: [u8; 16],
        /// The peer on the other side.
        peer: NodeId,
        /// The address to probe.
        addr: Address,
    },
    /// The application must sign and send a `relay_discovery` (§12.2).
    ///
    /// Building the message requires the requester's `Signer`, which the
    /// driver does not hold. The response returns through
    /// `on_peer_message` or the DHT client with the target attached.
    RelayDiscoveryRequested {
        /// The target we want to reach.
        target: NodeId,
        /// Maximum hops we will accept.
        max_hops: u8,
    },
}

/// The NAT traversal state machine.
#[derive(Clone, Debug)]
pub struct NatTraversal {
    config: NatConfig,
    node_id: NodeId,
    local_addr: Address,
    address: AddressState,
    sessions: BTreeMap<[u8; 16], SessionState>,
    relay_manager: RelayManager,
    outbound: VecDeque<Outbound>,
    events: VecDeque<NatEvent>,
    last_announce: Option<Timestamp>,
    /// Host candidates we advertise on every session.
    local_candidates: Vec<Candidate>,
}

impl NatTraversal {
    /// Create a new state machine.
    pub fn new(node_id: NodeId, local_addr: Address, config: NatConfig) -> Self {
        Self {
            config,
            node_id,
            local_addr,
            address: AddressState::new(),
            sessions: BTreeMap::new(),
            relay_manager: RelayManager::new(),
            outbound: VecDeque::new(),
            events: VecDeque::new(),
            last_announce: None,
            local_candidates: Vec::new(),
        }
    }

    /// The active configuration.
    pub fn config(&self) -> &NatConfig {
        &self.config
    }

    /// Our own NodeId.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Current best external address, if known.
    pub fn external_addr(&self) -> Option<Address> {
        self.address.external()
    }

    /// Current inferred NAT type.
    pub fn nat_type(&self) -> u64 {
        self.address.nat_type()
    }

    /// Add a host candidate to advertise on every session.
    pub fn add_local_candidate(&mut self, c: Candidate) {
        if !self.local_candidates.contains(&c) {
            self.local_candidates.push(c);
        }
    }

    /// Advance the state machine. Returns the outbound requests the
    /// driver should fulfil.
    pub fn poll(&mut self, now: Timestamp) -> Vec<Outbound> {
        // Periodic connectivity announcement.
        let interval = self.config.reannounce_interval_ms();
        let due = match self.last_announce {
            None => true,
            Some(t) => now.as_millis().saturating_sub(t.as_millis()) >= interval,
        };
        if due && self.address.external().is_some() {
            self.emit_connectivity_announce(now);
        }

        // Per-session maintenance: prune stale candidates, emit probes
        // for pending ones, and retire sessions with no path.
        let ttl = self.config.candidate_ttl_s;
        let mut probes: Vec<Outbound> = Vec::new();
        let mut failed: Vec<[u8; 16]> = Vec::new();
        for (sid, session) in self.sessions.iter_mut() {
            session.candidates.prune(now, ttl);

            if session.candidates.established().is_none() {
                if let Some(c) = session.candidates.next_to_probe(now, ttl) {
                    probes.push(Outbound::ProbeCandidate {
                        session_id: *sid,
                        peer: session.peer,
                        candidate: c,
                    });
                } else if session.candidates.pending_probes() == 0 {
                    // No established path and nothing left to try.
                    failed.push(*sid);
                }
            }
        }
        for p in probes {
            self.outbound.push_back(p);
        }
        for sid in failed {
            if let Some(s) = self.sessions.remove(&sid) {
                self.events.push_back(NatEvent::SessionFailed {
                    peer: s.peer,
                    session_id: sid,
                });
            }
        }

        self.outbound.drain(..).collect()
    }

    /// Drain queued events.
    pub fn drain_events(&mut self) -> Vec<NatEvent> {
        self.events.drain(..).collect()
    }

    /// Record an address observation from a DHT peer.
    pub fn on_address_observed(
        &mut self,
        observer: NodeId,
        observed: Address,
        _now: Timestamp,
    ) {
        let before = (self.address.external(), self.address.nat_type());
        self.address.observe(observer, observed);
        let after = (self.address.external(), self.address.nat_type());
        if before != after {
            if let Some(addr) = self.address.external() {
                self.events.push_back(NatEvent::ExternalAddressUpdated {
                    addr,
                    nat_type: self.address.nat_type(),
                });
            }
        }
    }

    /// Receive a `connectivity_announce` from a DHT lookup.
    ///
    /// We learn the announcer's address but not what it can reach, so
    /// the relay (if any) is registered without a target.
    pub fn on_connectivity_announce(
        &mut self,
        announce: ConnectivityAnnounce,
        _now: Timestamp,
    ) {
        if announce.relay_capable && announce.capacity > 0 {
            let entry = RelayEntry {
                relay_id: announce.node_id,
                external_addr: announce.external_addr,
                capacity: announce.capacity,
                load: 0,
                cost: 0,
            };
            self.relay_manager.offer(entry, None);
        }
    }

    /// Receive a `relay_response`.
    ///
    /// The target is carried in the response itself (see §12.2), so the
    /// state machine registers each relay against its declared target
    /// without needing any external correlation.
    pub fn on_relay_response(
        &mut self,
        response: RelayResponse,
        _now: Timestamp,
    ) {
        let target = response.target;
        for entry in response.relays {
            self.relay_manager.offer(entry, Some(target));
        }
    }

    /// Record a successful relay session.
    pub fn on_relay_success(&mut self, relay_id: NodeId) {
        self.relay_manager.record_success(&relay_id);
    }

    /// Record a failed relay session.
    pub fn on_relay_failure(&mut self, relay_id: NodeId) {
        self.relay_manager.record_failure(&relay_id);
    }

    /// Build the best relay chain we can to `target`, or `None` when no
    /// usable relay is known. Currently produces a single hop; multi-hop
    /// chaining requires an encryption scheme the spec leaves undefined.
    pub fn build_relay_chain(&self, target: NodeId, ttl_s: u64) -> Option<RelayChain> {
        let entry = self.relay_manager.best_for(&target)?;
        Some(RelayChain {
            hops: alloc::vec![RelayHop {
                relay_id: entry.relay_id,
                next_hop: entry.external_addr,
                encrypted_key: Vec::new(),
            }],
            target,
            ttl: ttl_s,
        })
    }

    /// Receive a `candidate_announce` from a peer.
    pub fn on_candidate_announce(&mut self, announce: CandidateAnnounce, now: Timestamp) {
        let session = match self.sessions.get_mut(&announce.session_id) {
            Some(s) => s,
            None => return, // unknown session; drop silently
        };
        let cap = self.config.max_candidates_per_session;
        let before = session.candidates.remote_len();
        for c in &announce.candidates {
            session.candidates.add_remote(c.clone(), now, cap);
        }
        let after = session.candidates.remote_len();
        if after > before {
            self.events.push_back(NatEvent::CandidatesReceived {
                session_id: announce.session_id,
                count: after,
            });
        }
    }

    /// Start a new session with `peer`.
    pub fn start_session(&mut self, peer: NodeId, session_id: [u8; 16], now: Timestamp) {
        if self.sessions.len() >= self.config.max_sessions {
            return;
        }
        if self.sessions.contains_key(&session_id) {
            return;
        }

        let mut table = CandidateTable::new(peer, session_id);
        let cap = self.config.max_candidates_per_session;
        for c in &self.local_candidates {
            table.add_local(c.clone(), cap);
        }

        self.sessions.insert(
            session_id,
            SessionState {
                peer,
                session_id,
                candidates: table,
                started_at: now,
            },
        );

        // Publish our candidates and look up theirs.
        let local = self.sessions[&session_id].candidates.local().to_vec();
        if !local.is_empty() {
            let announce = CandidateAnnounce {
                node_id: self.node_id,
                candidates: local,
                session_id,
                timestamp: now,
                signature: [0u8; 64], // signed by the caller
            };
            self.outbound.push_back(Outbound::PublishCandidates(announce));
        }
        self.outbound.push_back(Outbound::LookupCandidates {
            target: peer,
            session_id,
        });
        self.events.push_back(NatEvent::SessionStarted {
            peer,
            session_id,
        });
    }

    /// Record a probe result for a session.
    pub fn on_probe_result(
        &mut self,
        session_id: [u8; 16],
        addr: Address,
        success: bool,
        _now: Timestamp,
    ) {
        let (peer, established) = match self.sessions.get_mut(&session_id) {
            Some(s) => {
                s.candidates.record_probe(addr, success);
                (s.peer, s.candidates.established())
            }
            None => return,
        };
        if success {
            self.events.push_back(NatEvent::CandidateReachable {
                session_id,
                addr,
            });
            if let Some(a) = established {
                self.events.push_back(NatEvent::DirectPathEstablished { peer, addr: a });
            }
        }
    }

    /// Look up a session by ID.
    pub fn session(&self, session_id: &[u8; 16]) -> Option<&SessionState> {
        self.sessions.get(session_id)
    }

    /// Number of live sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Read access to the relay manager.
    pub fn relays(&self) -> &RelayManager {
        &self.relay_manager
    }

    /// Mutable access to the relay manager.
    pub fn relays_mut(&mut self) -> &mut RelayManager {
        &mut self.relay_manager
    }

    fn emit_connectivity_announce(&mut self, now: Timestamp) {
        let external = match self.address.external() {
            Some(a) => a,
            None => return,
        };
        let announce = ConnectivityAnnounce {
            node_id: self.node_id,
            external_addr: external,
            internal_addr: self.local_addr,
            nat_type: self.address.nat_type(),
            port_preservation: true, // TODO(M3b.3): infer from observation consistency
            relay_capable: false,
            capacity: 0,
            timestamp: now,
            signature: [0u8; 64], // signed by the caller
        };
        self.outbound
            .push_back(Outbound::PublishConnectivity(announce));
        self.last_announce = Some(now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn addr(b: u8) -> Address {
        Address::V4 {
            ip: [127, 0, 0, b],
            port: 4433,
        }
    }

    /// A relay entry with default capacity and cost.
    fn relay(b: u8) -> RelayEntry {
        RelayEntry {
            relay_id: nid(b),
            external_addr: addr(b),
            capacity: 100,
            load: 0,
            cost: 0,
        }
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    // ---- M3a ----

    #[test]
    fn hole_punch_succeeds_within_five_attempts() {
        let mut s = HolePunchSession::start(nid(1), HolePunchRole::Initiator);
        for _ in 0..5 {
            s.punch().unwrap();
        }
        assert_eq!(s.attempts, 5);
        assert!(!s.established);
    }

    #[test]
    fn hole_punch_fails_after_six_attempts() {
        let mut s = HolePunchSession::start(nid(1), HolePunchRole::Initiator);
        for _ in 0..5 {
            s.punch().unwrap();
        }
        assert!(matches!(s.punch(), Err(Error::NatUnreachable)));
    }

    #[test]
    fn hole_punch_established_is_terminal() {
        let mut s = HolePunchSession::start(nid(1), HolePunchRole::Responder);
        s.on_packet();
        for _ in 0..100 {
            s.punch().unwrap();
        }
    }

    #[test]
    fn relay_manager_finds_and_bounds() {
        let mut m = RelayManager::new();
        m.offer(relay(10), Some(nid(1)));
        m.offer(relay(20), Some(nid(1)));
        m.offer(relay(30), Some(nid(2)));
        assert_eq!(m.find(&nid(1)).len(), 2);
        assert_eq!(m.find(&nid(2)).len(), 1);
        assert_eq!(m.find(&nid(99)).len(), 0);
    }

    #[test]
    fn relay_manager_hop_limit() {
        assert!(RelayManager::check_hops(0).is_ok());
        assert!(RelayManager::check_hops(RELAY_HOP_LIMIT).is_ok());
        assert!(RelayManager::check_hops(RELAY_HOP_LIMIT + 1).is_err());
    }

    // ---- M3b.1 ----

    #[test]
    fn address_state_picks_most_consistent() {
        let mut s = AddressState::new();
        s.observe(nid(1), addr(10));
        s.observe(nid(2), addr(10));
        s.observe(nid(3), addr(20));
        assert_eq!(s.external(), Some(addr(10)));
    }

    #[test]
    fn address_state_infers_open_nat() {
        let mut s = AddressState::new();
        s.observe(nid(1), addr(10));
        s.observe(nid(2), addr(10));
        s.observe(nid(3), addr(10));
        assert_eq!(s.nat_type(), crate::nat_wire::NAT_TYPE_OPEN);
    }

    #[test]
    fn address_state_infers_symmetric_nat() {
        let mut s = AddressState::new();
        s.observe(nid(1), addr(10));
        s.observe(nid(2), addr(11));
        s.observe(nid(3), addr(12));
        assert_eq!(s.nat_type(), crate::nat_wire::NAT_TYPE_SYMMETRIC);
    }

    #[test]
    fn candidate_table_prunes_stale() {
        use crate::nat_wire::{Candidate, CANDIDATE_HOST};
        let mut t = CandidateTable::new(nid(1), [0u8; 16]);
        let c = Candidate {
            addr: addr(10),
            kind: CANDIDATE_HOST,
            priority: 100,
            foundation: "f".into(),
            component: 0,
        };
        t.add_remote(c, now(), 32);
        let later = Timestamp::from_millis(now().as_millis() + 60_000);
        let pruned = t.prune(later, 30);
        assert_eq!(pruned, 1);
    }

    #[test]
    fn candidate_table_orders_by_priority_class() {
        use crate::nat_wire::{Candidate, CANDIDATE_HOST, CANDIDATE_RELAYED};
        let mut t = CandidateTable::new(nid(1), [0u8; 16]);
        let relayed = Candidate {
            addr: addr(10),
            kind: CANDIDATE_RELAYED,
            priority: 100,
            foundation: "r".into(),
            component: 0,
        };
        let host = Candidate {
            addr: addr(11),
            kind: CANDIDATE_HOST,
            priority: 1,
            foundation: "h".into(),
            component: 0,
        };
        t.add_remote(relayed, now(), 32);
        t.add_remote(host.clone(), now(), 32);
        let next = t.next_to_probe(now(), 30).unwrap();
        assert_eq!(next.addr, host.addr, "host must be probed before relayed");
    }
}