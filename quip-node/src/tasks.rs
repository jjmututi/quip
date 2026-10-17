//! Background tasks: the machinery the [`Node`](crate::Node) spawns.
//!
//! Everything here runs as a `tokio` task behind the node's public
//! API: the DHT router, the accept loop, the per-peer establishment
//! and steady-state loops, and the NAT/discovery helpers those loops
//! drive. Moved out of `lib.rs` so the node's public surface stays
//! readable; the tasks are `pub(crate)` and are called only from the
//! `Node` implementation.

use quip_core::cbor::decode;
use quip_core::dvv::NodeId;
use quip_core::messages::{KeyClaim, Signer, WitnessStatement};
use quip_core::time::Timestamp;
use quip_net::coral::{LookupPath, LookupResponse};
use quip_net::crypto::{Ed25519Signer, Ed25519Verifier};
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
use quip_net::nat_wire::{
    Candidate, CandidateAnnounce, RelayEntry, RelayResponse, CANDIDATE_HOST,
};
use quip_net::transport::{
    ClientConfig, ConnectionDriver, Endpoint, Event,
};
use quip_net::{Error, GATEWAY_ROUTER_COUNT, Result};
use quip_storage::blob::BlobStore;
use quip_storage::QuipStore;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};

use crate::dht;
use crate::dht::DhtHandle;
use crate::discovery::DiscoveryHandle;
use crate::config::{make_key_claim, SharedClock, SharedSigner};
use crate::event::NodeEvent;
use crate::peer::{PeerLifecycle, PeerSlot};
use crate::registry::{register_peer, unregister_peer, PeerRegistry, TaskMap};
use crate::trust::PeerTrust;
use crate::witness::{issue_statement, WitnessStore};
use crate::{
    set_peer_lifecycle, DISCOVERY_WAIT_MS, LOCAL_CANDIDATE_PRIORITY, NAT_PHASE_TIMEOUT_MS,
    OUTBOUND_CAPACITY, SharedTrust,
};

/// Drain the DHT's outbound queue and forward each message to every
/// connected peer.
///
/// A later milestone replaces this with XOR-distance routing over a
/// real DHT peer set. For now the network is small enough that
/// broadcast is correct and cheap.
pub(crate) async fn dht_router_task(
    mut rx: mpsc::UnboundedReceiver<dht::Outbound>,
    peers: PeerRegistry,
    dht: DhtHandle,
) {
    while let Some(out) = rx.recv().await {
        let senders: Vec<mpsc::Sender<Message>> = {
            let reg = peers.lock().await;
            match out.target {
                Some(peer) => reg
                    .outbound_of(&peer)
                    .into_iter()
                    .collect(),
                None => {
                    // Mesh verb: forward to the k closest routing-eligible
                    // peers by XOR distance, not the whole mesh. A mesh verb
                    // always carries a key; if it does not, fall back to
                    // broadcast.
                    let targets: Vec<NodeId> = match out.key {
                        Some(key) => dht.closest_to(&key, GATEWAY_ROUTER_COUNT),
                        None => reg.peer_ids(),
                    };
                    targets
                        .into_iter()
                        .filter_map(|p| reg.outbound_of(&p))
                        .collect()
                }
            }
        };
        for tx in senders {
            let _ = tx.send(out.msg.clone()).await;
        }
    }
}

/// Accept inbound connections, drive each handshake, spawn a peer loop.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn accept_loop<B>(
    endpoint: Arc<Endpoint>,
    peers: PeerRegistry,
    peer_tasks: TaskMap,
    store: Arc<Mutex<QuipStore<B>>>,
    clock: SharedClock,
    auto_serve_pins: bool,
    relay_capable: bool,
    force_relay: bool,
    events_tx: mpsc::Sender<NodeEvent>,
    dht: DhtHandle,
    discovery: DiscoveryHandle,
    trust: SharedTrust,
    witness: WitnessStore,
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
        let witness = witness.clone();
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

            // On the accept side, our own NodeId comes from the
            // driver's local Key Claim — the server config baked it
            // in at bind time.
            let local_id = driver.local_key_claim().node_id;

            let task_peers = Arc::clone(&peers);
            peer_run(
                driver,
                peer,
                slot,
                local_id,
                store,
                clock,
                auto_serve_pins,
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
pub(crate) async fn drive_handshake(
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
pub(crate) fn make_lookup_paths(target: NodeId, _now: Timestamp) -> Vec<LookupPath> {
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
    flow: Option<&mut ConnectionFlow>,
    witness: &WitnessStore,
) {
    let now = clock.now();
    match msg {
        Message::CoralLookupResponse(resp) => {
            // M9.6a: the responder fills `values` with encoded
            // `WitnessStatement`s. Decode them, feed the flow (seam 2)
            // and the store (seam 1), then hand the discovery client a
            // NodeId view of the same response: the client's ring
            // resolution interprets each value as a 32-byte NodeId, so
            // it cannot consume the encoded form directly.
            let resp = decode_lookup_values(resp, flow, witness, now);
            if let Ok(outbound) = discovery.ingest_lookup_response(resp, now) {
                for out in outbound {
                    if let Some(m) = outbound_to_message(out) {
                        let _ = driver.send(&m, clock.now()).await;
                    }
                }
            }
        }
        Message::AnnounceWitness(stmt) => {
            // Seams 1 and 2: a statement arriving on the establishing
            // connection is stored node-wide and fed to the flow so
            // `compute_kt_status` counts it.
            feed_witness_statement(&stmt, flow, witness, now);
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

/// Feed one witness statement to the node-wide store and the flow.
///
/// Verification gates both: an unverified statement is neither stored
/// nor counted. A statement the store rejects as an *older replay* is
/// still offered to the flow only when it passed [`WitnessStore::accepts`];
/// the flow's per-witness map is last-write-wins, so a replay cannot
/// displace a fresher entry either.
fn feed_witness_statement(
    stmt: &WitnessStatement,
    flow: Option<&mut ConnectionFlow>,
    witness: &WitnessStore,
    now: Timestamp,
) {
    if !witness.accepts(stmt, now) {
        return;
    }
    let _ = witness.ingest(stmt.clone(), now);
    if let Some(flow) = flow {
        if flow.remote_node_id() == Some(stmt.subject) {
            let _ = flow.on_message(&Message::AnnounceWitness(stmt.clone()), now);
        }
    }
}

/// Decode witness statements out of a lookup response's `values`, feed
/// them to the flow and store, and return the response with `values`
/// rewritten to the 32-byte witness NodeIds the discovery client
/// expects.
///
/// A value that does not decode as a `WitnessStatement` is passed
/// through unchanged: an older responder may still return bare NodeIds.
fn decode_lookup_values(
    mut resp: LookupResponse,
    mut flow: Option<&mut ConnectionFlow>,
    witness: &WitnessStore,
    now: Timestamp,
) -> LookupResponse {
    let mut ids: Vec<Vec<u8>> = Vec::with_capacity(resp.values.len());
    let mut decoded: Vec<WitnessStatement> = Vec::new();
    for value in &resp.values {
        match decode(value)
            .ok()
            .and_then(|cbor| WitnessStatement::from_cbor(&cbor).ok())
        {
            Some(stmt) => {
                ids.push(stmt.witness.to_vec());
                decoded.push(stmt);
            }
            None => ids.push(value.clone()),
        }
    }
    for stmt in &decoded {
        feed_witness_statement(stmt, flow.as_deref_mut(), witness, now);
    }
    resp.values = ids;
    resp
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
    witness: &WitnessStore,
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
                // A failed discovery must not linger: the next attempt
                // for the same target would otherwise be treated as
                // already in flight and never issue a lookup. M9.6a's
                // reconnect path depends on this.
                discovery.forget(&peer);
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
                    handle_discovery_event(
                        driver, clock, discovery, m, Some(flow), witness,
                    )
                    .await;
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
// NAT phase (M9.5b-c parts 3, 5, and 6)
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
/// peer had announced it, announces our own host candidate, and drives
/// the state machine to a terminal event.
///
/// # Why the peer's transport address is seeded
///
/// The transport is up and the address it is using is the peer's
/// address, so it is known-reachable without a wire round trip.
/// Seeding it gives the state machine a candidate to probe
/// immediately, before the peer's own signed `candidate_announce`
/// arrives on the inbound path.
///
/// When `force_relay` is set, the session is put onto the relay branch
/// by policy and the seed is irrelevant — a forced session ignores
/// every inbound candidate, including the seeded one. The seed is
/// still applied so that the wire-visible announce is identical in
/// both modes; only the state machine's handling of the inbound
/// candidate differs.
///
/// # Signer
///
/// Outbound §12 verbs — candidate announces and relay discoveries —
/// are signed with `signer`. The peer's `dht_result_from` rejects
/// unsigned announces, so the signing is what makes *our* candidate
/// reach the peer's state machine.
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
///
/// # Inbound
///
/// Inbound §12 verbs on T0 are verified by `dht::dht_result_from`
/// before reaching the state machine. That is the same check the
/// steady loop applies; the alternative — pushing the raw message
/// into `NatDriver::on_peer_message` — does not verify, so it would
/// accept a forged `relay_response`.
///
/// An inbound `relay_discovery` is answered here as well, via
/// `try_serve_relay_discovery`, when `relay_capable` is set. The
/// steady loop answers it identically; handling it here too keeps a
/// discovery that arrives while this peer is still establishing from
/// being consumed and dropped by `driver.poll`.
#[allow(clippy::too_many_arguments)]
async fn run_nat_phase(
    driver: &mut ConnectionDriver,
    peer: NodeId,
    session_id: [u8; 16],
    local_id: NodeId,
    clock: &SharedClock,
    dht: &DhtHandle,
    signer: &SharedSigner,
    relay_capable: bool,
    force_relay: bool,
) -> NatPhaseOutcome {
    use quip_net::nat_driver::DhtClient;

    let now = clock.now();

    let local_addr = local_ip_address(driver);
    let transport_addr = socket_to_address(driver.remote_addr());

    // Build a per-peer NatConfig. `force_relay` is the only deviation
    // from `NatConfig::default`; every session this driver starts is
    // put onto the relay branch if the node is configured for it.
    let nat_config = NatConfig {
        force_relay,
        ..NatConfig::default()
    };

    let mut nat_driver = NatDriver::new(
        local_id,
        local_addr,
        nat_config,
        dht.clone(),
    );

    // Register the session so `publish_candidates` routes to `peer`.
    dht.note_session(session_id, peer);

    nat_driver.start_session(peer, session_id, now);

    // Belt-and-braces: the config above already forces every session,
    // but calling `force_relay_for` makes the intent explicit at the
    // call site and covers a driver that changed its config between
    // construction and start.
    if force_relay {
        nat_driver.force_relay_for(&session_id);
    }

    // Seed the peer's current transport address into our state
    // machine, as if the peer had announced it. A forced session will
    // ignore it; an unforced one probes it and short-circuits to
    // success below.
    let seeded_candidate = Candidate {
        addr: transport_addr,
        kind: CANDIDATE_HOST,
        priority: LOCAL_CANDIDATE_PRIORITY,
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
        priority: LOCAL_CANDIDATE_PRIORITY,
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
                        probe_candidate(addr, Duration::from_secs(5), now).await
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
                DriverNatEvent::RelayPathAvailable {
                    session_id,
                    relay,
                    ..
                } => {
                    // The state machine surfaced a relay; attempt it.
                    // On loopback the relay is the peer itself, which
                    // the transport already proves reachable, so the
                    // attempt trivially succeeds. A real network would
                    // route through the relay and report the outcome.
                    nat_driver.on_relay_result(
                        session_id,
                        relay.relay_id,
                        true,
                        now,
                    );
                }
                _ => {}
            }
        }

        if std::time::Instant::now() >= deadline {
            break 'outer NatPhaseOutcome::Failed;
        }

        // Feed inbound §12 NAT verbs on T0 into the state machine.
        //
        // The verbs are verified with `dht::dht_result_from`, which
        // checks the signature and the claimed sender, before they
        // reach the state machine. This mirrors the steady loop's
        // inbound path; the alternative — `on_peer_message` — does
        // not verify, and a forged `relay_response` would conclude a
        // session that never should have.
        let events = match driver.poll(now).await {
            Ok(e) => e,
            Err(_) => break 'outer NatPhaseOutcome::Failed,
        };
        for event in events {
            if let Event::Frame { tier, msg, .. } = event {
                if let Ok(m) = message::dispatch(&msg.raw, tier) {
                    // M9.5b-c part 6: answer an inbound
                    // `relay_discovery` here too, before the DHT
                    // intercept. The steady loop does the same, but a
                    // discovery that arrives while this peer is still
                    // in its own NAT phase would otherwise be consumed
                    // by `driver.poll` and dropped — the requester
                    // would never receive its relay.
                    if let Some(reply) = try_serve_relay_discovery(
                        &m,
                        &peer,
                        &local_id,
                        driver,
                        relay_capable,
                        signer,
                        now,
                    ) {
                        let _ = driver.send(&reply, now).await;
                        continue;
                    }
                    if let Some(result) = dht::dht_result_from(&m, &peer) {
                        nat_driver.on_dht_result(result, now);
                    }
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
///
/// # Probe identity
///
/// The seed is derived from the current time and the target address,
/// so two probes never share a key. The all-zero seed part 5 used was
/// a fixed identity any node could impersonate; a per-call seed
/// removes that, though it does not make the probe unidentifiable.
///
/// TODO: mark probe connections so the accept loop does not register
/// them as peers. A probe is a path-validation dial (§12.3), not a
/// session; the receiving node's accept loop cannot tell the
/// difference and allocates a slot for every probe. A future
/// transport-level marker (a reserved ALPN, a handshake extension)
/// will let the accept loop skip the peer task for probe connections.
async fn probe_candidate(
    addr: quip_core::address::Address,
    timeout: Duration,
    now: Timestamp,
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
    // *some* claim. The seed is mixed from the timestamp and the
    // target address so no two probes share a key; the resulting
    // identity is still a throwaway, not a long-lived secret.
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&now.as_millis().to_be_bytes());
    match addr {
        quip_core::address::Address::V4 { ip, port } => {
            seed[8..12].copy_from_slice(&ip);
            seed[12..14].copy_from_slice(&port.to_be_bytes());
        }
        quip_core::address::Address::V6 { ip, port } => {
            seed[8..24].copy_from_slice(&ip);
            seed[24..26].copy_from_slice(&port.to_be_bytes());
        }
    }
    let probe_signer = Ed25519Signer::from_seed(&seed);
    let claim = match make_key_claim(&probe_signer, now) {
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

/// Answer an inbound `relay_discovery` if we are relay-capable.
///
/// Returns `Some(response)` when the node should reply, `None`
/// otherwise. The caller sends the response on the same T0 connection
/// the discovery arrived on.
///
/// The conditions for answering:
///
/// - `relay_capable` is set. A node that has not opted in does not
///   relay; the default keeps the responder inert.
/// - The discovery's `requester` is the peer that sent it. This stops
///   a connected peer from asking us to relay on someone else's
///   behalf.
/// - The discovery's `target` is us. §12.2 semantics: a
///   `relay_discovery` asks "give me relays that can reach `target`."
///   We can reach ourselves, so we answer with ourselves.
/// - The discovery's signature verifies against its `requester`. No
///   other code path verifies a `RelayDiscovery`; the receiver is the
///   only place it can happen.
///
/// The `external_addr` in the `RelayEntry` is our transport address,
/// as observed from our side. That is the address a peer should send
/// relayed traffic to.
fn try_serve_relay_discovery(
    msg: &Message,
    peer: &NodeId,
    local_id: &NodeId,
    driver: &ConnectionDriver,
    relay_capable: bool,
    signer: &SharedSigner,
    now: Timestamp,
) -> Option<Message> {
    if !relay_capable {
        return None;
    }
    let discovery = match msg {
        Message::RelayDiscovery(d) => d,
        _ => return None,
    };
    // The requester must be the connection's peer: no relaying on
    // behalf of a third party.
    if discovery.requester != *peer {
        return None;
    }
    // We only relay to ourselves.
    if discovery.target != *local_id {
        return None;
    }
    // Verify the signature. `RelayDiscovery::verify` checks against
    // the message's own `requester` field.
    let verifier = Ed25519Verifier;
    if !matches!(discovery.verify(&verifier), Ok(true)) {
        return None;
    }

    let relay_external = match driver.local_addr() {
        Some(addr) => socket_to_address(addr),
        None => {
            // No local address means the endpoint had already closed
            // when the driver was built; there is no meaningful relay
            // to advertise.
            return None;
        }
    };

    let mut response = RelayResponse {
        request_id: discovery.request_id,
        target: discovery.target,
        requester: discovery.requester,
        relays: vec![RelayEntry {
            relay_id: *local_id,
            external_addr: relay_external,
            // A single relay slot; M9.7 makes this configurable.
            capacity: 1,
            load: 0,
            cost: 0,
        }],
        timestamp: now,
        signature: [0u8; 64],
    };
    let payload = match response.signing_payload() {
        Ok(p) => p,
        Err(_) => return None,
    };
    response.signature = signer.sign_ed25519(&payload);
    Some(Message::RelayResponse(response))
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
/// the peer. M9.6a's seams feed the flow the witness statements the
/// responder returns, so `Ready(Verified)` is reachable once four
/// independent, first-seen-matured witnesses have corroborated the
/// claim.
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
    witness: &WitnessStore,
    trust: &SharedTrust,
    peers: &PeerRegistry,
    dht: &DhtHandle,
    signer: &SharedSigner,
    relay_capable: bool,
    force_relay: bool,
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
                    relay_capable,
                    force_relay,
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
                run_discovery_phase(
                    driver, peer, clock, discovery, &mut flow, witness,
                )
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
pub(crate) async fn peer_run<B>(
    mut driver: ConnectionDriver,
    peer: NodeId,
    slot: PeerSlot,
    local_id: NodeId,
    store: Arc<Mutex<QuipStore<B>>>,
    clock: SharedClock,
    auto_serve_pins: bool,
    relay_capable: bool,
    force_relay: bool,
    events_tx: mpsc::Sender<NodeEvent>,
    mut outbound_rx: mpsc::Receiver<Message>,
    dht: DhtHandle,
    discovery: DiscoveryHandle,
    trust: SharedTrust,
    witness: WitnessStore,
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
        &witness,
        &trust,
        &peers,
        &dht,
        &signer,
        relay_capable,
        force_relay,
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
        local_id,
        &store,
        &clock,
        auto_serve_pins,
        relay_capable,
        &events_tx,
        &mut outbound_rx,
        &dht,
        &discovery,
        &trust,
        &peers,
        &witness,
        &signer,
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
    local_id: NodeId,
    store: &Mutex<QuipStore<B>>,
    clock: &SharedClock,
    auto_serve_pins: bool,
    relay_capable: bool,
    events_tx: &mpsc::Sender<NodeEvent>,
    outbound_rx: &mut mpsc::Receiver<Message>,
    dht: &DhtHandle,
    discovery: &DiscoveryHandle,
    trust: &SharedTrust,
    peers: &PeerRegistry,
    witness: &WitnessStore,
    signer: &SharedSigner,
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

        // M9.5b-c part 7: sample RTT for cluster membership. A peer
        // is routing-eligible only after NatDirect/NatRelayed, so the
        // steady loop is where a confirmed sample first becomes
        // available.
        if let Some(rtt) = driver.rtt() {
            let ms = rtt.as_millis() as u64;
            dht.note_rtt(&peer, &slot, ms);
        }

        // M9.6a §4: the placeholder issuance policy. `maybe_issue`
        // enforces the 12-hour cadence internally, so calling it on
        // every iteration is correct. The signed statement is broadcast
        // to every connected peer: corroboration is useful to any node
        // that asks, not just the connection this task owns, and the
        // subject must receive it too.
        let now = clock.now();
        let due = {
            let policy = trust.lock().await;
            witness.maybe_issue(&policy, now)
        };
        if !due.is_empty() {
            let senders: Vec<mpsc::Sender<Message>> = {
                let reg = peers.lock().await;
                reg.peer_ids()
                    .into_iter()
                    .filter_map(|p| reg.outbound_of(&p))
                    .collect()
            };
            for subject in due {
                let stmt =
                    issue_statement(subject, [0u8; 32], &**signer, now);
                let msg = Message::AnnounceWitness(stmt);
                for tx in &senders {
                    let _ = tx.send(msg.clone()).await;
                }
                witness.mark_issued(subject, now);
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
                            // M9.6a seam 3: a witness statement arriving
                            // in the steady state is stored node-wide
                            // and does not surface as a
                            // `NodeEvent::Message`.
                            if let Message::AnnounceWitness(stmt) = &m {
                                if witness.accepts(stmt, now) {
                                    let _ = witness.ingest(stmt.clone(), now);
                                }
                                continue;
                            }
                            // M9.5b-c part 6: answer an inbound
                            // `relay_discovery` before the DHT
                            // intercept, because the intercept does
                            // not handle that verb. Only a node with
                            // `relay_capable` set replies, and only
                            // when the discovery names this peer as
                            // its requester and this node as its
                            // target.
                            if let Some(reply) = try_serve_relay_discovery(
                                &m,
                                &peer,
                                &local_id,
                                driver,
                                relay_capable,
                                signer,
                                now,
                            ) {
                                if let Err(e) = driver.send(&reply, now).await {
                                    let _ = events_tx
                                        .send(NodeEvent::Error {
                                            peer: Some(peer),
                                            error: e,
                                        })
                                        .await;
                                }
                                continue;
                            }
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
                                    None,
                                    witness,
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
