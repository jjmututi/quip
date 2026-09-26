//! Async NAT traversal driver (spec §12).
//!
//! [`NatDriver`] wraps [`NatTraversal`] and drives it: outbound requests
//! are routed to the DHT client or the peer connection, and inbound DHT
//! results and peer messages feed back into the state machine.
//!
//! # DHT decoupling
//!
//! The DHT is behind [`DhtClient`]. The trait is synchronous: a real
//! implementation runs the network in a background task and queues
//! results, draining them via [`DhtClient::poll`]. This keeps the
//! driver runtime-agnostic beyond `tokio` for the QUIC side.

use crate::error::Result;
use crate::message::Message;
use crate::nat::{NatConfig, NatEvent, NatTraversal, Outbound};
use crate::nat_wire::{
    CandidateAnnounce, ConnectivityAnnounce, RelayDiscovery, RelayResponse,
};
use crate::transport::ConnectionDriver;
use alloc::string::String;
use alloc::vec::Vec;
use quip_core::address::Address;
use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;
use quip_core::messages::Signer;

/// A sink for outbound DHT requests and a source for inbound results.
///
/// Implementations route `publish_*` and `lookup_*` calls to the Coral
/// DHT and push results into an internal queue that [`Self::poll`]
/// drains.
pub trait DhtClient {
    /// Publish a connectivity announcement to the DHT.
    fn publish_connectivity(&mut self, announce: ConnectivityAnnounce);
    /// Ask the DHT for a peer's connectivity.
    fn lookup_connectivity(&mut self, target: NodeId);
    /// Publish candidates for a session.
    fn publish_candidates(&mut self, announce: CandidateAnnounce);
    /// Ask the DHT for a peer's candidates in a session.
    fn lookup_candidates(&mut self, target: NodeId, session_id: [u8; 16]);
    /// Ask the DHT for relays to a target.
    fn discover_relays(&mut self, discovery: RelayDiscovery);
    /// Drain the next inbound result, if any.
    fn poll(&mut self) -> Option<DhtResult>;
}

/// Application-side actions the driver cannot perform itself.
///
/// The driver owns the NAT state machine but not a QUIC `Endpoint`
/// and not a `Signer`. Two `NatEvent`s therefore require the
/// application to act:
///
/// - [`NatEvent::ProbeRequested`]: dial the candidate with a fresh
///   QUIC connection, apply the 5 s timeout from App. A.5, and call
///   back into [`NatDriver::on_probe_result`].
/// - [`NatEvent::RelayDiscoveryRequested`]: sign and send a
///   `relay_discovery` (§12.2). The driver builds the message for
///   you; see [`NatDriver::dispatch_event`].
pub trait NatApplication {
    /// Dial `addr` on a fresh QUIC connection. Must eventually call
    /// `NatDriver::on_probe_result` with the outcome.
    fn probe_candidate(&mut self, session_id: [u8; 16], peer: NodeId, addr: Address);

    /// Deliver a signed `relay_discovery` message. The driver has
    /// already signed it.
    fn send_relay_discovery(&mut self, msg: RelayDiscovery);

    /// Surface a session-level NAT event the application may want to
    /// observe (path established, session failed, external address
    /// changed, …). Default is a no-op.
    fn on_nat_event(&mut self, _event: &NatEvent) {}
}

/// One result from the DHT.
#[derive(Clone, Debug)]
pub enum DhtResult {
    /// A `connectivity_announce` the DHT returned.
    Connectivity(ConnectivityAnnounce),
    /// One or more `candidate_announce` messages.
    Candidates(Vec<CandidateAnnounce>),
    /// One or more `relay_response` messages.
    ///
    /// Each response carries its own `target` field (§12.2), so the
    /// driver can register relays against the correct target without
    /// any out-of-band correlation state.
    Relays(Vec<RelayResponse>),
    /// The DHT reported an error for a prior request.
    Error(String),
}

/// A `DhtClient` that drops everything. Useful for tests and for
/// deployments that run without DHT integration.
#[derive(Default)]
pub struct NullDhtClient;

impl DhtClient for NullDhtClient {
    fn publish_connectivity(&mut self, _: ConnectivityAnnounce) {}
    fn lookup_connectivity(&mut self, _: NodeId) {}
    fn publish_candidates(&mut self, _: CandidateAnnounce) {}
    fn lookup_candidates(&mut self, _: NodeId, _: [u8; 16]) {}
    fn discover_relays(&mut self, _: RelayDiscovery) {}
    fn poll(&mut self) -> Option<DhtResult> {
        None
    }
}

/// Async NAT traversal driver.
pub struct NatDriver<D: DhtClient> {
    state: NatTraversal,
    dht: D,
}

impl<D: DhtClient> NatDriver<D> {
    /// Build a new driver.
    pub fn new(node_id: NodeId, local_addr: Address, config: NatConfig, dht: D) -> Self {
        Self {
            state: NatTraversal::new(node_id, local_addr, config),
            dht,
        }
    }

    /// Read access to the state machine.
    pub fn state(&self) -> &NatTraversal {
        &self.state
    }

    /// Mutable access to the state machine.
    pub fn state_mut(&mut self) -> &mut NatTraversal {
        &mut self.state
    }

    /// Drain pending DHT results into the state machine.
    pub fn drain_dht(&mut self, now: Timestamp) {
        while let Some(result) = self.dht.poll() {
            match result {
                DhtResult::Connectivity(a) => self.state.on_connectivity_announce(a, now),
                DhtResult::Candidates(cs) => {
                    for c in cs {
                        self.state.on_candidate_announce(c, now);
                    }
                }
                DhtResult::Relays(responses) => {
                    for r in responses {
                        self.state.on_relay_response(r, now);
                    }
                }
                DhtResult::Error(_) => {
                    // Logged by the DHT client; nothing to do here.
                }
            }
        }
    }

    /// Advance the driver. Sends outbound requests via `conn` or the
    /// DHT client and returns any NAT events produced.
    pub async fn poll(
        &mut self,
        conn: &mut ConnectionDriver,
        now: Timestamp,
    ) -> Result<Vec<NatEvent>> {
        self.drain_dht(now);

        let outbound = self.state.poll(now);
        let mut forwarded: Vec<NatEvent> = Vec::new();
        for out in outbound {
            match out {
                Outbound::PublishConnectivity(a) => self.dht.publish_connectivity(a),
                Outbound::LookupConnectivity(t) => self.dht.lookup_connectivity(t),
                Outbound::PublishCandidates(a) => self.dht.publish_candidates(a),
                Outbound::LookupCandidates { target, session_id } => {
                    self.dht.lookup_candidates(target, session_id);
                }
                Outbound::DiscoverRelays(d) => self.dht.discover_relays(d),
                Outbound::SendToPeer { target: _, msg } => {
                    // M3b.2 sends on the one connection passed in. A
                    // full implementation would look up the per-peer
                    // connection or dial one; that is M6 territory.
                    let _ = conn.send(&msg, now).await;
                }
                Outbound::ProbeCandidate {
                    session_id,
                    peer,
                    candidate,
                } => {
                    // A connectivity check is QUIC path validation
                    // against an address we hold no connection to, so
                    // it needs an `Endpoint` this driver does not own.
                    forwarded.push(NatEvent::ProbeRequested {
                        session_id,
                        peer,
                        addr: candidate.addr,
                    });
                }
                Outbound::RequestRelays {
                    target,
                    max_hops,
                    request_id,
                } => {
                    // `relay_discovery` must carry the requester's signature
                    // (§12.2); the application holds the `Signer`. The request_id
                    // comes from the state machine so the matching response can be
                    // demultiplexed by request_id and target.
                    forwarded.push(NatEvent::RelayDiscoveryRequested {
                        target,
                        max_hops,
                        request_id,
                    });
                }
            }
        }

        let mut events = self.state.drain_events();
        events.extend(forwarded);
        Ok(events)
    }

    /// Sign a `relay_discovery` for an emitted request.
    ///
    /// The message shape is fixed by §12.2; the only application input
    /// is the `Signer`. Returns the signed message ready to be placed
    /// on the wire by the caller.
    pub fn build_relay_discovery<S: Signer>(
        &self,
        signer: &S,
        target: NodeId,
        max_hops: u8,
        request_id: [u8; 16],
        now: Timestamp,
    ) -> Result<RelayDiscovery> {
        let mut msg = RelayDiscovery {
            request_id,
            requester: *self.state.node_id(),
            target,
            max_hops: max_hops as u64,
            timestamp: now,
            signature: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.signature = signer.sign_ed25519(&payload);
        Ok(msg)
    }

    /// Route an emitted [`NatEvent`] to the application.
    ///
    /// Call this for every event returned by [`Self::poll`]. Events
    /// the application must act on are dispatched to `app`; events
    /// the application may merely observe are forwarded via
    /// [`NatApplication::on_nat_event`].
    ///
    /// Returns `Ok(())` for all currently-defined events. The
    /// `Result` exists so that future event types that require
    /// signing can surface a crypto error without changing the
    /// signature.
    pub fn dispatch_event<S: Signer, A: NatApplication>(
        &self,
        event: NatEvent,
        signer: &S,
        app: &mut A,
        now: Timestamp,
    ) -> Result<()> {
        match &event {
            NatEvent::ProbeRequested {
                session_id,
                peer,
                addr,
            } => {
                app.probe_candidate(*session_id, *peer, *addr);
            }
            NatEvent::RelayDiscoveryRequested {
                target,
                max_hops,
                request_id,
            } => {
                let msg = self.build_relay_discovery(
                    signer,
                    *target,
                    *max_hops,
                    *request_id,
                    now,
                )?;
                app.send_relay_discovery(msg);
            }
            _ => {}
        }
        app.on_nat_event(&event);
        Ok(())
    }

    /// Convenience: `poll` then `dispatch_event` for every event.
    ///
    /// Equivalent to calling [`Self::poll`] and looping over the
    /// result with [`Self::dispatch_event`]. Use this when the
    /// application does not need to inspect the events before
    /// dispatching.
    pub async fn poll_and_dispatch<S: Signer, A: NatApplication>(
        &mut self,
        conn: &mut ConnectionDriver,
        signer: &S,
        app: &mut A,
        now: Timestamp,
    ) -> Result<usize> {
        let events = self.poll(conn, now).await?;
        let n = events.len();
        for e in events {
            self.dispatch_event(e, signer, app, now)?;
        }
        Ok(n)
    }

    /// Feed an inbound NAT message from a peer into the state machine.
    ///
    /// `relay_response` messages carry their own `target` field (§12.2),
    /// so no out-of-band correlation is needed. Ignored for message
    /// types the state machine does not handle.
    pub fn on_peer_message(&mut self, msg: &Message, now: Timestamp) {
        match msg {
            Message::ConnectivityAnnounce(a) => {
                self.state.on_connectivity_announce(a.clone(), now)
            }
            Message::CandidateAnnounce(a) => {
                self.state.on_candidate_announce(a.clone(), now)
            }
            Message::RelayResponse(r) => {
                self.state.on_relay_response(r.clone(), now)
            }
            _ => {}
        }
    }

    /// Record an address observation from a DHT peer.
    pub fn on_address_observed(
        &mut self,
        observer: NodeId,
        observed: Address,
        now: Timestamp,
    ) {
        self.state.on_address_observed(observer, observed, now);
    }

    /// Begin a NAT traversal session with a peer.
    pub fn start_session(&mut self, peer: NodeId, session_id: [u8; 16], now: Timestamp) {
        self.state.start_session(peer, session_id, now);
    }

    /// Record a connectivity probe result.
    pub fn on_probe_result(
        &mut self,
        session_id: [u8; 16],
        addr: Address,
        success: bool,
        now: Timestamp,
    ) {
        self.state
            .on_probe_result(session_id, addr, success, now);
    }

    /// Consume the driver, returning the DHT client.
    pub fn into_dht(self) -> D {
        self.dht
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::{AddressState, CandidateTable, NatConfig};
    use alloc::vec::Vec;
    use alloc::string::ToString;
    use quip_core::address::Address;
    use quip_core::time::Timestamp;
    use crate::test_support::FakeSigner;
    use crate::nat_wire::RelayDiscovery;

    #[derive(Default)]
    struct RecordingApp {
        probes: Vec<([u8; 16], NodeId, Address)>,
        relays: Vec<RelayDiscovery>,
        observed: Vec<String>,
    }

    impl NatApplication for RecordingApp {
        fn probe_candidate(&mut self, session_id: [u8; 16], peer: NodeId, addr: Address) {
            self.probes.push((session_id, peer, addr));
        }
        fn send_relay_discovery(&mut self, msg: RelayDiscovery) {
            self.relays.push(msg);
        }
        fn on_nat_event(&mut self, event: &NatEvent) {
            let tag = match event {
                NatEvent::ProbeRequested { .. } => "probe",
                NatEvent::RelayDiscoveryRequested { .. } => "relay",
                NatEvent::SessionFailed { .. } => "failed",
                NatEvent::DirectPathEstablished { .. } => "direct",
                _ => "other",
            };
            self.observed.push(tag.into());
        }
    }

    #[test]
    fn dispatch_probe_event_calls_application() {
        let d = NatDriver::new(
            nid(1),
            addr(1),
            NatConfig::default(),
            RecordingDht::default(),
        );
        let signer = FakeSigner::new(1);
        let mut app = RecordingApp::default();

        d.dispatch_event(
            NatEvent::ProbeRequested {
                session_id: [0x11; 16],
                peer: nid(2),
                addr: addr(5),
            },
            &signer,
            &mut app,
            now(),
        )
        .unwrap();

        assert_eq!(app.probes.len(), 1);
        assert_eq!(app.probes[0], ([0x11; 16], nid(2), addr(5)));
        assert!(app.relays.is_empty());
        assert_eq!(app.observed, alloc::vec!["probe".to_string()]);
    }

    #[test]
    fn dispatch_relay_event_signs_and_forwards() {
        let d = NatDriver::new(
            nid(1),
            addr(1),
            NatConfig::default(),
            RecordingDht::default(),
        );
        let signer = FakeSigner::new(1);
        let mut app = RecordingApp::default();

        let request_id = [0xAA; 16];
        d.dispatch_event(
            NatEvent::RelayDiscoveryRequested {
                target: nid(7),
                max_hops: 2,
                request_id,
            },
            &signer,
            &mut app,
            now(),
        )
        .unwrap();

        assert_eq!(app.relays.len(), 1);
        let msg = &app.relays[0];
        assert_eq!(msg.requester, nid(1));
        assert_eq!(msg.target, nid(7));
        assert_eq!(msg.max_hops, 2);
        assert_eq!(msg.request_id, request_id);
        // Signature is non-zero, and matches the signing payload.
        assert_ne!(msg.signature, [0u8; 64]);
        let expected = signer.sign_ed25519(&msg.signing_payload().unwrap());
        assert_eq!(msg.signature, expected);
    }

    #[test]
    fn dispatch_ignores_observation_only_events() {
        let d = NatDriver::new(
            nid(1),
            addr(1),
            NatConfig::default(),
            RecordingDht::default(),
        );
        let signer = FakeSigner::new(1);
        let mut app = RecordingApp::default();

        d.dispatch_event(
            NatEvent::SessionFailed {
                peer: nid(2),
                session_id: [0u8; 16],
            },
            &signer,
            &mut app,
            now(),
        )
        .unwrap();

        assert!(app.probes.is_empty());
        assert!(app.relays.is_empty());
        assert_eq!(app.observed, alloc::vec!["failed".to_string()]);
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn addr(b: u8) -> Address {
        Address::V4 {
            ip: [127, 0, 0, b],
            port: 4433,
        }
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    /// Records every outbound request and lets the test push results.
    #[derive(Default)]
    struct RecordingDht {
        published_connectivity: Vec<ConnectivityAnnounce>,
        published_candidates: Vec<CandidateAnnounce>,
        connectivity_lookups: Vec<NodeId>,
        candidate_lookups: Vec<(NodeId, [u8; 16])>,
        relay_lookups: Vec<RelayDiscovery>,
        queue: Vec<DhtResult>,
    }

    impl DhtClient for RecordingDht {
        fn publish_connectivity(&mut self, a: ConnectivityAnnounce) {
            self.published_connectivity.push(a);
        }
        fn lookup_connectivity(&mut self, t: NodeId) {
            self.connectivity_lookups.push(t);
        }
        fn publish_candidates(&mut self, a: CandidateAnnounce) {
            self.published_candidates.push(a);
        }
        fn lookup_candidates(&mut self, t: NodeId, s: [u8; 16]) {
            self.candidate_lookups.push((t, s));
        }
        fn discover_relays(&mut self, d: RelayDiscovery) {
            self.relay_lookups.push(d);
        }
        fn poll(&mut self) -> Option<DhtResult> {
            self.queue.pop()
        }
    }

    #[test]
    fn start_session_emits_publish_and_lookup() {
        let mut d = NatDriver::new(nid(1), addr(1), NatConfig::default(), RecordingDht::default());
        d.state_mut().on_address_observed(nid(2), addr(10), now());
        d.start_session(nid(3), [7u8; 16], now());
        // Drain via a fake "drain_dht + poll" without a connection:
        // we call the state machine directly here.
        let out = d.state_mut().poll(now());
        // Expect LookupCandidates; PublishCandidates is only emitted
        // when local candidates exist.
        assert!(out.iter().any(|o| matches!(
            o,
            Outbound::LookupCandidates { target, .. } if target == &nid(3)
        )));
    }

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
        use crate::nat_wire::Candidate;
        let mut t = CandidateTable::new(nid(1), [0u8; 16]);
        let c = Candidate {
            addr: addr(10),
            kind: crate::nat_wire::CANDIDATE_HOST,
            priority: 100,
            foundation: "f".into(),
            component: 0,
        };
        t.add_remote(c.clone(), now(), 32);
        let later = Timestamp::from_millis(now().as_millis() + 60_000);
        let pruned = t.prune(later, 30);
        assert_eq!(pruned, 1);
    }

    #[test]
    fn candidate_table_orders_by_priority_class() {
        use crate::nat_wire::{
            Candidate, CANDIDATE_HOST, CANDIDATE_RELAYED,
        };
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

    #[test]
    fn dht_result_relays_carries_targets_in_responses() {
        let r = RelayResponse {
            request_id: [1u8; 16],
            target: nid(7),
            requester: nid(1),
            relays: vec![],
            timestamp: Timestamp::from_millis(0),
            signature: [0u8; 64],
        };
        let result = DhtResult::Relays(vec![r]);
        match result {
            DhtResult::Relays(rs) => {
                assert_eq!(rs.len(), 1);
                assert_eq!(rs[0].target, nid(7));
            }
            _ => panic!("expected Relays"),
        }
    }
}