//! Connection-establishment orchestration (spec §16).
//!
//! [`ConnectionFlow`] sequences the connection-establishment steps of
//! §16 from handshake through Key Claim exchange, NAT traversal, and
//! witness discovery. It is a pure state machine: it takes wire
//! messages and phase-completion signals in, and produces the actions
//! the caller should take out. It does not own a transport, a DHT, or
//! a NAT driver.
//!
//! This module is distinct from [`crate::flow`], which owns the
//! per-stream flow-control frames of §11. That module gates bytes on a
//! single stream; this one drives the phases a *connection* passes
//! through.
//!
//! # Flow
//!
//! ```text
//! AwaitHandshake  --on_handshake()-->  AwaitKeyClaim
//!                                           |
//!                              on_message(AnnounceKey)
//!                                           |
//!                                           v
//!                                     NatTraversal
//!                                           |
//!                              on_nat_complete(true)
//!                                           |
//!                                           v
//!                                 WitnessDiscovery
//!                                           |
//!                        on_discovery_complete(ring)
//!                                           |
//!                                           v
//!                                      Ready(kt_status)
//! ```
//!
//! At each transition the flow emits a [`FlowAction`] telling the
//! caller what to do next: send a Key Claim, start NAT traversal,
//! start witness discovery, or declare the connection ready.
//!
//! # KT status
//!
//! [`KtStatus`] mirrors the table in §5.3.3. The flow computes it from
//! the [`WitnessStatement`]s it has received for the remote NodeId:
//!
//! - `Verified`: 4+ independent, non-expired statements.
//! - `Pending`: fewer than 4, or none.
//!
//! The 6-hour "first seen" rule of §5.3.3 is not enforced here; it
//! concerns the witness's own Key Claim, which is a separate tracking
//! concern.
//!
//! # What this module does not do
//!
//! - It does not verify signatures. Callers MUST verify incoming
//!   `AnnounceKey` and `AnnounceWitness` messages before forwarding
//!   them to [`ConnectionFlow::on_message`].
//! - It does not drive the transport. [`FlowAction::Send`] carries a
//!   [`Message`] the caller encodes and writes on T0.
//! - It does not run NAT traversal or witness discovery. It emits
//!   `StartNatTraversal` and `StartWitnessDiscovery` and waits for
//!   the caller to report the outcome.

use crate::message::Message;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::dvv::NodeId;
use quip_core::messages::{KeyClaim, Signer, WitnessStatement};
use quip_core::time::Timestamp;

// -------------------------------------------------------------------------
// Configuration
// -------------------------------------------------------------------------

/// Timeouts for [`ConnectionFlow::poll`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlowConfig {
    /// How long to wait for the remote Key Claim after the handshake.
    pub key_claim_timeout_ms: u64,
    /// How long to wait for NAT traversal to finish.
    pub nat_timeout_ms: u64,
    /// How long to wait for witness discovery to finish.
    pub discovery_timeout_ms: u64,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self {
            key_claim_timeout_ms: 10_000,
            nat_timeout_ms: 30_000,
            discovery_timeout_ms: 30_000,
        }
    }
}

// -------------------------------------------------------------------------
// Phase, status, failure
// -------------------------------------------------------------------------

/// Coarse phase of a connection flow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowPhase {
    /// Waiting for the handshake to complete.
    AwaitHandshake,
    /// Handshake done; waiting for the remote Key Claim.
    AwaitKeyClaim,
    /// Key Claim exchanged; waiting for NAT traversal.
    NatTraversal,
    /// NAT done; waiting for witness discovery.
    WitnessDiscovery,
    /// Flow completed successfully with the given KT status.
    Ready(KtStatus),
    /// Flow failed.
    Failed(FlowFailure),
}

/// KT status of the remote NodeId (§5.3.3).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KtStatus {
    /// Fewer than 4 witnesses have corroborated the claim.
    Pending,
    /// 4+ independent, non-expired witnesses have corroborated the claim.
    Verified,
}

/// Why a flow failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum FlowFailure {
    /// The remote did not send a Key Claim within
    /// [`FlowConfig::key_claim_timeout_ms`].
    KeyClaimTimeout,
    /// NAT traversal failed.
    NatFailed,
    /// NAT traversal did not finish within [`FlowConfig::nat_timeout_ms`].
    NatTimeout,
    /// Witness discovery did not finish within
    /// [`FlowConfig::discovery_timeout_ms`].
    DiscoveryTimeout,
}

// -------------------------------------------------------------------------
// Actions
// -------------------------------------------------------------------------

/// Something the caller should do in response to a flow transition.
#[derive(Clone, Debug, PartialEq)]
pub enum FlowAction {
    /// Encode `Message` and send it on T0.
    Send(Box<Message>),
    /// Begin NAT traversal with `peer` under `session_id`.
    StartNatTraversal {
        /// The remote NodeId, once known.
        peer: NodeId,
        /// The session identifier the caller should use for
        /// `candidate_announce` and probe tracking.
        session_id: [u8; 16],
    },
    /// Begin witness discovery for `peer`.
    StartWitnessDiscovery {
        /// The remote NodeId, once known.
        peer: NodeId,
    },
    /// The connection is ready for T2/T3 traffic.
    Ready(KtStatus),
    /// The connection could not be established.
    Failed(FlowFailure),
}

// -------------------------------------------------------------------------
// Remote state
// -------------------------------------------------------------------------

/// Per-remote state accumulated by the flow.
#[derive(Clone, Debug)]
struct RemoteState {
    node_id: NodeId,
    /// Retained for future use (rotation checks, re-verification).
    #[allow(dead_code)]
    key_claim: KeyClaim,
    first_seen: Timestamp,
    /// Corroborating witness statements, keyed by witness NodeId so
    /// duplicates overwrite rather than accumulate.
    witnesses: BTreeMap<NodeId, WitnessStatement>,
}

// -------------------------------------------------------------------------
// ConnectionFlow
// -------------------------------------------------------------------------

/// Sequences §16 connection establishment.
pub struct ConnectionFlow {
    local_claim: KeyClaim,
    session_id: [u8; 16],
    config: FlowConfig,
    phase: FlowPhase,
    phase_entered_at: Timestamp,
    remote: Option<RemoteState>,
}

impl ConnectionFlow {
    /// Begin a new flow, constructing and signing the local Key Claim.
    pub fn new<S: Signer>(
        signer: S,
        session_id: [u8; 16],
        config: FlowConfig,
        now: Timestamp,
    ) -> Self {
        let node_id = signer.public_key();
        let unsigned = KeyClaim {
            node_id,
            timestamp: now,
            dht_id: node_id,
            signature: [0u8; 64],
        };
        let payload = unsigned
            .signing_payload()
            .expect("KeyClaim signing_payload cannot fail");
        let signature = signer.sign_ed25519(&payload);
        let local_claim = KeyClaim {
            signature,
            ..unsigned
        };

        Self {
            local_claim,
            session_id,
            config,
            phase: FlowPhase::AwaitHandshake,
            phase_entered_at: now,
            remote: None,
        }
    }

    /// Current phase.
    pub fn phase(&self) -> &FlowPhase {
        &self.phase
    }

    /// The remote NodeId, once the Key Claim has been received.
    pub fn remote_node_id(&self) -> Option<NodeId> {
        self.remote.as_ref().map(|r| r.node_id)
    }

    /// Our own NodeId.
    pub fn local_node_id(&self) -> NodeId {
        self.local_claim.node_id
    }

    /// The session identifier this flow was created with.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// Read access to the local Key Claim.
    pub fn local_key_claim(&self) -> &KeyClaim {
        &self.local_claim
    }

    /// Number of distinct witnesses recorded for the remote NodeId.
    pub fn witness_count(&self) -> usize {
        self.remote
            .as_ref()
            .map(|r| r.witnesses.len())
            .unwrap_or(0)
    }

    /// When the remote Key Claim was first seen.
    pub fn remote_first_seen(&self) -> Option<Timestamp> {
        self.remote.as_ref().map(|r| r.first_seen)
    }

    // ---------------------------------------------------------------------
    // Transitions
    // ---------------------------------------------------------------------

    /// Record that the handshake completed (either as initiator or
    /// responder). Emits the local Key Claim.
    pub fn on_handshake(&mut self, now: Timestamp) -> Vec<FlowAction> {
        if self.phase != FlowPhase::AwaitHandshake {
            return Vec::new();
        }
        self.phase = FlowPhase::AwaitKeyClaim;
        self.phase_entered_at = now;
        alloc::vec![FlowAction::Send(Box::new(Message::AnnounceKey(
            self.local_claim.clone()
        )))]
    }

    /// Feed an incoming T0 message.
    ///
    /// Callers MUST verify signatures on `AnnounceKey` and
    /// `AnnounceWitness` before calling this. Messages that do not
    /// advance the flow are ignored.
    pub fn on_message(
        &mut self,
        msg: &Message,
        now: Timestamp,
    ) -> Vec<FlowAction> {
        match msg {
            Message::AnnounceKey(claim) => self.on_remote_key_claim(claim, now),
            Message::AnnounceWitness(stmt) => {
                self.on_remote_witness(stmt);
                Vec::new()
            }
            _ => Vec::new(),
        }
    }

    /// Report the outcome of NAT traversal.
    pub fn on_nat_complete(&mut self, success: bool, now: Timestamp) -> Vec<FlowAction> {
        if self.phase != FlowPhase::NatTraversal {
            return Vec::new();
        }
        if !success {
            self.phase = FlowPhase::Failed(FlowFailure::NatFailed);
            return alloc::vec![FlowAction::Failed(FlowFailure::NatFailed)];
        }
        let peer = match self.remote.as_ref() {
            Some(r) => r.node_id,
            None => return Vec::new(),
        };
        self.phase = FlowPhase::WitnessDiscovery;
        self.phase_entered_at = now;
        alloc::vec![FlowAction::StartWitnessDiscovery { peer }]
    }

    /// Report that witness discovery produced a ring.
    ///
    /// The flow does not use the ring contents; the caller may keep it
    /// for diagnostics. The KT status is computed from the
    /// `AnnounceWitness` messages the flow has already seen.
    pub fn on_discovery_complete(
        &mut self,
        _ring: Vec<NodeId>,
        now: Timestamp,
    ) -> Vec<FlowAction> {
        if self.phase != FlowPhase::WitnessDiscovery {
            return Vec::new();
        }
        let status = self.compute_kt_status(now);
        self.phase = FlowPhase::Ready(status);
        alloc::vec![FlowAction::Ready(status)]
    }

    /// Report that witness discovery failed.
    ///
    /// A failed discovery does not necessarily fail the flow: the
    /// connection is still usable with PENDING trust (§16 step 18 does
    /// not require VERIFIED). Surfaces `Ready(Pending)` so the caller
    /// can decide.
    pub fn on_discovery_failed(&mut self) -> Vec<FlowAction> {
        if self.phase != FlowPhase::WitnessDiscovery {
            return Vec::new();
        }
        self.phase = FlowPhase::Ready(KtStatus::Pending);
        alloc::vec![FlowAction::Ready(KtStatus::Pending)]
    }

    /// Check for timeouts. Emits a `Failed` action if the current
    /// phase has exceeded its configured timeout.
    pub fn poll(&mut self, now: Timestamp) -> Vec<FlowAction> {
        let elapsed = now
            .as_millis()
            .saturating_sub(self.phase_entered_at.as_millis());
        let failure = match self.phase {
            FlowPhase::AwaitKeyClaim
                if elapsed >= self.config.key_claim_timeout_ms =>
            {
                Some(FlowFailure::KeyClaimTimeout)
            }
            FlowPhase::NatTraversal if elapsed >= self.config.nat_timeout_ms => {
                Some(FlowFailure::NatTimeout)
            }
            FlowPhase::WitnessDiscovery
                if elapsed >= self.config.discovery_timeout_ms =>
            {
                Some(FlowFailure::DiscoveryTimeout)
            }
            _ => None,
        };
        match failure {
            Some(f) => {
                self.phase = FlowPhase::Failed(f);
                alloc::vec![FlowAction::Failed(f)]
            }
            None => Vec::new(),
        }
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    fn on_remote_key_claim(
        &mut self,
        claim: &KeyClaim,
        now: Timestamp,
    ) -> Vec<FlowAction> {
        if self.phase != FlowPhase::AwaitKeyClaim {
            return Vec::new();
        }
        self.remote = Some(RemoteState {
            node_id: claim.node_id,
            key_claim: claim.clone(),
            first_seen: now,
            witnesses: BTreeMap::new(),
        });
        self.phase = FlowPhase::NatTraversal;
        self.phase_entered_at = now;
        alloc::vec![FlowAction::StartNatTraversal {
            peer: claim.node_id,
            session_id: self.session_id,
        }]
    }

    fn on_remote_witness(&mut self, stmt: &WitnessStatement) {
        let remote = match self.remote.as_mut() {
            Some(r) => r,
            None => return,
        };
        // The statement must be about the remote NodeId to count.
        if stmt.subject != remote.node_id {
            return;
        }
        // Last-write-wins per witness: a replay of an older statement
        // does not overwrite a fresher one. Callers are expected to
        // have verified the statement's signature already.
        remote
            .witnesses
            .entry(stmt.witness)
            .and_modify(|existing| {
                if stmt.timestamp > existing.timestamp {
                    *existing = stmt.clone();
                }
            })
            .or_insert_with(|| stmt.clone());
    }

    fn compute_kt_status(&self, now: Timestamp) -> KtStatus {
        let remote = match self.remote.as_ref() {
            Some(r) => r,
            None => return KtStatus::Pending,
        };
        let _ = remote.first_seen; // reserved for the §5.3.3 6-hour rule
        let valid = remote
            .witnesses
            .values()
            .filter(|w| w.valid_until > now)
            .count();
        if valid >= 4 {
            KtStatus::Verified
        } else {
            KtStatus::Pending
        }
    }
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::FakeSigner;
    use alloc::vec;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    fn new_flow() -> ConnectionFlow {
       ConnectionFlow::new(
           FakeSigner::new(1),
           [0x42; 16],
           FlowConfig::default(),
           t(0),
       )
    }

    fn claim_for(n: u8, at: Timestamp) -> KeyClaim {
        KeyClaim {
            node_id: nid(n),
            timestamp: at,
            dht_id: nid(n),
            signature: [0xcc; 64],
        }
    }

    fn statement_for(
        subject: u8,
        witness: u8,
        valid_until: Timestamp,
    ) -> WitnessStatement {
        WitnessStatement {
            subject: nid(subject),
            timestamp: t(0),
            valid_until,
            ring_id: [0x11; 32],
            witness: nid(witness),
            signature: [0xab; 64],
        }
    }

    fn drive_to_discovery(f: &mut ConnectionFlow) {
        let _ = f.on_handshake(t(1));
        let _ = f.on_message(&Message::AnnounceKey(claim_for(2, t(1))), t(2));
        let _ = f.on_nat_complete(true, t(3));
        assert_eq!(*f.phase(), FlowPhase::WitnessDiscovery);
    }

    #[test]
    fn new_starts_in_await_handshake() {
        let f = new_flow();
        assert_eq!(*f.phase(), FlowPhase::AwaitHandshake);
        assert!(f.remote_node_id().is_none());
    }

    #[test]
    fn on_handshake_sends_key_claim() {
        let mut f = new_flow();
        let actions = f.on_handshake(t(1));
        assert_eq!(*f.phase(), FlowPhase::AwaitKeyClaim);
        assert_eq!(actions.len(), 1);
        match &actions[0] {
            FlowAction::Send(m) => match &**m {
                Message::AnnounceKey(c) => {
                    assert_eq!(c.node_id, nid(1));
                    assert_ne!(c.signature, [0u8; 64], "claim is signed");
                }
                other => panic!("expected AnnounceKey, got {other:?}"),
            },
            other => panic!("expected Send, got {other:?}"),
        }
    }

    #[test]
    fn on_handshake_is_idempotent() {
        let mut f = new_flow();
        let _ = f.on_handshake(t(1));
        let second = f.on_handshake(t(2));
        assert!(second.is_empty());
    }

    #[test]
    fn remote_key_claim_starts_nat() {
        let mut f = new_flow();
        let _ = f.on_handshake(t(1));
        let msg = Message::AnnounceKey(claim_for(2, t(1)));
        let actions = f.on_message(&msg, t(2));
        assert_eq!(f.remote_node_id(), Some(nid(2)));
        assert_eq!(*f.phase(), FlowPhase::NatTraversal);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            FlowAction::StartNatTraversal { peer, session_id }
                if *peer == nid(2) && *session_id == [0x42; 16]
        ));
    }

    #[test]
    fn key_claim_before_handshake_is_ignored() {
        let mut f = new_flow();
        let msg = Message::AnnounceKey(claim_for(2, t(1)));
        let actions = f.on_message(&msg, t(2));
        assert!(actions.is_empty());
        assert_eq!(*f.phase(), FlowPhase::AwaitHandshake);
    }

    #[test]
    fn nat_complete_starts_discovery() {
        let mut f = new_flow();
        let _ = f.on_handshake(t(1));
        let _ = f.on_message(&Message::AnnounceKey(claim_for(2, t(1))), t(2));
        let actions = f.on_nat_complete(true, t(3));
        assert_eq!(*f.phase(), FlowPhase::WitnessDiscovery);
        assert_eq!(actions.len(), 1);
        assert!(matches!(
            &actions[0],
            FlowAction::StartWitnessDiscovery { peer } if *peer == nid(2)
        ));
    }

    #[test]
    fn nat_failure_fails_flow() {
        let mut f = new_flow();
        let _ = f.on_handshake(t(1));
        let _ = f.on_message(&Message::AnnounceKey(claim_for(2, t(1))), t(2));
        let actions = f.on_nat_complete(false, t(3));
        assert_eq!(*f.phase(), FlowPhase::Failed(FlowFailure::NatFailed));
        assert_eq!(actions, vec![FlowAction::Failed(FlowFailure::NatFailed)]);
    }

    #[test]
    fn discovery_complete_no_witnesses_is_pending() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        let actions = f.on_discovery_complete(vec![], t(10));
        assert_eq!(*f.phase(), FlowPhase::Ready(KtStatus::Pending));
        assert_eq!(actions, vec![FlowAction::Ready(KtStatus::Pending)]);
    }

    #[test]
    fn discovery_failed_falls_back_to_pending() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        let actions = f.on_discovery_failed();
        assert_eq!(*f.phase(), FlowPhase::Ready(KtStatus::Pending));
        assert_eq!(actions, vec![FlowAction::Ready(KtStatus::Pending)]);
    }

    #[test]
    fn witness_statements_accumulate() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        for w in 10..=13 {
            let s = statement_for(2, w, t(1_000_000));
            let actions = f.on_message(&Message::AnnounceWitness(s), t(5));
            assert!(actions.is_empty(), "witnesses never emit actions");
        }
        assert_eq!(f.witness_count(), 4);
    }

    #[test]
    fn four_witnesses_yield_verified() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        for w in 10..=13 {
            let s = statement_for(2, w, t(1_000_000));
            let _ = f.on_message(&Message::AnnounceWitness(s), t(5));
        }
        let actions = f.on_discovery_complete(vec![], t(10));
        assert_eq!(*f.phase(), FlowPhase::Ready(KtStatus::Verified));
        assert_eq!(actions, vec![FlowAction::Ready(KtStatus::Verified)]);
    }

    #[test]
    fn expired_witnesses_do_not_count() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        // valid_until = t(10); check at t(100) -> expired.
        for w in 10..=13 {
            let s = statement_for(2, w, t(10));
            let _ = f.on_message(&Message::AnnounceWitness(s), t(5));
        }
        let actions = f.on_discovery_complete(vec![], t(100));
        assert_eq!(*f.phase(), FlowPhase::Ready(KtStatus::Pending));
        assert_eq!(actions, vec![FlowAction::Ready(KtStatus::Pending)]);
    }

    #[test]
    fn witnesses_for_other_subjects_are_ignored() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        // Statement attests to nid(99) — not the remote.
        let s = statement_for(99, 10, t(1_000_000));
        let _ = f.on_message(&Message::AnnounceWitness(s), t(5));
        assert_eq!(f.witness_count(), 0);
    }

    #[test]
    fn duplicate_witness_only_counted_once() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        for _ in 0..4 {
            let s = statement_for(2, 10, t(1_000_000));
            let _ = f.on_message(&Message::AnnounceWitness(s), t(5));
        }
        assert_eq!(f.witness_count(), 1);
    }

    #[test]
    fn key_claim_timeout() {
        let mut f = new_flow();
        let _ = f.on_handshake(t(0));
        // Default timeout is 10s.
        let actions = f.poll(t(10_000));
        assert_eq!(*f.phase(), FlowPhase::Failed(FlowFailure::KeyClaimTimeout));
        assert_eq!(
            actions,
            vec![FlowAction::Failed(FlowFailure::KeyClaimTimeout)]
        );
    }

    #[test]
    fn nat_timeout() {
        let mut f = new_flow();
        let _ = f.on_handshake(t(0));
        let _ = f.on_message(&Message::AnnounceKey(claim_for(2, t(0))), t(0));
        // Default NAT timeout is 30s.
        let actions = f.poll(t(30_000));
        assert_eq!(*f.phase(), FlowPhase::Failed(FlowFailure::NatTimeout));
        assert_eq!(actions, vec![FlowAction::Failed(FlowFailure::NatTimeout)]);
    }

    #[test]
    fn discovery_timeout() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        // drive_to_discovery enters WitnessDiscovery at t(3).
        let actions = f.poll(t(3 + 30_000));
        assert_eq!(
            *f.phase(),
            FlowPhase::Failed(FlowFailure::DiscoveryTimeout)
        );
        assert_eq!(
            actions,
            vec![FlowAction::Failed(FlowFailure::DiscoveryTimeout)]
        );
    }

    #[test]
    fn poll_before_timeout_returns_nothing() {
        let mut f = new_flow();
        let _ = f.on_handshake(t(0));
        let actions = f.poll(t(1_000));
        assert!(actions.is_empty());
        assert_eq!(*f.phase(), FlowPhase::AwaitKeyClaim);
    }

    #[test]
    fn ready_flow_ignores_further_messages() {
        let mut f = new_flow();
        drive_to_discovery(&mut f);
        let _ = f.on_discovery_complete(vec![], t(10));
        let s = statement_for(2, 10, t(1_000_000));
        let actions = f.on_message(&Message::AnnounceWitness(s), t(11));
        assert!(actions.is_empty());
        assert_eq!(*f.phase(), FlowPhase::Ready(KtStatus::Pending));
    }

    #[test]
    fn session_id_round_trips() {
        let f = new_flow();
        assert_eq!(f.session_id(), [0x42; 16]);
    }

    #[test]
    fn local_node_id_matches_signer() {
        let f = new_flow();
        assert_eq!(f.local_node_id(), nid(1));
    }
}