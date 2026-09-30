//! BFT consensus driver (spec §5.3.4).
//!
//! [`BftDriver`] is the state machine a witness ring runs. It takes
//! operations to order, participates in the four-phase protocol
//! (preprepare → prepare → precommit → commit), applies the operation
//! to the caller's state on commit quorum, and periodically
//! checkpoints that state for recovery.
//!
//! # Scope (M4b.1)
//!
//! The round core. Propose, verify, vote, apply on commit quorum.
//!
//! # View change (M4b.2)
//!
//! A witness that suspects the primary calls
//! [`BftDriver::start_view_change`]. The driver broadcasts a
//! `bft_view_change` for `view + 1` and starts collecting votes from
//! its peers. When a member has collected a quorum of valid votes
//! *and* is the primary for the target view, it emits a
//! `bft_new_view` carrying those votes and adopts the new view.
//! Witnesses receiving a well-formed `bft_new_view` verify it and
//! adopt.
//!
//! # Checkpointing and state transfer (M4b.3)
//!
//! After every `CHECKPOINT_INTERVAL` sequences, the driver emits a
//! `bft_checkpoint` for the current state digest. When a quorum of
//! witnesses have signed the same `(sequence, state_digest)`, the
//! checkpoint is marked stable and its signatures retained. A driver
//! whose sequence has fallen behind can call
//! [`BftDriver::request_state_transfer`] to obtain the state at a
//! known checkpoint: a peer with a newer stable checkpoint responds
//! with the state bytes and a ring signature. The lagging driver
//! verifies the ring signature and the digest, installs the state,
//! and resumes.
//!
//! ## S8 — ring signature scope
//!
//! §5.3.4.1 says the `ring_signature` of a `bft_state_transfer`
//! covers that message's own signing payload. A responder cannot
//! produce a fresh quorum ring signature without an extra round trip
//! that the spec does not describe. This implementation treats the
//! ring signature as the collection of `bft_checkpoint` signatures
//! that made the checkpoint stable, and verifies it against the
//! `bft_checkpoint` payload for
//! `(ring_id, checkpoint_sequence, checkpoint_digest)`.
//!
//! # Quorum
//!
//! Quorum is `n - f` where `f = (n - 1) / 3` for an `n`-member ring.
//! For a full 7-member ring that is 5-of-7 (`QUORUM`); for a 4-member
//! DEGRADED ring it is 3-of-4 (`DEGRADED_QUORUM`). Two quorums of this
//! size always intersect in more than `f` members, which is the safety
//! property §5.3.4's quorum-intersection argument relies on.
//!
//! # Signing
//!
//! The driver holds a [`quip_core::messages::Signer`] because it
//! signs its own votes, the preprepare it proposes as primary, and
//! its own checkpoints. It holds a
//! [`quip_core::messages::Verifier`] because the four-phase protocol
//! and every state-transfer verification path would be meaningless
//! without verifying peers' signatures. Both are value types.

use crate::bft::{
    BftCheckpoint, BftCommit, BftNewView, BftPrecommit, BftPrepare, BftPreprepare,
    BftStateTransfer, BftViewChange, Digest, Operation, RingId,
};
use crate::error::{Error, Result};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use quip_core::cbor::encode;
use quip_core::constants::{CHECKPOINT_INTERVAL, MIN_WITNESSES};
use quip_core::dvv::NodeId;
use quip_core::messages::{
    IndividualRingSig, RingSignature, Signer, Verifier,
};

// -------------------------------------------------------------------------
// RingMembership
// -------------------------------------------------------------------------

/// The ring's membership, in canonical NodeId order.
///
/// S3 pinned the primary-rotation rule to canonical NodeId order: the
/// primary for view `v` is `members[v mod |R|]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingMembership {
    members: Vec<NodeId>,
}

impl RingMembership {
    /// Build a membership from a set of NodeIds.
    ///
    /// Sorts the members into canonical order and enforces the ring
    /// size floor. A membership with fewer than `MIN_WITNESSES`
    /// members is rejected: the four-phase protocol needs at least
    /// 3f+1 = 4 witnesses to tolerate any fault.
    pub fn new(mut members: Vec<NodeId>) -> Result<Self> {
        members.sort();
        members.dedup();
        if members.len() < MIN_WITNESSES {
            return Err(Error::Bft("ring has fewer than MIN_WITNESSES members"));
        }
        Ok(Self { members })
    }

    /// Number of members.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// True when empty. A valid membership is never empty.
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// Quorum threshold for this ring.
    ///
    /// `n - f` where `f = (n - 1) / 3`.
    pub fn quorum(&self) -> usize {
        let n = self.members.len();
        let f = (n - 1) / 3;
        n - f
    }

    /// Members, in canonical order.
    pub fn members(&self) -> &[NodeId] {
        &self.members
    }

    /// The primary for view `v`.
    pub fn primary_for(&self, view: u64) -> NodeId {
        let idx = (view as usize) % self.members.len();
        self.members[idx]
    }

    /// True when `node` is a member.
    pub fn is_member(&self, node: &NodeId) -> bool {
        self.members.iter().any(|m| m == node)
    }
}

// -------------------------------------------------------------------------
// BftHandler
// -------------------------------------------------------------------------

/// The application-side handler for ordered operations.
///
/// Called exactly once per sequence, after a commit quorum has been
/// reached. The handler applies the operation to whatever state it
/// owns (a DVV, a resource table, ...). An error is surfaced as
/// [`BftEvent::ApplyFailed`] and does not halt the driver — the
/// sequence has already committed; the caller decides whether to
/// abort, retry, or ignore.
///
/// The state-related methods are used by checkpointing and state
/// transfer (M4b.3). Their defaults are conservative: a handler that
/// does not implement state serialization still compiles and its
/// driver still operates, but its checkpoints carry an all-zeros
/// digest and its state transfers are empty. Implementations that
/// want real checkpointing override all three.
pub trait BftHandler {
    /// Apply `operation` at `sequence` in `ring_id`.
    fn apply(
        &mut self,
        ring_id: &RingId,
        sequence: u64,
        operation: &Operation,
    ) -> Result<()>;

    /// SHA-256 digest of the current application state.
    ///
    /// Used to identify a stable checkpoint. The default returns
    /// all-zeros, which marks the driver as not meaningfully
    /// checkpointing: state transfers are still accepted (the state
    /// is passed to [`Self::apply_state`]), but the driver's own
    /// emitted checkpoints carry a sentinel digest.
    fn state_digest(&self) -> Digest {
        [0u8; 32]
    }

    /// Encoded state at the latest checkpoint.
    ///
    /// Opaque to the protocol; §5.3.4.1 leaves the serialization to
    /// the application. The default is empty.
    fn state_bytes(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Install a state received via `bft_state_transfer`.
    ///
    /// The driver validates the ring signature and the
    /// `checkpoint_digest` against the transmitted bytes before
    /// calling this; the handler installs the state. The default is
    /// a no-op.
    fn apply_state(&mut self, _state: &[u8]) -> Result<()> {
        Ok(())
    }
}

// -------------------------------------------------------------------------
// Outbound and events
// -------------------------------------------------------------------------

/// A BFT message the driver wants the caller to send.
#[derive(Clone, Debug, PartialEq)]
pub enum BftOutbound {
    /// Pre-prepare, sent by the primary.
    Preprepare(BftPreprepare),
    /// Prepare vote.
    Prepare(BftPrepare),
    /// Precommit vote.
    Precommit(BftPrecommit),
    /// Commit vote.
    Commit(BftCommit),
    /// View-change vote, sent when the primary is suspected faulty.
    ViewChange(BftViewChange),
    /// New-view announcement, sent by the primary for the new view.
    NewView(BftNewView),
    /// Checkpoint, sent every `CHECKPOINT_INTERVAL` sequences.
    Checkpoint(BftCheckpoint),
    /// State-transfer request: sent by a lagging driver to a peer.
    /// Empty state and signature.
    StateTransferRequest(BftStateTransfer),
    /// State-transfer response: sent by a peer with a stable
    /// checkpoint. Carries the state bytes and a ring signature.
    StateTransferResponse(BftStateTransfer),
}

/// Something the driver wants the caller to observe.
#[derive(Clone, Debug, PartialEq)]
pub enum BftEvent {
    /// A new operation has been proposed and the driver is now
    /// participating in the round.
    Proposed {
        /// Sequence number.
        sequence: u64,
        /// Operation digest.
        digest: Digest,
    },
    /// The prepare quorum has been reached.
    Prepared {
        /// Sequence number.
        sequence: u64,
        /// Operation digest.
        digest: Digest,
    },
    /// The precommit quorum has been reached.
    PreCommitted {
        /// Sequence number.
        sequence: u64,
        /// Operation digest.
        digest: Digest,
    },
    /// The commit quorum has been reached and the operation has been
    /// applied to the handler.
    Applied {
        /// Sequence number.
        sequence: u64,
        /// Operation digest.
        digest: Digest,
    },
    /// The handler returned an error while applying a committed
    /// operation.
    ApplyFailed {
        /// Sequence number.
        sequence: u64,
        /// Human-readable error string.
        text: String,
    },
    /// A view change has been initiated for `target_view`.
    ViewChangeInitiated {
        /// The view the driver is moving to.
        target_view: u64,
    },
    /// A quorum of view-change votes has been collected.
    ViewChangeQuorum {
        /// The view the driver is moving to.
        target_view: u64,
    },
    /// The driver has adopted a new view.
    NewViewAdopted {
        /// The newly adopted view.
        view: u64,
    },
    /// This driver emitted a checkpoint for `(sequence, digest)`.
    CheckpointStarted {
        /// Sequence number.
        sequence: u64,
        /// State digest.
        digest: Digest,
    },
    /// A checkpoint reached quorum and is now stable.
    CheckpointStable {
        /// Sequence number.
        sequence: u64,
        /// State digest.
        digest: Digest,
    },
    /// A peer requested state transfer from us.
    StateTransferRequested {
        /// Peer making the request.
        peer: NodeId,
        /// The sequence the peer is at.
        from_sequence: u64,
    },
    /// A state transfer was received, verified, and installed.
    StateTransferApplied {
        /// Sequence number of the transferred checkpoint.
        sequence: u64,
        /// State digest.
        digest: Digest,
    },
}

// -------------------------------------------------------------------------
// Round state
// -------------------------------------------------------------------------

/// The driver's phase in the current round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoundState {
    /// No round in flight.
    Idle,
    /// A preprepare has been accepted; prepare votes are being
    /// collected.
    PrePrepared,
    /// Prepare quorum reached; precommit votes are being collected.
    Prepared,
    /// Precommit quorum reached; commit votes are being collected.
    PreCommitted,
}

/// In-flight round state.
#[derive(Clone, Debug)]
struct InFlight {
    operation: Operation,
    digest: Digest,
    prepares: BTreeMap<NodeId, [u8; 64]>,
    precommits: BTreeMap<NodeId, [u8; 64]>,
    commits: BTreeMap<NodeId, [u8; 64]>,
}

/// Internal bookkeeping for a view change in progress.
#[derive(Clone, Debug, Default)]
struct ViewChangeState {
    /// The target view, if a view change is in progress.
    target_view: Option<u64>,
    /// Collected view-change messages, keyed by sender.
    votes: BTreeMap<NodeId, BftViewChange>,
}

/// A checkpoint round: the `(sequence, digest)` being collected plus
/// the signatures seen so far.
#[derive(Clone, Debug)]
struct CheckpointRound {
    sequence: u64,
    digest: Digest,
    /// Witness signatures over the `bft_checkpoint` signing payload.
    signatures: BTreeMap<NodeId, [u8; 64]>,
}

// -------------------------------------------------------------------------
// BftDriver
// -------------------------------------------------------------------------

/// BFT consensus driver for one ring.
///
/// See the module docs for scope and the phase ladder.
pub struct BftDriver<S, V, H>
where
    S: Signer,
    V: Verifier,
    H: BftHandler,
{
    signer: S,
    verifier: V,
    handler: H,
    ring_id: RingId,
    membership: RingMembership,
    local: NodeId,
    view: u64,
    sequence: u64,
    state: RoundState,
    current: Option<InFlight>,
    outbound: VecDeque<BftOutbound>,
    events: VecDeque<BftEvent>,
    /// Digest of the latest stable checkpoint. `[0; 32]` until a
    /// checkpoint reaches quorum.
    checkpoint_digest: Digest,
    /// Sequence of the latest stable checkpoint. 0 until a checkpoint
    /// reaches quorum.
    checkpoint_sequence: u64,
    /// Stable checkpoint round, retained for state-transfer responses.
    stable_checkpoint: Option<CheckpointRound>,
    /// In-flight checkpoint round, if any.
    pending_checkpoint: Option<CheckpointRound>,
    /// View-change state.
    view_change: ViewChangeState,
}

impl<S, V, H> BftDriver<S, V, H>
where
    S: Signer,
    V: Verifier,
    H: BftHandler,
{
    /// Create a driver for `ring_id`.
    ///
    /// The local node is derived from `signer.public_key()`. Returns
    /// [`Error::Bft`] if the local node is not a member of the ring.
    pub fn new(
        signer: S,
        verifier: V,
        handler: H,
        ring_id: RingId,
        membership: RingMembership,
        view: u64,
    ) -> Result<Self> {
        let local = signer.public_key();
        if !membership.is_member(&local) {
            return Err(Error::Bft("local signer is not a ring member"));
        }
        Ok(Self {
            signer,
            verifier,
            handler,
            ring_id,
            membership,
            local,
            view,
            sequence: 0,
            state: RoundState::Idle,
            current: None,
            outbound: VecDeque::new(),
            events: VecDeque::new(),
            checkpoint_digest: [0u8; 32],
            checkpoint_sequence: 0,
            stable_checkpoint: None,
            pending_checkpoint: None,
            view_change: ViewChangeState::default(),
        })
    }

    // ---- introspection ----

    /// The ring identifier.
    pub fn ring_id(&self) -> &RingId {
        &self.ring_id
    }

    /// Read-only access to the ring's membership.
    pub fn membership(&self) -> &RingMembership {
        &self.membership
    }

    /// The local node's NodeId.
    pub fn local_node_id(&self) -> NodeId {
        self.local
    }

    /// The current view number.
    pub fn view(&self) -> u64 {
        self.view
    }

    /// The next sequence number to be ordered.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The driver's current round state.
    pub fn state(&self) -> &RoundState {
        &self.state
    }

    /// True when the local node is the primary for the current view.
    pub fn is_primary(&self) -> bool {
        self.membership.primary_for(self.view) == self.local
    }

    /// The operation in flight, if any.
    pub fn current_operation(&self) -> Option<&Operation> {
        self.current.as_ref().map(|c| &c.operation)
    }

    /// The sequence number of the latest stable checkpoint, or 0 if
    /// none has been reached.
    pub fn checkpoint_sequence(&self) -> u64 {
        self.checkpoint_sequence
    }

    /// The digest of the latest stable checkpoint, or `[0; 32]` if
    /// none has been reached.
    pub fn checkpoint_digest(&self) -> &Digest {
        &self.checkpoint_digest
    }

    /// The number of signatures collected for the stable checkpoint,
    /// if one has been reached.
    pub fn stable_checkpoint_signatures(&self) -> Option<usize> {
        self.stable_checkpoint.as_ref().map(|c| c.signatures.len())
    }

    /// The target view of an in-progress view change, if any.
    pub fn view_change_target(&self) -> Option<u64> {
        self.view_change.target_view
    }

    /// Number of view-change votes collected for the target view.
    pub fn view_change_votes(&self) -> usize {
        self.view_change.votes.len()
    }

    /// Read-only access to the handler.
    pub fn handler(&self) -> &H {
        &self.handler
    }

    /// Mutable access to the handler.
    pub fn handler_mut(&mut self) -> &mut H {
        &mut self.handler
    }

    // ---- draining ----

    /// Drain outbound BFT messages.
    pub fn drain_outbound(&mut self) -> Vec<BftOutbound> {
        self.outbound.drain(..).collect()
    }

    /// Drain events.
    pub fn drain_events(&mut self) -> Vec<BftEvent> {
        self.events.drain(..).collect()
    }

    // ---- proposing ----

    /// Propose `operation` for the next sequence.
    ///
    /// Only the primary for the current view may call this, and only
    /// when the driver is idle. Returns [`Error::Bft`] otherwise.
    pub fn start(&mut self, operation: Operation) -> Result<()> {
        if self.state != RoundState::Idle {
            return Err(Error::Bft("driver is not idle"));
        }
        if !self.is_primary() {
            return Err(Error::Bft("not the primary for this view"));
        }
        self.propose(operation)
    }

    fn propose(&mut self, operation: Operation) -> Result<()> {
        let digest = compute_digest_parts(
            &self.ring_id,
            self.view,
            self.sequence,
            &operation,
        )?;
        let mut msg = BftPreprepare {
            ring_id: self.ring_id,
            view: self.view,
            sequence: self.sequence,
            operation: operation.clone(),
            digest,
            primary_sig: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.primary_sig = self.signer.sign_ed25519(&payload);

        self.current = Some(InFlight {
            operation,
            digest,
            prepares: BTreeMap::new(),
            precommits: BTreeMap::new(),
            commits: BTreeMap::new(),
        });
        self.state = RoundState::PrePrepared;
        self.events.push_back(BftEvent::Proposed {
            sequence: self.sequence,
            digest,
        });
        self.outbound.push_back(BftOutbound::Preprepare(msg));
        self.emit_prepare()?;
        self.try_advance()?;
        Ok(())
    }

    // ---- inbound round messages ----

    /// Receive a `bft_preprepare`.
    ///
    /// `primary` is the NodeId of the sender as identified by the
    /// transport. It must equal the primary for the current view.
    pub fn on_preprepare(
        &mut self,
        primary: &NodeId,
        msg: &BftPreprepare,
    ) -> Result<()> {
        if msg.ring_id != self.ring_id {
            return Err(Error::Bft("preprepare for wrong ring"));
        }
        if msg.view != self.view || msg.sequence != self.sequence {
            // Stale or future view/sequence. M4b.2 handles view
            // change; M4b.3 handles resync via state transfer.
            return Ok(());
        }
        if *primary != self.membership.primary_for(self.view) {
            return Err(Error::Bft("preprepare sender is not the primary"));
        }
        if self.state != RoundState::Idle {
            // Already participating in a round for this sequence.
            return Ok(());
        }
        msg.verify_full(primary, &self.verifier)?;

        self.current = Some(InFlight {
            operation: msg.operation.clone(),
            digest: msg.digest,
            prepares: BTreeMap::new(),
            precommits: BTreeMap::new(),
            commits: BTreeMap::new(),
        });
        self.state = RoundState::PrePrepared;
        self.events.push_back(BftEvent::Proposed {
            sequence: self.sequence,
            digest: msg.digest,
        });
        self.emit_prepare()?;
        self.try_advance()?;
        Ok(())
    }

    /// Receive a `bft_prepare`.
    pub fn on_prepare(
        &mut self,
        witness: &NodeId,
        msg: &BftPrepare,
    ) -> Result<()> {
        self.handle_vote(witness, msg)
    }

    /// Receive a `bft_precommit`.
    pub fn on_precommit(
        &mut self,
        witness: &NodeId,
        msg: &BftPrecommit,
    ) -> Result<()> {
        self.handle_vote(witness, msg)
    }

    /// Receive a `bft_commit`.
    pub fn on_commit(
        &mut self,
        witness: &NodeId,
        msg: &BftCommit,
    ) -> Result<()> {
        self.handle_vote(witness, msg)
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    fn handle_vote<Vote: VoteShape>(
        &mut self,
        witness: &NodeId,
        msg: &Vote,
    ) -> Result<()> {
        if msg.ring_id() != &self.ring_id {
            return Err(Error::Bft("bft vote for wrong ring"));
        }
        if msg.view() != self.view || msg.sequence() != self.sequence {
            return Ok(());
        }
        if !self.membership.is_member(witness) {
            return Err(Error::Bft("bft vote from non-member"));
        }
        if !msg.verify(witness, &self.verifier)? {
            return Err(Error::Bft("bft vote signature invalid"));
        }
        let digest = *msg.digest();
        let sig = *msg.witness_sig();
        let mut matched = false;
        if let Some(current) = self.current.as_mut() {
            if current.digest == digest {
                msg.insert_vote(current, *witness, sig);
                matched = true;
            }
        }
        if matched {
            self.try_advance()?;
        }
        Ok(())
    }

    fn emit_prepare(&mut self) -> Result<()> {
        let digest = match self.current.as_ref() {
            Some(c) => c.digest,
            None => return Ok(()),
        };
        let mut msg = BftPrepare {
            ring_id: self.ring_id,
            view: self.view,
            sequence: self.sequence,
            digest,
            witness_sig: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.witness_sig = self.signer.sign_ed25519(&payload);
        if let Some(c) = self.current.as_mut() {
            c.prepares.insert(self.local, msg.witness_sig);
        }
        self.outbound.push_back(BftOutbound::Prepare(msg));
        Ok(())
    }

    fn emit_precommit(&mut self) -> Result<()> {
        let digest = match self.current.as_ref() {
            Some(c) => c.digest,
            None => return Ok(()),
        };
        let mut msg = BftPrecommit {
            ring_id: self.ring_id,
            view: self.view,
            sequence: self.sequence,
            digest,
            witness_sig: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.witness_sig = self.signer.sign_ed25519(&payload);
        if let Some(c) = self.current.as_mut() {
            c.precommits.insert(self.local, msg.witness_sig);
        }
        self.outbound.push_back(BftOutbound::Precommit(msg));
        Ok(())
    }

    fn emit_commit(&mut self) -> Result<()> {
        let digest = match self.current.as_ref() {
            Some(c) => c.digest,
            None => return Ok(()),
        };
        let mut msg = BftCommit {
            ring_id: self.ring_id,
            view: self.view,
            sequence: self.sequence,
            digest,
            witness_sig: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.witness_sig = self.signer.sign_ed25519(&payload);
        if let Some(c) = self.current.as_mut() {
            c.commits.insert(self.local, msg.witness_sig);
        }
        self.outbound.push_back(BftOutbound::Commit(msg));
        Ok(())
    }

    fn try_advance(&mut self) -> Result<()> {
        let quorum = self.membership.quorum();
        match self.state {
            RoundState::Idle => Ok(()),
            RoundState::PrePrepared => {
                let reached = self
                    .current
                    .as_ref()
                    .map(|c| c.prepares.len() >= quorum)
                    .unwrap_or(false);
                if !reached {
                    return Ok(());
                }
                let digest = self.current.as_ref().unwrap().digest;
                self.state = RoundState::Prepared;
                self.events.push_back(BftEvent::Prepared {
                    sequence: self.sequence,
                    digest,
                });
                self.emit_precommit()
            }
            RoundState::Prepared => {
                let reached = self
                    .current
                    .as_ref()
                    .map(|c| c.precommits.len() >= quorum)
                    .unwrap_or(false);
                if !reached {
                    return Ok(());
                }
                let digest = self.current.as_ref().unwrap().digest;
                self.state = RoundState::PreCommitted;
                self.events.push_back(BftEvent::PreCommitted {
                    sequence: self.sequence,
                    digest,
                });
                self.emit_commit()
            }
            RoundState::PreCommitted => {
                let reached = self
                    .current
                    .as_ref()
                    .map(|c| c.commits.len() >= quorum)
                    .unwrap_or(false);
                if !reached {
                    return Ok(());
                }
                self.apply_current()
            }
        }
    }

    fn apply_current(&mut self) -> Result<()> {
        let current = match self.current.take() {
            Some(c) => c,
            None => return Ok(()),
        };
        let result = self.handler.apply(
            &self.ring_id,
            self.sequence,
            &current.operation,
        );
        match result {
            Ok(()) => {
                self.events.push_back(BftEvent::Applied {
                    sequence: self.sequence,
                    digest: current.digest,
                });
            }
            Err(e) => {
                self.events.push_back(BftEvent::ApplyFailed {
                    sequence: self.sequence,
                    text: format!("{e:?}"),
                });
            }
        }
        self.state = RoundState::Idle;
        self.sequence = self.sequence.saturating_add(1);

        // Checkpoint every CHECKPOINT_INTERVAL sequences. The
        // condition is strict `> 0` so a driver that constructs at
        // sequence 0 and applies its first operation does not
        // immediately checkpoint.
        if self.sequence > 0 && self.sequence % CHECKPOINT_INTERVAL == 0 {
            self.start_checkpoint()?;
        }
        Ok(())
    }

    // ---- view change ----

    /// Begin a view change to `view + 1`.
    ///
    /// Callers invoke this when the primary is suspected faulty. The
    /// driver broadcasts its own view-change vote and starts
    /// collecting peers'. If a view change is already in progress,
    /// returns [`Error::Bft`].
    pub fn start_view_change(&mut self) -> Result<()> {
        if self.view_change.target_view.is_some() {
            return Err(Error::Bft("view change already in progress"));
        }
        let target_view = self.view.saturating_add(1);

        // Abort any round in flight; the new primary will re-propose.
        self.current = None;
        self.state = RoundState::Idle;

        // Include the digest of the aborted round, if any, so peers
        // see what we had prepared. M4b.3 does not yet re-propose
        // prepared operations on the new view.
        let prepared_digests: Vec<Digest> = Vec::new();

        let mut msg = BftViewChange {
            ring_id: self.ring_id,
            new_view: target_view,
            last_sequence: self.sequence,
            prepared_digests,
            checkpoint_digest: self.checkpoint_digest,
            witness_sig: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.witness_sig = self.signer.sign_ed25519(&payload);

        self.view_change.target_view = Some(target_view);
        self.view_change.votes.insert(self.local, msg.clone());

        self.events.push_back(BftEvent::ViewChangeInitiated { target_view });
        self.outbound.push_back(BftOutbound::ViewChange(msg));

        self.maybe_emit_new_view()?;
        Ok(())
    }

    /// Receive a `bft_view_change`.
    ///
    /// If the driver has not yet started a view change, the vote
    /// triggers one. Votes for a different target view are ignored
    /// until the current one resolves.
    pub fn on_view_change(
        &mut self,
        sender: &NodeId,
        msg: &BftViewChange,
    ) -> Result<()> {
        if msg.ring_id != self.ring_id {
            return Err(Error::Bft("view change for wrong ring"));
        }
        if !self.membership.is_member(sender) {
            return Err(Error::Bft("view change from non-member"));
        }
        // A vote for a view we have already passed is stale and is
        // discarded before signature verification: it cannot affect
        // state, so there is no reason to pay the crypto cost.
        if msg.new_view <= self.view {
            return Ok(());
        }
        if !msg.verify(sender, &self.verifier)? {
            return Err(Error::Bft("view change signature invalid"));
        }

        match self.view_change.target_view {
            Some(t) if msg.new_view != t => {
                // A different view change is in progress; ignore.
                return Ok(());
            }
            None => {
                // Peer-initiated view change: join it.
                self.current = None;
                self.state = RoundState::Idle;
                self.view_change.target_view = Some(msg.new_view);
                self.events.push_back(BftEvent::ViewChangeInitiated {
                    target_view: msg.new_view,
                });
            }
            _ => {}
        }

        if self.view_change.votes.contains_key(sender) {
            return Ok(()); // duplicate vote
        }
        self.view_change.votes.insert(*sender, msg.clone());
        self.maybe_emit_new_view()?;
        Ok(())
    }

    /// Receive a `bft_new_view`.
    ///
    /// Verifies the sender is the primary for `msg.view`, the primary
    /// signature is valid, and the enclosed view-change messages
    /// constitute a quorum of distinct members. On success, adopts
    /// the new view.
    pub fn on_new_view(
        &mut self,
        sender: &NodeId,
        msg: &BftNewView,
    ) -> Result<()> {
        if msg.ring_id != self.ring_id {
            return Err(Error::Bft("new view for wrong ring"));
        }
        if *sender != self.membership.primary_for(msg.view) {
            return Err(Error::Bft("new view sender is not the new primary"));
        }
        if msg.view <= self.view {
            return Ok(()); // stale or duplicate
        }
        if !msg.verify(sender, &self.verifier)? {
            return Err(Error::Bft("new view signature invalid"));
        }

        // Decode and verify each view-change message, tracking
        // signers to enforce distinctness.
        let mut signers: BTreeMap<NodeId, ()> = BTreeMap::new();
        for bytes in &msg.view_change_messages {
            let vc = BftViewChange::from_bytes(bytes)?;
            if vc.ring_id != self.ring_id {
                return Err(Error::Bft("view change in new view for wrong ring"));
            }
            if vc.new_view != msg.view {
                return Err(Error::Bft("view change in new view for wrong view"));
            }
            let signer = self
                .find_view_change_signer(&vc)?
                .ok_or(Error::Bft("view change signer not a ring member"))?;
            if signers.insert(signer, ()).is_some() {
                return Err(Error::Bft("duplicate view change signer"));
            }
        }

        if signers.len() < self.membership.quorum() {
            return Err(Error::Bft("new view has too few view-change messages"));
        }

        self.adopt_view(msg.view);
        Ok(())
    }

    /// Emit a `bft_new_view` if we are the primary for the target
    /// view and have collected a quorum of votes.
    fn maybe_emit_new_view(&mut self) -> Result<()> {
        let target_view = match self.view_change.target_view {
            Some(v) => v,
            None => return Ok(()),
        };
        if self.view_change.votes.len() < self.membership.quorum() {
            return Ok(());
        }
        if self.membership.primary_for(target_view) != self.local {
            return Ok(());
        }

        let view_change_messages: Vec<Vec<u8>> = self
            .view_change
            .votes
            .values()
            .map(|vc| vc.to_bytes())
            .collect::<Result<_>>()?;

        let mut msg = BftNewView {
            ring_id: self.ring_id,
            view: target_view,
            view_change_messages,
            prepared_messages: Vec::new(),
            checkpoint_messages: Vec::new(),
            primary_sig: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.primary_sig = self.signer.sign_ed25519(&payload);

        self.events.push_back(BftEvent::ViewChangeQuorum { target_view });
        self.outbound.push_back(BftOutbound::NewView(msg));

        self.adopt_view(target_view);
        Ok(())
    }

    /// Adopt `target_view`, resetting any in-flight round and
    /// clearing view-change state. Stable and pending checkpoints
    /// are unaffected: they are keyed by sequence, not by view.
    fn adopt_view(&mut self, target_view: u64) {
        self.view = target_view;
        self.current = None;
        self.state = RoundState::Idle;
        self.view_change = ViewChangeState::default();
        self.events.push_back(BftEvent::NewViewAdopted {
            view: target_view,
        });
    }

    /// Locate the ring member whose key signed `vc`, or `None`.
    ///
    /// `BftViewChange` does not carry a signer NodeId on the wire; the
    /// driver resolves it by trial verification against each member.
    /// For the ring sizes this protocol supports (≤ 9) the cost is
    /// negligible.
    fn find_view_change_signer(
        &self,
        vc: &BftViewChange,
    ) -> Result<Option<NodeId>> {
        let payload = vc.signing_payload()?;
        for member in self.membership.members() {
            if self
                .verifier
                .verify_ed25519(member, &payload, &vc.witness_sig)
            {
                return Ok(Some(*member));
            }
        }
        Ok(None)
    }

    // ---- checkpointing ----

    /// Begin a checkpoint round for the current sequence.
    ///
    /// Called automatically every `CHECKPOINT_INTERVAL` sequences.
    /// Public so callers can force a checkpoint outside the interval
    /// (e.g. before an orderly shutdown).
    ///
    /// If a checkpoint round for this sequence is already in flight,
    /// this is a no-op.
    pub fn start_checkpoint(&mut self) -> Result<()> {
        if let Some(p) = self.pending_checkpoint.as_ref() {
            if p.sequence == self.sequence {
                return Ok(());
            }
        }
        let digest = self.handler.state_digest();

        let mut msg = BftCheckpoint {
            ring_id: self.ring_id,
            sequence: self.sequence,
            state_digest: digest,
            witness_sig: [0u8; 64],
        };
        let payload = msg.signing_payload()?;
        msg.witness_sig = self.signer.sign_ed25519(&payload);

        let mut signatures = BTreeMap::new();
        signatures.insert(self.local, msg.witness_sig);

        self.pending_checkpoint = Some(CheckpointRound {
            sequence: self.sequence,
            digest,
            signatures,
        });
        self.events.push_back(BftEvent::CheckpointStarted {
            sequence: self.sequence,
            digest,
        });
        self.outbound.push_back(BftOutbound::Checkpoint(msg));
        self.maybe_promote_checkpoint();
        Ok(())
    }

    /// Receive a `bft_checkpoint`.
    pub fn on_checkpoint(
        &mut self,
        sender: &NodeId,
        msg: &BftCheckpoint,
    ) -> Result<()> {
        if msg.ring_id != self.ring_id {
            return Err(Error::Bft("checkpoint for wrong ring"));
        }
        if !self.membership.is_member(sender) {
            return Err(Error::Bft("checkpoint from non-member"));
        }
        if !msg.verify(sender, &self.verifier)? {
            return Err(Error::Bft("checkpoint signature invalid"));
        }
        // We can only participate in a checkpoint for a sequence we
        // have reached; a checkpoint for a future sequence means the
        // sender is ahead of us and we should request a state
        // transfer rather than accumulate.
        if msg.sequence > self.sequence {
            return Ok(());
        }
        // A checkpoint for a sequence at or before our stable
        // checkpoint is stale. Until a checkpoint is stable,
        // `checkpoint_sequence` is 0 and does not imply "already at
        // sequence 0".
        if let Some(stable) = self.stable_checkpoint.as_ref() {
            if msg.sequence <= stable.sequence {
                return Ok(());
            }
        }

        match self.pending_checkpoint.as_mut() {
            Some(p) if p.sequence == msg.sequence && p.digest == msg.state_digest => {
                p.signatures.insert(*sender, msg.witness_sig);
            }
            Some(_) => {
                // A different (sequence, digest) is in flight; ignore
                // this one. The next checkpoint round will pick it
                // up.
                return Ok(());
            }
            None => {
                let mut signatures = BTreeMap::new();
                signatures.insert(*sender, msg.witness_sig);
                self.pending_checkpoint = Some(CheckpointRound {
                    sequence: msg.sequence,
                    digest: msg.state_digest,
                    signatures,
                });
            }
        }
        self.maybe_promote_checkpoint();
        Ok(())
    }

    fn maybe_promote_checkpoint(&mut self) {
        let quorum = self.membership.quorum();
        let promote = matches!(
            self.pending_checkpoint.as_ref(),
            Some(p) if p.signatures.len() >= quorum
        );
        if !promote {
            return;
        }
        let round = self.pending_checkpoint.take().unwrap();
        self.checkpoint_sequence = round.sequence;
        self.checkpoint_digest = round.digest;
        self.events.push_back(BftEvent::CheckpointStable {
            sequence: round.sequence,
            digest: round.digest,
        });
        self.stable_checkpoint = Some(round);
    }

    // ---- state transfer ----

    /// Request a state transfer from a peer with a newer checkpoint.
    ///
    /// Emits a `bft_state_transfer` with the driver's current
    /// `checkpoint_sequence` (or 0 if none), empty state, and an
    /// empty ring signature. Peers with a newer stable checkpoint
    /// will respond with a fully-populated `bft_state_transfer`.
    pub fn request_state_transfer(&mut self) -> Result<()> {
        let msg = BftStateTransfer {
            ring_id: self.ring_id,
            checkpoint_sequence: self.checkpoint_sequence,
            state: Vec::new(),
            checkpoint_digest: self.checkpoint_digest,
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: Vec::new(),
                signers: Vec::new(),
            }),
        };
        self.outbound
            .push_back(BftOutbound::StateTransferRequest(msg));
        Ok(())
    }

    /// Receive a `bft_state_transfer`.
    ///
    /// Distinguishes requests from responses by inspecting the ring
    /// signature: an empty `IndividualRingSig` is a request, a
    /// populated one is a response.
    ///
    /// On a request, if the driver has a stable checkpoint newer than
    /// the requester's `checkpoint_sequence`, it emits a response.
    ///
    /// On a response, the driver verifies the ring signature against
    /// the `bft_checkpoint` payload for
    /// `(ring_id, checkpoint_sequence, checkpoint_digest)`, checks
    /// that `checkpoint_digest` is the SHA-256 of `state`, installs
    /// the state via the handler, and resumes from the checkpoint
    /// sequence.
    pub fn on_state_transfer(
        &mut self,
        sender: &NodeId,
        msg: &BftStateTransfer,
    ) -> Result<()> {
        if msg.ring_id != self.ring_id {
            return Err(Error::Bft("state transfer for wrong ring"));
        }
        if !self.membership.is_member(sender) {
            return Err(Error::Bft("state transfer from non-member"));
        }

        let is_request = match &msg.ring_signature {
            RingSignature::Individual(irs) => irs.signatures.is_empty(),
            RingSignature::Frost(_) => false,
        };

        if is_request {
            self.handle_state_transfer_request(sender, msg)
        } else {
            self.handle_state_transfer_response(sender, msg)
        }
    }

    fn handle_state_transfer_request(
        &mut self,
        sender: &NodeId,
        msg: &BftStateTransfer,
    ) -> Result<()> {
        self.events.push_back(BftEvent::StateTransferRequested {
            peer: *sender,
            from_sequence: msg.checkpoint_sequence,
        });

        let stable = match self.stable_checkpoint.as_ref() {
            Some(s) => s.clone(),
            None => return Ok(()), // nothing to send
        };
        if stable.sequence <= msg.checkpoint_sequence {
            return Ok(()); // requester is caught up or ahead
        }

        // Build the ring signature from the checkpoint signatures.
        // BTreeMap iteration yields signers in canonical NodeId order,
        // which matches the IndividualRingSig contract.
        let mut signers = Vec::with_capacity(stable.signatures.len());
        let mut signatures = Vec::with_capacity(stable.signatures.len());
        for (signer, sig) in &stable.signatures {
            signers.push(*signer);
            signatures.push(*sig);
        }

        let state = self.handler.state_bytes();
        let response = BftStateTransfer {
            ring_id: self.ring_id,
            checkpoint_sequence: stable.sequence,
            state,
            checkpoint_digest: stable.digest,
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures,
                signers,
            }),
        };
        self.outbound
            .push_back(BftOutbound::StateTransferResponse(response));
        Ok(())
    }

    fn handle_state_transfer_response(
        &mut self,
        _sender: &NodeId,
        msg: &BftStateTransfer,
    ) -> Result<()> {
        // Reject a state transfer for a sequence we have already
        // passed. It would roll our state backwards.
        if msg.checkpoint_sequence <= self.checkpoint_sequence {
            return Ok(());
        }

        // Verify the ring signature against the checkpoint payload.
        if !verify_checkpoint_ring_sig(
            &self.ring_id,
            msg.checkpoint_sequence,
            &msg.checkpoint_digest,
            &msg.ring_signature,
            &self.membership,
            &self.verifier,
        ) {
            return Err(Error::Bft("state transfer ring signature invalid"));
        }

        // Verify the digest matches the transmitted state.
        let computed = sha256(&msg.state);
        if computed != msg.checkpoint_digest {
            return Err(Error::Bft("state transfer digest mismatch"));
        }

        // Install.
        self.handler.apply_state(&msg.state)?;
        self.checkpoint_sequence = msg.checkpoint_sequence;
        self.checkpoint_digest = msg.checkpoint_digest;
        self.sequence = msg.checkpoint_sequence;
        self.current = None;
        self.state = RoundState::Idle;
        self.events.push_back(BftEvent::StateTransferApplied {
            sequence: msg.checkpoint_sequence,
            digest: msg.checkpoint_digest,
        });
        Ok(())
    }
}

// -------------------------------------------------------------------------
// Vote abstraction
// -------------------------------------------------------------------------

/// Common shape of the three vote messages.
///
/// `bft_prepare`, `bft_precommit`, and `bft_commit` are structurally
/// identical; the distinction is a protocol-level one, not a wire-level
/// one. This trait lets [`BftDriver::handle_vote`] be written once.
trait VoteShape {
    fn ring_id(&self) -> &RingId;
    fn view(&self) -> u64;
    fn sequence(&self) -> u64;
    fn digest(&self) -> &Digest;
    fn witness_sig(&self) -> &[u8; 64];
    fn verify(&self, witness: &NodeId, v: &impl Verifier) -> Result<bool>;
    fn insert_vote(&self, current: &mut InFlight, witness: NodeId, sig: [u8; 64]);
}

macro_rules! impl_vote_shape {
    ($ty:ident, $field:ident) => {
        impl VoteShape for $ty {
            fn ring_id(&self) -> &RingId {
                &self.ring_id
            }
            fn view(&self) -> u64 {
                self.view
            }
            fn sequence(&self) -> u64 {
                self.sequence
            }
            fn digest(&self) -> &Digest {
                &self.digest
            }
            fn witness_sig(&self) -> &[u8; 64] {
                &self.witness_sig
            }
            fn verify(&self, witness: &NodeId, v: &impl Verifier) -> Result<bool> {
                $ty::verify(self, witness, v)
            }
            fn insert_vote(
                &self,
                current: &mut InFlight,
                witness: NodeId,
                sig: [u8; 64],
            ) {
                current.$field.insert(witness, sig);
            }
        }
    };
}

impl_vote_shape!(BftPrepare, prepares);
impl_vote_shape!(BftPrecommit, precommits);
impl_vote_shape!(BftCommit, commits);

// -------------------------------------------------------------------------
// Digest helper
// -------------------------------------------------------------------------

/// Compute the pre-prepare digest for `(ring_id, view, sequence,
/// operation)` without needing a `BftPreprepare` in hand.
fn compute_digest_parts(
    ring_id: &RingId,
    view: u64,
    sequence: u64,
    operation: &Operation,
) -> Result<Digest> {
    let op_cbor = encode(&operation.to_cbor())?;
    let mut preimage = Vec::with_capacity(32 + 8 + 8 + op_cbor.len());
    preimage.extend_from_slice(ring_id);
    preimage.extend_from_slice(&view.to_be_bytes());
    preimage.extend_from_slice(&sequence.to_be_bytes());
    preimage.extend_from_slice(&op_cbor);
    Ok(sha256(&preimage))
}

/// SHA-256 of `data`, as a 32-byte array.
fn sha256(data: &[u8]) -> Digest {
    use sha2::{Digest as _, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let out = hasher.finalize();
    let mut d = [0u8; 32];
    d.copy_from_slice(&out);
    d
}

/// Verify a ring signature over a checkpoint.
///
/// Each signature is checked against the `bft_checkpoint` signing
/// payload for `(ring_id, checkpoint_sequence, checkpoint_digest)`,
/// not against the state transfer's own payload. See the module-level
/// "S8" note for why.
///
/// FROST ring signatures are not verified in this revision: the
/// function returns `false` and the caller rejects the transfer.
fn verify_checkpoint_ring_sig(
    ring_id: &RingId,
    checkpoint_sequence: u64,
    checkpoint_digest: &Digest,
    ring_sig: &RingSignature,
    membership: &RingMembership,
    verifier: &impl Verifier,
) -> bool {
    // Reconstruct the checkpoint signing payload for the transferred
    // sequence and digest.
    let payload = match (BftCheckpoint {
        ring_id: *ring_id,
        sequence: checkpoint_sequence,
        state_digest: *checkpoint_digest,
        witness_sig: [0u8; 64],
    })
    .signing_payload()
    {
        Ok(p) => p,
        Err(_) => return false,
    };

    let irs = match ring_sig {
        RingSignature::Individual(irs) => irs,
        RingSignature::Frost(_) => return false,
    };
    if irs.signatures.len() != irs.signers.len() {
        return false;
    }
    if irs.signatures.len() < membership.quorum() {
        return false;
    }

    let mut seen: BTreeMap<NodeId, ()> = BTreeMap::new();
    for (signer, sig) in irs.signers.iter().zip(irs.signatures.iter()) {
        if !membership.is_member(signer) {
            return false;
        }
        if seen.insert(*signer, ()).is_some() {
            return false; // duplicate signer
        }
        if !verifier.verify_ed25519(signer, &payload, sig) {
            return false;
        }
    }
    true
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Ed25519Signer, Ed25519Verifier};
    use quip_core::cbor::CborValue;

    fn seed(i: u8) -> [u8; 32] {
        let mut s = [0u8; 32];
        s[0] = i;
        s
    }

    fn signer(i: u8) -> Ed25519Signer {
        Ed25519Signer::from_seed(&seed(i))
    }

    /// A 7-member ring of deterministic signers.
    fn ring7() -> (RingMembership, Vec<Ed25519Signer>) {
        let signers: Vec<_> = (1..=7).map(signer).collect();
        let ids: Vec<NodeId> = signers.iter().map(|s| s.public_key()).collect();
        (RingMembership::new(ids).unwrap(), signers)
    }

    fn operation(kind: &str) -> Operation {
        Operation {
            kind: String::from(kind),
            subject: vec![0x11; 32],
            body: CborValue::Null,
        }
    }

    /// A handler that tracks a single u64 counter. Each `apply`
    /// increments it; state_bytes is the big-endian counter;
    /// apply_state installs a transmitted counter.
    #[derive(Default)]
    struct CountingHandler {
        counter: u64,
        applied: Vec<(RingId, u64, Operation)>,
    }

    impl BftHandler for CountingHandler {
        fn apply(
            &mut self,
            ring_id: &RingId,
            sequence: u64,
            operation: &Operation,
        ) -> Result<()> {
            self.counter = self.counter.saturating_add(1);
            self.applied.push((*ring_id, sequence, operation.clone()));
            Ok(())
        }

        fn state_digest(&self) -> Digest {
            sha256(&self.counter.to_be_bytes())
        }

        fn state_bytes(&self) -> Vec<u8> {
            self.counter.to_be_bytes().to_vec()
        }

        fn apply_state(&mut self, state: &[u8]) -> Result<()> {
            if state.len() != 8 {
                return Err(Error::Bft("counting state must be 8 bytes"));
            }
            let mut arr = [0u8; 8];
            arr.copy_from_slice(state);
            self.counter = u64::from_be_bytes(arr);
            Ok(())
        }
    }

    /// A handler that records operations but has no meaningful state
    /// (the trait's default state methods apply).
    #[derive(Default)]
    struct RecordingHandler {
        applied: Vec<(RingId, u64, Operation)>,
    }

    impl BftHandler for RecordingHandler {
        fn apply(
            &mut self,
            ring_id: &RingId,
            sequence: u64,
            operation: &Operation,
        ) -> Result<()> {
            self.applied.push((*ring_id, sequence, operation.clone()));
            Ok(())
        }
    }

    struct FailingHandler;
    impl BftHandler for FailingHandler {
        fn apply(&mut self, _: &RingId, _: u64, _: &Operation) -> Result<()> {
            Err(Error::Bft("handler refused"))
        }
    }

    type Driver = BftDriver<Ed25519Signer, Ed25519Verifier, RecordingHandler>;
    type CountingDriver = BftDriver<Ed25519Signer, Ed25519Verifier, CountingHandler>;

    /// Build drivers in canonical membership order, so `drivers[i]`
    /// has NodeId `m.members()[i]`.
    fn drivers_in_order<H: BftHandler>(
        m: &RingMembership,
        signers: Vec<Ed25519Signer>,
        handlers: impl Fn() -> H,
        ring_id: RingId,
        view: u64,
    ) -> Vec<BftDriver<Ed25519Signer, Ed25519Verifier, H>> {
        let by_id: BTreeMap<NodeId, Ed25519Signer> = signers
            .into_iter()
            .map(|s| (s.public_key(), s))
            .collect();
        m.members()
            .iter()
            .map(|id| {
                BftDriver::new(
                    by_id[id].clone(),
                    Ed25519Verifier,
                    handlers(),
                    ring_id,
                    m.clone(),
                    view,
                )
                .unwrap()
            })
            .collect()
    }

    fn build_ring() -> (RingMembership, Vec<Driver>) {
        let (m, signers) = ring7();
        let drivers = drivers_in_order(
            &m,
            signers,
            RecordingHandler::default,
            [1; 32],
            0,
        );
        (m, drivers)
    }

    fn build_counting_ring() -> (RingMembership, Vec<CountingDriver>) {
        let (m, signers) = ring7();
        let drivers = drivers_in_order(
            &m,
            signers,
            CountingHandler::default,
            [1; 32],
            0,
        );
        (m, drivers)
    }

    /// Propagate messages until quiescent. Returns collected events
    /// per driver.
    fn pump(
        drivers: &mut [Driver],
        membership: &RingMembership,
    ) -> Vec<Vec<BftEvent>> {
        let n = drivers.len();
        let mut all: Vec<Vec<BftEvent>> = (0..n).map(|_| Vec::new()).collect();
        for _ in 0..20 {
            for (i, d) in drivers.iter_mut().enumerate() {
                all[i].extend(d.drain_events());
            }
            let mut msgs: Vec<(usize, BftOutbound)> = Vec::new();
            for (i, d) in drivers.iter_mut().enumerate() {
                for out in d.drain_outbound() {
                    msgs.push((i, out));
                }
            }
            if msgs.is_empty() {
                break;
            }
            for (sender_idx, out) in msgs {
                let sender = membership.members()[sender_idx];
                for (i, d) in drivers.iter_mut().enumerate() {
                    if i == sender_idx {
                        continue;
                    }
                    let _ = match &out {
                        BftOutbound::Preprepare(m) => d.on_preprepare(&sender, m),
                        BftOutbound::Prepare(m) => d.on_prepare(&sender, m),
                        BftOutbound::Precommit(m) => d.on_precommit(&sender, m),
                        BftOutbound::Commit(m) => d.on_commit(&sender, m),
                        BftOutbound::ViewChange(m) => d.on_view_change(&sender, m),
                        BftOutbound::NewView(m) => d.on_new_view(&sender, m),
                        BftOutbound::Checkpoint(m) => d.on_checkpoint(&sender, m),
                        BftOutbound::StateTransferRequest(m)
                        | BftOutbound::StateTransferResponse(m) => {
                            d.on_state_transfer(&sender, m)
                        }
                    };
                }
            }
        }
        all
    }

    /// Deliver only checkpoint messages, so checkpoint stability can
    /// be tested in isolation from state transfers.
    fn pump_checkpoints(
        drivers: &mut [CountingDriver],
        membership: &RingMembership,
    ) {
        for _ in 0..20 {
            let mut msgs: Vec<(usize, BftOutbound)> = Vec::new();
            for (i, d) in drivers.iter_mut().enumerate() {
                for out in d.drain_outbound() {
                    msgs.push((i, out));
                }
            }
            if msgs.is_empty() {
                return;
            }
            for (sender_idx, out) in msgs {
                let sender = membership.members()[sender_idx];
                for (i, d) in drivers.iter_mut().enumerate() {
                    if i == sender_idx {
                        continue;
                    }
                    if let BftOutbound::Checkpoint(m) = &out {
                        let _ = d.on_checkpoint(&sender, m);
                    }
                }
            }
        }
    }

    /// Pump messages including checkpoints and state transfers, used
    /// by the counting-handler tests.
    fn pump_counting(
        drivers: &mut [CountingDriver],
        membership: &RingMembership,
    ) -> Vec<Vec<BftEvent>> {
        let n = drivers.len();
        let mut all: Vec<Vec<BftEvent>> = (0..n).map(|_| Vec::new()).collect();
        for _ in 0..20 {
            for (i, d) in drivers.iter_mut().enumerate() {
                all[i].extend(d.drain_events());
            }
            let mut msgs: Vec<(usize, BftOutbound)> = Vec::new();
            for (i, d) in drivers.iter_mut().enumerate() {
                for out in d.drain_outbound() {
                    msgs.push((i, out));
                }
            }
            if msgs.is_empty() {
                break;
            }
            for (sender_idx, out) in msgs {
                let sender = membership.members()[sender_idx];
                for (i, d) in drivers.iter_mut().enumerate() {
                    if i == sender_idx {
                        continue;
                    }
                    let _ = match &out {
                        BftOutbound::Preprepare(m) => d.on_preprepare(&sender, m),
                        BftOutbound::Prepare(m) => d.on_prepare(&sender, m),
                        BftOutbound::Precommit(m) => d.on_precommit(&sender, m),
                        BftOutbound::Commit(m) => d.on_commit(&sender, m),
                        BftOutbound::ViewChange(m) => d.on_view_change(&sender, m),
                        BftOutbound::NewView(m) => d.on_new_view(&sender, m),
                        BftOutbound::Checkpoint(m) => d.on_checkpoint(&sender, m),
                        BftOutbound::StateTransferRequest(m)
                        | BftOutbound::StateTransferResponse(m) => {
                            d.on_state_transfer(&sender, m)
                        }
                    };
                }
            }
        }
        all
    }

    /// Pump view-change messages only.
    fn pump_view_change(
        drivers: &mut [Driver],
        membership: &RingMembership,
    ) {
        for _ in 0..30 {
            let mut msgs: Vec<(usize, BftOutbound)> = Vec::new();
            for (i, d) in drivers.iter_mut().enumerate() {
                for out in d.drain_outbound() {
                    msgs.push((i, out));
                }
            }
            if msgs.is_empty() {
                return;
            }
            for (sender_idx, out) in msgs {
                let sender = membership.members()[sender_idx];
                for (i, d) in drivers.iter_mut().enumerate() {
                    if i == sender_idx {
                        continue;
                    }
                    let _ = match &out {
                        BftOutbound::ViewChange(m) => d.on_view_change(&sender, m),
                        BftOutbound::NewView(m) => d.on_new_view(&sender, m),
                        _ => Ok(()),
                    };
                }
            }
        }
    }

    // ---- RingMembership ----

    #[test]
    fn ring_sorts_into_canonical_order() {
        let ids: Vec<NodeId> = (1..=7).map(|i| [i; 32]).collect();
        let mut shuffled = ids.clone();
        shuffled.reverse();
        let m = RingMembership::new(shuffled).unwrap();
        assert_eq!(m.members(), ids.as_slice());
    }

    #[test]
    fn ring_dedups() {
        let mut ids: Vec<NodeId> = (1..=7).map(|i| [i; 32]).collect();
        ids.push([1; 32]);
        let m = RingMembership::new(ids).unwrap();
        assert_eq!(m.len(), 7);
    }

    #[test]
    fn ring_rejects_too_small() {
        let ids: Vec<NodeId> = (1..=3).map(|i| [i; 32]).collect();
        assert!(RingMembership::new(ids).is_err());
    }

    #[test]
    fn ring_quorum_is_five_of_seven() {
        let (m, _) = ring7();
        assert_eq!(m.quorum(), 5);
    }

    #[test]
    fn ring_quorum_is_three_of_four() {
        let ids: Vec<NodeId> = (1..=4).map(|i| [i; 32]).collect();
        let m = RingMembership::new(ids).unwrap();
        assert_eq!(m.quorum(), 3);
    }

    #[test]
    fn primary_rotates_by_view() {
        let (m, _) = ring7();
        assert_eq!(m.primary_for(0), m.members()[0]);
        assert_eq!(m.primary_for(1), m.members()[1]);
        assert_eq!(m.primary_for(7), m.members()[0]);
        assert_eq!(m.primary_for(8), m.members()[1]);
    }

    // ---- driver construction ----

    #[test]
    fn new_rejects_non_member_signer() {
        let (m, _) = ring7();
        let outsider = signer(99);
        let r = BftDriver::new(
            outsider,
            Ed25519Verifier,
            RecordingHandler::default(),
            [1; 32],
            m,
            0,
        );
        assert!(r.is_err());
    }

    // ---- proposing ----

    #[test]
    fn non_primary_cannot_start() {
        let (m, signers) = ring7();
        let mut d = BftDriver::new(
            signers.into_iter().nth(1).unwrap(),
            Ed25519Verifier,
            RecordingHandler::default(),
            [1; 32],
            m,
            0,
        )
        .unwrap();
        assert!(d.start(operation("key_rotation")).is_err());
        assert_eq!(*d.state(), RoundState::Idle);
    }

    #[test]
    fn primary_start_emits_preprepare_and_prepare() {
        let (m, signers) = ring7();
        let primary_id = m.primary_for(0);
        let primary_signer = signers
            .into_iter()
            .find(|s| s.public_key() == primary_id)
            .unwrap();
        let mut d = BftDriver::new(
            primary_signer,
            Ed25519Verifier,
            RecordingHandler::default(),
            [1; 32],
            m,
            0,
        )
        .unwrap();
        d.start(operation("key_rotation")).unwrap();
        let out = d.drain_outbound();
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], BftOutbound::Preprepare(_)));
        assert!(matches!(out[1], BftOutbound::Prepare(_)));
        assert_eq!(*d.state(), RoundState::PrePrepared);

        let ev = d.drain_events();
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0], BftEvent::Proposed { .. }));
    }

    // ---- full round ----

    #[test]
    fn full_round_applies_on_all_nodes() {
        let (m, mut drivers) = build_ring();
        drivers[0].start(operation("key_rotation")).unwrap();
        let events = pump(&mut drivers, &m);

        for (i, evs) in events.iter().enumerate() {
            let applied = evs
                .iter()
                .filter(|e| matches!(e, BftEvent::Applied { .. }))
                .count();
            assert_eq!(applied, 1, "driver {i} applied exactly once");
        }
        for d in &drivers {
            assert_eq!(d.handler().applied.len(), 1);
            assert_eq!(d.sequence(), 1, "sequence advanced");
            assert_eq!(*d.state(), RoundState::Idle);
        }
    }

    #[test]
    fn apply_failure_is_an_event_not_an_error() {
        let signers: Vec<_> = (1..=4).map(signer).collect();
        let ids: Vec<NodeId> = signers.iter().map(|s| s.public_key()).collect();
        let m4 = RingMembership::new(ids).unwrap();
        let mut drivers = drivers_in_order(
            &m4,
            signers,
            || FailingHandler,
            [1; 32],
            0,
        );
        drivers[0].start(operation("revocation")).unwrap();
        let events = pump_generic(&mut drivers, &m4);

        let any_failed = events
            .iter()
            .any(|evs| evs.iter().any(|e| matches!(e, BftEvent::ApplyFailed { .. })));
        assert!(any_failed);
        for d in &drivers {
            assert_eq!(d.sequence(), 1);
        }
    }

    /// Like `pump` but generic over any handler.
    fn pump_generic<H: BftHandler>(
        drivers: &mut [BftDriver<Ed25519Signer, Ed25519Verifier, H>],
        membership: &RingMembership,
    ) -> Vec<Vec<BftEvent>> {
        let n = drivers.len();
        let mut all: Vec<Vec<BftEvent>> = (0..n).map(|_| Vec::new()).collect();
        for _ in 0..20 {
            for (i, d) in drivers.iter_mut().enumerate() {
                all[i].extend(d.drain_events());
            }
            let mut msgs: Vec<(usize, BftOutbound)> = Vec::new();
            for (i, d) in drivers.iter_mut().enumerate() {
                for out in d.drain_outbound() {
                    msgs.push((i, out));
                }
            }
            if msgs.is_empty() {
                break;
            }
            for (sender_idx, out) in msgs {
                let sender = membership.members()[sender_idx];
                for (i, d) in drivers.iter_mut().enumerate() {
                    if i == sender_idx {
                        continue;
                    }
                    let _ = match &out {
                        BftOutbound::Preprepare(m) => d.on_preprepare(&sender, m),
                        BftOutbound::Prepare(m) => d.on_prepare(&sender, m),
                        BftOutbound::Precommit(m) => d.on_precommit(&sender, m),
                        BftOutbound::Commit(m) => d.on_commit(&sender, m),
                        BftOutbound::ViewChange(m) => d.on_view_change(&sender, m),
                        BftOutbound::NewView(m) => d.on_new_view(&sender, m),
                        BftOutbound::Checkpoint(m) => d.on_checkpoint(&sender, m),
                        BftOutbound::StateTransferRequest(m)
                        | BftOutbound::StateTransferResponse(m) => {
                            d.on_state_transfer(&sender, m)
                        }
                    };
                }
            }
        }
        all
    }

    // ---- view change ----

    #[test]
    fn start_view_change_emits_view_change_vote() {
        let (m, mut drivers) = build_ring();
        drivers[1].start_view_change().unwrap();
        let ev = drivers[1].drain_events();
        assert!(ev
            .iter()
            .any(|e| matches!(e, BftEvent::ViewChangeInitiated { target_view: 1 })));
        let out = drivers[1].drain_outbound();
        assert_eq!(out.len(), 1);
        match &out[0] {
            BftOutbound::ViewChange(vc) => {
                assert_eq!(vc.new_view, 1);
                assert_eq!(vc.ring_id, [1; 32]);
            }
            other => panic!("expected ViewChange, got {other:?}"),
        }
        assert_eq!(drivers[1].view_change_votes(), 1);
        assert_eq!(drivers[1].view(), 0);
        let _ = m;
    }

    #[test]
    fn view_change_promotes_new_primary() {
        let (m, mut drivers) = build_ring();
        for d in &mut drivers {
            d.start_view_change().unwrap();
        }
        pump_view_change(&mut drivers, &m);
        for d in &drivers {
            assert_eq!(d.view(), 1, "all drivers adopt view 1");
        }
    }

    #[test]
    fn new_view_rejected_below_quorum() {
        let (m, mut drivers) = build_ring();
        for d in drivers.iter_mut().take(4) {
            d.start_view_change().unwrap();
        }
        pump_view_change(&mut drivers, &m);
        for d in &drivers {
            assert_eq!(d.view(), 0, "no view change without quorum");
        }
    }

    #[test]
    fn stale_view_change_vote_is_ignored() {
        let (m, mut drivers) = build_ring();
        for d in &mut drivers {
            d.start_view_change().unwrap();
        }
        pump_view_change(&mut drivers, &m);
        for d in &drivers {
            assert_eq!(d.view(), 1);
        }
        let stale = BftViewChange {
            ring_id: [1; 32],
            new_view: 0,
            last_sequence: 0,
            prepared_digests: vec![],
            checkpoint_digest: [0; 32],
            witness_sig: [0; 64],
        };
        let sender = m.members()[2];
        let r = drivers[3].on_view_change(&sender, &stale);
        assert!(r.is_ok(), "stale vote silently ignored");
        assert_eq!(drivers[3].view(), 1);
    }

    #[test]
    fn new_view_from_wrong_sender_rejected() {
        let (m, mut drivers) = build_ring();
        for d in &mut drivers {
            d.start_view_change().unwrap();
        }
        pump_view_change(&mut drivers, &m);
        let mut msg = BftNewView {
            ring_id: [1; 32],
            view: 2,
            view_change_messages: vec![],
            prepared_messages: vec![],
            checkpoint_messages: vec![],
            primary_sig: [0; 64],
        };
        let payload = msg.signing_payload().unwrap();
        msg.primary_sig = drivers[0].signer.sign_ed25519(&payload);
        let not_primary = m.members()[0];
        let r = drivers[3].on_new_view(&not_primary, &msg);
        assert!(r.is_err());
    }

    #[test]
    fn duplicate_view_change_votes_are_deduped() {
        let (m, mut drivers) = build_ring();
        let m1 = m.members()[1];
        let m2 = m.members()[2];
        drivers[1].start_view_change().unwrap();
        let out = drivers[1].drain_outbound();
        let vc = match &out[0] {
            BftOutbound::ViewChange(v) => v.clone(),
            _ => panic!("expected ViewChange"),
        };
        drivers[3].on_view_change(&m1, &vc).unwrap();
        let before = drivers[3].view_change_votes();
        drivers[3].on_view_change(&m1, &vc).unwrap();
        assert_eq!(drivers[3].view_change_votes(), before);
        let _ = drivers[3].on_view_change(&m2, &vc);
    }

    // ---- checkpointing ----

    #[test]
    fn start_checkpoint_emits_signed_checkpoint() {
        let (m, mut drivers) = build_counting_ring();
        let d = &mut drivers[2];
        d.start_checkpoint().unwrap();
        let out = d.drain_outbound();
        assert_eq!(out.len(), 1);
        match &out[0] {
            BftOutbound::Checkpoint(cp) => {
                assert_eq!(cp.ring_id, [1; 32]);
                assert_eq!(cp.sequence, 0);
                assert_ne!(cp.witness_sig, [0u8; 64]);
            }
            other => panic!("expected Checkpoint, got {other:?}"),
        }
        let _ = m;
    }

    #[test]
    fn checkpoint_reaches_stability_at_quorum() {
        let (m, mut drivers) = build_counting_ring();
        for d in &mut drivers {
            d.start_checkpoint().unwrap();
        }
        pump_checkpoints(&mut drivers, &m);
        for (i, d) in drivers.iter().enumerate() {
            assert!(
                d.stable_checkpoint_signatures().is_some(),
                "driver {i} should have a stable checkpoint"
            );
            assert_eq!(d.checkpoint_sequence(), 0);
            assert!(d.stable_checkpoint_signatures().unwrap() >= m.quorum());
        }
    }

    // ---- state transfer ----

    #[test]
    fn request_state_transfer_emits_empty_message() {
        let (m, mut drivers) = build_counting_ring();
        drivers[0].request_state_transfer().unwrap();
        let out = drivers[0].drain_outbound();
        assert_eq!(out.len(), 1);
        match &out[0] {
            BftOutbound::StateTransferRequest(msg) => {
                assert_eq!(msg.checkpoint_sequence, 0);
                assert!(msg.state.is_empty());
            }
            other => panic!("expected StateTransferRequest, got {other:?}"),
        }
        let _ = m;
    }

    #[test]
    fn state_transfer_roundtrip() {
        let (m, mut drivers) = build_counting_ring();

        // Drive one successful round so the counting handlers all
        // increment to 1.
        drivers[0].start(operation("revocation")).unwrap();
        let _ = pump_counting(&mut drivers, &m);
        for d in &drivers {
            assert_eq!(d.handler().counter, 1);
            assert_eq!(d.sequence(), 1);
        }

        // Force a checkpoint at sequence 1. It is not a multiple of
        // CHECKPOINT_INTERVAL, so the caller drives it explicitly.
        for d in &mut drivers {
            d.start_checkpoint().unwrap();
        }
        pump_checkpoints(&mut drivers, &m);
        assert_eq!(drivers[0].checkpoint_sequence(), 1);
        assert!(drivers[0].stable_checkpoint_signatures().unwrap() >= m.quorum());

        // Snapshot a healthy driver's state.
        let healthy_state = drivers[3].handler().state_bytes();
        let healthy_digest = drivers[3].handler().state_digest();
        assert_eq!(healthy_digest, *drivers[0].checkpoint_digest());

        // Make driver 0 look lagging.
        drivers[0].handler_mut().counter = 0;
        drivers[0].checkpoint_sequence = 0;
        drivers[0].checkpoint_digest = [0u8; 32];
        drivers[0].stable_checkpoint = None;
        drivers[0].sequence = 0;

        // Request state transfer.
        drivers[0].request_state_transfer().unwrap();
        let request = match drivers[0].drain_outbound().into_iter().next() {
            Some(BftOutbound::StateTransferRequest(msg)) => msg,
            other => panic!("expected request, got {other:?}"),
        };

        // Deliver it to a healthy peer and collect its response.
        drivers[2]
            .on_state_transfer(&m.members()[0], &request)
            .unwrap();
        let response = match drivers[2].drain_outbound().into_iter().next() {
            Some(BftOutbound::StateTransferResponse(msg)) => msg,
            other => panic!("expected response, got {other:?}"),
        };

        // Deliver the response to driver 0.
        drivers[0]
            .on_state_transfer(&m.members()[2], &response)
            .unwrap();

        assert_eq!(drivers[0].checkpoint_sequence, 1);
        assert_eq!(drivers[0].checkpoint_digest, healthy_digest);
        assert_eq!(drivers[0].handler().counter, 1);
        assert_eq!(drivers[0].sequence(), 1);
        assert_eq!(drivers[0].handler().state_bytes(), healthy_state);
    }

    #[test]
    fn state_transfer_rejects_digest_mismatch() {
        let (m, mut drivers) = build_counting_ring();

        // Bring the ring to a stable checkpoint at sequence 1.
        drivers[0].start(operation("revocation")).unwrap();
        let _ = pump_counting(&mut drivers, &m);
        for d in &mut drivers {
            d.start_checkpoint().unwrap();
        }
        pump_checkpoints(&mut drivers, &m);
        assert_eq!(drivers[0].checkpoint_sequence(), 1);

        // Make driver 0 lagging.
        drivers[0].handler_mut().counter = 0;
        drivers[0].checkpoint_sequence = 0;
        drivers[0].checkpoint_digest = [0u8; 32];
        drivers[0].stable_checkpoint = None;
        drivers[0].sequence = 0;

        // Get a real response.
        let request = BftStateTransfer {
            ring_id: [1; 32],
            checkpoint_sequence: 0,
            state: Vec::new(),
            checkpoint_digest: [0u8; 32],
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: Vec::new(),
                signers: Vec::new(),
            }),
        };
        drivers[2]
            .on_state_transfer(&m.members()[0], &request)
            .unwrap();
        let mut response = match drivers[2].drain_outbound().into_iter().next() {
            Some(BftOutbound::StateTransferResponse(msg)) => msg,
            other => panic!("expected response, got {other:?}"),
        };

        // Tamper with the state bytes, leaving the digest untouched.
        response.state.push(0xFF);

        let err = drivers[0].on_state_transfer(&m.members()[2], &response);
        assert!(err.is_err(), "digest mismatch must be rejected");
    }

    #[test]
    fn state_transfer_rejects_bad_ring_signature() {
        let (m, mut drivers) = build_counting_ring();

        let bad = BftStateTransfer {
            ring_id: [1; 32],
            checkpoint_sequence: 5,
            state: vec![0, 0, 0, 0, 0, 0, 0, 1],
            checkpoint_digest: sha256(&[0u8, 0, 0, 0, 0, 0, 0, 1]),
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0u8; 64]; 5],
                signers: vec![
                    m.members()[0],
                    m.members()[1],
                    m.members()[2],
                    m.members()[3],
                    m.members()[4],
                ],
            }),
        };
        let err = drivers[0].on_state_transfer(&m.members()[3], &bad);
        assert!(err.is_err(), "invalid ring signature must be rejected");
    }

    #[test]
    fn state_transfer_ignores_older_sequence() {
        let (m, mut drivers) = build_counting_ring();
        drivers[0].sequence = 5;
        drivers[0].checkpoint_sequence = 5;

        let old = BftStateTransfer {
            ring_id: [1; 32],
            checkpoint_sequence: 3,
            state: vec![0u8; 8],
            checkpoint_digest: sha256(&[0u8; 8]),
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0u8; 64]; 5],
                signers: vec![
                    m.members()[0],
                    m.members()[1],
                    m.members()[2],
                    m.members()[3],
                    m.members()[4],
                ],
            }),
        };
        drivers[0].on_state_transfer(&m.members()[3], &old).unwrap();
        assert_eq!(drivers[0].checkpoint_sequence, 5);
    }

    // ---- rejection paths ----

    #[test]
    fn preprepare_from_wrong_sender_rejected() {
        let (m, signers) = ring7();
        let not_primary = signers.into_iter().nth(1).unwrap();
        let mut d = BftDriver::new(
            signer(2),
            Ed25519Verifier,
            RecordingHandler::default(),
            [1; 32],
            m,
            0,
        )
        .unwrap();
        let bogus = BftPreprepare {
            ring_id: [1; 32],
            view: 0,
            sequence: 0,
            operation: operation("key_rotation"),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        let sender = not_primary.public_key();
        assert!(d.on_preprepare(&sender, &bogus).is_err());
    }

    #[test]
    fn prepare_from_non_member_rejected() {
        let (m, signers) = ring7();
        let primary_id = m.primary_for(0);
        let primary_signer = signers
            .into_iter()
            .find(|s| s.public_key() == primary_id)
            .unwrap();
        let mut d = BftDriver::new(
            primary_signer,
            Ed25519Verifier,
            RecordingHandler::default(),
            [1; 32],
            m,
            0,
        )
        .unwrap();
        d.start(operation("key_rotation")).unwrap();
        let _ = d.drain_outbound();

        let outsider = [0xeeu8; 32];
        let bogus = BftPrepare {
            ring_id: [1; 32],
            view: 0,
            sequence: 0,
            digest: [0; 32],
            witness_sig: [0; 64],
        };
        assert!(d.on_prepare(&outsider, &bogus).is_err());
    }

    #[test]
    fn preprepare_for_wrong_ring_rejected() {
        let (m, signers) = ring7();
        let primary = signers.into_iter().next().unwrap();
        let sender = primary.public_key();
        let mut d = BftDriver::new(
            signer(2),
            Ed25519Verifier,
            RecordingHandler::default(),
            [1; 32],
            m,
            0,
        )
        .unwrap();
        let bogus = BftPreprepare {
            ring_id: [0xff; 32],
            view: 0,
            sequence: 0,
            operation: operation("key_rotation"),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        assert!(d.on_preprepare(&sender, &bogus).is_err());
    }

    #[test]
    fn out_of_sequence_preprepare_dropped_silently() {
        let (m, signers) = ring7();
        let primary = signers.into_iter().next().unwrap();
        let sender = primary.public_key();
        let mut d = BftDriver::new(
            signer(2),
            Ed25519Verifier,
            RecordingHandler::default(),
            [1; 32],
            m,
            0,
        )
        .unwrap();
        let stale = BftPreprepare {
            ring_id: [1; 32],
            view: 0,
            sequence: 42,
            operation: operation("key_rotation"),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        assert!(d.on_preprepare(&sender, &stale).is_ok());
        assert_eq!(*d.state(), RoundState::Idle);
    }
}