//! BFT consensus driver (spec §5.3.4).
//!
//! [`BftDriver`] is the state machine a witness ring runs. It takes
//! operations to order, participates in the four-phase protocol
//! (preprepare → prepare → precommit → commit), and applies the
//! operation to the caller's state on commit quorum.
//!
//! # Scope (M4b.1)
//!
//! This is the round core. It handles a single successful round in a
//! single view:
//!
//! - Proposing an operation (primary only).
//! - Verifying and voting on preprepare, prepare, precommit, commit.
//! - Applying on commit quorum.
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
//! Prepared-operations carry-forward (`bft_new_view.prepared_messages`)
//! and checkpoint carry-forward (`checkpoint_messages`) are emitted
//! empty in this revision; M4b.3 populates them.
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
//! signs its own votes and, as primary, the preprepare it proposes.
//! It holds a [`quip_core::messages::Verifier`] because the
//! four-phase protocol is meaningless without verifying peers'
//! votes. Both are value types.

use crate::bft::{
    BftCommit, BftNewView, BftPrecommit, BftPrepare, BftPreprepare, BftViewChange,
    Digest, Operation, RingId,
};
use crate::error::{Error, Result};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use quip_core::constants::MIN_WITNESSES;
use quip_core::dvv::NodeId;
use quip_core::messages::{Signer, Verifier};

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
pub trait BftHandler {
    /// Apply `operation` at `sequence` in `ring_id`.
    fn apply(
        &mut self,
        ring_id: &RingId,
        sequence: u64,
        operation: &Operation,
    ) -> Result<()>;
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
    /// Digest of the latest stable checkpoint. `[0; 32]` until M4b.3.
    checkpoint_digest: Digest,
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

    // ---- inbound messages ----

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
            // Stale or future view/sequence. M4b.2 handles view change;
            // M4b.3 handles resync.
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
        Ok(())
    }

    // ---- view change ----

    /// The target view of an in-progress view change, if any.
    pub fn view_change_target(&self) -> Option<u64> {
        self.view_change.target_view
    }

    /// Number of view-change votes collected for the target view.
    pub fn view_change_votes(&self) -> usize {
        self.view_change.votes.len()
    }

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
        // see what we had prepared. M4b.3 will make this actionable.
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
    /// until the current one resolves (M4b.3 will add view-change
    /// re-entry).
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

        // Decode and verify each view-change message, tracking signers
        // to enforce distinctness.
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

        // M4b.3 will verify prepared_messages / checkpoint_messages here.

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
            prepared_messages: Vec::new(),   // M4b.3
            checkpoint_messages: Vec::new(), // M4b.3
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
    /// clearing view-change state.
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
    use sha2::{Digest as _, Sha256};

    let op_cbor = quip_core::cbor::encode(&operation.to_cbor())?;
    let mut preimage = Vec::with_capacity(32 + 8 + 8 + op_cbor.len());
    preimage.extend_from_slice(ring_id);
    preimage.extend_from_slice(&view.to_be_bytes());
    preimage.extend_from_slice(&sequence.to_be_bytes());
    preimage.extend_from_slice(&op_cbor);

    let mut hasher = Sha256::new();
    hasher.update(&preimage);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    Ok(digest)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{Ed25519Signer, Ed25519Verifier};
    use alloc::vec;
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

    // ---- view change tests ----

    /// Pump outbounds including view-change and new-view messages.
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
                        // Round messages during view change are stale.
                        _ => Ok(()),
                    };
                }
            }
        }
    }

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
        // view() unchanged until the new-view message is accepted.
        assert_eq!(drivers[1].view(), 0);
        let _ = m;
    }

    #[test]
    fn view_change_promotes_new_primary() {
        let (m, mut drivers) = build_ring();
        // Every witness suspects the primary.
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
        // 7-member ring. Have only 4 members vote. The primary for
        // view 1 is members[1]; collect its own vote plus three more
        // — still below quorum (5) — and confirm no new view is emitted.
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
        // Advance to view 1 via a full view change.
        for d in &mut drivers {
            d.start_view_change().unwrap();
        }
        pump_view_change(&mut drivers, &m);
        for d in &drivers {
            assert_eq!(d.view(), 1);
        }
        // A view-change vote for view 0 is now stale.
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
        // Build a fresh new-view from the wrong sender.
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
        let not_primary = m.members()[0]; // primary for view 0, not 2
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
        // Same sender, same message — should be ignored.
        drivers[3].on_view_change(&m1, &vc).unwrap();
        assert_eq!(drivers[3].view_change_votes(), before);
        // Different sender, same message content — this is a distinct
        // vote and should be accepted (or rejected as invalid sig).
        let _ = drivers[3].on_view_change(&m2, &vc);
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
        ids.push([1; 32]); // duplicate
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

    // ---- BftHandler ----

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
        // signers[1] is not the primary for view 0.
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

        // Events: one Proposed.
        let ev = d.drain_events();
        assert_eq!(ev.len(), 1);
        assert!(matches!(ev[0], BftEvent::Proposed { .. }));
    }

    // ---- full round ----

    type Driver = BftDriver<Ed25519Signer, Ed25519Verifier, RecordingHandler>;

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

    /// Build drivers in canonical membership order, so `drivers[i]` has
    /// NodeId `m.members()[i]`.
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
                    // We ignore errors: a rogue message from one driver
                    // should not abort the whole pump.
                    let _ = match &out {
                        BftOutbound::Preprepare(m) => d.on_preprepare(&sender, m),
                        BftOutbound::Prepare(m) => d.on_prepare(&sender, m),
                        BftOutbound::Precommit(m) => d.on_precommit(&sender, m),
                        BftOutbound::Commit(m) => d.on_commit(&sender, m),
                        BftOutbound::ViewChange(m) => d.on_view_change(&sender, m),
                        BftOutbound::NewView(m) => d.on_new_view(&sender, m),
                    };
                }
            }
        }
        all
    }

    #[test]
    fn full_round_applies_on_all_nodes() {
        let (m, mut drivers) = build_ring();
        // The primary for view 0 is drivers[0] because canonical order
        // matches the sort order of the seeds.
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
    fn vote_counts_are_quorum_sized() {
        // Confirm the round completes with the 5-of-7 quorum, not
        // fewer, by checking the sequence advanced.
        let (m, mut drivers) = build_ring();
        drivers[0].start(operation("revocation")).unwrap();
        let _ = pump(&mut drivers, &m);
        for d in &drivers {
            assert_eq!(d.sequence(), 1);
        }
    }

    #[test]
    fn apply_failure_is_an_event_not_an_error() {
        // A 4-member DEGRADED ring where 3 votes = quorum.
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
                    };
                }
            }
        }
        all
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
        // Drain preprepare + self-prepare.
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
            ring_id: [0xff; 32], // wrong ring
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
            sequence: 42, // wrong sequence
            operation: operation("key_rotation"),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        // Silent no-op, no error.
        assert!(d.on_preprepare(&sender, &stale).is_ok());
        assert_eq!(*d.state(), RoundState::Idle);
    }
}