//! Peer-slot and connection-lifecycle types (M9.5b).
//!
//! [`PeerSlot`] distinguishes connection generations for a logical
//! [`NodeId`]. A peer that disconnects and reconnects gets a fresh
//! slot; events from the previous slot must not mutate the node's
//! current routing, cluster, or trust state. The generation counter
//! never reuses a value, so a stale slot can never be confused with a
//! current one.
//!
//! [`PeerLifecycle`] is the connection-lifecycle vocabulary from
//! §2 of `docs/M9.5b-design.md`. It is one of three independent
//! dimensions the node tracks per peer: the other two are witness
//! verification (`Pending` / `Verified`) from the §16 discovery
//! phase, and application trust (`Unknown` / `Trusted` / `Untrusted`
//! / `Revoked`) from [`crate::trust::TrustPolicy`]. A peer can be
//! `NatDirect` with witness status `Pending` and application trust
//! `Unknown`; none of those combinations requires a new lifecycle
//! state.
//!
//! # Where slots come from
//!
//! [`crate::Node`] owns a per-`NodeId` generation counter that
//! increments each time a new connection is accepted or dialed for
//! that identity. The counter is persistent for the node's lifetime
//! — it is never reset when a peer disconnects — so a slot value is
//! never reused. This is what makes `slot_a == slot_b` a sound
//! "same generation" test.
//!
//! # What a slot guarantees
//!
//! Once the peer task is spawned with a slot, the node holds it as
//! the current generation for that `NodeId`. When a newer connection
//! registers, the previous task is aborted (its `JoinHandle` is
//! removed from the node's task map and `.abort()` is called on it).
//! The aborted task cannot emit further events, so the application
//! never observes two live generations for the same `NodeId`
//! simultaneously.
//!
//! See `docs/M9.5b-design.md` §1–§2 for the full contract.

use quip_core::dvv::NodeId;

/// A particular connection generation for a logical peer.
///
/// The `node_id` is the peer's logical identity; the `generation`
/// increments each time a new connection is accepted or dialed for
/// that identity. The pair is unique for the lifetime of the
/// [`Node`](crate::Node) that allocated it.
///
/// A slot is `Copy`, cheap to pass by value, and comparable: two
/// slots are equal only if they refer to the same generation of the
/// same peer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerSlot {
    /// The logical peer.
    pub node_id: NodeId,
    /// Per-`Node` generation counter. Increments on every new
    /// connection for `node_id`; never reused.
    pub generation: u64,
}

impl PeerSlot {
    /// Build a slot from its parts.
    pub const fn new(node_id: NodeId, generation: u64) -> Self {
        Self {
            node_id,
            generation,
        }
    }
}

/// Connection lifecycle for one [`PeerSlot`] (§2 of the design note).
///
/// `Established` means the §4 handshake and §16 Key Claim exchange
/// both completed. `NatDirect` and `NatRelayed` describe the NAT
/// path outcome, once the NAT phase of the §16 establishment flow
/// concludes.
///
/// # Transitions (§2a)
///
/// ```text
/// Connecting  → Established
/// Established → NatDirect | NatRelayed | Failed
/// NatDirect  ↔ NatRelayed
/// NatDirect | NatRelayed → Failed
/// Any nonterminal state  → Closing
/// Failed, Closing → terminal for this PeerSlot
/// ```
///
/// The transition set is exactly what the design note enumerates:
/// in particular, `Connecting → Failed` is *not* permitted — a
/// connect attempt that gives up goes through `Closing`. This is a
/// deliberate reading of §2a; if the design note is later amended to
/// add the edge, this table is the single place to change.
///
/// # Recovery
///
/// `Failed` and `Closing` are terminal for a slot. Recovery after
/// either state creates a new [`PeerSlot`]; the new slot starts in
/// `Connecting` with a strictly higher generation counter than the
/// old one.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeerLifecycle {
    /// The §4 handshake has not yet completed.
    Connecting,
    /// The §4 handshake and §16 Key Claim exchange both completed.
    Established,
    /// The NAT phase concluded with a direct path.
    NatDirect,
    /// The NAT phase concluded with a relayed path.
    NatRelayed,
    /// The connection failed. Terminal for this slot.
    Failed,
    /// The connection is closing. Terminal for this slot.
    Closing,
}

impl PeerLifecycle {
    /// True if no further transitions are allowed for this slot.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Failed | Self::Closing)
    }

    /// True if the transition `self -> to` is permitted by §2a.
    ///
    /// The check is total: every `(from, to)` pair returns a definite
    /// answer. Use [`Self::transition_to`] if you also want the new
    /// state on success.
    pub const fn can_transition(self, to: Self) -> bool {
        use PeerLifecycle::*;
        matches!(
            (self, to),
            (Connecting, Established)
                | (Connecting, Closing)
                | (Established, NatDirect)
                | (Established, NatRelayed)
                | (Established, Failed)
                | (Established, Closing)
                | (NatDirect, NatRelayed)
                | (NatDirect, Failed)
                | (NatDirect, Closing)
                | (NatRelayed, NatDirect)
                | (NatRelayed, Failed)
                | (NatRelayed, Closing)
        )
    }

    /// Perform a transition, returning the new state or a
    /// [`TransitionError`] describing the rejected edge.
    pub fn transition_to(self, to: Self) -> Result<Self, TransitionError> {
        if self.can_transition(to) {
            Ok(to)
        } else {
            Err(TransitionError { from: self, to })
        }
    }
}

/// A rejected lifecycle transition.
///
/// Carries both endpoints so a caller can log or assert on the exact
/// edge that was refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TransitionError {
    /// The state the caller was in.
    pub from: PeerLifecycle,
    /// The state the caller attempted to reach.
    pub to: PeerLifecycle,
}

impl core::fmt::Display for TransitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "invalid peer lifecycle transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for TransitionError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    // ---- PeerSlot ----

    #[test]
    fn slot_equality_is_by_both_fields() {
        let a = PeerSlot::new(nid(1), 1);
        let b = PeerSlot::new(nid(1), 1);
        let c = PeerSlot::new(nid(1), 2);
        let d = PeerSlot::new(nid(2), 1);
        assert_eq!(a, b);
        assert_ne!(a, c, "same NodeId, different generation is a different slot");
        assert_ne!(a, d, "same generation, different NodeId is a different slot");
    }

    #[test]
    fn slot_orders_by_node_then_generation() {
        let a = PeerSlot::new(nid(1), 1);
        let b = PeerSlot::new(nid(1), 2);
        let c = PeerSlot::new(nid(2), 1);
        assert!(a < b);
        assert!(b < c);
    }

    // ---- PeerLifecycle: allowed transitions ----

    #[test]
    fn connecting_to_established_is_allowed() {
        assert!(PeerLifecycle::Connecting
            .can_transition(PeerLifecycle::Established));
    }

    #[test]
    fn established_to_nat_direct_and_relayed() {
        assert!(PeerLifecycle::Established
            .can_transition(PeerLifecycle::NatDirect));
        assert!(PeerLifecycle::Established
            .can_transition(PeerLifecycle::NatRelayed));
    }

    #[test]
    fn established_to_failed_is_allowed() {
        assert!(PeerLifecycle::Established
            .can_transition(PeerLifecycle::Failed));
    }

    #[test]
    fn nat_states_are_bidirectional() {
        assert!(PeerLifecycle::NatDirect
            .can_transition(PeerLifecycle::NatRelayed));
        assert!(PeerLifecycle::NatRelayed
            .can_transition(PeerLifecycle::NatDirect));
    }

    #[test]
    fn nat_states_can_fail() {
        assert!(PeerLifecycle::NatDirect.can_transition(PeerLifecycle::Failed));
        assert!(PeerLifecycle::NatRelayed.can_transition(PeerLifecycle::Failed));
    }

    #[test]
    fn any_nonterminal_can_close() {
        for state in [
            PeerLifecycle::Connecting,
            PeerLifecycle::Established,
            PeerLifecycle::NatDirect,
            PeerLifecycle::NatRelayed,
        ] {
            assert!(
                state.can_transition(PeerLifecycle::Closing),
                "{state:?} should be able to close"
            );
        }
    }

    // ---- PeerLifecycle: rejected transitions ----

    #[test]
    fn terminal_states_are_stuck() {
        for terminal in [PeerLifecycle::Failed, PeerLifecycle::Closing] {
            for next in [
                PeerLifecycle::Connecting,
                PeerLifecycle::Established,
                PeerLifecycle::NatDirect,
                PeerLifecycle::NatRelayed,
                PeerLifecycle::Failed,
                PeerLifecycle::Closing,
            ] {
                assert!(
                    !terminal.can_transition(next),
                    "{terminal:?} -> {next:?} must be rejected"
                );
            }
        }
    }

    #[test]
    fn no_backwards_transition_to_connecting() {
        for from in [
            PeerLifecycle::Established,
            PeerLifecycle::NatDirect,
            PeerLifecycle::NatRelayed,
        ] {
            assert!(
                !from.can_transition(PeerLifecycle::Connecting),
                "{from:?} -> Connecting must be rejected"
            );
        }
    }

    #[test]
    fn connecting_cannot_go_directly_to_nat() {
        assert!(!PeerLifecycle::Connecting
            .can_transition(PeerLifecycle::NatDirect));
        assert!(!PeerLifecycle::Connecting
            .can_transition(PeerLifecycle::NatRelayed));
    }

    #[test]
    fn connecting_cannot_fail_directly() {
        // §2a lists no Connecting -> Failed edge. A connect attempt
        // that gives up goes through Closing.
        assert!(!PeerLifecycle::Connecting
            .can_transition(PeerLifecycle::Failed));
    }

    #[test]
    fn established_cannot_re_establish() {
        // The transition Connecting -> Established is the only edge
        // into Established. Re-establishing on the same slot is not
        // permitted; that is what a new PeerSlot is for.
        assert!(!PeerLifecycle::Established
            .can_transition(PeerLifecycle::Established));
    }

    // ---- transition_to ----

    #[test]
    fn transition_to_returns_new_state_on_success() {
        let s = PeerLifecycle::Connecting
            .transition_to(PeerLifecycle::Established)
            .unwrap();
        assert_eq!(s, PeerLifecycle::Established);
    }

    #[test]
    fn transition_to_reports_error_on_failure() {
        let err = PeerLifecycle::Connecting
            .transition_to(PeerLifecycle::NatDirect)
            .unwrap_err();
        assert_eq!(err.from, PeerLifecycle::Connecting);
        assert_eq!(err.to, PeerLifecycle::NatDirect);
    }

    #[test]
    fn terminal_predicate() {
        assert!(PeerLifecycle::Failed.is_terminal());
        assert!(PeerLifecycle::Closing.is_terminal());
        for s in [
            PeerLifecycle::Connecting,
            PeerLifecycle::Established,
            PeerLifecycle::NatDirect,
            PeerLifecycle::NatRelayed,
        ] {
            assert!(!s.is_terminal(), "{s:?} must not be terminal");
        }
    }
}