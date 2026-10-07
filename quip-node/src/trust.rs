//! Peer trust policy.
//!
//! The node records every peer's Key Claim on first contact, but does
//! not decide trust by default: a first-seen peer is `Unknown` until
//! the application calls `trust_peer(peer, Trusted)`. This is the SSH
//! `StrictHostKeyChecking=ask` model — the node surfaces the fact of
//! first contact; the application (or the user behind it) makes the
//! trust decision.
//!
//! # Two axes
//!
//! `PeerTrust` combines two independent decisions:
//!
//! - The **policy** (`Unknown` ↔ `Trusted` ↔ `Untrusted` ↔ `Revoked`)
//!   is decided by this module from the local store and explicit
//!   [`TrustPolicy::record_decision`] calls.
//! - The **flow status** (`Pending` ↔ `Verified`) is decided by the
//!   §16 witness-discovery phase and reflects corroboration by 4+
//!   independent witnesses.
//!
//! `Verified` is never set by the policy; it is derived from the
//! flow. An application cannot escalate a peer to `Verified` — only
//! witnesses can. `Trusted` is the application's own assertion.

use quip_core::dvv::NodeId;
use quip_core::messages::KeyClaim;
use quip_core::time::Timestamp;
use std::collections::{BTreeMap, BTreeSet};

/// A peer's trust level.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PeerTrust {
    /// A valid Key Claim seen for the first time. No trust decision
    /// has been made. The UI should treat this as unverified.
    Unknown,
    /// The application has explicitly accepted this peer.
    Trusted,
    /// 4+ independent witnesses have corroborated this peer's Key
    /// Claim. `Verified` implies `Trusted` — the policy must have
    /// accepted the peer before witnesses could corroborate it.
    Verified,
    /// The peer's Key Claim differs from the pinned one without a
    /// valid rotation chain, or the application has explicitly denied
    /// it.
    Untrusted,
    /// An explicit revocation tombstone exists for this NodeId.
    /// Terminal — no subsequent state transition lifts it.
    Revoked,
}

/// A stored Key Claim and the trust decision attached to it.
#[derive(Clone, Debug)]
pub struct StoredClaim {
    /// The claim as first observed.
    pub claim: KeyClaim,
    /// When the claim was first recorded.
    pub first_seen: Timestamp,
    /// When the trust decision was last changed, if any.
    pub decided_at: Option<Timestamp>,
    /// The current trust level.
    pub trust: PeerTrust,
}

/// The node's trust policy.
///
/// One instance per `Node`, shared across peer tasks. Holds a
/// `NodeId`-keyed store of accepted claims and a set of revocation
/// tombstones.
#[derive(Default)]
pub struct TrustPolicy {
    claims: BTreeMap<NodeId, StoredClaim>,
    tombstoned: BTreeSet<NodeId>,
}

impl TrustPolicy {
    /// An empty policy.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of peers in the store.
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    /// True if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    /// Look up the current trust level for `peer`.
    ///
    /// Returns `Unknown` for an unseen peer and `Revoked` for a
    /// tombstoned one, without consulting the store.
    pub fn trust_of(&self, peer: &NodeId) -> PeerTrust {
        if self.tombstoned.contains(peer) {
            return PeerTrust::Revoked;
        }
        self.claims
            .get(peer)
            .map(|s| s.trust)
            .unwrap_or(PeerTrust::Unknown)
    }

    /// Record first contact with a peer.
    ///
    /// If the peer is already stored, compares the new claim against
    /// the stored one:
    ///
    /// - Identical claim: no change; returns the current trust level.
    /// - Different claim with no rotation chain: marks the peer
    ///   `Untrusted` and returns it. The application must resolve the
    ///   mismatch before the peer can be trusted again.
    /// - Tombstoned peer: returns `Revoked`; nothing changes.
    ///
    /// A first-seen peer is stored with trust `Unknown`.
    pub fn observe_claim(
        &mut self,
        claim: KeyClaim,
        now: Timestamp,
    ) -> PeerTrust {
        let peer = claim.node_id;

        if self.tombstoned.contains(&peer) {
            return PeerTrust::Revoked;
        }

        match self.claims.get_mut(&peer) {
            Some(stored) => {
                if stored.claim == claim {
                    stored.trust
                } else {
                    stored.trust = PeerTrust::Untrusted;
                    stored.decided_at = Some(now);
                    PeerTrust::Untrusted
                }
            }
            None => {
                self.claims.insert(
                    peer,
                    StoredClaim {
                        claim,
                        first_seen: now,
                        decided_at: None,
                        trust: PeerTrust::Unknown,
                    },
                );
                PeerTrust::Unknown
            }
        }
    }

    /// Record an application-level trust decision.
    ///
    /// `Trusted` accepts a peer that is currently `Unknown` or
    /// `Untrusted`. `Untrusted` denies a peer regardless of prior
    /// state. `Revoked` tombstones a peer permanently.
    ///
    /// `Unknown` and `Verified` cannot be set through this method:
    /// `Unknown` is a starting state, and `Verified` is derived from
    /// the flow's witness discovery, not from application choice.
    /// Passing either returns `false` and leaves the policy unchanged.
    pub fn record_decision(
        &mut self,
        peer: &NodeId,
        decision: PeerTrust,
        now: Timestamp,
    ) -> bool {
        match decision {
            PeerTrust::Trusted | PeerTrust::Untrusted => {}
            PeerTrust::Revoked => {
                self.tombstoned.insert(*peer);
                if let Some(stored) = self.claims.get_mut(peer) {
                    stored.trust = PeerTrust::Revoked;
                    stored.decided_at = Some(now);
                }
                return true;
            }
            PeerTrust::Unknown | PeerTrust::Verified => return false,
        }

        match self.claims.get_mut(peer) {
            Some(stored) => {
                stored.trust = decision;
                stored.decided_at = Some(now);
                true
            }
            None => false,
        }
    }

    /// Update a peer's trust to `Verified` after the §16 flow
    /// confirmed 4+ witness statements.
    ///
    /// Fails if the peer is not currently `Trusted`: witness
    /// corroboration is not a substitute for the application's own
    /// decision.
    pub fn promote_to_verified(&mut self, peer: &NodeId) -> bool {
        match self.claims.get_mut(peer) {
            Some(stored) if stored.trust == PeerTrust::Trusted => {
                stored.trust = PeerTrust::Verified;
                true
            }
            _ => false,
        }
    }

    /// Whether `peer` may proceed with application-level traffic.
    ///
    /// `Trusted` and `Verified` allow; everything else denies.
    pub fn is_accepted(&self, peer: &NodeId) -> bool {
        matches!(
            self.trust_of(peer),
            PeerTrust::Trusted | PeerTrust::Verified
        )
    }

    /// The stored claim for `peer`, if any.
    pub fn stored_claim(&self, peer: &NodeId) -> Option<&StoredClaim> {
        self.claims.get(peer)
    }

    /// A snapshot of the store, for inspection.
    pub fn snapshot(&self) -> Vec<(NodeId, StoredClaim)> {
        self.claims
            .iter()
            .map(|(k, v)| (*k, v.clone()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn claim_for(b: u8, now: Timestamp) -> KeyClaim {
        KeyClaim {
            node_id: nid(b),
            timestamp: now,
            dht_id: nid(b),
            signature: [0xcc; 64],
        }
    }

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn new_policy_is_empty() {
        let p = TrustPolicy::new();
        assert!(p.is_empty());
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Unknown);
    }

    #[test]
    fn first_contact_records_unknown() {
        let mut p = TrustPolicy::new();
        let trust = p.observe_claim(claim_for(1, t(0)), t(0));
        assert_eq!(trust, PeerTrust::Unknown);
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Unknown);
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn identical_claim_preserves_trust() {
        let mut p = TrustPolicy::new();
        p.observe_claim(claim_for(1, t(0)), t(0));
        p.record_decision(&nid(1), PeerTrust::Trusted, t(1));
        let trust = p.observe_claim(claim_for(1, t(0)), t(2));
        assert_eq!(trust, PeerTrust::Trusted);
    }

    #[test]
    fn mismatched_claim_marks_untrusted() {
        let mut p = TrustPolicy::new();
        p.observe_claim(claim_for(1, t(0)), t(0));
        p.record_decision(&nid(1), PeerTrust::Trusted, t(1));

        let mut bad = claim_for(1, t(0));
        bad.signature = [0xdd; 64];
        let trust = p.observe_claim(bad, t(2));
        assert_eq!(trust, PeerTrust::Untrusted);
    }

    #[test]
    fn application_can_trust_unknown_peer() {
        let mut p = TrustPolicy::new();
        p.observe_claim(claim_for(1, t(0)), t(0));
        assert!(p.record_decision(&nid(1), PeerTrust::Trusted, t(1)));
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Trusted);
        assert!(p.is_accepted(&nid(1)));
    }

    #[test]
    fn cannot_trust_unknown_peer() {
        let mut p = TrustPolicy::new();
        // Peer never observed.
        assert!(!p.record_decision(&nid(1), PeerTrust::Trusted, t(1)));
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Unknown);
    }

    #[test]
    fn cannot_set_verified_directly() {
        let mut p = TrustPolicy::new();
        p.observe_claim(claim_for(1, t(0)), t(0));
        assert!(!p.record_decision(&nid(1), PeerTrust::Verified, t(1)));
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Unknown);
    }

    #[test]
    fn cannot_set_unknown_directly() {
        let mut p = TrustPolicy::new();
        p.observe_claim(claim_for(1, t(0)), t(0));
        p.record_decision(&nid(1), PeerTrust::Trusted, t(1));
        assert!(!p.record_decision(&nid(1), PeerTrust::Unknown, t(2)));
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Trusted);
    }

    #[test]
    fn promote_requires_trusted() {
        let mut p = TrustPolicy::new();
        p.observe_claim(claim_for(1, t(0)), t(0));
        // Not yet trusted.
        assert!(!p.promote_to_verified(&nid(1)));
        p.record_decision(&nid(1), PeerTrust::Trusted, t(1));
        assert!(p.promote_to_verified(&nid(1)));
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Verified);
    }

    #[test]
    fn revocation_is_terminal() {
        let mut p = TrustPolicy::new();
        p.observe_claim(claim_for(1, t(0)), t(0));
        p.record_decision(&nid(1), PeerTrust::Trusted, t(1));
        p.record_decision(&nid(1), PeerTrust::Revoked, t(2));
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Revoked);

        // Even a valid identical claim does not lift revocation.
        let trust = p.observe_claim(claim_for(1, t(0)), t(3));
        assert_eq!(trust, PeerTrust::Revoked);

        // And explicit trust doesn't either.
        assert!(p.record_decision(&nid(1), PeerTrust::Trusted, t(4)));
        assert_eq!(p.trust_of(&nid(1)), PeerTrust::Revoked);
    }
}