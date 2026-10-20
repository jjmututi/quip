//! Node-wide witness accumulation.
//!
//! [`WitnessStore`] holds `WitnessStatement`s keyed by
//! `(subject, witness)`. It is the node's answer to "who has
//! corroborated this peer's Key Claim?", consulted by the Coral
//! responder and populated from two seams in `tasks.rs`.
//!
//! See `docs/M9.6a-design.md` for the full contract. In brief:
//!
//! - The store is data. It does not orchestrate and does not decide
//!   trust.
//! - §5.3.3's 6-hour first-seen rule is applied at *query* time, not
//!   at ingest. A statement from a recently-seen witness is stored
//!   (it may mature) and filtered on retrieval.
//! - The 4+ threshold is the *requester's* rule, not the responder's.
//!   `statements_for` returns everything valid; the requester counts.
//!
//! # Issuance
//!
//! [`WitnessStore::maybe_issue`] is the placeholder issuance policy
//! of §4: a node issues about a peer once the peer's claim is
//! `Trusted` and no statement has been issued in the last 12 hours.
//! The draft describes re-issuance but not first issuance; that gap
//! is Spec item S9.

use quip_core::constants::{WITNESS_COUNT, WITNESS_VALIDITY_S};
use quip_core::dvv::NodeId;
use quip_core::messages::{Signer, WitnessStatement};
use quip_core::time::Timestamp;
use quip_net::crypto::Ed25519Verifier;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use crate::claim_log::ClaimLog;
use crate::trust::TrustPolicy;

/// How long a witness's own claim must have been first-seen before the
/// witness's statements count toward `Verified` (§5.3.3).
pub const WITNESS_FIRST_SEEN_SECONDS: u64 = 6 * 60 * 60;

/// How often a witness re-issues its statements (§5.3.3).
pub const WITNESS_REISSUE_INTERVAL_SECONDS: u64 = 12 * 60 * 60;

/// A node-wide store of witness statements.
///
/// Clones share the underlying map, matching the other node-wide
/// handles.
#[derive(Clone, Default)]
pub struct WitnessStore {
    inner: std::sync::Arc<Mutex<WitnessInner>>,
}

#[derive(Default)]
struct WitnessInner {
    /// Statement per `(subject, witness)` pair. Later-timestamp wins.
    statements: BTreeMap<(NodeId, NodeId), WitnessStatement>,
    /// When this node last issued a statement about each subject.
    /// Used by `maybe_issue` to enforce the 12-hour cadence.
    last_issued: BTreeMap<NodeId, Timestamp>,
}

impl WitnessStore {
    /// Build an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a statement.
    ///
    /// The caller is responsible for having *received* the statement;
    /// this method verifies it before storing and returns whether it
    /// was stored.
    ///
    /// Rejects, without storing:
    ///
    /// - a statement whose signature does not verify against its
    ///   `witness` field;
    /// - a statement whose `subject` or `witness` is all-zero;
    /// - a statement whose `subject == witness` (not independent);
    /// - a statement whose `valid_until` is not in the future at
    ///   `now`;
    /// - a statement older than the one already stored for the same
    ///   `(subject, witness)` pair.
    ///
    /// The last rule makes ingest idempotent on a replay and
    /// monotonic on a newer statement, which is what §5.3.3's
    /// re-issuance produces.
    pub fn ingest(&self, statement: WitnessStatement, now: Timestamp) -> bool {
        if !self.accepts(&statement, now) {
            return false;
        }

        let mut inner = self.inner.lock().expect("witness store poisoned");
        let key = (statement.subject, statement.witness);
        match inner.statements.get(&key) {
            Some(existing) if existing.timestamp >= statement.timestamp => false,
            _ => {
                inner.statements.insert(key, statement);
                true
            }
        }
    }

    /// Whether `statement` is well-formed and valid at `now`.
    ///
    /// This is [`Self::ingest`]'s validation half, exposed separately so
    /// the KT seam can decide whether to feed a statement to the
    /// `ConnectionFlow` even when the store already holds an identical
    /// copy. Re-feeding is harmless but feeding an unverified statement
    /// is not, so the two decisions need different predicates.
    pub fn accepts(&self, statement: &WitnessStatement, now: Timestamp) -> bool {
        if is_all_zero(&statement.subject) || is_all_zero(&statement.witness) {
            return false;
        }
        if statement.subject == statement.witness {
            return false;
        }
        if statement.valid_until <= now {
            return false;
        }
        let verifier = Ed25519Verifier;
        matches!(statement.verify(&verifier), Ok(true))
    }

    /// Statements about `subject` that are valid and whose witness has
    /// a first-seen claim at least `WITNESS_FIRST_SEEN_SECONDS` old.
    ///
    /// This is the query the Coral responder answers. It returns every
    /// qualifying statement, capped at [`WITNESS_COUNT`]; it
    /// does not filter to the caller's trust policy and does not
    /// require 4 statements, because the 4+ threshold is the
    /// requester's rule (§3 of the design note).
    pub fn statements_for(
        &self,
        subject: &NodeId,
        claim_log: &ClaimLog,
        now: Timestamp,
    ) -> Vec<WitnessStatement> {
        let first_seen_cutoff =
            Timestamp::from_millis(now.as_millis().saturating_sub(
                WITNESS_FIRST_SEEN_SECONDS.saturating_mul(1000),
            ));

        let inner = self.inner.lock().expect("witness store poisoned");
        let mut out: Vec<WitnessStatement> = inner
            .statements
            .iter()
            .filter(|((s, _w), stmt)| {
                s == subject
                    && stmt.valid_until > now
                    && claim_log
                        .first_seen(&stmt.witness)
                        .map(|fs| fs <= first_seen_cutoff)
                        .unwrap_or(false)
            })
            .map(|(_, stmt)| stmt.clone())
            .collect();

        // Newest first, so a caller that truncates keeps the freshest.
        out.sort_by_key(|s| std::cmp::Reverse(s.timestamp));
        out.truncate(WITNESS_COUNT);
        out
    }

    /// Record that a statement about `subject` was issued at `now`.
    pub fn note_issued(&self, subject: NodeId, now: Timestamp) {
        let mut inner = self.inner.lock().expect("witness store poisoned");
        inner.last_issued.insert(subject, now);
    }

    /// Subjects the store knows a statement about, from any witness.
    ///
    /// Used by tests and by diagnostic accessors.
    pub fn known_subjects(&self) -> Vec<NodeId> {
        let inner = self.inner.lock().expect("witness store poisoned");
        inner
            .statements
            .keys()
            .map(|(s, _w)| *s)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    /// The number of statements held.
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .expect("witness store poisoned")
            .statements
            .len()
    }

    /// True if the store holds no statements.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this node should issue a statement about `subject` at
    /// `now` under the placeholder issuance policy of §4.
    ///
    /// Returns the subjects that are due. A subject is due when:
    ///
    /// - the trust policy has `subject` at `Trusted` or `Verified`
    ///   (only the former is reachable at issuance time — the flow is
    ///   the only writer of `Verified`, and it runs after issuance);
    /// - this node has not issued a statement about `subject` in the
    ///   last `WITNESS_REISSUE_INTERVAL_SECONDS`.
    ///
    /// The caller signs and sends the statement; this method only
    /// decides *whether* to, and returns the subject so the caller
    /// does not have to enumerate.
    pub fn maybe_issue(
        &self,
        trust: &TrustPolicy,
        now: Timestamp,
    ) -> Vec<NodeId> {
        let trusted = trust.trusted_peers();
        if trusted.is_empty() {
            return Vec::new();
        }

        let interval_ms =
            WITNESS_REISSUE_INTERVAL_SECONDS.saturating_mul(1000);
        let mut due = Vec::new();

        {
            let inner = self.inner.lock().expect("witness store poisoned");
            for subject in trusted {
                let last = inner.last_issued.get(&subject).copied();
                let due_now = match last {
                    None => true,
                    Some(at) => now
                        .as_millis()
                        .saturating_sub(at.as_millis())
                        >= interval_ms,
                };
                if due_now {
                    due.push(subject);
                }
            }
        }

        due
    }

    /// Note that a subject has been issued about, without checking
    /// the cadence. Used by the caller right after `maybe_issue`
    /// returns a subject, so the next call does not re-issue.
    pub fn mark_issued(&self, subject: NodeId, now: Timestamp) {
        self.note_issued(subject, now);
    }
}

fn is_all_zero(id: &NodeId) -> bool {
    id.iter().all(|b| *b == 0)
}

/// Build and sign a `WitnessStatement` about `subject`.
///
/// The statement is valid for [`WITNESS_VALIDITY_S`] (24 h, §5.3.3).
/// `ring_id` identifies the DHT ring the subject belongs to; 6a does not
/// populate it (nothing in the store or the responder consults it yet),
/// so callers pass the value they hold, conventionally all-zero.
pub fn issue_statement<S: Signer>(
    subject: NodeId,
    ring_id: [u8; 32],
    signer: &S,
    now: Timestamp,
) -> WitnessStatement {
    let valid_until = Timestamp::from_millis(
        now.as_millis()
            .saturating_add(WITNESS_VALIDITY_S.saturating_mul(1_000)),
    );
    let unsigned = WitnessStatement {
        subject,
        timestamp: now,
        valid_until,
        ring_id,
        witness: signer.public_key(),
        signature: [0u8; 64],
    };
    let payload = unsigned
        .signing_payload()
        .expect("WitnessStatement signing_payload cannot fail");
    WitnessStatement {
        signature: signer.sign_ed25519(&payload),
        ..unsigned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::{PeerTrust, TrustPolicy};
    use quip_net::crypto::Ed25519Signer;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    /// Build a signed statement for tests. The signer is the witness;
    /// `valid_until` is deliberately far in the future.
    fn statement(
        subject: u8,
        witness: u8,
        issued_at: u64,
    ) -> WitnessStatement {
        use quip_core::messages::Signer;
        let signer = Ed25519Signer::from_seed(&[witness; 32]);
        let unsigned = WitnessStatement {
            subject: nid(subject),
            timestamp: t(issued_at),
            valid_until: t(issued_at + 100_000_000),
            ring_id: [0u8; 32],
            witness: signer.public_key(),
            signature: [0u8; 64],
        };
        let payload = unsigned.signing_payload().unwrap();
        let signature = signer.sign_ed25519(&payload);
        WitnessStatement {
            signature,
            ..unsigned
        }
    }

    /// The NodeId a test witness seed derives. `NodeId` is the Ed25519
    /// public key, not the seed itself.
    fn witness_id(seed: u8) -> NodeId {
        Ed25519Signer::from_seed(&[seed; 32]).public_key()
    }

    fn claim_log_with(peers: &[u8], at: u64) -> ClaimLog {
        let log = ClaimLog::new();
        for p in peers {
            log.observe(witness_id(*p), t(at));
        }
        log
    }

    #[test]
    fn ingest_stores_a_valid_statement() {
        let store = WitnessStore::new();
        let stmt = statement(1, 2, 1_000);
        assert!(store.ingest(stmt.clone(), t(2_000)));
        assert_eq!(store.len(), 1);
        assert_eq!(store.known_subjects(), vec![nid(1)]);
    }

    #[test]
    fn ingest_rejects_a_forged_statement() {
        let store = WitnessStore::new();
        let mut stmt = statement(1, 2, 1_000);
        stmt.signature = [0xff; 64];
        assert!(!store.ingest(stmt, t(2_000)));
        assert!(store.is_empty());
    }

    #[test]
    fn ingest_rejects_subject_equals_witness() {
        let store = WitnessStore::new();
        let mut stmt = statement(1, 3, 1_000);
        // Make the subject equal to the witness. The check runs before
        // signature verification, so the now-stale signature is
        // irrelevant.
        stmt.subject = stmt.witness;
        assert!(!store.ingest(stmt, t(2_000)));
    }

    #[test]
    fn ingest_rejects_expired_statement() {
        let store = WitnessStore::new();
        let stmt = statement(1, 2, 1_000);
        // valid_until is at issued_at + 100_000_000ms; ask at a time
        // past that.
        assert!(!store.ingest(stmt, t(200_000_000)));
    }

    #[test]
    fn ingest_keeps_the_later_statement_on_reissue() {
        let store = WitnessStore::new();
        let older = statement(1, 2, 1_000);
        let newer = statement(1, 2, 5_000);
        assert!(store.ingest(older.clone(), t(6_000)));
        assert!(store.ingest(newer.clone(), t(6_000)));
        assert_eq!(store.len(), 1);
        let stored = store
            .statements_for(&nid(1), &claim_log_with(&[2], 0), t(6_000));
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].timestamp, newer.timestamp);
    }

    #[test]
    fn ingest_rejects_an_older_replay() {
        let store = WitnessStore::new();
        let older = statement(1, 2, 1_000);
        let newer = statement(1, 2, 5_000);
        assert!(store.ingest(newer.clone(), t(6_000)));
        assert!(
            !store.ingest(older, t(6_000)),
            "an older statement must not replace a newer one",
        );
    }

    #[test]
    fn statements_for_excludes_witnesses_without_first_seen() {
        let store = WitnessStore::new();
        store.ingest(statement(1, 2, 1_000), t(2_000));
        let empty_log = ClaimLog::new();
        let out = store.statements_for(&nid(1), &empty_log, t(2_000));
        assert!(
            out.is_empty(),
            "a witness with no first-seen time cannot count",
        );
    }

    #[test]
    fn statements_for_excludes_witnesses_younger_than_the_6h_window() {
        let store = WitnessStore::new();
        store.ingest(statement(1, 2, 1_000), t(2_000));
        let log = claim_log_with(&[2], 1_500);
        let cutoff_ms = 1_500 + (WITNESS_FIRST_SEEN_SECONDS - 1) * 1_000;
        let out = store.statements_for(&nid(1), &log, t(cutoff_ms));
        assert!(out.is_empty());
    }

    #[test]
    fn statements_for_includes_witnesses_past_the_6h_window() {
        let store = WitnessStore::new();
        store.ingest(statement(1, 2, 1_000), t(2_000));
        let log = claim_log_with(&[2], 1_500);
        let after_ms = 1_500 + WITNESS_FIRST_SEEN_SECONDS * 1_000 + 1;
        let out = store.statements_for(&nid(1), &log, t(after_ms));
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn statements_for_caps_at_the_statement_cap() {
        let store = WitnessStore::new();
        // Nine valid witnesses; the cap is seven.
        for w in 10..19u8 {
            store.ingest(statement(1, w, 1_000), t(2_000));
        }
        let log = claim_log_with(&[10, 11, 12, 13, 14, 15, 16, 17, 18], 0);
        let after_ms = WITNESS_FIRST_SEEN_SECONDS * 1_000 + 2_000;
        let out = store.statements_for(&nid(1), &log, t(after_ms));
        assert_eq!(out.len(), WITNESS_COUNT);
    }

    #[test]
    fn statements_for_excludes_statements_past_valid_until() {
        let store = WitnessStore::new();
        store.ingest(statement(1, 2, 1_000), t(2_000));
        let log = claim_log_with(&[2], 1_500);

        // Mature but still valid: the 6-hour rule is satisfied and the
        // statement counts.
        let mature_ms = 1_500 + WITNESS_FIRST_SEEN_SECONDS * 1_000 + 1;
        assert_eq!(
            store.statements_for(&nid(1), &log, t(mature_ms)).len(),
            1,
            "a valid statement counts"
        );

        // Past `valid_until` (issued_at + 100_000_000 in the helper): it
        // no longer counts, whether or not the witness has re-issued.
        let expired_ms = 100_001_000;
        assert!(
            store.statements_for(&nid(1), &log, t(expired_ms)).is_empty(),
            "§5.3.3: a statement past valid_until no longer counts"
        );
    }

    #[test]
    fn maybe_issue_skips_untrusted_subjects() {
        let store = WitnessStore::new();
        let trust = TrustPolicy::new();
        // No trusted peers: nothing to issue.
        assert!(store.maybe_issue(&trust, t(0)).is_empty());
    }

    #[test]
    fn maybe_issue_enforces_the_12h_cadence() {
        use quip_core::messages::KeyClaim;
        let store = WitnessStore::new();
        let mut trust = TrustPolicy::new();
        // Put a peer at Trusted.
        let claim = KeyClaim {
            node_id: nid(1),
            timestamp: t(0),
            dht_id: nid(1),
            signature: [0u8; 64],
        };
        trust.observe_claim(claim, t(0));
        trust.record_decision(&nid(1), PeerTrust::Trusted, t(0));

        let due = store.maybe_issue(&trust, t(0));
        assert_eq!(due, vec![nid(1)], "first issue is always due");

        store.mark_issued(nid(1), t(0));
        let too_soon = t(WITNESS_REISSUE_INTERVAL_SECONDS * 1_000 - 1);
        assert!(store.maybe_issue(&trust, too_soon).is_empty());

        let due_again = t(WITNESS_REISSUE_INTERVAL_SECONDS * 1_000 + 1);
        assert_eq!(store.maybe_issue(&trust, due_again), vec![nid(1)]);
    }
}