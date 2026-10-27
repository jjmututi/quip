//! Shared Coral discovery client.
//!
//! [`DiscoveryHandle`] wraps a
//! [`WitnessDiscovery`] behind an
//! `Arc<Mutex<…>>` so every peer task shares one instance: the ring and
//! spillover caches, the in-flight discovery state, and the responder
//! role. It also exposes the responder paths that §13.7/§13.8 define
//! but `WitnessDiscovery` (a client-only state machine) does not.
//!
//! # Why shared
//!
//! `WitnessDiscovery` holds two caches (`WitnessRingCache` at 24 h,
//! `SpilloverResponseCache` at 5 min). Per-peer instances would
//! fragment those caches and duplicate the responder work. A shared
//! handle keeps them unified and matches how the DHT is organised.
//!
//! # Responder role
//!
//! A running node plays two roles in Coral: it initiates lookups (its
//! own §16 witness discovery) and it answers them (as a DHT node). The
//! responder methods here are deliberately minimal — they answer with
//! no witnesses and no consensus, because M9.5a's node holds no
//! `WitnessStatement`s to report. When a later milestone wires witness
//! accumulation the responders start returning real data; the wire
//! shape and the signing path are already correct.
//!
//! # Concurrency
//!
//! The internal mutex is `std::sync::Mutex`, not `tokio::sync::Mutex`:
//! every operation on [`WitnessDiscovery`] is synchronous and returns
//! quickly, and none of the handle's methods hold the guard across an
//! `await`.
//!
//! # Conflict between peers
//!
//! All peer tasks share one discovery state. In practice they discover
//! distinct remotes — each peer task discovers the peer it was spawned
//! for — so key collisions on `target` don't happen. A future
//! milestone that fans out a discovery across multiple peers will need
//! per-target refcounting; the handle is the right place for it.

use quip_core::cbor::{encode, CborValue};
use quip_core::cid::HashAlgo;
use quip_core::dvv::NodeId;
use quip_core::messages::Signer;
use quip_core::time::Timestamp;
use quip_net::coral::{
    CoralLookup, LookupPath, LookupResponse, PathId, PathProof, SpilloverRequest, SpilloverResponse,
};
use quip_net::crypto::{Ed25519Signer, Sha256Hasher};
use quip_net::discovery::{DiscoveryStatus, Outbound, StartOutcome, WitnessDiscovery};
use quip_net::{Error, Result};
use quip_storage::ContentHasher;

use std::sync::{Arc, Mutex, MutexGuard};

use crate::claim_log::ClaimLog;
use crate::witness::WitnessStore;

/// Shared handle to the node's Coral discovery client.
///
/// Clones refer to the same `WitnessDiscovery` and the same signer.
/// The handle is `Clone` so a per-peer task can carry a copy without
/// re-plumbing the node.
#[derive(Clone)]
pub struct DiscoveryHandle {
    client: Arc<Mutex<WitnessDiscovery<Ed25519Signer>>>,
    signer: Arc<Ed25519Signer>,
    /// The node-wide witness store the responder answers from.
    witness: WitnessStore,
    /// The first-seen log the store's 6-hour rule consults.
    claim_log: ClaimLog,
}

impl DiscoveryHandle {
    /// Build a handle that signs with `signer` and answers lookups from
    /// `witness`, applying `claim_log`'s first-seen rule.
    ///
    /// Crate-internal: the node constructs one per `Node`; the
    /// application uses `Node::discovery()` to obtain a clone.
    pub(crate) fn new(
        signer: Arc<Ed25519Signer>,
        witness: WitnessStore,
        claim_log: ClaimLog,
    ) -> Self {
        let client = WitnessDiscovery::new((*signer).clone());
        Self {
            client: Arc::new(Mutex::new(client)),
            signer,
            witness,
            claim_log,
        }
    }

    /// Our own NodeId, per the signer.
    pub fn local_node_id(&self) -> NodeId {
        self.signer.public_key()
    }

    /// Start (or look up from cache) a witness ring for `target`.
    pub fn start(
        &self,
        target: NodeId,
        paths: Vec<LookupPath>,
        now: Timestamp,
    ) -> Result<StartOutcome> {
        self.lock()?.start(target, paths, now)
    }

    /// Feed a `CoralLookupResponse` into the discovery.
    ///
    /// Returns any outbound messages the state machine emitted as a
    /// result — typically a `SpilloverRequest` when the paths
    /// disagreed.
    pub fn ingest_lookup_response(
        &self,
        resp: LookupResponse,
        now: Timestamp,
    ) -> Result<Vec<Outbound>> {
        self.lock()?.ingest_lookup_response(resp, now)
    }

    /// Feed a `SpilloverResponse` into the discovery.
    pub fn ingest_spillover_response(&self, resp: SpilloverResponse, now: Timestamp) -> Result<()> {
        self.lock()?.ingest_spillover_response(resp, now)
    }

    /// Mark a path as failed and re-evaluate consensus.
    pub fn mark_path_failed(
        &self,
        target: &NodeId,
        path_id: PathId,
        now: Timestamp,
    ) -> Result<Vec<Outbound>> {
        self.lock()?.mark_path_failed(target, path_id, now)
    }

    /// Take the completed ring for `target`, if any.
    pub fn take_ring(&self, target: &NodeId) -> Option<Vec<NodeId>> {
        self.lock().ok()?.take_ring(target)
    }

    /// Snapshot of an in-flight discovery.
    pub fn status(&self, target: &NodeId) -> Option<DiscoveryStatus> {
        self.lock().ok()?.status(target)
    }

    /// Forget an in-flight discovery without completing it.
    pub fn forget(&self, target: &NodeId) {
        if let Ok(mut c) = self.client.lock() {
            c.forget(target);
        }
    }

    /// Answer a `coral_lookup` from the node-wide witness store.
    ///
    /// The response carries one encoded `WitnessStatement` per entry in
    /// `values`, limited to statements that are valid now and whose
    /// witness has been first-seen for at least §5.3.3's 6 hours
    /// (`WitnessStore::statements_for`). The 4+ threshold and the
    /// requester's trust policy are the *requester's* rules: the
    /// responder returns what it holds, no more and no less.
    ///
    /// Every `PathProof` commits to the same `values` blob — the wire
    /// shape has one shared value list, not one per path (§3 of
    /// `docs/M9.6a-design.md`). Each proof is marked `responded: true`;
    /// the response is signed with the node's own key, matching §10.1.
    pub fn respond_to_lookup(&self, lookup: &CoralLookup, now: Timestamp) -> LookupResponse {
        let values: Vec<Vec<u8>> = self
            .witness
            .statements_for(&lookup.key, &self.claim_log, now)
            .iter()
            .filter_map(|stmt| encode(&stmt.to_cbor()).ok())
            .collect();
        let value_hash = values_hash(&values);

        let path_proofs: Vec<PathProof> = lookup
            .lookup_paths
            .iter()
            .map(|p| PathProof {
                path_id: p.path_id,
                node_signatures: Vec::new(),
                value_hash,
                responded: true,
            })
            .collect();
        let mut resp = LookupResponse {
            key: lookup.key,
            values,
            path_proofs,
            responder: self.signer.public_key(),
            timestamp: now,
            signature: [0u8; 64],
        };
        // `signing_payload` cannot fail for a well-formed response.
        // Fall back to an unsigned response if it somehow does, so the
        // caller always gets a decodable reply.
        if let Ok(payload) = resp.signing_payload() {
            resp.signature = self.signer.sign_ed25519(&payload);
        }
        resp
    }

    /// Answer a `spillover` with zero consensus.
    ///
    /// Honest for a node that holds no alternate witnesses.
    pub fn respond_to_spillover(
        &self,
        req: &SpilloverRequest,
        now: Timestamp,
    ) -> SpilloverResponse {
        let mut resp = SpilloverResponse {
            original_key: req.original_key,
            alternate_witnesses: Vec::new(),
            path_proofs: Vec::new(),
            consensus: 0,
            responder: self.signer.public_key(),
            timestamp: now,
            signature: [0u8; 64],
        };
        if let Ok(payload) = resp.signing_payload() {
            resp.signature = self.signer.sign_ed25519(&payload);
        }
        resp
    }

    fn lock(&self) -> Result<MutexGuard<'_, WitnessDiscovery<Ed25519Signer>>> {
        self.client
            .lock()
            .map_err(|_| Error::Transport("discovery mutex poisoned".into()))
    }
}

/// Hash the shared `values` blob a lookup response commits to.
///
/// The wire has one value list, not one per path, so every `PathProof`
/// carries this same digest (§3 of the design note). The digest is over
/// the CBOR encoding of the value array, which is what the requester
/// receives on the wire; an empty list hashes to SHA-256 of `80` (the
/// CBOR empty array), not to zero.
fn values_hash(values: &[Vec<u8>]) -> [u8; 32] {
    let array = CborValue::Array(values.iter().map(|v| CborValue::Bytes(v.clone())).collect());
    let blob = encode(&array).unwrap_or_default();
    Sha256Hasher
        .digest(HashAlgo::Sha256, &blob)
        .unwrap_or([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::messages::Signer;

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    fn handle() -> DiscoveryHandle {
        DiscoveryHandle::new(
            Arc::new(Ed25519Signer::from_seed(&[0x42; 32])),
            WitnessStore::new(),
            ClaimLog::new(),
        )
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn path(id: u8, node: u8) -> LookupPath {
        let mut path_id = [0u8; 16];
        path_id[0] = id;
        LookupPath {
            path_id,
            nodes: vec![nid(node)],
            value_hash: [0u8; 32],
            ttl: 60,
        }
    }

    #[test]
    fn respond_to_lookup_signs_and_carries_every_path() {
        let h = handle();
        let now = t(0);
        let lookup = CoralLookup {
            key: nid(1),
            lookup_paths: vec![path(1, 2), path(2, 3)],
            witness_ring_id: [0u8; 32],
            timestamp: now,
            requester: nid(2),
            signature: [0u8; 64],
        };
        let resp = h.respond_to_lookup(&lookup, now);
        assert_eq!(resp.key, nid(1));
        assert_eq!(resp.path_proofs.len(), 2);
        assert!(resp.path_proofs.iter().all(|p| p.responded));
        assert_ne!(resp.signature, [0u8; 64]);

        // The signature verifies against the responder.
        let verifier = quip_net::crypto::Ed25519Verifier;
        assert!(resp.verify(&verifier).unwrap());
    }

    #[test]
    fn respond_to_lookup_returns_matured_statements_with_a_shared_hash() {
        let witness_signer = Ed25519Signer::from_seed(&[0x07; 32]);
        let witness = WitnessStore::new();
        let claim_log = ClaimLog::new();
        claim_log.observe(witness_signer.public_key(), t(0));
        let stmt = crate::witness::issue_statement(nid(1), [0u8; 32], &witness_signer, t(0));
        assert!(witness.ingest(stmt, t(0)));

        let h = DiscoveryHandle::new(
            Arc::new(Ed25519Signer::from_seed(&[0x42; 32])),
            witness,
            claim_log,
        );
        let lookup = CoralLookup {
            key: nid(1),
            lookup_paths: vec![path(1, 2), path(2, 3)],
            witness_ring_id: [0u8; 32],
            timestamp: t(0),
            requester: nid(2),
            signature: [0u8; 64],
        };
        // Seven hours after first contact: past the 6-hour window and
        // well inside the statement's 24-hour validity.
        let resp = h.respond_to_lookup(&lookup, t(7 * 3_600_000));
        assert_eq!(resp.values.len(), 1, "one matured statement");
        assert_eq!(resp.path_proofs.len(), 2);
        assert_eq!(
            resp.path_proofs[0].value_hash, resp.path_proofs[1].value_hash,
            "every path commits to the same values blob",
        );
        assert_ne!(resp.path_proofs[0].value_hash, [0u8; 32]);
    }

    #[test]
    fn respond_to_spillover_reports_zero_consensus() {
        let h = handle();
        let now = t(0);
        let req = SpilloverRequest {
            original_key: nid(1),
            rejected_witnesses: Vec::new(),
            rejection_reason: 2,
            alternate_paths: Vec::new(),
            requester: nid(2),
            timestamp: now,
            signature: [0u8; 64],
        };
        let resp = h.respond_to_spillover(&req, now);
        assert_eq!(resp.original_key, nid(1));
        assert_eq!(resp.consensus, 0);
        assert!(resp.alternate_witnesses.is_empty());
        assert_ne!(resp.signature, [0u8; 64]);

        let verifier = quip_net::crypto::Ed25519Verifier;
        assert!(resp.verify(&verifier).unwrap());
    }

    #[test]
    fn local_node_id_matches_signer() {
        let h = handle();
        let signer = Ed25519Signer::from_seed(&[0x42; 32]);
        assert_eq!(h.local_node_id(), signer.public_key());
    }

    #[test]
    fn start_returns_started_with_a_signed_coral_lookup() {
        let h = handle();
        let target = nid(0x10);
        let paths = vec![path(1, 0x10)];
        let outcome = h.start(target, paths, t(0)).unwrap();
        match outcome {
            StartOutcome::Started(msgs) => {
                assert_eq!(msgs.len(), 1);
                match &msgs[0] {
                    Outbound::CoralLookup(m) => {
                        assert_eq!(m.key, target);
                        assert_ne!(m.signature, [0u8; 64]);
                    }
                    _ => panic!("expected CoralLookup"),
                }
            }
            _ => panic!("expected Started"),
        }
    }

    #[test]
    fn clones_share_the_underlying_discovery() {
        let h = handle();
        let h2 = h.clone();
        let target = nid(0x10);
        // Start through one clone.
        let _ = h.start(target, vec![path(1, 0x10)], t(0)).unwrap();
        // The other clone sees the same in-flight state.
        assert!(h2.status(&target).is_some());
    }
}
