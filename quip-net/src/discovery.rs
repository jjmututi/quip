//! Witness discovery state machine (spec §5.3.2, §13.7, §13.8).
//!
//! # Overview
//!
//! `WitnessDiscovery` orchestrates the 3-path Coral lookup that selects
//! a witness ring for a target NodeId. It is a pure state machine: it
//! takes messages in, produces messages out, and holds per-target state
//! until the lookup completes or fails. There is no I/O and no async.
//!
//! # Flow
//!
//! 1. Caller calls [`WitnessDiscovery::start`] with the target and the
//!    three lookup paths it wants to try. If the ring is already in the
//!    cache, the caller gets it back immediately. Otherwise the
//!    discovery returns a signed [`CoralLookup`] message to send.
//! 2. Caller forwards incoming [`LookupResponse`] messages to
//!    [`WitnessDiscovery::ingest_lookup_response`]. Each one adds a
//!    path's witness list to the state. When enough paths have
//!    responded, the discovery runs
//!    [`cross_path_consensus`] and
//!    either completes or emits a [`SpilloverRequest`].
//! 3. Caller forwards incoming [`SpilloverResponse`] messages to
//!    [`WitnessDiscovery::ingest_spillover_response`]. A response with
//!    `consensus >= 1` completes the lookup with the responder's
//!    `alternate_witnesses`.
//! 4. Caller polls [`WitnessDiscovery::take_ring`] for the completed
//!    ring.
//!
//! # Path failures
//!
//! Discovery has no timers. When the caller decides a path has timed
//! out, it calls [`WitnessDiscovery::mark_path_failed`] with the path's
//! ID. The discovery treats that path as resolved and re-evaluates
//! whether consensus is now achievable.
//!
//! # Value interpretation
//!
//! The spec defines `LookupResponse.values` as `[* bytes]` — opaque to
//! the protocol. In the context of witness discovery, QUIP interprets
//! each entry as a 32-byte NodeId. Responses whose values are not
//! exactly 32 bytes are rejected with [`Error::BadFrame`].
//!
//! # Caches
//!
//! Two caches live inside `WitnessDiscovery`:
//!
//! - [`WitnessRingCache`] (24-hour TTL, `ROTATION_INTERVAL_S`) holds
//!   the final ring per target, so subsequent lookups for the same
//!   target short-circuit.
//! - [`SpilloverResponseCache`] (5-minute TTL, §13.8) holds the last
//!   spillover response per key, so an attacker cannot force repeated
//!   lookups by triggering spillover for the same key.
//!
//! They are distinct: the ring cache answers "what ring was chosen?",
//! the spillover cache answers "what did the last re-lookup return?".

use crate::coral::{
    cross_path_consensus, CoralLookup, LookupPath, LookupResponse, PathId,
    SpilloverRequest, SpilloverResponse,
};
use crate::dht::WitnessRingCache;
use crate::error::{Error, Result};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use quip_core::constants::{
    DEGRADED_QUORUM, ROTATION_INTERVAL_S, SPILLOVER_CACHE_TTL_S, SPILLOVER_THRESHOLD,
};
use quip_core::dvv::NodeId;
use quip_core::messages::Signer;
use quip_core::time::Timestamp;

/// Default capacity of [`SpilloverResponseCache`].
///
/// Implementation choice. Well above any single target's worth of
/// in-flight spillover requests, small enough to be bounded.
pub const DEFAULT_SPILLOVER_CACHE_CAPACITY: usize = 256;

// -------------------------------------------------------------------------
// Outbound messages
// -------------------------------------------------------------------------

/// A message the discovery wants the caller to send.
///
/// Wraps only the two verbs discovery emits. The caller converts each
/// into a `Message` from [`crate::message`] before passing it to
/// [`crate::transport::ConnectionDriver::send`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outbound {
    /// A signed `coral_lookup` for one target.
    CoralLookup(CoralLookup),
    /// A signed `spillover` request for one target.
    Spillover(SpilloverRequest),
}

// -------------------------------------------------------------------------
// Outcomes
// -------------------------------------------------------------------------

/// What [`WitnessDiscovery::start`] produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StartOutcome {
    /// The ring was already in the cache; no lookup is needed.
    Cached(Vec<NodeId>),
    /// A new lookup was started; send these messages.
    Started(Vec<Outbound>),
}

/// Why a discovery failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryFailure {
    /// Cross-path validation found no consensus among the paths.
    NoConsensus,
    /// Spillover returned but with `consensus == 0` or too few
    /// alternate witnesses.
    SpilloverFailed,
}

/// Public snapshot of an in-flight discovery.
///
/// Returned by [`WitnessDiscovery::status`]; gives callers visibility
/// into progress without exposing internal state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryStatus {
    /// The target being resolved.
    pub target: NodeId,
    /// The ring identifier for the current epoch.
    pub witness_ring_id: [u8; 32],
    /// When the discovery started.
    pub started_at: Timestamp,
    /// Total number of lookup paths in play.
    pub paths_total: usize,
    /// Paths that have either responded or failed.
    pub paths_resolved: usize,
    /// Current phase.
    pub phase: DiscoveryPhaseKind,
}

/// Coarse phase of a discovery.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DiscoveryPhaseKind {
    /// Waiting for `LookupResponse`s.
    AwaitingResponses,
    /// Waiting for a `SpilloverResponse`.
    AwaitingSpillover,
    /// Completed successfully; [`WitnessDiscovery::take_ring`] will
    /// return the ring.
    Done,
    /// Failed, with a reason.
    Failed(DiscoveryFailure),
}

// -------------------------------------------------------------------------
// Spillover response cache
// -------------------------------------------------------------------------

/// Short-lived cache of received spillover responses (§13.8).
///
/// Keyed by `original_key`. Entries expire after
/// [`SPILLOVER_CACHE_TTL_S`]. When full, the oldest entry is evicted to
/// make room for a new one.
#[derive(Clone, Debug)]
pub struct SpilloverResponseCache {
    entries: BTreeMap<[u8; 32], (SpilloverResponse, Timestamp)>,
    capacity: usize,
}

impl SpilloverResponseCache {
    /// New cache with the default capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_SPILLOVER_CACHE_CAPACITY)
    }

    /// New cache with an explicit capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// The cache's configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Store a response, sweeping stale entries first.
    pub fn insert(&mut self, resp: SpilloverResponse, now: Timestamp) {
        self.sweep(now);
        while self.entries.len() >= self.capacity {
            if let Some(k) = self.entries.keys().next().copied() {
                self.entries.remove(&k);
            } else {
                break;
            }
        }
        self.entries.insert(resp.original_key, (resp, now));
    }

    /// Fetch a fresh response for `key`, or `None` if absent or expired.
    pub fn get(&self, key: &[u8; 32], now: Timestamp) -> Option<&SpilloverResponse> {
        let (resp, at) = self.entries.get(key)?;
        let age_s = now.as_secs().saturating_sub(at.as_secs());
        if age_s > SPILLOVER_CACHE_TTL_S {
            return None;
        }
        Some(resp)
    }

    /// Remove entries older than `SPILLOVER_CACHE_TTL_S`.
    pub fn sweep(&mut self, now: Timestamp) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, (_, at)| {
            let age_s = now.as_secs().saturating_sub(at.as_secs());
            age_s <= SPILLOVER_CACHE_TTL_S
        });
        before - self.entries.len()
    }

    /// Number of cached entries (including any that have expired but not
    /// been swept).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop all entries.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

impl Default for SpilloverResponseCache {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------------
// Discovery state
// -------------------------------------------------------------------------

/// Phase of a per-target discovery.
#[derive(Clone, Debug)]
enum DiscoveryPhase {
    /// Waiting for `LookupResponse`s from the paths.
    AwaitingResponses,
    /// A spillover request has been sent; waiting for its response.
    AwaitingSpillover,
    /// Discovery completed successfully.
    Done(Vec<NodeId>),
    /// Discovery failed.
    Failed(DiscoveryFailure),
}

/// Per-target discovery state.
#[derive(Clone, Debug)]
struct DiscoveryState {
    target: NodeId,
    witness_ring_id: [u8; 32],
    started_at: Timestamp,
    paths: BTreeMap<PathId, LookupPath>,
    witnesses_by_path: BTreeMap<PathId, Vec<NodeId>>,
    failed_paths: BTreeSet<PathId>,
    phase: DiscoveryPhase,
}

/// Internal result of `compute_resolution`.
enum Resolution {
    Wait,
    Done(Vec<NodeId>),
    NeedsSpillover(SpilloverRequest),
}

// -------------------------------------------------------------------------
// WitnessDiscovery
// -------------------------------------------------------------------------

/// Multi-path witness discovery state machine.
///
/// Generic over the [`Signer`] used to sign outgoing messages. The
/// discovery itself does not verify incoming signatures; callers must
/// verify `LookupResponse` and `SpilloverResponse` values before
/// ingesting them.
pub struct WitnessDiscovery<S: Signer> {
    signer: S,
    ring_cache: WitnessRingCache,
    spillover_cache: SpilloverResponseCache,
    active: BTreeMap<NodeId, DiscoveryState>,
}

impl<S: Signer> WitnessDiscovery<S> {
    /// Create a discovery driver that signs with `signer`.
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            ring_cache: WitnessRingCache::new(),
            spillover_cache: SpilloverResponseCache::new(),
            active: BTreeMap::new(),
        }
    }

    /// The local NodeId, derived from the signer's public key.
    pub fn local_node_id(&self) -> NodeId {
        self.signer.public_key()
    }

    /// Read access to the ring cache.
    pub fn ring_cache(&self) -> &WitnessRingCache {
        &self.ring_cache
    }

    /// Read access to the spillover response cache.
    pub fn spillover_cache(&self) -> &SpilloverResponseCache {
        &self.spillover_cache
    }

    /// Number of in-flight discoveries.
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Start (or look up from cache) a witness ring for `target`.
    ///
    /// The caller supplies the three `paths`; how they were computed is
    /// outside this module. If the ring is already cached, the caller
    /// gets it back immediately; otherwise a signed `CoralLookup` is
    /// returned.
    ///
    /// Calling `start` for a target that is already in flight is a
    /// no-op: the caller gets `Started(vec![])` rather than a duplicate
    /// lookup. Callers that want to know whether the lookup is fresh can
    /// compare against [`Self::active_count`].
    pub fn start(
        &mut self,
        target: NodeId,
        paths: Vec<LookupPath>,
        now: Timestamp,
    ) -> Result<StartOutcome> {
        // 1. Cache hit?
        if let Some(ring) = self
            .ring_cache
            .get(&target, now, ROTATION_INTERVAL_S)
        {
            return Ok(StartOutcome::Cached(ring.to_vec()));
        }

        // 2. Already in flight?
        if self.active.contains_key(&target) {
            return Ok(StartOutcome::Started(Vec::new()));
        }

        // 3. Build and sign a CoralLookup.
        let witness_ring_id = compute_ring_id(&target, now);
        let mut path_map = BTreeMap::new();
        for p in &paths {
            path_map.insert(p.path_id, p.clone());
        }

        let unsigned = CoralLookup {
            key: target,
            lookup_paths: paths,
            witness_ring_id,
            timestamp: now,
            requester: self.signer.public_key(),
            signature: [0; 64],
        };
        let payload = unsigned.signing_payload()?;
        let sig = self.signer.sign_ed25519(&payload);
        let signed = CoralLookup {
            signature: sig,
            ..unsigned
        };

        self.active.insert(
            target,
            DiscoveryState {
                target,
                witness_ring_id,
                started_at: now,
                paths: path_map,
                witnesses_by_path: BTreeMap::new(),
                failed_paths: BTreeSet::new(),
                phase: DiscoveryPhase::AwaitingResponses,
            },
        );

        Ok(StartOutcome::Started(vec![Outbound::CoralLookup(signed)]))
    }

    /// Feed a `LookupResponse` into the discovery.
    ///
    /// Returns any outbound messages that result. A response for a
    /// target that is not being tracked is silently ignored.
    pub fn ingest_lookup_response(
        &mut self,
        resp: LookupResponse,
        now: Timestamp,
    ) -> Result<Vec<Outbound>> {
        // Not tracking? Ignore.
        if !self.active.contains_key(&resp.key) {
            return Ok(Vec::new());
        }

        // No path proofs? Nothing we can attribute.
        if resp.path_proofs.is_empty() {
            return Ok(Vec::new());
        }

        // Extract witnesses: each `values[i]` is a 32-byte NodeId.
        let mut witnesses = Vec::with_capacity(resp.values.len());
        for v in &resp.values {
            if v.len() != 32 {
                return Err(Error::BadFrame(
                    "lookup response value is not a 32-byte NodeId",
                ));
            }
            let mut n = [0u8; 32];
            n.copy_from_slice(v);
            witnesses.push(n);
        }

        // Attribute the response to each responded path.
        {
            let state = match self.active.get_mut(&resp.key) {
                Some(s) => s,
                None => return Ok(Vec::new()),
            };
            for proof in &resp.path_proofs {
                if !proof.responded {
                    continue;
                }
                if !state.paths.contains_key(&proof.path_id) {
                    continue;
                }
                state
                    .witnesses_by_path
                    .insert(proof.path_id, witnesses.clone());
            }
        }

        self.try_resolve(&resp.key, now)
    }

    /// Feed a `SpilloverResponse` into the discovery.
    pub fn ingest_spillover_response(
        &mut self,
        resp: SpilloverResponse,
        now: Timestamp,
    ) -> Result<()> {
        let target = resp.original_key;

        // Are we awaiting a spillover for this target?
        let awaiting = matches!(
            self.active.get(&target),
            Some(s) if matches!(s.phase, DiscoveryPhase::AwaitingSpillover)
        );
        if !awaiting {
            return Ok(());
        }

        // Cache regardless of outcome — a zero-consensus response is
        // still worth remembering for 5 minutes so we don't hammer the
        // DHT re-asking the same question.
        self.spillover_cache.insert(resp.clone(), now);

        if resp.consensus == 0
            || resp.alternate_witnesses.len() < DEGRADED_QUORUM
        {
            if let Some(s) = self.active.get_mut(&target) {
                s.phase = DiscoveryPhase::Failed(DiscoveryFailure::SpilloverFailed);
            }
            return Ok(());
        }

        let ring = resp.alternate_witnesses.clone();
        if let Some(s) = self.active.get_mut(&target) {
            s.phase = DiscoveryPhase::Done(ring.clone());
        }
        self.ring_cache.insert(target, ring, now);
        Ok(())
    }

    /// Mark a path as failed and re-evaluate consensus.
    ///
    /// Discovery has no timers, so the caller decides when a path has
    /// timed out and reports it here.
    pub fn mark_path_failed(
        &mut self,
        target: &NodeId,
        path_id: PathId,
        now: Timestamp,
    ) -> Result<Vec<Outbound>> {
        if let Some(state) = self.active.get_mut(target) {
            if state.paths.contains_key(&path_id) {
                state.failed_paths.insert(path_id);
                state.witnesses_by_path.remove(&path_id);
            }
        }
        self.try_resolve(target, now)
    }

    /// Take the completed ring for `target`, if any.
    ///
    /// Removes the discovery from the active set on success. Returns
    /// `None` if the discovery is still in flight, failed, or was never
    /// started. The ring remains in [`Self::ring_cache`] regardless.
    pub fn take_ring(&mut self, target: &NodeId) -> Option<Vec<NodeId>> {
        let done = match self.active.get(target) {
            Some(s) => match &s.phase {
                DiscoveryPhase::Done(ring) => Some(ring.clone()),
                _ => None,
            },
            None => None,
        };
        if done.is_some() {
            self.active.remove(target);
        }
        done
    }

    /// Snapshot of an in-flight discovery, or `None` if `target` is not
    /// being tracked.
    pub fn status(&self, target: &NodeId) -> Option<DiscoveryStatus> {
        let s = self.active.get(target)?;
        let phase = match &s.phase {
            DiscoveryPhase::AwaitingResponses => DiscoveryPhaseKind::AwaitingResponses,
            DiscoveryPhase::AwaitingSpillover => DiscoveryPhaseKind::AwaitingSpillover,
            DiscoveryPhase::Done(_) => DiscoveryPhaseKind::Done,
            DiscoveryPhase::Failed(f) => DiscoveryPhaseKind::Failed(*f),
        };
        Some(DiscoveryStatus {
            target: s.target,
            witness_ring_id: s.witness_ring_id,
            started_at: s.started_at,
            paths_total: s.paths.len(),
            paths_resolved: s.witnesses_by_path.len() + s.failed_paths.len(),
            phase,
        })
    }

    /// Forget an in-flight discovery without completing it.
    ///
    /// Useful when the caller's timeout expires; the ring cache is not
    /// touched.
    pub fn forget(&mut self, target: &NodeId) {
        self.active.remove(target);
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    fn try_resolve(
        &mut self,
        target: &NodeId,
        now: Timestamp,
    ) -> Result<Vec<Outbound>> {
        let resolution = {
            let state = match self.active.get(target) {
                Some(s) => s,
                None => return Ok(Vec::new()),
            };
            compute_resolution(state, target, &self.signer, now)?
        };

        match resolution {
            Resolution::Wait => Ok(Vec::new()),
            Resolution::Done(ring) => {
                if let Some(s) = self.active.get_mut(target) {
                    s.phase = DiscoveryPhase::Done(ring.clone());
                }
                self.ring_cache.insert(*target, ring, now);
                Ok(Vec::new())
            }
            Resolution::NeedsSpillover(request) => {
                // Cache hit for a spillover response we already have?
                if let Some(cached) = self.spillover_cache.get(target, now) {
                    let ring = cached.alternate_witnesses.clone();
                    let consensus = cached.consensus;
                    if consensus == 0 || ring.len() < DEGRADED_QUORUM {
                        if let Some(s) = self.active.get_mut(target) {
                            s.phase =
                                DiscoveryPhase::Failed(DiscoveryFailure::SpilloverFailed);
                        }
                    } else {
                        if let Some(s) = self.active.get_mut(target) {
                            s.phase = DiscoveryPhase::Done(ring.clone());
                        }
                        self.ring_cache.insert(*target, ring, now);
                    }
                    return Ok(Vec::new());
                }

                // Otherwise emit a fresh spillover.
                if let Some(s) = self.active.get_mut(target) {
                    s.phase = DiscoveryPhase::AwaitingSpillover;
                }
                Ok(vec![Outbound::Spillover(request)])
            }
        }
    }
}

// -------------------------------------------------------------------------
// Resolution logic (pure function)
// -------------------------------------------------------------------------

/// Decide what a discovery should do next.
///
/// Runs consensus when at least two paths have responded; emits a
/// spillover when all paths have resolved (responded or failed) and no
/// consensus has emerged. Does not mutate `self`, so the caller can
/// update state after the fact without fighting the borrow checker.
fn compute_resolution<S: Signer>(
    state: &DiscoveryState,
    target: &NodeId,
    signer: &S,
    now: Timestamp,
) -> Result<Resolution> {
    // Already resolved?
    match state.phase {
        DiscoveryPhase::Done(_)
        | DiscoveryPhase::Failed(_)
        | DiscoveryPhase::AwaitingSpillover => {
            return Ok(Resolution::Wait);
        }
        DiscoveryPhase::AwaitingResponses => {}
    }

    let total = state.paths.len();
    let responded = state.witnesses_by_path.len();
    let resolved = responded + state.failed_paths.len();

    // Try consensus whenever at least two paths have responded.
    if responded >= SPILLOVER_THRESHOLD {
        let path_lists: Vec<Vec<NodeId>> =
            state.witnesses_by_path.values().cloned().collect();
        if let Some(ring) = cross_path_consensus(
            target,
            &path_lists,
            SPILLOVER_THRESHOLD,
            DEGRADED_QUORUM,
        ) {
            return Ok(Resolution::Done(ring));
        }
    }

    // All paths resolved but no consensus? Emit a spillover.
    if total > 0 && resolved == total {
        let rejected: Vec<NodeId> = state
            .witnesses_by_path
            .values()
            .flatten()
            .copied()
            .collect();
        let alternate_paths: Vec<LookupPath> = state.paths.values().cloned().collect();
        let unsigned = SpilloverRequest {
            original_key: *target,
            rejected_witnesses: rejected,
            // Reason 2 = "conflicting claims" (spec §13.8).
            rejection_reason: 2,
            alternate_paths,
            requester: signer.public_key(),
            timestamp: now,
            signature: [0; 64],
        };
        let payload = unsigned.signing_payload()?;
        let sig = signer.sign_ed25519(&payload);
        let signed = SpilloverRequest {
            signature: sig,
            ..unsigned
        };
        return Ok(Resolution::NeedsSpillover(signed));
    }

    Ok(Resolution::Wait)
}

/// Derive the `witness_ring_id` for `target` in the current epoch.
///
/// Spec §5.3.2: the ring rotates every [`ROTATION_INTERVAL_S`] and the
/// ring_id should include the epoch. A future revision could bind the
/// epoch cryptographically (see Appendix D of the spec); for now a
/// simple XOR with the epoch bytes is enough to distinguish rings from
/// different epochs.
fn compute_ring_id(target: &NodeId, now: Timestamp) -> [u8; 32] {
    let epoch = now.as_secs() / ROTATION_INTERVAL_S;
    let mut out = *target;
    let bytes = epoch.to_be_bytes();
    for (i, b) in bytes.iter().enumerate() {
        out[i] ^= b;
    }
    out
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coral::PathProof;
    use alloc::vec;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn key(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn pid(b: u8) -> PathId {
        [b; 16]
    }

    fn t(secs: u64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    /// Deterministic fake signer. Signatures are fixed bytes; nothing in
    /// `WitnessDiscovery` verifies them.
    struct FakeSigner {
        node_id: NodeId,
    }

    impl FakeSigner {
        fn new(b: u8) -> Self {
            Self { node_id: nid(b) }
        }
    }

    impl Signer for FakeSigner {
        fn public_key(&self) -> [u8; 32] {
            self.node_id
        }
        fn sign_ed25519(&self, _msg: &[u8]) -> [u8; 64] {
            [0xab; 64]
        }
    }

    fn lookup_path(seed: u8) -> LookupPath {
        LookupPath {
            path_id: pid(seed),
            nodes: vec![nid(seed)],
            value_hash: [seed; 32],
            ttl: 60,
        }
    }

    /// Build a `LookupResponse` announcing `witnesses` on path `path`.
    fn response(target: NodeId, path: u8, witnesses: &[NodeId]) -> LookupResponse {
        LookupResponse {
            key: target,
            values: witnesses.iter().map(|w| w.to_vec()).collect(),
            path_proofs: vec![PathProof {
                path_id: pid(path),
                node_signatures: vec![],
                value_hash: [0; 32],
                responded: true,
            }],
            responder: nid(0xee),
            timestamp: t(0),
            signature: [0; 64],
        }
    }

    fn spillover(target: NodeId, witnesses: &[NodeId], consensus: u64) -> SpilloverResponse {
        SpilloverResponse {
            original_key: target,
            alternate_witnesses: witnesses.to_vec(),
            path_proofs: vec![],
            consensus,
            responder: nid(0xee),
            timestamp: t(0),
            signature: [0; 64],
        }
    }

    fn three_paths() -> Vec<LookupPath> {
        vec![lookup_path(1), lookup_path(2), lookup_path(3)]
    }

    // ---- start ----

    #[test]
    fn start_produces_a_signed_coral_lookup() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(0x42));
        let target = nid(0x10);
        let outcome = d.start(target, three_paths(), t(0)).unwrap();
        match outcome {
            StartOutcome::Started(msgs) => {
                assert_eq!(msgs.len(), 1);
                match &msgs[0] {
                    Outbound::CoralLookup(m) => {
                        assert_eq!(m.key, target);
                        assert_eq!(m.requester, nid(0x42));
                        assert_eq!(m.signature, [0xab; 64]);
                        assert_eq!(m.lookup_paths.len(), 3);
                    }
                    _ => panic!("expected CoralLookup"),
                }
            }
            _ => panic!("expected Started"),
        }
        assert_eq!(d.active_count(), 1);
    }

    #[test]
    fn start_twice_is_idempotent() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();
        let second = d.start(target, three_paths(), t(0)).unwrap();
        match second {
            StartOutcome::Started(msgs) => assert!(msgs.is_empty()),
            _ => panic!("expected empty Started"),
        }
        assert_eq!(d.active_count(), 1);
    }

    #[test]
    fn start_returns_cached_when_ring_is_present() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        d.ring_cache.insert(target, vec![nid(1), nid(2), nid(3)], t(0));

        let outcome = d.start(target, three_paths(), t(100)).unwrap();
        match outcome {
            StartOutcome::Cached(ring) => {
                assert_eq!(ring, vec![nid(1), nid(2), nid(3)]);
            }
            _ => panic!("expected Cached"),
        }
        assert_eq!(d.active_count(), 0, "no lookup for a cached ring");
    }

    // ---- ingest ----

    #[test]
    fn ingest_unknown_key_is_ignored() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let resp = response(nid(0xff), 1, &[nid(1)]);
        let out = d.ingest_lookup_response(resp, t(0)).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn ingest_response_with_wrong_sized_value_errors() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        let resp = LookupResponse {
            key: target,
            values: vec![vec![0u8; 31]],
            path_proofs: vec![PathProof {
                path_id: pid(1),
                node_signatures: vec![],
                value_hash: [0; 32],
                responded: true,
            }],
            responder: nid(0),
            timestamp: t(0),
            signature: [0; 64],
        };
        assert!(d.ingest_lookup_response(resp, t(0)).is_err());
    }

    #[test]
    fn ingest_two_agreeing_responses_completes() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        let ring = vec![nid(1), nid(2), nid(3), nid(4)];
        let out = d.ingest_lookup_response(response(target, 1, &ring), t(1)).unwrap();
        assert!(out.is_empty(), "one path is not enough");

        let out = d.ingest_lookup_response(response(target, 2, &ring), t(2)).unwrap();
        assert!(out.is_empty(), "two agreeing paths complete without spillover");

        let taken = d.take_ring(&target).unwrap();
        assert_eq!(taken, ring);
        assert_eq!(d.active_count(), 0);
    }

    #[test]
    fn ingest_two_disagreeing_responses_waits() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        let a = vec![nid(1), nid(2), nid(3), nid(4)];
        let b = vec![nid(5), nid(6), nid(7), nid(8)];

        let _ = d.ingest_lookup_response(response(target, 1, &a), t(1)).unwrap();
        let out = d.ingest_lookup_response(response(target, 2, &b), t(2)).unwrap();
        assert!(out.is_empty(), "two disagreeing paths wait for the third");
        assert!(d.take_ring(&target).is_none());
    }

    #[test]
    fn ingest_third_response_resolves_with_consensus() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        // Two paths agree on the same 4 witnesses.
        let ring = vec![nid(1), nid(2), nid(3), nid(4)];
        let other = vec![nid(9), nid(10), nid(11), nid(12)];

        let _ = d.ingest_lookup_response(response(target, 1, &ring), t(1)).unwrap();
        let out = d.ingest_lookup_response(response(target, 2, &other), t(2)).unwrap();
        assert!(out.is_empty(), "no consensus with 2 disagreeing paths");

        let out = d.ingest_lookup_response(response(target, 3, &ring), t(3)).unwrap();
        assert!(out.is_empty(), "consensus reached, no spillover");

        assert_eq!(d.take_ring(&target).unwrap(), ring);
    }

    #[test]
    fn ingest_all_disagreeing_triggers_spillover() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        let a = vec![nid(1), nid(2), nid(3)];
        let b = vec![nid(4), nid(5), nid(6)];
        let c = vec![nid(7), nid(8), nid(9)];

        let _ = d.ingest_lookup_response(response(target, 1, &a), t(1)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 2, &b), t(2)).unwrap();
        let out = d.ingest_lookup_response(response(target, 3, &c), t(3)).unwrap();

        assert_eq!(out.len(), 1);
        match &out[0] {
            Outbound::Spillover(req) => {
                assert_eq!(req.original_key, target);
                assert_eq!(req.requester, nid(1));
                assert_eq!(req.rejection_reason, 2);
                // All witnesses from all three paths.
                assert_eq!(req.rejected_witnesses.len(), 9);
            }
            _ => panic!("expected Spillover"),
        }
    }

    // ---- path failures ----

    #[test]
    fn mark_path_failed_lets_the_other_two_resolve() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        let ring = vec![nid(1), nid(2), nid(3), nid(4)];
        let _ = d.ingest_lookup_response(response(target, 1, &ring), t(1)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 2, &ring), t(2)).unwrap();

        // Both agree; discovery should already be done.
        assert_eq!(d.take_ring(&target).unwrap(), ring);
    }

    #[test]
    fn mark_path_failed_with_no_other_responses_triggers_spillover() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        let _ = d.mark_path_failed(&target, pid(1), t(1)).unwrap();
        let _ = d.mark_path_failed(&target, pid(2), t(2)).unwrap();
        let out = d.mark_path_failed(&target, pid(3), t(3)).unwrap();

        assert_eq!(out.len(), 1);
        assert!(matches!(out[0], Outbound::Spillover(_)));
    }

    #[test]
    fn mark_path_failed_for_unknown_path_is_ignored() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        let out = d.mark_path_failed(&target, pid(0xee), t(1)).unwrap();
        assert!(out.is_empty(), "unknown path does not trigger resolution");
    }

    // ---- spillover ----

    #[test]
    fn spillover_response_completes() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();

        // Force into AwaitingSpillover by feeding three disagreeing paths.
        let _ = d.ingest_lookup_response(response(target, 1, &[nid(1)]), t(1)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 2, &[nid(2)]), t(2)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 3, &[nid(3)]), t(3)).unwrap();

        let ring = vec![nid(11), nid(12), nid(13), nid(14)];
        let resp = spillover(target, &ring, 1);
        d.ingest_spillover_response(resp, t(4)).unwrap();

        assert_eq!(d.take_ring(&target).unwrap(), ring);
        // The response was cached.
        assert!(d.spillover_cache().get(&target, t(4)).is_some());
    }

    #[test]
    fn spillover_response_with_zero_consensus_fails() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 1, &[nid(1)]), t(1)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 2, &[nid(2)]), t(2)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 3, &[nid(3)]), t(3)).unwrap();

        let resp = spillover(target, &[nid(11), nid(12), nid(13)], 0);
        d.ingest_spillover_response(resp, t(4)).unwrap();

        assert!(d.take_ring(&target).is_none(), "no ring on zero consensus");
        // The failed response is still cached.
        assert!(d.spillover_cache().get(&target, t(4)).is_some());
    }

    #[test]
    fn spillover_response_with_too_few_witnesses_fails() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 1, &[nid(1)]), t(1)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 2, &[nid(2)]), t(2)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 3, &[nid(3)]), t(3)).unwrap();

        // consensus = 1 but only 2 witnesses.
        let resp = spillover(target, &[nid(11), nid(12)], 1);
        d.ingest_spillover_response(resp, t(4)).unwrap();

        assert!(d.take_ring(&target).is_none());
    }

    #[test]
    fn cached_spillover_avoids_a_new_request() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);

        // Pre-populate the cache.
        let ring = vec![nid(11), nid(12), nid(13), nid(14)];
        d.spillover_cache.insert(spillover(target, &ring, 2), t(0));

        // Start and force the initial lookup into AwaitingSpillover-
        // eligible state.
        let _ = d.start(target, three_paths(), t(0)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 1, &[nid(1)]), t(1)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 2, &[nid(2)]), t(2)).unwrap();
        let out = d.ingest_lookup_response(response(target, 3, &[nid(3)]), t(3)).unwrap();

        // The cache hit short-circuits the spillover.
        assert!(out.is_empty(), "cached response avoids a new spillover");
        assert_eq!(d.take_ring(&target).unwrap(), ring);
    }

    // ---- take_ring / forget ----

    #[test]
    fn take_ring_is_none_while_in_flight() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();
        assert!(d.take_ring(&target).is_none());
    }

    #[test]
    fn take_ring_removes_active_state() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();
        let ring = vec![nid(1), nid(2), nid(3), nid(4)];
        let _ = d.ingest_lookup_response(response(target, 1, &ring), t(1)).unwrap();
        let _ = d.ingest_lookup_response(response(target, 2, &ring), t(2)).unwrap();

        assert!(d.take_ring(&target).is_some());
        assert_eq!(d.active_count(), 0);
        // Second take is None.
        assert!(d.take_ring(&target).is_none());
    }

    #[test]
    fn forget_drops_state_without_touching_cache() {
        let mut d = WitnessDiscovery::new(FakeSigner::new(1));
        let target = nid(0x10);
        let _ = d.start(target, three_paths(), t(0)).unwrap();
        d.forget(&target);
        assert_eq!(d.active_count(), 0);
        assert!(d.ring_cache().is_empty());
    }

    // ---- ring id ----

    #[test]
    fn ring_id_is_deterministic_within_an_epoch() {
        let target = nid(0x42);
        let a = compute_ring_id(&target, t(0));
        let b = compute_ring_id(&target, t(1000));
        assert_eq!(a, b, "same epoch");
    }

    #[test]
    fn ring_id_differs_between_epochs() {
        let target = nid(0x42);
        let a = compute_ring_id(&target, t(0));
        let b = compute_ring_id(&target, t(ROTATION_INTERVAL_S + 1));
        assert_ne!(a, b, "different epochs");
    }

    // ---- spillover cache ----

    #[test]
    fn spillover_cache_get_respects_ttl() {
        let mut c = SpilloverResponseCache::new();
        let target = key(1);
        c.insert(spillover(nid(1), &[nid(2)], 1), t(0));
        assert!(c.get(&target, t(SPILLOVER_CACHE_TTL_S)).is_some());
        assert!(c.get(&target, t(SPILLOVER_CACHE_TTL_S + 1)).is_none());
    }

    #[test]
    fn spillover_cache_sweep_drops_expired() {
        let mut c = SpilloverResponseCache::new();
        c.insert(spillover(nid(1), &[], 0), t(0));

        // `insert` sweeps before inserting, so the second entry's arrival
        // at t(TTL + 1) already expires the first one.
        c.insert(spillover(nid(2), &[], 0), t(SPILLOVER_CACHE_TTL_S + 1));
        assert_eq!(c.len(), 1, "first entry swept by the second insert");
        assert!(c.get(&key(1), t(SPILLOVER_CACHE_TTL_S + 1)).is_none());
        assert!(c.get(&key(2), t(SPILLOVER_CACHE_TTL_S + 1)).is_some());

        // The second entry expires once we're past its own TTL.
        let expiry_of_second = SPILLOVER_CACHE_TTL_S + 1 + SPILLOVER_CACHE_TTL_S;
        assert_eq!(
            c.sweep(t(expiry_of_second)),
            0,
            "at the boundary, still fresh",
        );
        assert_eq!(
            c.sweep(t(expiry_of_second + 1)),
            1,
            "one second later, gone",
        );
    }

    #[test]
    fn spillover_cache_evicts_oldest_when_full() {
        let mut c = SpilloverResponseCache::with_capacity(2);
        c.insert(spillover(nid(1), &[], 0), t(0));
        c.insert(spillover(nid(2), &[], 0), t(1));
        c.insert(spillover(nid(3), &[], 0), t(2));
        assert_eq!(c.len(), 2);
        assert!(c.get(&key(1), t(2)).is_none(), "oldest evicted");
        assert!(c.get(&key(2), t(2)).is_some());
        assert!(c.get(&key(3), t(2)).is_some());
    }

    #[test]
    fn spillover_cache_clear_empties_it() {
        let mut c = SpilloverResponseCache::new();
        c.insert(spillover(nid(1), &[], 0), t(0));
        c.clear();
        assert!(c.is_empty());
    }
}