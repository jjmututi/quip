//! Coral cluster state machine (spec §13.2–§13.6).
//!
//! Pure state machine. No I/O, no async, no transport dependency. The
//! caller drives it: feeds in observations (RTT samples, heartbeat
//! ticks, peer reports) and reads out decisions (accept or reject a
//! cluster, merge to a neighbour, split, create new).
//!
//! # What it is
//!
//! `ClusterState` models the Coral self-organisation protocol from the
//! perspective of one member. It knows:
//!
//! - which level of the hierarchy it belongs to;
//! - whether it is still within the RTT threshold (§13.2);
//! - whether a neighbour is large enough to warrant a merge (§13.4);
//! - whether it has been over-threshold long enough to split (§13.5);
//! - which split branch to take — near, far, or new (§13.5).
//!
//! It does not own a routing table, does not send messages, and does not
//! know about DHT lookups. Those are `WitnessDiscovery`'s job.
//!
//! # Level numbering
//!
//! [`ClusterLevel`] uses the spec's numbering: Global is 0, Regional is
//! 1, Local is 2. The [`crate::dht::LOCAL_CLUSTER`] /
//! [`crate::dht::REGIONAL_CLUSTER`] / [`crate::dht::GLOBAL_CLUSTER`]
//! constants use the same convention, so the two are interchangeable.

use crate::codec::{as_bytes_n, as_u64, envelope, fields, verb_of};
use crate::constants::{
    CLUSTER_ACCEPTANCE_PERCENTILE, CLUSTER_HEARTBEAT_S, CLUSTER_LEVELS,
    COORDINATOR_INTERVAL_S, MAX_CLUSTER_SIZE, MAX_SPLIT_ATTEMPTS,
    MERGE_DELTA_INTERVAL_S, MIN_CLUSTER_SIZE, RTT_GLOBAL_MS, RTT_LOCAL_MS,
    RTT_REGIONAL_MS,
};
use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::dvv::NodeId;
use quip_core::messages::Verifier;
use quip_core::time::Timestamp;

/// A 16-byte Coral cluster identifier (§13).
pub type ClusterId = [u8; 16];

/// Minimum number of RTT samples required for an acceptance test.
///
/// Spec §13.2: *"Obtain a random subset of at least 20 nodes."*
pub const ACCEPTANCE_MIN_SAMPLES: usize = 20;

/// §2d of docs/m9.6b-merge-design.md: a merge proposal is abandoned
/// if a majority of the smaller cluster has not announced the larger
/// id within three cluster heartbeats.
pub const MERGE_PROPOSAL_TIMEOUT_S: u64 = CLUSTER_HEARTBEAT_S * 3;

// -------------------------------------------------------------------------
// Cluster level
// -------------------------------------------------------------------------

/// Level in the Coral hierarchy (§13).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum ClusterLevel {
    /// Planet-wide. RTT threshold: unbounded.
    Global = 0,
    /// Continent-scale. RTT threshold: 100 ms.
    Regional = 1,
    /// City/region-scale. RTT threshold: 30 ms.
    Local = 2,
}

impl ClusterLevel {
    /// Default RTT threshold for this level, in milliseconds.
    pub const fn default_rtt_threshold_ms(self) -> u64 {
        match self {
            ClusterLevel::Local => RTT_LOCAL_MS,
            ClusterLevel::Regional => RTT_REGIONAL_MS,
            ClusterLevel::Global => RTT_GLOBAL_MS,
        }
    }

    /// All levels, in declaration order (global → local).
    pub const ALL: [ClusterLevel; CLUSTER_LEVELS] = [
        ClusterLevel::Global,
        ClusterLevel::Regional,
        ClusterLevel::Local,
    ];

    /// The next-more-specific level (towards local), or `None` for
    /// `Local`.
    pub const fn more_specific(self) -> Option<ClusterLevel> {
        match self {
            ClusterLevel::Global => Some(ClusterLevel::Regional),
            ClusterLevel::Regional => Some(ClusterLevel::Local),
            ClusterLevel::Local => None,
        }
    }

    /// The next-less-specific level (towards global), or `None` for
    /// `Global`.
    pub const fn less_specific(self) -> Option<ClusterLevel> {
        match self {
            ClusterLevel::Local => Some(ClusterLevel::Regional),
            ClusterLevel::Regional => Some(ClusterLevel::Global),
            ClusterLevel::Global => None,
        }
    }
}

// -------------------------------------------------------------------------
// Cluster info (peer reports)
// -------------------------------------------------------------------------

/// A peer's report about the cluster it belongs to (§13.4).
///
/// The wire form is a CBOR map with a signature field; M2b.1 operates on
/// the *value* after the signature has been verified by the caller. That
/// keeps this state machine independent of the `Verifier` trait and of
/// the `crypto` feature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterInfo {
    /// The cluster's identifier.
    pub id: ClusterId,
    /// The cluster's estimated size.
    pub size: u64,
    /// The cluster's creation time.
    pub ctime: Timestamp,
}

/// A signed cluster-information announcement (§13.4, §13.5).
///
/// The tuple carries no node id: the signer is the connection peer, and
/// [`verify`](Self::verify) takes that authenticated id explicitly. That
/// is what stops a peer from announcing a cluster id on another's
/// behalf — the same shape as `connectivity_announce`'s self-signed id
/// and `RelayResponse`'s explicit responder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterInfoAnnounce {
    /// The announced tuple.
    pub info: ClusterInfo,
    /// Ed25519 signature by the announcing node.
    pub signature: [u8; 64],
}

impl ClusterInfoAnnounce {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_info",
            alloc::vec![
                CborValue::Bytes(self.info.id.to_vec()),
                CborValue::Int(self.info.size as i128),
                CborValue::Int(self.info.ctime.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "cluster_info" {
            return Err(Error::BadFrame("not a cluster_info"));
        }
        let f = fields(&v, "cluster_info")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("cluster_info arity"));
        }
        Ok(Self {
            info: ClusterInfo {
                id: as_bytes_n::<16>(&f[0])?,
                size: as_u64(&f[1])?,
                ctime: Timestamp::from_millis(as_u64(&f[2])?),
            },
            signature: as_bytes_n::<64>(&f[3])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_info",
            alloc::vec![
                CborValue::Bytes(self.info.id.to_vec()),
                CborValue::Int(self.info.size as i128),
                CborValue::Int(self.info.ctime.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `sender`, the authenticated peer id.
    pub fn verify(&self, sender: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(sender, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// Merge wire verbs (§13.4, docs/m9.6b-merge-design.md §2b)
// -------------------------------------------------------------------------

/// Why a larger cluster's coordinator refused a merge proposal (§2b).
///
/// Encoded as a single `u8` in the CBOR array rather than as text: the
/// draft's other reason codes are numeric and the rejected frame is small.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MergeRejectReason {
    /// The size ratio no longer satisfies the δ rule.
    Size = 0,
    /// The two clusters are not at the same [`ClusterLevel`].
    Level = 1,
    /// The acceptor already has a proposal in flight (`incoming_merge`).
    Busy = 2,
    /// The proposal's signature did not verify against the sender.
    Signature = 3,
}

impl MergeRejectReason {
    /// The wire value.
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Decode a wire value; `None` for an unassigned code.
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Size),
            1 => Some(Self::Level),
            2 => Some(Self::Busy),
            3 => Some(Self::Signature),
            _ => None,
        }
    }
}

/// `cluster_merge_propose` — the smaller cluster's coordinator asks to be
/// merged into a larger one (§2b).
///
/// Signed by the proposing coordinator; [`verify`](Self::verify) takes
/// the authenticated connection peer, so a member cannot propose on its
/// coordinator's behalf — the same shape as [`ClusterInfoAnnounce`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterMergePropose {
    /// The smaller (proposing) cluster's id.
    pub proposer_cluster_id: ClusterId,
    /// The smaller cluster's advertised size.
    pub proposer_size: u64,
    /// When the proposal was made.
    pub proposed_at: Timestamp,
    /// Ed25519 signature by the proposing coordinator.
    pub signature: [u8; 64],
}

impl ClusterMergePropose {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_merge_propose",
            alloc::vec![
                CborValue::Bytes(self.proposer_cluster_id.to_vec()),
                CborValue::Int(self.proposer_size as i128),
                CborValue::Int(self.proposed_at.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "cluster_merge_propose" {
            return Err(Error::BadFrame("not a cluster_merge_propose"));
        }
        let f = fields(&v, "cluster_merge_propose")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("cluster_merge_propose arity"));
        }
        Ok(Self {
            proposer_cluster_id: as_bytes_n::<16>(&f[0])?,
            proposer_size: as_u64(&f[1])?,
            proposed_at: Timestamp::from_millis(as_u64(&f[2])?),
            signature: as_bytes_n::<64>(&f[3])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_merge_propose",
            alloc::vec![
                CborValue::Bytes(self.proposer_cluster_id.to_vec()),
                CborValue::Int(self.proposer_size as i128),
                CborValue::Int(self.proposed_at.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `sender`, the authenticated peer id.
    pub fn verify(&self, sender: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(sender, &payload, &self.signature))
    }
}

/// `cluster_merge_accept` — the larger cluster's coordinator accepts a
/// proposal (§2b).
///
/// Broadcast to its own members and to the proposing coordinator. The
/// accepting cluster's id survives; the proposing cluster migrates to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterMergeAccept {
    /// The larger (surviving) cluster's id.
    pub accept_cluster_id: ClusterId,
    /// The larger cluster's size at acceptance (§2c re-checks it).
    pub accept_size: u64,
    /// When the proposal was accepted.
    pub accepted_at: Timestamp,
    /// Ed25519 signature by the accepting coordinator.
    pub signature: [u8; 64],
}

impl ClusterMergeAccept {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_merge_accept",
            alloc::vec![
                CborValue::Bytes(self.accept_cluster_id.to_vec()),
                CborValue::Int(self.accept_size as i128),
                CborValue::Int(self.accepted_at.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "cluster_merge_accept" {
            return Err(Error::BadFrame("not a cluster_merge_accept"));
        }
        let f = fields(&v, "cluster_merge_accept")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("cluster_merge_accept arity"));
        }
        Ok(Self {
            accept_cluster_id: as_bytes_n::<16>(&f[0])?,
            accept_size: as_u64(&f[1])?,
            accepted_at: Timestamp::from_millis(as_u64(&f[2])?),
            signature: as_bytes_n::<64>(&f[3])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_merge_accept",
            alloc::vec![
                CborValue::Bytes(self.accept_cluster_id.to_vec()),
                CborValue::Int(self.accept_size as i128),
                CborValue::Int(self.accepted_at.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `sender`, the authenticated peer id.
    pub fn verify(&self, sender: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(sender, &payload, &self.signature))
    }
}

/// `cluster_merge_reject` — the larger cluster's coordinator refuses a
/// proposal (§2b).
///
/// The proposer's cluster id is echoed for correlation; the proposal is
/// not retried within the same episode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterMergeReject {
    /// The proposing cluster's id, echoed for correlation.
    pub proposer_cluster_id: ClusterId,
    /// Why the proposal was refused.
    pub reason: MergeRejectReason,
    /// When the proposal was refused.
    pub rejected_at: Timestamp,
    /// Ed25519 signature by the accepting coordinator.
    pub signature: [u8; 64],
}

impl ClusterMergeReject {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_merge_reject",
            alloc::vec![
                CborValue::Bytes(self.proposer_cluster_id.to_vec()),
                CborValue::Int(self.reason.as_u8() as i128),
                CborValue::Int(self.rejected_at.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "cluster_merge_reject" {
            return Err(Error::BadFrame("not a cluster_merge_reject"));
        }
        let f = fields(&v, "cluster_merge_reject")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("cluster_merge_reject arity"));
        }
        let code = as_u64(&f[1])?;
        let reason = u8::try_from(code)
            .ok()
            .and_then(MergeRejectReason::from_u8)
            .ok_or(Error::BadFrame("cluster_merge_reject reason"))?;
        Ok(Self {
            proposer_cluster_id: as_bytes_n::<16>(&f[0])?,
            reason,
            rejected_at: Timestamp::from_millis(as_u64(&f[2])?),
            signature: as_bytes_n::<64>(&f[3])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cluster_merge_reject",
            alloc::vec![
                CborValue::Bytes(self.proposer_cluster_id.to_vec()),
                CborValue::Int(self.reason.as_u8() as i128),
                CborValue::Int(self.rejected_at.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `sender`, the authenticated peer id.
    pub fn verify(&self, sender: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(sender, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// Merge decision (§13.4)
// -------------------------------------------------------------------------

/// Whether to leave the current cluster for a neighbour.
///
/// `Merge` implies "merge into the peer [`ClusterInfo`] this decision was
/// evaluated against"; the caller has the `ClusterInfo` in hand, so the
/// target is not carried on the variant.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MergeDecision {
    /// Stay where you are.
    Stay,
    /// Migrate to the neighbour in the [`ClusterInfo`].
    Merge,
}

// -------------------------------------------------------------------------
// Split id derivation (§13.5)
// -------------------------------------------------------------------------

/// `hash` from §13.5, truncated to an id: SHA-256 over `data`, first 16
/// bytes.
#[cfg(feature = "crypto")]
fn hash16(data: &[u8]) -> ClusterId {
    let digest = crate::crypto::sha256_bytes(data);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// The "near" branch's id: `cid^N = hash(cid)` (§13.5).
///
/// 6b's reading of §13.5's undefined `hash` is recorded in
/// `docs/M9.6b-design.md` §8 and is provisional until the draft defines
/// it: SHA-256 over the 16-byte id, truncated to 16 bytes.
#[cfg(feature = "crypto")]
pub fn near_cluster_id(cid: &ClusterId) -> ClusterId {
    hash16(cid)
}

/// The "far" branch's id: `cid^N` with bit 0 of the first byte flipped.
#[cfg(feature = "crypto")]
pub fn far_cluster_id(cid: &ClusterId) -> ClusterId {
    let mut far = near_cluster_id(cid);
    far[0] ^= 0x01;
    far
}

/// The key §13.5 looks up to find the cluster center: `hash(cid^N)`.
///
/// A full 256-bit XOR key, not a truncated id: it is a lookup key, not a
/// cluster identifier.
#[cfg(feature = "crypto")]
pub fn center_lookup_key(cid: &ClusterId) -> NodeId {
    crate::crypto::sha256_bytes(&near_cluster_id(cid))
}

/// A fresh cluster id for [`SplitAction::CreateNew`].
///
/// `SHA-256(local_node_id || now_ms || attempts)[..16]`. Not
/// cryptographically random — there is no `rand` in the workspace and
/// `quip-core` is `no_std` — but unpredictable to a remote peer and
/// re-validated by acceptance on the far side.
#[cfg(feature = "crypto")]
pub fn fresh_cluster_id(node: &NodeId, now: Timestamp, attempts: u32) -> ClusterId {
    let mut buf = Vec::with_capacity(44);
    buf.extend_from_slice(node);
    buf.extend_from_slice(&now.as_millis().to_be_bytes());
    buf.extend_from_slice(&attempts.to_be_bytes());
    hash16(&buf)
}

// -------------------------------------------------------------------------
// Split decision (§13.5)
// -------------------------------------------------------------------------

/// Which cluster to join when the current cluster is splitting.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SplitAction {
    /// Join the "near" split cluster `cid^N`.
    JoinNear,
    /// Join the "far" split cluster `cid^F`.
    JoinFar,
    /// Neither was acceptable; create a new cluster with a random ID.
    CreateNew,
}

// -------------------------------------------------------------------------
// Cluster configuration
// -------------------------------------------------------------------------

/// Per-level configuration for [`ClusterState`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ClusterConfig {
    /// Which level of the hierarchy this cluster belongs to.
    pub level: ClusterLevel,
    /// RTT ceiling for cluster acceptance, in milliseconds.
    pub rtt_threshold_ms: u64,
    /// Latency percentile used in the acceptance test (§13.2).
    pub acceptance_percentile: u8,
    /// Maximum number of members before the cluster should split (§3.1).
    pub max_size: usize,
    /// Minimum number of members for viability (§3.1).
    pub min_size: usize,
    /// Heartbeat interval, in seconds (§3.1).
    pub heartbeat_s: u64,
    /// Coordinator rotation interval, in seconds (§3.1).
    pub coordinator_interval_s: u64,
    /// δ preference function interval, in seconds (§3.1).
    pub merge_delta_interval_s: u64,
    /// Maximum split attempts before creating a new cluster (§3.1).
    pub max_split_attempts: u32,
}

impl ClusterConfig {
    /// Protocol defaults for the given level.
    pub fn for_level(level: ClusterLevel) -> Self {
        Self {
            level,
            rtt_threshold_ms: level.default_rtt_threshold_ms(),
            acceptance_percentile: CLUSTER_ACCEPTANCE_PERCENTILE,
            max_size: MAX_CLUSTER_SIZE,
            min_size: MIN_CLUSTER_SIZE,
            heartbeat_s: CLUSTER_HEARTBEAT_S,
            coordinator_interval_s: COORDINATOR_INTERVAL_S,
            merge_delta_interval_s: MERGE_DELTA_INTERVAL_S,
            max_split_attempts: MAX_SPLIT_ATTEMPTS,
        }
    }
}

// -------------------------------------------------------------------------
// Cluster state
// -------------------------------------------------------------------------

/// One member's view of its cluster.
#[derive(Clone, Debug)]
pub struct ClusterState {
    /// The cluster's identifier.
    pub id: ClusterId,
    /// Which level of the hierarchy the cluster belongs to.
    pub level: ClusterLevel,
    /// Estimated number of members.
    pub size: u64,
    /// When the cluster was created.
    pub ctime: Timestamp,
    /// Current coordinator, if one has been elected.
    pub coordinator: Option<NodeId>,
    /// When the coordinator's term began.
    pub coordinator_since: Timestamp,
    /// Last heartbeat observed from any member.
    pub last_heartbeat: Timestamp,
    /// When the RTT threshold was first exceeded in the current run, or
    /// `None` if the cluster is currently within threshold.
    pub rtt_exceeded_since: Option<Timestamp>,
    /// Number of split attempts made so far in the current episode.
    pub split_attempts: u32,
    /// The attempt in flight, if any (§13.5).
    ///
    /// Set by [`Self::migrate`], cleared only when an *eligible*
    /// recompute decides the attempt. A pending attempt has no outcome
    /// yet, so it neither counts against the cap nor clears the counter.
    pub pending_split: Option<PendingSplit>,
    /// The merge proposal this node has in flight, if any (§2b, §2c).
    pub pending_merge: Option<PendingMerge>,
    /// Receiver-side slot for a proposal the local coordinator is
    /// deciding, if any (§2c). Distinct from `pending_merge`: the
    /// proposer records what it sent, the acceptor records what it has
    /// not yet answered, and the two exist on different nodes.
    pub incoming_merge: Option<PendingMergeIncoming>,
}

/// A merge proposal this node has proposed and not yet concluded (§2b).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PendingMerge {
    /// The larger cluster the proposal targets.
    pub target: ClusterId,
    /// When the proposal was made.
    pub proposed_at: Timestamp,
}

/// A merge proposal the local coordinator has received and not yet
/// answered (§2c). The acceptor's single slot: a second proposal
/// displaces the first.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PendingMergeIncoming {
    /// The proposing coordinator's node id.
    pub proposer_id: NodeId,
    /// The proposing cluster's id.
    pub proposer_cluster_id: ClusterId,
    /// When the proposal was made.
    pub proposed_at: Timestamp,
}

/// An attempt whose outcome has not yet been decided (§13.5).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PendingSplit {
    /// When the migration completed.
    pub migrated_at: Timestamp,
    /// The cluster id the node moved to.
    pub new_id: ClusterId,
}

impl ClusterState {
    /// Create a fresh cluster with the given ID and level.
    ///
    /// The caller is the first member; `size` starts at 1.
    pub fn new(id: ClusterId, level: ClusterLevel, now: Timestamp) -> Self {
        Self {
            id,
            level,
            size: 1,
            ctime: now,
            coordinator: None,
            coordinator_since: now,
            last_heartbeat: now,
            rtt_exceeded_since: None,
            split_attempts: 0,
            pending_split: None,
            pending_merge: None,
            incoming_merge: None,
        }
    }

    // ---------------------------------------------------------------------
    // Liveness
    // ---------------------------------------------------------------------

    /// Record a heartbeat from a peer.
    pub fn note_heartbeat(&mut self, now: Timestamp) {
        self.last_heartbeat = now;
    }

    /// True if the last heartbeat is older than `config.heartbeat_s`.
    pub fn heartbeat_expired(&self, now: Timestamp, config: &ClusterConfig) -> bool {
        let elapsed_s = now
            .as_secs()
            .saturating_sub(self.last_heartbeat.as_secs());
        elapsed_s > config.heartbeat_s
    }

    /// True if the coordinator's term has reached
    /// `config.coordinator_interval_s`.
    pub fn coordinator_rotation_due(&self, now: Timestamp, config: &ClusterConfig) -> bool {
        let elapsed_s = now
            .as_secs()
            .saturating_sub(self.coordinator_since.as_secs());
        elapsed_s >= config.coordinator_interval_s
    }

    /// Record a new coordinator and reset its term.
    pub fn elect_coordinator(&mut self, node: NodeId, now: Timestamp) {
        self.coordinator = Some(node);
        self.coordinator_since = now;
    }

    /// Replace the size estimate.
    pub fn update_size(&mut self, size: u64) {
        self.size = size.max(1);
    }

    // ---------------------------------------------------------------------
    // Acceptance (§13.2)
    // ---------------------------------------------------------------------

    /// Test whether this cluster is acceptable given measured RTTs to a
    /// sample of its members.
    ///
    /// Returns `false` if fewer than [`ACCEPTANCE_MIN_SAMPLES`] samples
    /// are provided.
    ///
    /// The criterion is: the `config.acceptance_percentile`-th percentile
    /// RTT is at or below `config.rtt_threshold_ms`.
    pub fn is_acceptable(&self, rtts_ms: &[u64], config: &ClusterConfig) -> bool {
        if rtts_ms.len() < ACCEPTANCE_MIN_SAMPLES {
            return false;
        }
        percentile_at_or_below(
            rtts_ms,
            config.acceptance_percentile,
            config.rtt_threshold_ms,
        )
    }

    // ---------------------------------------------------------------------
    // Merge decision (§13.4)
    // ---------------------------------------------------------------------

    /// Decide whether to merge into `other`.
    ///
    /// The preference function δ flips every
    /// `config.merge_delta_interval_s` seconds based on wall-clock time,
    /// so all nodes in the network see the same parity at the same
    /// moment. A node migrates to a strictly larger cluster only when
    /// `|log2(sizeA) - log2(sizeB)| > δ`. Otherwise the tie-break is
    /// "lower `cluster_id`".
    ///
    /// # Interpretation
    ///
    /// Spec §13.4 writes `δ(min(ageA, ageB))` where `age` is called
    /// "cluster creation time". Both readings — "current wall clock" and
    /// "older cluster's age" — produce the same value at any given
    /// moment for two clusters alive at the same time, so this
    /// implementation uses wall clock. If a future revision specifies a
    /// per-cluster derivation, the change is confined to `delta_for`.
    pub fn should_merge(
        &self,
        other: &ClusterInfo,
        now: Timestamp,
        config: &ClusterConfig,
    ) -> MergeDecision {
        if other.id == self.id {
            return MergeDecision::Stay;
        }
        let delta = delta_for(now, config);

        let other_is_larger = other.size > self.size;
        let ratio_exceeds_delta = log2_diff_exceeds(self.size, other.size, delta);

        if ratio_exceeds_delta {
            if other_is_larger {
                MergeDecision::Merge
            } else {
                MergeDecision::Stay
            }
        } else if other.id < self.id {
            // Deterministic tie-break: lower cluster_id wins.
            MergeDecision::Merge
        } else {
            MergeDecision::Stay
        }
    }

    // ---------------------------------------------------------------------
    // Merge lifecycle (§2b, §2c of docs/m9.6b-merge-design.md)
    // ---------------------------------------------------------------------

    /// True if the §2a conditions other than size are met: no pending
    /// split, and no outgoing or incoming merge in flight.
    ///
    /// The size condition (§2a rule 1) is evaluated by
    /// [`Self::should_merge`] at the call site, where the peer
    /// [`ClusterInfo`] is in hand. The level condition (§2a rule 4) is
    /// also the caller's filter: the peer's level is not carried in
    /// `ClusterInfo`, so this method cannot see it.
    ///
    /// `now` and `config` are accepted for symmetry with the rest of
    /// `ClusterState` and are unused today; they leave room for a further
    /// rule without a signature change.
    pub fn merge_proposal_eligible(
        &self,
        peer_info: &ClusterInfo,
        _now: Timestamp,
        _config: &ClusterConfig,
    ) -> bool {
        if peer_info.id == self.id {
            return false;
        }
        if self.pending_split.is_some() {
            return false;
        }
        if self.pending_merge.is_some() {
            return false;
        }
        if self.incoming_merge.is_some() {
            return false;
        }
        true
    }

    /// Start a pending merge proposal to `target`. Idempotent while a
    /// proposal is outstanding: returns `false` and leaves the existing
    /// proposal in place.
    pub fn start_merge_proposal(&mut self, target: ClusterId, now: Timestamp) -> bool {
        if self.pending_merge.is_some() {
            return false;
        }
        self.pending_merge = Some(PendingMerge {
            target,
            proposed_at: now,
        });
        true
    }

    /// Whether the outgoing pending merge has had its full
    /// [`MERGE_PROPOSAL_TIMEOUT_S`] to settle.
    pub fn pending_merge_settled(&self, now: Timestamp) -> bool {
        match self.pending_merge {
            None => false,
            Some(p) => {
                now.as_secs().saturating_sub(p.proposed_at.as_secs()) >= MERGE_PROPOSAL_TIMEOUT_S
            }
        }
    }

    /// Decide the outgoing pending merge. On accept, records the
    /// completion; on reject or timeout, clears the pending state and
    /// does not retry within the same episode. Returns the larger
    /// cluster id on accept, `None` otherwise.
    ///
    /// Acceptance is immediate, so the timestamp is not consulted.
    pub fn note_merge_result(&mut self, accepted: bool, _now: Timestamp) -> Option<ClusterId> {
        let pending = self.pending_merge.take()?;
        if accepted {
            Some(pending.target)
        } else {
            None
        }
    }

    /// Record an incoming proposal from `proposer_id`.
    ///
    /// The acceptor holds one slot, so a second proposal displaces the
    /// first. Returns `true` if the slot was empty (nothing displaced)
    /// and `false` if a prior proposal was replaced.
    pub fn note_incoming_merge(
        &mut self,
        proposer_id: NodeId,
        proposer_cluster_id: ClusterId,
        proposed_at: Timestamp,
    ) -> bool {
        let was_empty = self.incoming_merge.is_none();
        self.incoming_merge = Some(PendingMergeIncoming {
            proposer_id,
            proposer_cluster_id,
            proposed_at,
        });
        was_empty
    }

    /// Clear the incoming proposal slot; called when the coordinator has
    /// sent an accept or a reject for it.
    pub fn clear_incoming_merge(&mut self) {
        self.incoming_merge = None;
    }

    // ---------------------------------------------------------------------
    // Split decision (§13.5)
    // ---------------------------------------------------------------------

    /// Record the current 90th-percentile RTT of the cluster.
    ///
    /// If the observation is within threshold, the "over-threshold since"
    /// timer is cleared. Otherwise, it is started on the first
    /// observation that crosses the threshold and left running.
    pub fn note_rtt_observation(
        &mut self,
        rtt_90_percentile_ms: u64,
        now: Timestamp,
        config: &ClusterConfig,
    ) {
        if rtt_90_percentile_ms <= config.rtt_threshold_ms {
            self.rtt_exceeded_since = None;
        } else if self.rtt_exceeded_since.is_none() {
            self.rtt_exceeded_since = Some(now);
        }
    }

    /// True if the cluster has been above its RTT threshold for longer
    /// than `config.heartbeat_s * 3` (§13.5).
    pub fn should_split(&self, now: Timestamp, config: &ClusterConfig) -> bool {
        let Some(since) = self.rtt_exceeded_since else {
            return false;
        };
        let elapsed_s = now.as_secs().saturating_sub(since.as_secs());
        elapsed_s > config.heartbeat_s.saturating_mul(3)
    }

    /// Choose which cluster to join when splitting (§13.5).
    ///
    /// The two `*_acceptable` arguments are the caller's verdicts on
    /// whether each candidate cluster passed its own acceptance test
    /// (§13.2). Combining both decisions in one call keeps this method
    /// pure.
    pub fn choose_split_target(
        &self,
        rtt_to_center_ms: u64,
        near_acceptable: bool,
        far_acceptable: bool,
        config: &ClusterConfig,
    ) -> SplitAction {
        if rtt_to_center_ms <= config.rtt_threshold_ms && near_acceptable {
            SplitAction::JoinNear
        } else if far_acceptable {
            SplitAction::JoinFar
        } else {
            SplitAction::CreateNew
        }
    }

    /// Move this node to a different cluster (§13.5).
    ///
    /// A new id and creation time; the member count resets to this node
    /// alone; the coordinator is cleared, because a coordinator elected
    /// by the old cluster does not lead the new one; and the RTT timer
    /// resets, so the new cluster is not born already due to split.
    ///
    /// The split-attempt counter is deliberately **not** reset here, and
    /// the migration does not decide the attempt either. §13.5 makes the
    /// attempt *pending* from the move until the first eligible
    /// post-migration acceptance test — one taken at least
    /// `CLUSTER_HEARTBEAT` later, so a peer has had the chance to
    /// advertise the new id and the member set is non-empty. A pending
    /// attempt neither counts against the cap nor clears the counter.
    pub fn migrate(&mut self, new_id: ClusterId, now: Timestamp) {
        self.id = new_id;
        self.ctime = now;
        self.size = 1;
        self.coordinator = None;
        self.coordinator_since = now;
        self.rtt_exceeded_since = None;
        self.pending_split = Some(PendingSplit {
            migrated_at: now,
            new_id,
        });
    }

    /// Whether a split attempt is in flight (§13.5).
    pub fn split_attempt_pending(&self) -> bool {
        self.pending_split.is_some()
    }

    /// Whether the pending attempt has had a full heartbeat interval to
    /// settle, so a recompute may decide it.
    ///
    /// Before this is true the new cluster has had no opportunity to
    /// accumulate members: no peer has re-announced its cluster id yet,
    /// so a recompute would see an empty member set and call every
    /// attempt a failure by construction.
    pub fn pending_split_settled(&self, now: Timestamp, config: &ClusterConfig) -> bool {
        match self.pending_split {
            None => false,
            Some(p) => {
                let elapsed_ms = now.as_millis().saturating_sub(p.migrated_at.as_millis());
                elapsed_ms >= config.heartbeat_s.saturating_mul(1000)
            }
        }
    }

    /// Decide the pending attempt at the first eligible recompute
    /// (§13.5).
    ///
    /// Success clears the counter; failure increments it, which is what
    /// makes `MAX_SPLIT_ATTEMPTS` reachable. Either way the attempt
    /// stops being pending. Calling this with no attempt in flight is a
    /// no-op, so a caller that recomputes more often than once per
    /// heartbeat cannot decide the same attempt twice.
    pub fn note_split_outcome(&mut self, acceptable: bool, config: &ClusterConfig) {
        if self.pending_split.is_none() {
            return;
        }
        if acceptable {
            self.clear_split_attempts();
        } else {
            let _ = self.record_split_attempt(config);
        }
        self.pending_split = None;
    }

    /// Record a split attempt.
    ///
    /// Returns `Err(Error::Dht(_))` if `config.max_split_attempts` has
    /// been exceeded; the caller should then create a new cluster with a
    /// random ID instead of retrying.
    pub fn record_split_attempt(&mut self, config: &ClusterConfig) -> Result<()> {
        self.split_attempts = self.split_attempts.saturating_add(1);
        if self.split_attempts > config.max_split_attempts {
            return Err(Error::Dht("split attempt limit exceeded"));
        }
        Ok(())
    }

    /// Reset the split-attempt counter; called when a split succeeds.
    pub fn clear_split_attempts(&mut self) {
        self.split_attempts = 0;
    }
}

// -------------------------------------------------------------------------
// Size estimation (§13.6)
// -------------------------------------------------------------------------

/// Estimate a cluster's size from the average routing-table size (§13.6).
///
/// The spec formula is `size = 2^(average_routing_table_size)`. This
/// implementation accepts an integer average and truncates fractional
/// input, which is adequate for merge decisions — those only care about
/// log2 of the sizes.
pub fn estimate_size_from_routing_table(avg_routing_table_size: u64) -> u64 {
    1u64
        .checked_shl(avg_routing_table_size as u32)
        .unwrap_or(u64::MAX)
}

// -------------------------------------------------------------------------
// Internal arithmetic
// -------------------------------------------------------------------------

/// Compute `δ(now)` for the merge preference function (§13.4).
///
/// Returns 0 or 2, alternating every `config.merge_delta_interval_s`.
fn delta_for(now: Timestamp, config: &ClusterConfig) -> u64 {
    let interval = config.merge_delta_interval_s.max(1);
    let intervals = now.as_secs() / interval;
    if intervals % 2 == 0 {
        0
    } else {
        2
    }
}

/// True if `|log2(a) - log2(b)| > delta`.
///
/// Equivalent to `max(a,b) > min(a,b) * 2^delta`. Uses integer
/// arithmetic only; overflow on the `* 2^delta` step is treated as "not
/// exceeding", since the sizes are bounded by network scale.
fn log2_diff_exceeds(a: u64, b: u64, delta: u64) -> bool {
    let a = a.max(1);
    let b = b.max(1);
    if a == b {
        return false;
    }
    let (larger, smaller) = if a > b { (a, b) } else { (b, a) };
    let factor = 1u64.checked_shl(delta as u32).unwrap_or(u64::MAX);
    match smaller.checked_mul(factor) {
        Some(threshold) => larger > threshold,
        None => false,
    }
}

/// The `percentile`-th percentile of `values`, or `None` if empty.
///
/// Uses the nearest-rank method: sort ascending, then take the element
/// at index `ceil(percentile/100 * N) - 1`, clamped to `N - 1`.
///
/// Exposed for the node layer, which needs the raw percentile value to
/// feed [`ClusterState::note_rtt_observation`]; the boolean threshold
/// check [`ClusterState::is_acceptable`] performs is derived from it.
pub fn percentile(values: &[u64], percentile: u8) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let n = values.len() as u64;
    let p = percentile.min(100) as u64;
    let idx = (p * n).div_ceil(100)
        .saturating_sub(1)
        .min(n - 1) as usize;
    let mut sorted: Vec<u64> = values.to_vec();
    sorted.sort_unstable();
    Some(sorted[idx])
}

/// True if the `percentile`-th percentile of `values` is at most
/// `max_value`.
fn percentile_at_or_below(values: &[u64], percentile: u8, max_value: u64) -> bool {
    self::percentile(values, percentile)
        .map(|v| v <= max_value)
        .unwrap_or(false)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn cid(b: u8) -> ClusterId {
        [b; 16]
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn t(secs: u64) -> Timestamp {
        Timestamp::from_secs(secs)
    }

    fn local_config() -> ClusterConfig {
        ClusterConfig::for_level(ClusterLevel::Local)
    }

    fn info(id: u8, size: u64) -> ClusterInfo {
        ClusterInfo {
            id: cid(id),
            size,
            ctime: t(0),
        }
    }

    // ---- level ----

    #[test]
    fn level_discriminants_match_spec() {
        assert_eq!(ClusterLevel::Global as u8, 0);
        assert_eq!(ClusterLevel::Regional as u8, 1);
        assert_eq!(ClusterLevel::Local as u8, 2);
    }

    #[test]
    fn level_default_thresholds() {
        assert_eq!(ClusterLevel::Local.default_rtt_threshold_ms(), 30);
        assert_eq!(ClusterLevel::Regional.default_rtt_threshold_ms(), 100);
        assert_eq!(ClusterLevel::Global.default_rtt_threshold_ms(), u64::MAX);
    }

    #[test]
    fn level_transitions() {
        assert_eq!(
            ClusterLevel::Global.more_specific(),
            Some(ClusterLevel::Regional)
        );
        assert_eq!(
            ClusterLevel::Regional.more_specific(),
            Some(ClusterLevel::Local)
        );
        assert_eq!(ClusterLevel::Local.more_specific(), None);

        assert_eq!(ClusterLevel::Local.less_specific(), Some(ClusterLevel::Regional));
        assert_eq!(ClusterLevel::Global.less_specific(), None);
    }

    // ---- constructor ----

    #[test]
    fn new_cluster_starts_with_one_member() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(1000));
        assert_eq!(c.id, cid(1));
        assert_eq!(c.level, ClusterLevel::Local);
        assert_eq!(c.size, 1);
        assert_eq!(c.ctime, t(1000));
        assert_eq!(c.coordinator, None);
        assert_eq!(c.rtt_exceeded_since, None);
        assert_eq!(c.split_attempts, 0);
    }

    // ---- liveness ----

    #[test]
    fn heartbeat_expires_after_interval() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_heartbeat(t(0));
        assert!(!c.heartbeat_expired(t(60), &cfg), "at the interval, not yet");
        assert!(c.heartbeat_expired(t(61), &cfg), "past the interval, expired");

        c.note_heartbeat(t(100));
        assert!(!c.heartbeat_expired(t(150), &cfg));
    }

    #[test]
    fn coordinator_rotation_due_at_interval() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.elect_coordinator(nid(1), t(0));
        assert!(!c.coordinator_rotation_due(t(86_399), &cfg));
        assert!(c.coordinator_rotation_due(t(86_400), &cfg));
    }

    #[test]
    fn elect_coordinator_resets_term() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        c.elect_coordinator(nid(1), t(0));
        c.elect_coordinator(nid(2), t(50_000));
        assert_eq!(c.coordinator, Some(nid(2)));
        assert_eq!(c.coordinator_since, t(50_000));
    }

    // ---- acceptance ----

    #[test]
    fn acceptance_rejects_too_few_samples() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        let samples = vec![10u64; 19];
        assert!(!c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn acceptance_accepts_all_within_threshold() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        let samples = vec![20u64; 20];
        assert!(c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn acceptance_rejects_when_p90_above_threshold() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        // 20 samples: three above 30ms. The 90th percentile of 20
        // items is index 17 (0-based, nearest-rank), which is the 18th
        // item — the first of the three outliers.
        let mut samples = vec![10u64; 17];
        samples.extend_from_slice(&[100, 100, 100]);
        assert_eq!(samples.len(), 20);
        assert!(!c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn acceptance_accepts_when_only_far_outliers() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        // Two outliers at the top; the 90th percentile falls below them.
        let mut samples = vec![10u64; 18];
        samples.extend_from_slice(&[100, 100]);
        assert_eq!(samples.len(), 20);
        assert!(c.is_acceptable(&samples, &cfg));
    }

    #[test]
    fn percentile_math_20_samples() {
        // 20 items ascending 1..=20. p90 should be 18.
        let values: Vec<u64> = (1..=20).collect();
        assert!(percentile_at_or_below(&values, 90, 18));
        assert!(!percentile_at_or_below(&values, 90, 17));
    }

    #[test]
    fn percentile_math_100_samples() {
        // 100 items ascending 1..=100. p90 should be 90.
        let values: Vec<u64> = (1..=100).collect();
        assert!(percentile_at_or_below(&values, 90, 90));
        assert!(!percentile_at_or_below(&values, 90, 89));
    }

    // ---- merge ----

    #[test]
    fn merge_same_id_stays() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        let other = info(1, 100); // same id
        assert_eq!(c.should_merge(&other, t(0), &cfg), MergeDecision::Stay);
    }

    #[test]
    fn merge_to_larger_when_delta_zero() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(10);
        let cfg = local_config();
        // Pick `now` inside an even interval so δ = 0.
        let now = Timestamp::from_secs(0);
        let other = info(1, 100);
        // log2(100) - log2(10) ≈ 3.3 > 0, so merge to the larger.
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);
    }

    #[test]
    fn merge_stays_when_own_size_larger() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(100);
        let cfg = local_config();
        let now = Timestamp::from_secs(0);
        let other = info(1, 10);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Stay);
    }

    #[test]
    fn merge_tie_break_lower_cluster_id_wins() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(100);
        let cfg = local_config();
        // δ = 2 during odd intervals; use a time inside one.
        let now = Timestamp::from_secs(3600); // interval 1, δ = 2
        let other = info(1, 100); // same size, lower id
        // |log2(100) - log2(100)| = 0, not > 2; tie-break to lower id.
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);

        let other = info(99, 100); // same size, higher id
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Stay);
    }

    #[test]
    fn merge_delta_two_requires_size_ratio_greater_than_four() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(10);
        let cfg = local_config();
        let now = Timestamp::from_secs(3600); // δ = 2

        // Ratio 3:1 (below δ=2 threshold), other has higher id: the
        // ratio rule doesn't fire, and the tie-break (lower id wins)
        // says stay.
        let other = info(99, 30);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Stay);

        // Ratio 3:1, other has lower id: the tie-break fires and says
        // merge, even though the sizes are within δ.
        let other = info(1, 30);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);

        // Ratio 5:1 exceeds 2^δ = 4: the size rule fires and says
        // merge regardless of id.
        let other = info(99, 50);
        assert_eq!(c.should_merge(&other, now, &cfg), MergeDecision::Merge);
    }

    // ---- merge lifecycle (§2a, §2b, §2c of the merge note) ----

    /// §2a rule 1 is the δ rule, not a literal 1/4 check.
    ///
    /// 5 members against 19: `5 * 4 = 20 > 19`, so a literal 1/4 test
    /// would refuse at every δ. At δ=2 the δ rule refuses too
    /// (`log2(19/5) ≈ 1.93 < 2`), and at δ=0 it accepts, because the
    /// tested function is authoritative. The two outcomes together are
    /// what distinguishes the δ rule from a separate floor.
    #[test]
    fn merge_requires_the_size_condition() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        c.update_size(5);
        let cfg = local_config();

        let delta_two = t(3600); // odd interval: δ = 2
        let other = info(99, 19); // higher id, so the tie-break says stay
        assert_eq!(
            c.should_merge(&other, delta_two, &cfg),
            MergeDecision::Stay,
            "log2(19/5) is below δ=2, and the tie-break favours the lower id"
        );

        let delta_zero = t(0); // even interval: δ = 0
        assert_eq!(
            c.should_merge(&other, delta_zero, &cfg),
            MergeDecision::Merge,
            "at δ=0 the same pair merges: the δ rule is the check, not 5 * 4 <= 19"
        );
    }

    /// §2a rule 2: the RTT sample floor.
    ///
    /// The floor lives in [`ClusterState::is_acceptable`], which is where
    /// the §13.2 acceptance test is. `merge_proposal_eligible` takes no
    /// samples, so it cannot express rule 2 — the caller evaluates the p90
    /// pair with the measurements in hand. This test pins the floor where
    /// it actually is and records that boundary.
    #[test]
    fn merge_requires_enough_rtt_samples() {
        let c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        let cfg = local_config();

        let short = [10u64; ACCEPTANCE_MIN_SAMPLES - 1];
        let exact = [10u64; ACCEPTANCE_MIN_SAMPLES];
        assert!(
            !c.is_acceptable(&short, &cfg),
            "one sample below the floor is not acceptable in either direction"
        );
        assert!(c.is_acceptable(&exact, &cfg), "at the floor");

        // Eligibility has no sample input, so a peer that fails rule 2 is
        // still "eligible" here; rule 2 is the caller's check.
        assert!(c.merge_proposal_eligible(&info(1, 100), t(0), &cfg));
    }

    /// §2a rule 3: a cluster in the middle of a split episode does not
    /// start a merge.
    #[test]
    fn merge_rejected_when_pending_split() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.pending_split = Some(PendingSplit {
            migrated_at: t(0),
            new_id: cid(7),
        });

        assert!(!c.merge_proposal_eligible(&info(1, 100), t(1), &cfg));

        // A caller that gates on eligibility never reaches the setter.
        if c.merge_proposal_eligible(&info(1, 100), t(1), &cfg) {
            c.start_merge_proposal(cid(1), t(1));
        }
        assert!(
            c.pending_merge.is_none(),
            "no proposal is started while a split is in flight"
        );
    }

    #[test]
    fn merge_wire_roundtrips() {
        let p = ClusterMergePropose {
            proposer_cluster_id: cid(0x22),
            proposer_size: 5,
            proposed_at: t(10),
            signature: [0xaa; 64],
        };
        let bytes = p.to_bytes().unwrap();
        assert_eq!(ClusterMergePropose::from_bytes(&bytes).unwrap(), p);

        let a = ClusterMergeAccept {
            accept_cluster_id: cid(0x33),
            accept_size: 19,
            accepted_at: t(11),
            signature: [0xbb; 64],
        };
        let bytes = a.to_bytes().unwrap();
        assert_eq!(ClusterMergeAccept::from_bytes(&bytes).unwrap(), a);

        let r = ClusterMergeReject {
            proposer_cluster_id: cid(0x22),
            reason: MergeRejectReason::Busy,
            rejected_at: t(12),
            signature: [0xcc; 64],
        };
        let bytes = r.to_bytes().unwrap();
        assert_eq!(ClusterMergeReject::from_bytes(&bytes).unwrap(), r);

        // All three are control-tier messages.
        assert_eq!(
            crate::message::Message::ClusterMergePropose(p.clone()).required_tier(),
            crate::frame::Tier::Ctrl
        );
        assert_eq!(
            crate::message::Message::ClusterMergeAccept(a.clone()).required_tier(),
            crate::frame::Tier::Ctrl
        );
        assert_eq!(
            crate::message::Message::ClusterMergeReject(r.clone()).required_tier(),
            crate::frame::Tier::Ctrl
        );

        // The verb is checked, not ignored.
        let foreign = envelope("coral_lookup", alloc::vec![CborValue::Int(1)]);
        let encoded = encode(&foreign).unwrap();
        assert!(ClusterMergePropose::from_bytes(&encoded).is_err());
        assert!(ClusterMergeAccept::from_bytes(&encoded).is_err());
        assert!(ClusterMergeReject::from_bytes(&encoded).is_err());

        // Arity is enforced.
        let short = envelope(
            "cluster_merge_propose",
            alloc::vec![CborValue::Bytes(cid(1).to_vec())],
        );
        assert!(ClusterMergePropose::from_bytes(&encode(&short).unwrap()).is_err());

        // An unassigned reason code is refused rather than defaulted.
        let bad_reason = envelope(
            "cluster_merge_reject",
            alloc::vec![
                CborValue::Bytes(cid(1).to_vec()),
                CborValue::Int(9),
                CborValue::Int(0),
                CborValue::Bytes([0u8; 64].to_vec()),
            ],
        );
        assert!(ClusterMergeReject::from_bytes(&encode(&bad_reason).unwrap()).is_err());
    }

    #[test]
    fn note_merge_result_clears_pending() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));

        assert!(c.start_merge_proposal(cid(1), t(0)));
        assert!(
            !c.start_merge_proposal(cid(2), t(1)),
            "a second proposal is refused while one is outstanding"
        );

        // §2d's timeout is three heartbeats.
        assert!(!c.pending_merge_settled(t(MERGE_PROPOSAL_TIMEOUT_S - 1)));
        assert!(c.pending_merge_settled(t(MERGE_PROPOSAL_TIMEOUT_S)));

        assert_eq!(c.note_merge_result(false, t(5)), None);
        assert!(
            c.pending_merge.is_none(),
            "a rejection clears the pending state"
        );

        // Not retried within the same episode: a second result is a no-op.
        assert_eq!(c.note_merge_result(true, t(6)), None);
        assert!(c.pending_merge.is_none());
    }

    #[test]
    fn note_merge_result_on_accept_returns_the_larger_id() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));
        assert!(c.start_merge_proposal(cid(1), t(0)));

        assert_eq!(c.note_merge_result(true, t(1)), Some(cid(1)));
        assert!(
            c.pending_merge.is_none(),
            "acceptance concludes the episode"
        );
    }

    #[test]
    fn incoming_merge_slot_replaces_a_prior_proposal() {
        let mut c = ClusterState::new(cid(9), ClusterLevel::Local, t(0));

        assert!(
            c.note_incoming_merge(nid(1), cid(0x21), t(10)),
            "the first proposal finds the slot empty"
        );
        assert!(
            !c.note_incoming_merge(nid(2), cid(0x22), t(20)),
            "the second displaces the first"
        );

        let slot = c.incoming_merge.expect("a proposal is recorded");
        assert_eq!(slot.proposer_id, nid(2));
        assert_eq!(slot.proposer_cluster_id, cid(0x22));
        assert_eq!(slot.proposed_at, t(20));

        c.clear_incoming_merge();
        assert!(c.incoming_merge.is_none());
    }

    #[test]
    fn delta_for_flips_every_interval() {
        let cfg = local_config();
        assert_eq!(delta_for(t(0), &cfg), 0);
        assert_eq!(delta_for(t(3599), &cfg), 0);
        assert_eq!(delta_for(t(3600), &cfg), 2);
        assert_eq!(delta_for(t(7199), &cfg), 2);
        assert_eq!(delta_for(t(7200), &cfg), 0);
    }

    // ---- split ----

    #[test]
    fn split_not_triggered_within_threshold() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(20, t(0), &cfg);
        assert!(c.rtt_exceeded_since.is_none());
        assert!(!c.should_split(t(10_000), &cfg));
    }

    #[test]
    fn split_not_triggered_after_two_heartbeats() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(100, t(0), &cfg);
        assert_eq!(c.rtt_exceeded_since, Some(t(0)));
        // 3 heartbeats = 180s; 120s < 180s.
        assert!(!c.should_split(t(120), &cfg));
    }

    #[test]
    fn split_triggered_after_three_heartbeats() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(100, t(0), &cfg);
        assert!(c.should_split(t(181), &cfg));
    }

    #[test]
    fn recovery_clears_over_threshold_timer() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        c.note_rtt_observation(100, t(0), &cfg);
        c.note_rtt_observation(20, t(100), &cfg);
        assert!(c.rtt_exceeded_since.is_none());
        assert!(!c.should_split(t(1000), &cfg));
    }

    #[test]
    fn choose_split_target_prefers_near_when_rtt_ok() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        assert_eq!(
            c.choose_split_target(20, true, true, &cfg),
            SplitAction::JoinNear,
        );
    }

    #[test]
    fn choose_split_target_falls_back_to_far() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        // RTT to near center is above threshold; far is acceptable.
        assert_eq!(
            c.choose_split_target(200, true, true, &cfg),
            SplitAction::JoinFar,
        );
        // Near refuses on policy grounds even with good RTT.
        assert_eq!(
            c.choose_split_target(20, false, true, &cfg),
            SplitAction::JoinFar,
        );
    }

    #[test]
    fn choose_split_target_creates_new_when_both_reject() {
        let c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        assert_eq!(
            c.choose_split_target(200, false, false, &cfg),
            SplitAction::CreateNew,
        );
    }

    #[test]
    fn record_split_attempt_errors_at_limit() {
        let mut c = ClusterState::new(cid(1), ClusterLevel::Local, t(0));
        let cfg = local_config();
        assert!(c.record_split_attempt(&cfg).is_ok()); // 1
        assert!(c.record_split_attempt(&cfg).is_ok()); // 2
        assert!(c.record_split_attempt(&cfg).is_ok()); // 3
        assert!(c.record_split_attempt(&cfg).is_err()); // 4 > max
        c.clear_split_attempts();
        assert!(c.record_split_attempt(&cfg).is_ok());
    }

    // ---- size estimation ----

    #[test]
    fn estimate_size_from_routing_table_basic() {
        assert_eq!(estimate_size_from_routing_table(0), 1);
        assert_eq!(estimate_size_from_routing_table(1), 2);
        assert_eq!(estimate_size_from_routing_table(10), 1024);
    }

    #[test]
    fn estimate_size_from_routing_table_saturates() {
        assert_eq!(estimate_size_from_routing_table(64), u64::MAX);
        assert_eq!(estimate_size_from_routing_table(1000), u64::MAX);
    }

#[cfg(test)]
mod cluster_info_wire_tests {
    use super::*;

    #[cfg(feature = "crypto")]
    use quip_core::messages::Signer;

    fn cid(b: u8) -> ClusterId {
        [b; 16]
    }

    fn sample() -> ClusterInfo {
        ClusterInfo {
            id: cid(0x33),
            size: 42,
            ctime: Timestamp::from_secs(1_000),
        }
    }

    #[test]
    fn roundtrips_and_rejects_other_verbs() {
        let a = ClusterInfoAnnounce {
            info: sample(),
            signature: [9u8; 64],
        };
        let bytes = a.to_bytes().unwrap();
        assert_eq!(ClusterInfoAnnounce::from_bytes(&bytes).unwrap(), a);

        // The verb is checked, not ignored: a `cluster_info` decoder given
        // a `coral_lookup` frame must refuse it rather than read fields
        // positionally out of a foreign message.
        let foreign = envelope("coral_lookup", alloc::vec![CborValue::Int(1)]);
        let encoded = encode(&foreign).unwrap();
        assert!(ClusterInfoAnnounce::from_bytes(&encoded).is_err());
    }

    #[test]
    fn arity_is_enforced() {
        let short = envelope(
            "cluster_info",
            alloc::vec![CborValue::Bytes(cid(1).to_vec())],
        );
        let encoded = encode(&short).unwrap();
        assert!(ClusterInfoAnnounce::from_bytes(&encoded).is_err());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn signature_verifies_against_the_sender_only() {
        use crate::crypto::{Ed25519Signer, Ed25519Verifier};

        let signer = Ed25519Signer::from_seed(&[7u8; 32]);
        let sender: NodeId = signer.public_key();
        let mut a = ClusterInfoAnnounce {
            info: sample(),
            signature: [0u8; 64],
        };
        a.signature = signer.sign_ed25519(&a.signing_payload().unwrap());
        let v = Ed25519Verifier;

        assert!(a.verify(&sender, &v).unwrap(), "authentic sender verifies");

        // A different node cannot announce on the signer's behalf: the
        // payload carries no node id, so the id must come from the
        // authenticated connection and be part of the check.
        let mut other: NodeId = sender;
        other[0] ^= 0xff;
        assert!(!a.verify(&other, &v).unwrap(), "wrong sender must not verify");

        // Any field the signature covers is covered in fact.
        let mut tampered = a.clone();
        tampered.info.size = 43;
        assert!(!tampered.verify(&sender, &v).unwrap());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn signing_payload_excludes_signature() {
        use crate::crypto::Ed25519Signer;

        let signer = Ed25519Signer::from_seed(&[3u8; 32]);
        let mut a = ClusterInfoAnnounce {
            info: sample(),
            signature: [0u8; 64],
        };
        let payload = a.signing_payload().unwrap();
        a.signature = signer.sign_ed25519(&payload);
        assert_eq!(
            a.signing_payload().unwrap(),
            payload,
            "signing the payload must not change it"
        );
    }
}

}

#[cfg(test)]
mod split_id_tests {
    use super::*;

    fn cid(b: u8) -> ClusterId {
        [b; 16]
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn near_is_sha256_truncated_and_far_flips_bit_zero() {
        let id = cid(0x21);
        let near = near_cluster_id(&id);
        let far = far_cluster_id(&id);

        // Positive assertion, not `near != id`: the test is meaningful
        // only if it pins the derivation to the hash it claims to use.
        let digest = crate::crypto::sha256_bytes(&id);
        assert_eq!(near, digest[..16], "near is hash(cid)[..16]");
        assert_ne!(near, id, "the derivation actually moves the id");

        assert_eq!(far[1..], near[1..], "only the first byte differs");
        assert_eq!(near[0] ^ far[0], 0x01, "exactly bit 0 is flipped");
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn center_key_is_the_hash_of_the_near_id() {
        let id = cid(0x42);
        assert_eq!(
            center_lookup_key(&id),
            crate::crypto::sha256_bytes(&near_cluster_id(&id)),
            "the lookup key is hash(cid^N), not cid^N"
        );
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn fresh_id_depends_on_node_time_and_attempts() {
        let node = [7u8; 32];
        let a = fresh_cluster_id(&node, Timestamp::from_millis(1_000), 1);
        assert_eq!(a, fresh_cluster_id(&node, Timestamp::from_millis(1_000), 1));

        assert_ne!(a, fresh_cluster_id(&node, Timestamp::from_millis(1_001), 1));
        assert_ne!(a, fresh_cluster_id(&node, Timestamp::from_millis(1_000), 2));
        assert_ne!(
            a,
            fresh_cluster_id(&[8u8; 32], Timestamp::from_millis(1_000), 1)
        );
    }

    #[test]
    fn migrate_preserves_the_attempt_counter() {
        let cfg = ClusterConfig::for_level(ClusterLevel::Local);
        let mut c = ClusterState::new(cid(1), cfg.level, Timestamp::from_secs(0));
        c.update_size(40);
        c.elect_coordinator([9u8; 32], Timestamp::from_secs(0));
        c.note_rtt_observation(200, Timestamp::from_secs(0), &cfg);
        c.split_attempts = 2;

        c.migrate(cid(2), Timestamp::from_secs(500));

        assert_eq!(c.id, cid(2));
        assert_eq!(c.ctime, Timestamp::from_secs(500));
        assert_eq!(c.size, 1, "a migrated cluster starts alone");
        assert_eq!(c.coordinator, None, "the old coordinator does not lead");
        assert_eq!(
            c.rtt_exceeded_since, None,
            "the new cluster is not born due to split"
        );
        assert_eq!(
            c.split_attempts, 2,
            "§13.5: the move is not the attempt's outcome; the caller resets it"
        );
    }

    #[test]
    fn consecutive_failures_reach_the_split_cap() {
        let cfg = ClusterConfig::for_level(ClusterLevel::Local);
        let mut c = ClusterState::new(cid(1), cfg.level, Timestamp::from_secs(0));

        for expected in 1..=cfg.max_split_attempts {
            c.record_split_attempt(&cfg).expect("under the cap");
            c.migrate(cid(expected as u8), Timestamp::from_secs(1));
            assert_eq!(c.split_attempts, expected, "failures accumulate");
        }

        assert!(
            c.record_split_attempt(&cfg).is_err(),
            "one more failure is past the cap: the node must create a new cluster"
        );
    }
}
