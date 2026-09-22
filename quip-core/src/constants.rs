//! Protocol constants.
//!
//! Values are organized by the spec section that defines them. Anything in a
//! submodule here is normative: implementations MUST NOT change it. Values
//! that are RECOMMENDED defaults (rather than fixed) carry a note in their
//! doc comment.
//!
//! Transport-local implementation choices (stream IDs, per-tier stream caps,
//! handshake timeouts, MTU bounds) live in `quip-net::constants` instead.
//!
//! # Naming
//!
//! Time-valued constants carry their unit in the name (`_MS`, `_S`) to
//! prevent millisecond/second confusion — the spec mixes both.
//!
//! # Backward compatibility
//!
//! Every submodule's contents are glob re-exported at the top level, so
//! `quip_core::constants::WITNESS_COUNT` and
//! `quip_core::constants::witness::WITNESS_COUNT` both resolve. New code
//! SHOULD prefer the sectioned path.

// -------------------------------------------------------------------------
// §3, §10, §11 — wire identity and framing
// -------------------------------------------------------------------------

/// Wire-level protocol identity and framing constants.
pub mod wire {
    /// Wire protocol version.
    pub const PROTOCOL_VERSION: u8 = 1;

    /// ALPN identifier for QUIP over QUIC.
    pub const ALPN_QUIP: &[u8] = b"quip";

    /// Prefix string required as the first element of every QUIP message.
    pub const MSG_PREFIX: &str = "quip-v1";

    /// Maximum size of a single QUIP-CBOR message, in bytes.
    pub const MAX_MESSAGE_SIZE: usize = 65_536;
}

// -------------------------------------------------------------------------
// §5.2, §5.3.6 — Dotted Version Vectors
// -------------------------------------------------------------------------

/// Dotted Version Vector constants (spec §5.2 and §5.3.6).
pub mod dvv {
    /// Sentinel counter for pruned writers (`0xFFFFFFFF`).
    pub const INF: u64 = 0xFFFF_FFFF;

    /// Maximum number of `deps` entries before pruning triggers.
    ///
    /// Implementation choice, not spec-mandated. Deliberately distinct from
    /// `MAX_RANGES` even though both equal 1024.
    pub const MAX_DEPENDENCIES: usize = 1024;

    /// Replay window for `seq_reset` timestamps, in milliseconds.
    pub const MAX_REPLAY_WINDOW_MS: u64 = 300_000; // 5 minutes
}

// -------------------------------------------------------------------------
// §5.3.2, §5.3.3 — Witness ring
// -------------------------------------------------------------------------

/// Witness ring selection and validity (spec §5.3.2, §5.3.3).
pub mod witness {
    /// Number of witnesses in a ring (`3f + 1` with `f = 2`).
    pub const WITNESS_COUNT: usize = 7;

    /// Minimum number of witnesses required to form a ring.
    pub const MIN_WITNESSES: usize = 4;

    /// Full BFT quorum (5 of 7).
    pub const QUORUM: usize = 5;

    /// Degraded-mode quorum (3 of 4).
    pub const DEGRADED_QUORUM: usize = 3;

    /// Below this count, force ring rotation.
    pub const MIN_ACTIVE_WITNESSES: usize = 3;

    /// Witness ring rotation interval, in seconds.
    pub const ROTATION_INTERVAL_S: u64 = 86_400; // 24 hours

    /// Witness statement validity period, in seconds.
    pub const WITNESS_VALIDITY_S: u64 = 86_400; // 24 hours
}

// -------------------------------------------------------------------------
// §5.3.4 — BFT consensus
// -------------------------------------------------------------------------

/// BFT consensus and checkpointing (spec §5.3.4).
pub mod bft {
    /// Quorum size for view changes and checkpoints (5 of 7).
    pub const VIEW_CHANGE_QUORUM: usize = 5;

    /// Checkpoint every N consensus rounds.
    pub const CHECKPOINT_INTERVAL: u64 = 100;
}

// -------------------------------------------------------------------------
// §8.2 — Merkle range fetching
// -------------------------------------------------------------------------

/// Merkle range fetching constants (spec §8.2).
pub mod merkle {
    /// BLAKE3 chunk size, in bytes.
    ///
    /// BLAKE3's tree structure divides input into 1024-byte chunks; the
    /// spec adopts this value verbatim rather than redefining it.
    pub const BLAKE3_CHUNK_SIZE: usize = 1_024;

    /// Maximum byte range a peer will serve in one `fetch_range` response.
    ///
    /// Bounds the memory cost of a single response and the client-side
    /// buffer needed to receive it. Peers MAY negotiate a larger value
    /// via the `max_range_length` handshake extension (0x0C).
    pub const MAX_RANGE_LENGTH: u64 = 1_048_576;
}

// -------------------------------------------------------------------------
// §12 — NAT traversal
// -------------------------------------------------------------------------

/// NAT traversal (spec §12).
pub mod nat {
    /// Relay table capacity.
    pub const RELAY_CAPACITY: usize = 1000;

    /// Maximum relay hops per path.
    pub const RELAY_HOP_LIMIT: u8 = 2;

    /// Lifetime of a `connectivity_announce` record, in seconds.
    pub const CONNECTIVITY_TTL_S: u64 = 600;

    /// Candidate lifetime, in seconds.
    pub const CANDIDATE_TTL_S: u64 = 30;
}

// -------------------------------------------------------------------------
// §13 — Coral DHT
// -------------------------------------------------------------------------

/// Coral DHT (spec §13).
pub mod coral {
    /// Independent lookup paths per key.
    pub const LOOKUP_PATHS: usize = 3;

    /// Paths that must agree for consensus.
    pub const SPILLOVER_THRESHOLD: usize = 2;

    /// Spillover response cache TTL, in seconds.
    pub const SPILLOVER_CACHE_TTL_S: u64 = 300;

    /// Number of hierarchical cluster levels.
    pub const CLUSTER_LEVELS: usize = 3;

    /// Maximum nodes per cluster.
    pub const MAX_CLUSTER_SIZE: usize = 256;

    /// Minimum nodes for cluster viability.
    pub const MIN_CLUSTER_SIZE: usize = 16;

    /// Cluster heartbeat interval, in seconds.
    pub const CLUSTER_HEARTBEAT_S: u64 = 60;

    /// Coordinator rotation interval, in seconds.
    pub const COORDINATOR_INTERVAL_S: u64 = 86_400;

    /// Latency percentile for cluster acceptance, as a whole percentage.
    pub const CLUSTER_ACCEPTANCE_PERCENTILE: u8 = 90;

    /// Interval between merge-delta preference flips, in seconds.
    pub const MERGE_DELTA_INTERVAL_S: u64 = 3_600;

    /// Maximum split attempts before creating a new cluster.
    pub const MAX_SPLIT_ATTEMPTS: u32 = 3;

    /// Gateway routers consulted during cluster discovery.
    pub const GATEWAY_ROUTER_COUNT: usize = 5;

    /// Local cluster RTT threshold, in milliseconds.
    pub const RTT_LOCAL_MS: u64 = 30;

    /// Regional cluster RTT threshold, in milliseconds.
    pub const RTT_REGIONAL_MS: u64 = 100;

    /// Global cluster RTT threshold, in milliseconds.
    ///
    /// The spec writes this as "∞"; `u64::MAX` is the wire-compatible
    /// sentinel for "no upper bound".
    pub const RTT_GLOBAL_MS: u64 = u64::MAX;
}

// -------------------------------------------------------------------------
// §14.2, App. A.5 — Pinning
// -------------------------------------------------------------------------

/// Resource pinning (spec §14.2, App. A.5).
pub mod pin {
    /// Maximum number of pinned resources per peer.
    pub const PIN_CAPACITY: usize = 1_000;

    /// Default TTL, in seconds, selected when a `pin` carries `ttl = 0`.
    ///
    /// Spec App. A.5: *"RECOMMENDED: 7 days / 604800 seconds."*
    pub const DEFAULT_PIN_TTL_S: u64 = 604_800;

    /// TTL sentinel meaning "store indefinitely".
    ///
    /// Spec §14.2: *"A TTL of 0xFFFFFFFF indicates indefinite storage
    /// (subject to capacity constraints)."*
    ///
    /// Coincidentally equal to [`dvv::INF`](crate::constants::dvv::INF), but deliberately defined
    /// independently: `INF` is the DVV pruning sentinel,
    /// `INDEFINITE_TTL_S` is the pin TTL sentinel, and they should not
    /// move together.
    pub const INDEFINITE_TTL_S: u64 = 0xFFFF_FFFF;

    /// Pin refresh threshold, as a whole percentage of the TTL.
    ///
    /// Spec App. A.5: *"Peers SHOULD refresh pins before TTL expiry
    /// (at 80% of TTL)."*
    pub const PIN_REFRESH_PERCENT: u64 = 80;
}

// -------------------------------------------------------------------------
// §7.1 — Content governance
// -------------------------------------------------------------------------

/// Content governance (spec §7.1).
pub mod governance {
    /// Maximum number of Trusted CID registrations per peer.
    pub const GOV_CAPACITY: usize = 100;
}

// -------------------------------------------------------------------------
// §14.2 — SYNC / RBSR
// -------------------------------------------------------------------------

/// SYNC-plane bounds (spec §14.2).
pub mod sync {
    /// Maximum number of ranges in a single RBSR request.
    pub const MAX_RANGES: usize = 1_024;
}

// -------------------------------------------------------------------------
// §14.5 — Resource discovery
// -------------------------------------------------------------------------

/// Resource discovery (spec §14.5).
pub mod resource {
    /// Maximum age of a `resource_announce` record, in seconds.
    pub const MAX_ANNOUNCEMENT_AGE_S: u64 = 86_400;
}

// -------------------------------------------------------------------------
// §14 — Verb strings for core-defined message types
// -------------------------------------------------------------------------

/// Verb strings for message types whose payloads are defined in `quip-core`.
///
/// Verbs whose codecs live in `quip-net` (`set`, `get`, `sync`, `emit`, …)
/// are not listed here; those belong to the crate that owns their codecs.
pub mod verbs {
    /// Verb for [`crate::messages::KeyClaim`].
    pub const VERB_KEY_CLAIM: &str = "key_claim";
    /// Verb for [`crate::messages::WitnessStatement`].
    pub const VERB_WITNESS: &str = "kt_witness";
    /// Verb for [`crate::messages::KeyRotation`].
    pub const VERB_ROTATION: &str = "key_rotation";
    /// Verb for [`crate::messages::RevocationNotice`].
    pub const VERB_REVOCATION: &str = "revocation";
    /// Verb for [`crate::messages::TrustedCidRegistration`].
    pub const VERB_REGISTER_TCID: &str = "register_tcid";
    /// Verb for [`crate::messages::QuarantineRequest`].
    pub const VERB_QUARANTINE: &str = "quarantine";
    /// Verb for [`crate::messages::QuarantineNotice`].
    pub const VERB_QUARANTINE_NOTICE: &str = "quarantine_notice";
    /// Verb for [`crate::messages::UnquarantineRequest`].
    pub const VERB_UNQUARANTINE: &str = "unquarantine";
    /// Verb for [`crate::messages::DerivativeLink`].
    pub const VERB_DERIVATIVE_LINK: &str = "derivative_link";
    /// Verb for [`crate::messages::DelegationCertificate`].
    pub const VERB_DELEGATION: &str = "delegation";
    /// Verb for [`crate::messages::SeqReset`].
    pub const VERB_SEQ_RESET: &str = "seq_reset";
    /// Verb for [`crate::messages::Discontinuity`].
    pub const VERB_IDENTITY_DISCONTINUITY: &str = "identity_discontinuity";
}

// -------------------------------------------------------------------------
// Top-level re-exports for backward compatibility.
//
// New code SHOULD prefer the sectioned paths above. These globs exist so
// existing callers (`crate::constants::INF`, `::WITNESS_COUNT`, …) keep
// compiling without change.
// -------------------------------------------------------------------------

pub use wire::*;
pub use dvv::*;
pub use witness::*;
pub use bft::*;
pub use nat::*;
pub use coral::*;
pub use pin::*;
pub use governance::*;
pub use sync::*;
pub use resource::*;
pub use verbs::*;
pub use merkle::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spec_derived_sentinels_are_stable() {
        assert_eq!(dvv::INF, 0xFFFF_FFFF);
        assert_eq!(pin::INDEFINITE_TTL_S, 0xFFFF_FFFF);
    }

    #[test]
    fn bit_sentinels_are_independent_despite_equal_value() {
        // Both are 0xFFFFFFFF, but they mean different things. If a future
        // spec change moves one, this test will fail and prompt a review.
        assert_eq!(dvv::INF, pin::INDEFINITE_TTL_S);
    }

    #[test]
    fn baseline_quorums() {
        assert_eq!(witness::WITNESS_COUNT, 7);
        assert_eq!(witness::QUORUM, 5);
        assert_eq!(witness::DEGRADED_QUORUM, 3);
        assert_eq!(bft::VIEW_CHANGE_QUORUM, witness::QUORUM);
    }

    #[test]
    fn top_level_glob_reexports_resolve() {
        // These are the names existing callers use; keep them live.
        assert_eq!(INF, dvv::INF);
        assert_eq!(WITNESS_COUNT, witness::WITNESS_COUNT);
        assert_eq!(MAX_MESSAGE_SIZE, wire::MAX_MESSAGE_SIZE);
        assert_eq!(LOOKUP_PATHS, coral::LOOKUP_PATHS);
        assert_eq!(RELAY_CAPACITY, nat::RELAY_CAPACITY);
        assert_eq!(CHECKPOINT_INTERVAL, bft::CHECKPOINT_INTERVAL);
        assert_eq!(PIN_CAPACITY, pin::PIN_CAPACITY);
        assert_eq!(DEFAULT_PIN_TTL_S, pin::DEFAULT_PIN_TTL_S);
        assert_eq!(INDEFINITE_TTL_S, pin::INDEFINITE_TTL_S);
    }

    #[test]
    fn merkle_constants_match_spec() {
        // Spec §3 and §8.2.
        assert_eq!(merkle::BLAKE3_CHUNK_SIZE, 1_024);
        assert_eq!(merkle::MAX_RANGE_LENGTH, 1_048_576);
    }
}