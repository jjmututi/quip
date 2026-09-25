//! Transport-layer constants.
//!
//! This file holds only **transport-local implementation choices** — values
//! the spec does not fix. Everything with a spec section number lives in
//! [`quip_core::constants`] and is re-exported below for source compatibility.
//!
//! # What belongs here
//!
//! - Stream IDs reserved by §11 (they are transport-local in practice: they
//!   name a QUIC primitive, not a protocol value).
//! - Per-tier backpressure caps (§12 recommends "explicit backpressure"; the
//!   numeric caps are our choice).
//! - MTU and buffer bounds.
//! - Handshake timeout.
//!
//! # What does NOT belong here
//!
//! Anything in the spec's §3 constants table. Those are re-exported from
//! [`quip_core::constants`] at the bottom of this file. Once callers have
//! migrated to the core path, the re-exports will be removed.

// -------------------------------------------------------------------------
// §11 — Reserved QUIC stream IDs
// -------------------------------------------------------------------------

/// QUIC stream carrying the handshake + CTRL verbs (spec §11).
///
/// Stream 0, client-initiated bidirectional.
pub const CTRL_STREAM_ID: u64 = 0;

/// QUIC stream carrying SYNC-plane verbs (spec §11).
///
/// Stream 4, client-initiated bidirectional.
pub const SYNC_STREAM_ID: u64 = 4;

/// First BULK stream ID (spec §11).
///
/// BULK uses 8, 12, 16, … — client-initiated bidirectional streams from 8
/// upward in steps of 4. `StreamId::kind()` in [`crate::frame`] enforces this.
pub const BULK_STREAM_BASE_ID: u64 = 8;

// -------------------------------------------------------------------------
// §12 — Backpressure caps
// -------------------------------------------------------------------------

/// Concurrent streams permitted on T0 (the Control Stream is singular).
pub const T0_MAX_STREAMS: usize = 1;

/// Concurrent SYNC (T1) streams per connection.
pub const T1_MAX_STREAMS: usize = 32;

/// Per-connection maximum number of concurrent BULK (T2) streams.
///
/// §19.4 "Operational Security Considerations" recommends 256.
pub const T2_MAX_STREAMS: usize = 256;

/// In-flight EVENT (T3) datagrams per connection.
pub const T3_MAX_DATAGRAMS: usize = 64;

// -------------------------------------------------------------------------
// Payload bounds — implementation choices
// -------------------------------------------------------------------------

/// Largest T3 datagram payload, in bytes.
///
/// T3 datagrams ride QUIC DATAGRAM frames whose MTU (~1200 B) is far below
/// the 64 KiB message cap, so EVENT payloads are bounded separately.
pub const MAX_DGRAM_BYTES: usize = 1_200;

/// Largest BULK `send_chunk` payload, in bytes (spec §14.3 chunk stream).
pub const MAX_CHUNK_BYTES: usize = 16_384;

// -------------------------------------------------------------------------
// Timing — implementation choices
// -------------------------------------------------------------------------

/// Handshake timeout, in milliseconds.
///
/// Implementation choice. The spec does not fix a handshake deadline.
pub const HANDSHAKE_TIMEOUT_MS: u64 = 10_000;

// -------------------------------------------------------------------------
// Re-exports from quip-core (spec-derived values)
//
// Kept for source compatibility while callers migrate. New code SHOULD use
// `quip_core::constants::*` directly.
// -------------------------------------------------------------------------

/// Wire protocol version (spec §3).
pub use quip_core::constants::PROTOCOL_VERSION;

/// ALPN identifier (spec §3).
pub use quip_core::constants::ALPN_QUIP;

/// Per-message cap (spec §3, §11).
pub use quip_core::constants::MAX_MESSAGE_SIZE;

/// RBSR range cap (spec §3, §14.2).
pub use quip_core::constants::MAX_RANGES;

/// Witness ring size (spec §5.3.2).
pub use quip_core::constants::WITNESS_COUNT;

/// Minimum witnesses to form a ring (spec §5.3.2).
pub use quip_core::constants::MIN_WITNESSES;

/// Full BFT quorum (spec §5.3.4).
pub use quip_core::constants::QUORUM;

/// Degraded-mode quorum (spec §5.3.4).
pub use quip_core::constants::DEGRADED_QUORUM;

/// Minimum active witnesses before forced rotation (spec §3).
pub use quip_core::constants::MIN_ACTIVE_WITNESSES;

/// BFT view-change quorum (spec §3, §5.3.4).
pub use quip_core::constants::VIEW_CHANGE_QUORUM;

/// BFT checkpoint interval (spec §3, §5.3.4).
pub use quip_core::constants::CHECKPOINT_INTERVAL;

/// Independent Coral lookup paths (spec §3, §13).
pub use quip_core::constants::LOOKUP_PATHS;

/// Coral spillover consensus threshold (spec §3, §13).
pub use quip_core::constants::SPILLOVER_THRESHOLD;

/// Coral spillover cache TTL, in seconds (spec §3, §13).
pub use quip_core::constants::SPILLOVER_CACHE_TTL_S;

/// Coral cluster hierarchy depth (spec §3, §13).
pub use quip_core::constants::CLUSTER_LEVELS;

/// Maximum nodes per cluster (spec §3, §13).
pub use quip_core::constants::MAX_CLUSTER_SIZE;

/// Minimum nodes per cluster (spec §3, §13).
pub use quip_core::constants::MIN_CLUSTER_SIZE;

/// Cluster heartbeat, in seconds (spec §3, §13).
pub use quip_core::constants::CLUSTER_HEARTBEAT_S;

/// Coordinator rotation interval, in seconds (spec §3, §13).
pub use quip_core::constants::COORDINATOR_INTERVAL_S;

/// Cluster acceptance percentile (spec §3, §13.2).
pub use quip_core::constants::CLUSTER_ACCEPTANCE_PERCENTILE;

/// Merge-delta preference interval, in seconds (spec §3, §13.4).
pub use quip_core::constants::MERGE_DELTA_INTERVAL_S;

/// Maximum split attempts (spec §3, §13.5).
pub use quip_core::constants::MAX_SPLIT_ATTEMPTS;

/// Gateway routers per discovery (spec §3, §13.3).
pub use quip_core::constants::GATEWAY_ROUTER_COUNT;

/// Relay table capacity (spec §3, §12).
pub use quip_core::constants::RELAY_CAPACITY;

/// Relay hop limit (spec §3, §12).
pub use quip_core::constants::RELAY_HOP_LIMIT;

/// Connectivity announcement TTL, in seconds (spec §3, §12).
pub use quip_core::constants::CONNECTIVITY_TTL_S;

/// Candidate TTL, in seconds (spec §12.3).
pub use quip_core::constants::CANDIDATE_TTL_S;

/// Local cluster RTT threshold, in milliseconds (spec §13).
pub use quip_core::constants::RTT_LOCAL_MS;

/// Regional cluster RTT threshold, in milliseconds (spec §13).
pub use quip_core::constants::RTT_REGIONAL_MS;

/// Global cluster RTT threshold, in milliseconds (spec §13).
pub use quip_core::constants::RTT_GLOBAL_MS;

// -------------------------------------------------------------------------
// Notes on removed names
//
// The following identifiers existed in earlier drafts of this file. They
// were removed because they duplicated a `quip-core` value or expressed no
// distinct concept. Callers should update:
//
// - `MAX_FRAME_BYTES`     -> `MAX_MESSAGE_SIZE` (they were aliases)
// - `MAX_BULK_STREAMS`    -> `T2_MAX_STREAMS` (duplicate)
// - `DEGRADED_RING_MIN`   -> `DEGRADED_QUORUM` (duplicate; spec uses
//                            "DEGRADED_QUORUM" for the same 3-of-4 quorum)
//
// `LOCAL_CLUSTER`, `REGIONAL_CLUSTER`, `GLOBAL_CLUSTER` moved to
// `crate::dht` as local discriminants — see the note there about the
// mismatch with the spec's level numbering.
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t2_max_streams_matches_section_19_4() {
        assert_eq!(T2_MAX_STREAMS, 256);
    }
}
