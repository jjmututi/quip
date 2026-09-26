//! # quip-net
//!
//! QUIP transport plane (draft-mututi-quip-03, §4, §6, §11–§15).
//!
//! `quip-core` owns the wire message types, `quip-storage` owns persistent
//! state; this crate owns everything that moves bytes between peers.
//!
//! ## Modules
//!
//! - [`frame`] — varint-length-prefixed framing and stream classification.
//! - [`handshake`] — ALPN + profile negotiation on the Control Stream.
//! - [`flow`] — BLOCK / UNBLOCK / WINDOW frames and per-stream state.
//! - [`conn`] — connection lifecycle and per-stream bookkeeping.
//! - [`message`] — the [`Message`] enum and [`dispatch`] router.
//! - [`sync`], [`bulk`], [`event`], [`resource`], [`query`] — verb codecs.
//! - [`sync_stream`] — T1 SYNC stream state machine (§11).
//! - [`nat`], [`dht`] — NAT traversal and Coral DHT state (M2, M3).
//! - [`rate`] — per-NodeId token-bucket rate limiter.
//! - [`backoff`] — per-key exponential backoff (§19.4).
//! - [`constants`] — transport-local constants plus core re-exports.
//! - [`error`] — transport error type with §15 wire-code mapping.
//! - [`clock`] — wall-clock helper (only with `std`).
//!
//! ## Optional features
//!
//! - `std` (default): wall-clock helpers + `alloc`.
//! - `crypto`: pluggable hash and Ed25519 back-ends.
//! - `quic`: the QUIC runtime binding (adds [`transport`]).
//! - `full`: enables both `crypto` and `quic`.
//!
//! ## Transport-agnostic design
//!
//! Like the rest of the workspace, this crate never touches a socket
//! unless the `quic` feature is enabled. Every time-dependent entry point
//! takes an explicit [`Timestamp`](quip_core::time::Timestamp) so
//! behaviour is deterministic and testable.
//!
//! ## Example
//!
//! The example below uses the transport-agnostic state machine, so it
//! runs without the `quic` feature:
//!
//! ```
//! use quip_core::time::Timestamp;
//! use quip_net::{Connection, QuipNetConfig};
//!
//! let mut conn = Connection::new_initiator(QuipNetConfig::default());
//! let hello = conn.handshake_bytes().unwrap(); // send on QUIC stream 0
//! assert!(Connection::is_quip_handshake(&hello));
//! let now = Timestamp::from_millis(1_700_000_000_000);
//! let action = conn.note_bytes_received(hello.len() as u64, now);
//! assert!(action.backpressure_applied());
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

extern crate alloc;

pub mod backoff;
pub mod bft;
pub mod bulk;
pub mod clock;
pub(crate) mod codec;
pub mod conn;
pub mod constants;
pub mod coral;
pub mod cluster;
pub mod dht;
pub mod discovery;
pub mod establishment;
pub mod error;
pub mod event;
pub mod flow;
pub mod frame;
pub mod handshake;
pub mod message;
pub mod nat;
pub mod nat_wire;
pub mod query;
pub mod range;
pub mod rate;
pub mod resource;
pub mod sync;
pub(crate) mod sync_codec;
pub mod sync_stream;

/// Optional crypto back-ends (§5 identities, App. A.3 hashing).
#[cfg(feature = "crypto")]
pub mod crypto;

/// Cached bao chunk trees for range responses (§8.2, App. A.4).
#[cfg(feature = "crypto")]
pub mod bao_cache;

/// Optional QUIC runtime binding (§11, §12).
#[cfg(feature = "quic")]
pub mod transport;

#[cfg(feature = "quic")]
pub mod nat_driver;

// -------------------------------------------------------------------------
// Crate-level re-exports
// -------------------------------------------------------------------------

pub use backoff::{BackoffTracker, DEFAULT_BASE_MS, DEFAULT_MAX_KEYS, DEFAULT_MAX_MS};
pub use bulk::{BulkReceiver, BulkSender, BulkTransferConfig, CHUNK_SIZE};
#[cfg(feature = "std")]
pub use clock::unix_now;
pub use conn::{BackpressureAction, Connection, ConnectionPhase, QuipNetConfig};
pub use constants::{
    ALPN_QUIP, BULK_STREAM_BASE_ID, CANDIDATE_TTL_S, CHECKPOINT_INTERVAL,
    CLUSTER_ACCEPTANCE_PERCENTILE, CLUSTER_HEARTBEAT_S, CLUSTER_LEVELS, CONNECTIVITY_TTL_S,
    COORDINATOR_INTERVAL_S, CTRL_STREAM_ID, DEGRADED_QUORUM, GATEWAY_ROUTER_COUNT,
    HANDSHAKE_TIMEOUT_MS, LOOKUP_PATHS, MAX_CHUNK_BYTES, MAX_CLUSTER_SIZE, MAX_DGRAM_BYTES,
    MAX_MESSAGE_SIZE, MAX_RANGES, MAX_SPLIT_ATTEMPTS, MERGE_DELTA_INTERVAL_S,
    MIN_ACTIVE_WITNESSES, MIN_CLUSTER_SIZE, MIN_WITNESSES, PROTOCOL_VERSION, QUORUM,
    RELAY_CAPACITY, RELAY_HOP_LIMIT, RTT_GLOBAL_MS, RTT_LOCAL_MS, RTT_REGIONAL_MS,
    SPILLOVER_CACHE_TTL_S, SPILLOVER_THRESHOLD, SYNC_STREAM_ID, T0_MAX_STREAMS, T1_MAX_STREAMS,
    T2_MAX_STREAMS, T3_MAX_DATAGRAMS, VIEW_CHANGE_QUORUM, WITNESS_COUNT,
};
pub use dht::{
    CoralConfig, CrossPathCheck, LookupPathState, LookupProgress, LookupState, RttClass,
    WitnessLoad, WitnessRingCache, ACCEPTANCE_PERCENTILE, DEFAULT_MAX_RINGS, GLOBAL_CLUSTER,
    LOCAL_CLUSTER, REGIONAL_CLUSTER,
};
pub use coral::{
    compare_by_distance, cross_path_consensus, select_witness_ring, xor_distance, CoralLookup,
    CrossPathResult, CrossPathValidation, Key, LookupPath, LookupResponse, PathId, PathProof,
    SpilloverRequest, SpilloverResponse,
};
pub use cluster::{
    estimate_size_from_routing_table, ClusterConfig, ClusterId, ClusterInfo, ClusterLevel,
    ClusterState, MergeDecision, SplitAction, ACCEPTANCE_MIN_SAMPLES,
};
pub use discovery::{
    DiscoveryFailure, DiscoveryPhaseKind, DiscoveryStatus, Outbound, SpilloverResponseCache,
    StartOutcome, WitnessDiscovery, DEFAULT_SPILLOVER_CACHE_CAPACITY,
};
pub use establishment::{
    ConnectionFlow, FlowAction, FlowConfig, FlowFailure, FlowPhase, KtStatus,
};
pub use error::{Error, Result};
pub use event::{EmitEvent, PinAnnounce};
pub use flow::{
    dispatch_flow, FlowFrame, FlowState, FlowStateMachine, BLOCK_KIND, UNBLOCK_KIND, WINDOW_KIND,
};
pub use frame::{
    decode_varint, deframe_all, encode_message, encode_varint, try_deframe, varint_len, StreamId,
    StreamKind, Tier, CTRL_STREAM, MAX_STREAMS_PER_TIER, SYNC_STREAM, T0, T1, T2, T3,
};
pub use handshake::{Capabilities, ExtensionId, Handshake};
pub use message::{
    dispatch, ErrorMessage, Message, SendChunk, SendComplete, SendStart,
};
pub use query::Query;
pub use rate::{
    BucketConfig, OperationKind, RateLimiter, RateLimiterConfig, DEFAULT_MAX_ENTRIES,
};
pub use resource::{QueryResource, ResourceAnnounce};
pub use sync::{
    Fingerprint, FingerprintAlgo, GetRequest, PinList, PinQuery, QueryPins, QueryQuarantined,
    Range, RbsrReconciler, RbsrRequest, RbsrResponse, SetRequest, SyncRequest, SyncResponse,
    UnpinRequest, XorFingerprint,
};
pub use sync_stream::{SyncEvent, SyncState, SyncStream};
pub use nat::{
    AddressState, CandidateTable, ConnectivityState, HolePunchRole, HolePunchSession,
    NatConfig, NatEvent, NatKind, NatTraversal, Outbound as NatOutbound, RelayManager,
    SessionState,
};
pub use nat_wire::{
    Candidate, CandidateAnnounce, ConnectivityAnnounce, RelayDiscovery, RelayEntry,
    RelayResponse, CANDIDATE_HOST, CANDIDATE_PEER_REFLEXIVE, CANDIDATE_RELAYED,
    CANDIDATE_SERVER_REFLEXIVE, NAT_TYPE_CONE, NAT_TYPE_OPEN, NAT_TYPE_RESTRICTED,
    NAT_TYPE_SYMMETRIC, NAT_TYPE_UNKNOWN,
};
pub use range::{
    is_blake3, split_range, FetchRange, NoQuarantine, QuarantineCheck, RangeResponse,
    MAX_RANGE_IN_SINGLE_RESPONSE,
};
pub use bft::{
    BftCheckpoint, BftCommit, BftNewView, BftPrecommit, BftPreprepare, BftPrepare,
    BftStateTransfer, BftViewChange, Digest, Operation, RingId,
};

#[cfg(feature = "crypto")]
pub use range::bao_support;

#[cfg(feature = "crypto")]
pub use range::bao_support::RangeResponder;

#[cfg(feature = "crypto")]
pub use bao_cache::{
    BaoCache, CacheStats, CachedTree, DEFAULT_BAO_CACHE_BYTES, DEFAULT_BAO_CACHE_ENTRIES,
    DEFAULT_BAO_CACHE_ENTRY_BYTES,
};

#[cfg(feature = "crypto")]
pub use crypto::{Blake3Hasher, Ed25519Signer, Ed25519Verifier, Sha256Hasher};

#[cfg(feature = "quic")]
pub use transport::{
    ClientConfig, ConnectionDriver, DriverPhase, Endpoint, Event, IncomingMessage, Role,
    ServerConfig,
};

#[cfg(feature = "quic")]
pub use nat_driver::{DhtClient, DhtResult, NatDriver, NullDhtClient};

#[cfg(test)]
pub(crate) mod test_support;