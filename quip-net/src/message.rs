//! Message dispatch (spec §14).
//!
//! The transport plane receives bytes on a tier and needs to route them to
//! a typed handler. [`Message`] is the single enum every verb maps to, and
//! [`dispatch`] turns `(bytes, tier)` into a `Message`.
//!
//! # Scope
//!
//! `dispatch` takes **already-deframed** CBOR bytes: the varint length
//! prefix used on T0/T1/T2 has been stripped by [`crate::frame::try_deframe`],
//! and T3 datagram payloads are passed directly. The function never sees a
//! length prefix.
//!
//! It also does not handle the handshake. The first bytes on a fresh T0
//! stream are a `Handshake`, not a verb; the transport driver peeks at
//! them (via [`crate::conn::Connection::is_quip_handshake`]) before calling
//! `dispatch` for subsequent messages.
//!
//! # Why a typed enum
//!
//! The v1 verb set is closed — the spec lists exactly which verbs exist.
//! Encoding them as an enum gives compile-time exhaustiveness: adding a
//! variant makes the compiler point at every dispatch site.
//!
//! # Tier validation
//!
//! Every verb has a required tier (§12). [`dispatch`] rejects a message
//! that arrives on the wrong tier with [`Error::WrongTier`]. This is a
//! security check, not a convenience: a `set` smuggled onto T2 or an
//! `emit` on T0 could otherwise bypass the backpressure and reliability
//! guarantees the tier system exists to provide.
//!
//! # Capability enforcement
//!
//! Verbs whose required capability is not the baseline advertise it via
//! [`Message::required_capability`]. The transport driver is the
//! enforcement point for the §4 invariant, but the mapping from verb to
//! capability lives here so there is a single source of truth.
//!
//! # CDDL nesting for CTRL payload verbs
//!
//! Spec §14.1 writes the envelopes for `announce_key`, `announce_witness`,
//! and the five governance verbs as e.g.
//! `announce_key = [ "quip-v1", "announce_key", KeyClaim ]`. The third
//! slot is a value of the named type, and `KeyClaim` is itself an array
//! that begins with `"quip-v1", "key_claim"`. This module emits the
//! **nested** form:
//!
//! ```text
//! ["quip-v1", "announce_key", ["quip-v1", "key_claim", …]]
//! ```
//!
//! The signing convention of §10.1 covers only the inner array, which is
//! consistent with `quip_core::messages::KeyClaim::signing_payload`
//! producing `["quip-v1", "key_claim", …]` without the outer wrapper. If
//! the spec instead intended to inline the inner fields, the wire shape
//! would have to change in both this crate and `quip-core`.

use crate::codec::{as_bytes, as_u64, envelope, fields, verb_of};
use crate::coral::{
    CoralLookup, CrossPathResult, CrossPathValidation, LookupResponse, SpilloverRequest,
    SpilloverResponse,
};
use crate::error::{Error, Result};
use crate::event::{EmitEvent, PinAnnounce};
use crate::frame::Tier;
use crate::nat_wire::{
    CandidateAnnounce, ConnectivityAnnounce, RelayDiscovery, RelayResponse,
};
use crate::query::Query;
use crate::range::{FetchRange, RangeResponse};
use crate::resource::{QueryResource, ResourceAnnounce};
use crate::sync::{
    GetRequest, PinList, PinQuery, QueryPins, QueryQuarantined, RbsrRequest, RbsrResponse,
    SetRequest, SyncRequest, UnpinRequest,
};
use crate::bft::{
    BftCheckpoint, BftCommit, BftNewView, BftPrecommit, BftPreprepare, BftPrepare,
    BftStateTransfer, BftViewChange,
};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::cid::CidOrV1;
use quip_core::messages::{
    DelegationCertificate, DerivativeLink, KeyClaim, QuarantineRequest, TrustedCidRegistration,
    UnquarantineRequest, WitnessStatement,
};
use quip_core::ErrorCode;

// -------------------------------------------------------------------------
// `error` verb
// -------------------------------------------------------------------------

/// `error = ["quip-v1", "error", code: ErrorCode, message_id: uint, text: tstr]`.
///
/// This is the only verb whose fields are not wrapped in a distinct struct
/// in a sibling module — it is small enough that the codec lives here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ErrorMessage {
    /// Wire-level error code (§15).
    pub code: ErrorCode,
    /// Request correlation ID from the sender.
    pub message_id: u64,
    /// Human-readable reason.
    pub text: String,
}

impl ErrorMessage {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "error",
            alloc::vec![
                CborValue::Int(self.code as i128),
                CborValue::Int(self.message_id as i128),
                CborValue::String(self.text.clone()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "error" {
            return Err(Error::BadFrame("not an error"));
        }
        let f = fields(&v, "error")?;
        if f.len() != 3 {
            return Err(Error::BadFrame("error arity"));
        }
        let code = match &f[0] {
            CborValue::Int(n) if *n >= 0 && *n <= u8::MAX as i128 => {
                ErrorCode::try_from(*n as u8).map_err(|_| Error::BadFrame("unknown error code"))?
            }
            _ => return Err(Error::BadFrame("error code must be a small uint")),
        };
        Ok(Self {
            code,
            message_id: as_u64(&f[1])?,
            text: match &f[2] {
                CborValue::String(s) => s.clone(),
                _ => return Err(Error::BadFrame("error text must be a string")),
            },
        })
    }
}

// -------------------------------------------------------------------------
// BULK verbs (T2)
// -------------------------------------------------------------------------

/// `send_start` verb fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendStart {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Total payload size in bytes.
    pub total_size: u64,
    /// Legacy hash slot (deprecated; duplicates `cid.digest()`).
    pub hash: Vec<u8>,
    /// CID of the payload.
    pub cid: CidOrV1,
    /// Optional hash algorithm id (0 = SHA-256, 1 = BLAKE3).
    pub hash_algo: Option<u64>,
}

impl SendStart {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = alloc::vec![
            CborValue::Bytes(self.resource_id.clone()),
            CborValue::Int(self.total_size as i128),
            CborValue::Bytes(self.hash.clone()),
            self.cid.to_cbor(),
        ];
        if let Some(a) = self.hash_algo {
            f.push(CborValue::Int(a as i128));
        }
        Ok(encode(&envelope("send_start", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "send_start" {
            return Err(Error::BadFrame("not a send_start"));
        }
        let f = fields(&v, "send_start")?;
        if f.len() != 4 && f.len() != 5 {
            return Err(Error::BadFrame("send_start arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            total_size: as_u64(&f[1])?,
            hash: as_bytes(&f[2])?,
            cid: CidOrV1::from_cbor(&f[3])?,
            hash_algo: if f.len() == 5 {
                Some(as_u64(&f[4])?)
            } else {
                None
            },
        })
    }
}

/// `send_chunk` verb fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendChunk {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Sequence number (0-based).
    pub seq: u64,
    /// Byte offset in the payload.
    pub offset: u64,
    /// Chunk bytes.
    pub bytes: Vec<u8>,
}

impl SendChunk {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "send_chunk",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                CborValue::Int(self.seq as i128),
                CborValue::Int(self.offset as i128),
                CborValue::Bytes(self.bytes.clone()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "send_chunk" {
            return Err(Error::BadFrame("not a send_chunk"));
        }
        let f = fields(&v, "send_chunk")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("send_chunk arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            seq: as_u64(&f[1])?,
            offset: as_u64(&f[2])?,
            bytes: as_bytes(&f[3])?,
        })
    }
}

/// `send_complete` verb fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SendComplete {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Legacy hash slot (duplicates `cid`'s digest when present).
    pub final_hash: Vec<u8>,
    /// Optional CID of the completed payload.
    pub cid: Option<CidOrV1>,
}

impl SendComplete {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = alloc::vec![
            CborValue::Bytes(self.resource_id.clone()),
            CborValue::Bytes(self.final_hash.clone()),
        ];
        if let Some(c) = &self.cid {
            f.push(c.to_cbor());
        }
        Ok(encode(&envelope("send_complete", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "send_complete" {
            return Err(Error::BadFrame("not a send_complete"));
        }
        let f = fields(&v, "send_complete")?;
        if f.len() != 2 && f.len() != 3 {
            return Err(Error::BadFrame("send_complete arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            final_hash: as_bytes(&f[1])?,
            cid: if f.len() == 3 {
                Some(CidOrV1::from_cbor(&f[2])?)
            } else {
                None
            },
        })
    }
}

// -------------------------------------------------------------------------
// CTRL payload helpers
// -------------------------------------------------------------------------

/// Encode a verb whose CBOR payload is a single `quip-core` message value.
fn encode_core_verb(verb: &str, payload: CborValue) -> Result<Vec<u8>> {
    Ok(encode(&envelope(verb, alloc::vec![payload]))?)
}

/// Extract the single CBOR payload from a verb envelope and decode it
/// with the supplied core-type decoder.
fn decode_verb_payload<T>(
    value: &CborValue,
    verb: &str,
    decode: impl FnOnce(&CborValue) -> core::result::Result<T, quip_core::Error>,
) -> Result<T> {
    let f = fields(value, verb)?;
    if f.len() != 1 {
        return Err(Error::BadFrame("verb payload must be a single item"));
    }
    Ok(decode(&f[0])?)
}

// -------------------------------------------------------------------------
// Message enum
// -------------------------------------------------------------------------

/// A decoded QUIP wire message.
#[derive(Clone, Debug, PartialEq)]
pub enum Message {
    // ---- T0 CTRL ----
    /// `error` — protocol error response.
    Error(ErrorMessage),
    /// `query_resource` — resource lookup.
    QueryResource(QueryResource),
    /// `resource_announce` — resource location gossip.
    ResourceAnnounce(ResourceAnnounce),
    /// `announce_key` — self-signed Key Claim (§5.1, §14.1).
    AnnounceKey(KeyClaim),
    /// `announce_witness` — witness corroboration (§5.3.3, §14.1).
    AnnounceWitness(WitnessStatement),
    /// `query` — request a Key Claim or witness ring (§14.1).
    Query(Query),
    /// `register_tcid` — Trusted CID registration (§7.1, §14.1).
    RegisterTcid(TrustedCidRegistration),
    /// `delegation` — governance delegation (§7.1, §14.1).
    Delegation(DelegationCertificate),
    /// `quarantine` — quarantine request (§7.2, §14.1).
    Quarantine(QuarantineRequest),
    /// `unquarantine` — lift a quarantine (§7.2, §14.1).
    Unquarantine(UnquarantineRequest),
    /// `derivative_link` — link a derivative to a Trusted CID (§7.3, §14.1).
    DerivativeLink(DerivativeLink),
    /// `coral_lookup` — multi-path DHT lookup (§13.7).
    CoralLookup(CoralLookup),
    /// `coral_lookup_response` — a path's lookup result (§13.7).
    CoralLookupResponse(LookupResponse),
    /// `spillover` — re-lookup request when a path misbehaves (§13.8).
    Spillover(SpilloverRequest),
    /// `spillover_response` — the outcome of a spillover lookup (§13.8).
    SpilloverResponse(SpilloverResponse),
    /// `cross_path_validation` — check that multiple paths agree (§13.8).
    CrossPathValidation(CrossPathValidation),
    /// `cross_path_result` — the outcome of cross-path validation (§13.8).
    CrossPathResult(CrossPathResult),
    /// `connectivity_announce` — DHT connectivity advertisement (§12.1).
    ConnectivityAnnounce(ConnectivityAnnounce),
    /// `candidate_announce` — ICE-like candidate offer (§12.3).
    CandidateAnnounce(CandidateAnnounce),
    /// `relay_discovery` — request relays to a target (§12.2).
    RelayDiscovery(RelayDiscovery),
    /// `relay_response` — relays that can reach a target (§12.2).
    RelayResponse(RelayResponse),
        /// `bft_preprepare` — primary proposes an operation (§5.3.4).
    BftPreprepare(BftPreprepare),
    /// `bft_prepare` — witness acknowledges a proposal (§5.3.4).
    BftPrepare(BftPrepare),
    /// `bft_precommit` — witness commits to prepare (§5.3.4).
    BftPrecommit(BftPrecommit),
    /// `bft_commit` — witness finalizes (§5.3.4).
    BftCommit(BftCommit),
    /// `bft_view_change` — witness signals a view change (§5.3.4).
    BftViewChange(BftViewChange),
    /// `bft_new_view` — primary announces a completed view change (§5.3.4).
    BftNewView(BftNewView),
    /// `bft_checkpoint` — witness signs a stable state (§5.3.4).
    BftCheckpoint(BftCheckpoint),
    /// `bft_state_transfer` — ring-signed state for a lagging witness (§5.3.4).
    BftStateTransfer(BftStateTransfer),

    // ---- T1 SYNC ----
    /// `get` — DVV state query.
    Get(GetRequest),
    /// `set` — DVV write.
    Set(SetRequest),
    /// `sync` — DVV delta exchange.
    Sync(SyncRequest),
    /// `rbsr_sync` — range-based set reconciliation request.
    RbsrSync(RbsrRequest),
    /// `rbsr_response` — range-based set reconciliation reply.
    RbsrResponse(RbsrResponse),
    /// `pin` — request a pin.
    Pin(PinQuery),
    /// `unpin` — release a pin.
    Unpin(UnpinRequest),
    /// `query_pins` — list held pins.
    QueryPins(QueryPins),
    /// `pin_list` — pins response.
    PinList(PinList),
    /// `query_quarantined` — list quarantined CIDs.
    QueryQuarantined(QueryQuarantined),
    /// `fetch_range` — request a byte range from a BLAKE3 resource (§8.2).
    FetchRange(FetchRange),
    /// `range_response` — a range fetch's reply (§8.2).
    RangeResponse(RangeResponse),

    // ---- T2 BULK ----
    /// `send_start` — begin a bulk transfer.
    SendStart(SendStart),
    /// `send_chunk` — a chunk of a bulk transfer.
    SendChunk(SendChunk),
    /// `send_complete` — finish a bulk transfer.
    SendComplete(SendComplete),

    // ---- T3 EVENT ----
    /// `emit` — application event.
    Emit(EmitEvent),
    /// `pin_announce` — pin gossip.
    PinAnnounce(PinAnnounce),
}

impl Message {
    /// The wire verb for this message.
    pub fn verb(&self) -> &'static str {
        match self {
            Message::Error(_) => "error",
            Message::QueryResource(_) => "query_resource",
            Message::ResourceAnnounce(_) => "resource_announce",
            Message::AnnounceKey(_) => "announce_key",
            Message::AnnounceWitness(_) => "announce_witness",
            Message::Query(_) => "query",
            Message::RegisterTcid(_) => "register_tcid",
            Message::Delegation(_) => "delegation",
            Message::Quarantine(_) => "quarantine",
            Message::Unquarantine(_) => "unquarantine",
            Message::DerivativeLink(_) => "derivative_link",
            Message::CoralLookup(_) => "coral_lookup",
            Message::CoralLookupResponse(_) => "coral_lookup_response",
            Message::Spillover(_) => "spillover",
            Message::SpilloverResponse(_) => "spillover_response",
            Message::CrossPathValidation(_) => "cross_path_validation",
            Message::CrossPathResult(_) => "cross_path_result",
            Message::ConnectivityAnnounce(_) => "connectivity_announce",
            Message::CandidateAnnounce(_) => "candidate_announce",
            Message::RelayDiscovery(_) => "relay_discovery",
            Message::RelayResponse(_) => "relay_response",
            Message::Get(_) => "get",
            Message::Set(_) => "set",
            Message::Sync(_) => "sync",
            Message::RbsrSync(_) => "rbsr_sync",
            Message::RbsrResponse(_) => "rbsr_response",
            Message::Pin(_) => "pin",
            Message::Unpin(_) => "unpin",
            Message::QueryPins(_) => "query_pins",
            Message::PinList(_) => "pin_list",
            Message::QueryQuarantined(_) => "query_quarantined",
            Message::FetchRange(_) => "fetch_range",
            Message::RangeResponse(_) => "range_response",
            Message::SendStart(_) => "send_start",
            Message::SendChunk(_) => "send_chunk",
            Message::SendComplete(_) => "send_complete",
            Message::Emit(_) => "emit",
            Message::PinAnnounce(_) => "pin_announce",
            Message::BftPreprepare(_) => "bft_preprepare",
            Message::BftPrepare(_) => "bft_prepare",
            Message::BftPrecommit(_) => "bft_precommit",
            Message::BftCommit(_) => "bft_commit",
            Message::BftViewChange(_) => "bft_view_change",
            Message::BftNewView(_) => "bft_new_view",
            Message::BftCheckpoint(_) => "bft_checkpoint",
            Message::BftStateTransfer(_) => "bft_state_transfer",
        }
    }

    /// The tier this message is required to arrive on (spec §12).
    pub fn required_tier(&self) -> Tier {
        match self {
            // ---- T0 CTRL ----
            Message::Error(_)
            | Message::QueryResource(_)
            | Message::ResourceAnnounce(_)
            | Message::AnnounceKey(_)
            | Message::AnnounceWitness(_)
            | Message::Query(_)
            | Message::RegisterTcid(_)
            | Message::Delegation(_)
            | Message::Quarantine(_)
            | Message::Unquarantine(_)
            | Message::DerivativeLink(_)
            | Message::CoralLookup(_)
            | Message::CoralLookupResponse(_)
            | Message::Spillover(_)
            | Message::SpilloverResponse(_)
            | Message::CrossPathValidation(_)
            | Message::CrossPathResult(_)
            | Message::ConnectivityAnnounce(_)
            | Message::CandidateAnnounce(_)
            | Message::RelayDiscovery(_)
            | Message::RelayResponse(_) => Tier::Ctrl,
            | Message::BftPreprepare(_)
            | Message::BftPrepare(_)
            | Message::BftPrecommit(_)
            | Message::BftCommit(_)
            | Message::BftViewChange(_)
            | Message::BftNewView(_)
            | Message::BftCheckpoint(_)
            | Message::BftStateTransfer(_) => Tier::Ctrl,

            // ---- T1 SYNC ----
            Message::Get(_)
            | Message::Set(_)
            | Message::Sync(_)
            | Message::RbsrSync(_)
            | Message::RbsrResponse(_)
            | Message::Pin(_)
            | Message::Unpin(_)
            | Message::QueryPins(_)
            | Message::PinList(_)
            | Message::QueryQuarantined(_)
            | Message::FetchRange(_)
            | Message::RangeResponse(_) => Tier::Sync,

            // ---- T2 BULK ----
            Message::SendStart(_)
            | Message::SendChunk(_)
            | Message::SendComplete(_) => Tier::Bulk,

            // ---- T3 EVENT ----
            Message::Emit(_) | Message::PinAnnounce(_) => Tier::Event,
        }
    }

    /// The capability bit required to process this message, if any (spec §4).
    pub fn required_capability(&self) -> Option<u64> {
        match self {
            Message::RegisterTcid(_)
            | Message::Delegation(_)
            | Message::Quarantine(_)
            | Message::Unquarantine(_)
            | Message::DerivativeLink(_) => {
                Some(crate::handshake::Capabilities::GOVERNANCE)
            }
            Message::CoralLookup(_)
            | Message::CoralLookupResponse(_)
            | Message::Spillover(_)
            | Message::SpilloverResponse(_)
            | Message::CrossPathValidation(_)
            | Message::CrossPathResult(_) => {
                Some(crate::handshake::Capabilities::DHT_DISCOVERY)
            }
            Message::ConnectivityAnnounce(_)
            | Message::CandidateAnnounce(_)
            | Message::RelayDiscovery(_)
            | Message::RelayResponse(_) => {
                Some(crate::handshake::Capabilities::NAT_TRAVERSAL)
            }
            Message::FetchRange(_) | Message::RangeResponse(_) => {
                Some(crate::handshake::Capabilities::MERKLE_RANGE)
            }
            Message::BftCheckpoint(_) | Message::BftStateTransfer(_) => {
                Some(crate::handshake::Capabilities::BFT_CHECKPOINT)
            }
            _ => None,
        }
    }

    /// Enforce the capability invariant (spec §4).
    pub fn check_capability(
        &self,
        negotiated: crate::handshake::Capabilities,
    ) -> Result<()> {
        if let Some(required) = self.required_capability() {
            if !negotiated.has(required) {
                return Err(Error::CapabilityViolation {
                    verb: self.verb(),
                    required,
                });
            }
        }
        Ok(())
    }

    /// Encode to QUIP-CBOR bytes (no length prefix; use
    /// [`crate::frame::encode_message`] for T0/T1/T2 framing).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        match self {
            Message::Error(m) => m.to_bytes(),
            Message::QueryResource(m) => m.to_bytes(),
            Message::ResourceAnnounce(m) => m.to_bytes(),
            Message::AnnounceKey(m) => encode_core_verb("announce_key", m.to_cbor()),
            Message::AnnounceWitness(m) => {
                encode_core_verb("announce_witness", m.to_cbor())
            }
            Message::Query(m) => m.to_bytes(),
            Message::RegisterTcid(m) => {
                encode_core_verb("register_tcid", m.to_cbor())
            }
            Message::Delegation(m) => encode_core_verb("delegation", m.to_cbor()),
            Message::Quarantine(m) => encode_core_verb("quarantine", m.to_cbor()),
            Message::Unquarantine(m) => {
                encode_core_verb("unquarantine", m.to_cbor())
            }
            Message::DerivativeLink(m) => {
                encode_core_verb("derivative_link", m.to_cbor())
            }
            Message::CoralLookup(m) => m.to_bytes(),
            Message::CoralLookupResponse(m) => m.to_bytes(),
            Message::Spillover(m) => m.to_bytes(),
            Message::SpilloverResponse(m) => m.to_bytes(),
            Message::CrossPathValidation(m) => m.to_bytes(),
            Message::CrossPathResult(m) => m.to_bytes(),
            Message::ConnectivityAnnounce(m) => m.to_bytes(),
            Message::CandidateAnnounce(m) => m.to_bytes(),
            Message::RelayDiscovery(m) => m.to_bytes(),
            Message::RelayResponse(m) => m.to_bytes(),
            Message::Get(m) => m.to_bytes(),
            Message::Set(m) => m.to_bytes(),
            Message::Sync(m) => m.to_bytes(),
            Message::RbsrSync(m) => m.to_bytes(),
            Message::RbsrResponse(m) => m.to_bytes(),
            Message::FetchRange(m) => m.to_bytes(),
            Message::RangeResponse(m) => m.to_bytes(),
            Message::Pin(m) => m.to_bytes(),
            Message::Unpin(m) => m.to_bytes(),
            Message::QueryPins(m) => m.to_bytes(),
            Message::PinList(m) => m.to_bytes(),
            Message::QueryQuarantined(m) => m.to_bytes(),
            Message::SendStart(m) => m.to_bytes(),
            Message::SendChunk(m) => m.to_bytes(),
            Message::SendComplete(m) => m.to_bytes(),
            Message::Emit(m) => m.to_bytes(),
            Message::PinAnnounce(m) => m.to_bytes(),
            Message::BftPreprepare(m) => m.to_bytes(),
            Message::BftPrepare(m) => m.to_bytes(),
            Message::BftPrecommit(m) => m.to_bytes(),
            Message::BftCommit(m) => m.to_bytes(),
            Message::BftViewChange(m) => m.to_bytes(),
            Message::BftNewView(m) => m.to_bytes(),
            Message::BftCheckpoint(m) => m.to_bytes(),
            Message::BftStateTransfer(m) => m.to_bytes(),
        }
    }
}

// -------------------------------------------------------------------------
// Dispatch
// -------------------------------------------------------------------------

/// Decode one already-deframed QUIP message and validate its tier.
pub fn dispatch(bytes: &[u8], tier: Tier) -> Result<Message> {
    let value = decode(bytes)?;
    let verb = verb_of(&value)?;
    let msg = match verb {
        "error" => Message::Error(ErrorMessage::from_bytes(bytes)?),
        "query_resource" => Message::QueryResource(QueryResource::from_bytes(bytes)?),
        "resource_announce" => Message::ResourceAnnounce(ResourceAnnounce::from_bytes(bytes)?),
        "announce_key" => Message::AnnounceKey(decode_verb_payload(
            &value,
            "announce_key",
            KeyClaim::from_cbor,
        )?),
        "announce_witness" => Message::AnnounceWitness(decode_verb_payload(
            &value,
            "announce_witness",
            WitnessStatement::from_cbor,
        )?),
        "query" => Message::Query(Query::from_bytes(bytes)?),
        "register_tcid" => Message::RegisterTcid(decode_verb_payload(
            &value,
            "register_tcid",
            TrustedCidRegistration::from_cbor,
        )?),
        "delegation" => Message::Delegation(decode_verb_payload(
            &value,
            "delegation",
            DelegationCertificate::from_cbor,
        )?),
        "quarantine" => Message::Quarantine(decode_verb_payload(
            &value,
            "quarantine",
            QuarantineRequest::from_cbor,
        )?),
        "unquarantine" => Message::Unquarantine(decode_verb_payload(
            &value,
            "unquarantine",
            UnquarantineRequest::from_cbor,
        )?),
        "derivative_link" => Message::DerivativeLink(decode_verb_payload(
            &value,
            "derivative_link",
            DerivativeLink::from_cbor,
        )?),
        "coral_lookup" => Message::CoralLookup(CoralLookup::from_bytes(bytes)?),
        "coral_lookup_response" => {
            Message::CoralLookupResponse(LookupResponse::from_bytes(bytes)?)
        }
        "spillover" => Message::Spillover(SpilloverRequest::from_bytes(bytes)?),
        "spillover_response" => {
            Message::SpilloverResponse(SpilloverResponse::from_bytes(bytes)?)
        }
        "cross_path_validation" => {
            Message::CrossPathValidation(CrossPathValidation::from_bytes(bytes)?)
        }
        "cross_path_result" => {
            Message::CrossPathResult(CrossPathResult::from_bytes(bytes)?)
        }
        "connectivity_announce" => {
            Message::ConnectivityAnnounce(ConnectivityAnnounce::from_bytes(bytes)?)
        }
        "candidate_announce" => {
            Message::CandidateAnnounce(CandidateAnnounce::from_bytes(bytes)?)
        }
        "relay_discovery" => {
            Message::RelayDiscovery(RelayDiscovery::from_bytes(bytes)?)
        }
        "relay_response" => {
            Message::RelayResponse(RelayResponse::from_bytes(bytes)?)
        }
        "get" => Message::Get(GetRequest::from_bytes(bytes)?),
        "set" => Message::Set(SetRequest::from_bytes(bytes)?),
        "sync" => Message::Sync(SyncRequest::from_bytes(bytes)?),
        "rbsr_sync" => Message::RbsrSync(RbsrRequest::from_bytes(bytes)?),
        "rbsr_response" => Message::RbsrResponse(RbsrResponse::from_bytes(bytes)?),
        "pin" => Message::Pin(PinQuery::from_bytes(bytes)?),
        "unpin" => Message::Unpin(UnpinRequest::from_bytes(bytes)?),
        "query_pins" => Message::QueryPins(QueryPins::from_bytes(bytes)?),
        "pin_list" => Message::PinList(PinList::from_bytes(bytes)?),
        "query_quarantined" => {
            Message::QueryQuarantined(QueryQuarantined::from_bytes(bytes)?)
        }
        "fetch_range" => Message::FetchRange(FetchRange::from_bytes(bytes)?),
        "range_response" => Message::RangeResponse(RangeResponse::from_bytes(bytes)?),
        "send_start" => Message::SendStart(SendStart::from_bytes(bytes)?),
        "send_chunk" => Message::SendChunk(SendChunk::from_bytes(bytes)?),
        "send_complete" => Message::SendComplete(SendComplete::from_bytes(bytes)?),
        "emit" => Message::Emit(EmitEvent::from_bytes(bytes)?),
        "pin_announce" => Message::PinAnnounce(PinAnnounce::from_bytes(bytes)?),
        "bft_preprepare" => Message::BftPreprepare(BftPreprepare::from_bytes(bytes)?),
        "bft_prepare" => Message::BftPrepare(BftPrepare::from_bytes(bytes)?),
        "bft_precommit" => Message::BftPrecommit(BftPrecommit::from_bytes(bytes)?),
        "bft_commit" => Message::BftCommit(BftCommit::from_bytes(bytes)?),
        "bft_view_change" => {
            Message::BftViewChange(BftViewChange::from_bytes(bytes)?)
        }
        "bft_new_view" => Message::BftNewView(BftNewView::from_bytes(bytes)?),
        "bft_checkpoint" => {
            Message::BftCheckpoint(BftCheckpoint::from_bytes(bytes)?)
        }
        "bft_state_transfer" => {
            Message::BftStateTransfer(BftStateTransfer::from_bytes(bytes)?)
        }
        other => return Err(Error::UnknownVerb(other.to_string())),
    };

    let required = msg.required_tier();
    if required != tier {
        return Err(Error::WrongTier {
            verb: msg.verb(),
            tier: tier as u8,
        });
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::Tier;
    use alloc::vec;
    use quip_core::cid::Cid;
    use quip_core::dvv::{Dvv, NodeId};
    use quip_core::time::Timestamp;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }
    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }
    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn assert_roundtrip(msg: Message, tier: Tier) {
        let bytes = msg.to_bytes().unwrap();
        let back = dispatch(&bytes, tier).unwrap();
        assert_eq!(back, msg, "roundtrip for verb {}", msg.verb());
    }

    #[test]
    fn every_variant_roundtrips_on_its_own_tier() {
        // CTRL
        assert_roundtrip(
            Message::Error(ErrorMessage {
                code: ErrorCode::Violation,
                message_id: 7,
                text: "nope".into(),
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::QueryResource(QueryResource {
                resource_id: b"r".to_vec(),
                cid: None,
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::ResourceAnnounce(ResourceAnnounce {
                resource_id: b"r".to_vec(),
                latest_cid: cid(1),
                witness_ring: vec![nid(2), nid(3)],
                dht_locations: vec![nid(4)],
                relay_locations: vec![],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::AnnounceKey(KeyClaim {
                node_id: nid(1),
                timestamp: now(),
                dht_id: nid(1),
                signature: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::AnnounceWitness(WitnessStatement {
                subject: nid(1),
                timestamp: now(),
                valid_until: Timestamp::from_millis(1_700_086_400_000),
                ring_id: [0x42; 32],
                witness: nid(2),
                signature: [0xab; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(Message::Query(Query::Key(nid(3))), Tier::Ctrl);
        assert_roundtrip(Message::Query(Query::Witnesses(nid(4))), Tier::Ctrl);
        assert_roundtrip(
            Message::RegisterTcid(TrustedCidRegistration {
                cid: cid(10),
                app_metadata: vec![],
                owner: nid(1),
                timestamp: now(),
                signature: [0xef; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::Delegation(DelegationCertificate {
                trusted_cid: cid(10),
                delegate: nid(2),
                permissions: 0b1011,
                valid_from: now(),
                valid_until: Timestamp::from_millis(1_700_086_400_000),
                owner_signature: [0xdd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::Quarantine(QuarantineRequest {
                trusted_cid: cid(10),
                affected_cids: vec![cid(20)],
                reason: "DMCA".into(),
                app_data: vec![],
                timestamp: now(),
                requestor: nid(1),
                signature: [0xaa; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::Unquarantine(UnquarantineRequest {
                trusted_cid: cid(10),
                affected_cids: vec![cid(20)],
                reason: "error".into(),
                timestamp: now(),
                requestor: nid(1),
                signature: [0xbb; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::DerivativeLink(DerivativeLink {
                trusted_cid: cid(10),
                derivative_cid: cid(20),
                app_data: vec![],
                link_type: "perceptual_hash".into(),
                timestamp: now(),
                reporter: nid(1),
                signature: [0xcc; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::CoralLookup(CoralLookup {
                key: [1; 32],
                lookup_paths: vec![],
                witness_ring_id: [2; 32],
                timestamp: now(),
                requester: nid(3),
                signature: [0xaa; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::CoralLookupResponse(LookupResponse {
                key: [1; 32],
                values: vec![vec![9, 9]],
                path_proofs: vec![],
                responder: nid(4),
                timestamp: now(),
                signature: [0xbb; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::Spillover(SpilloverRequest {
                original_key: [1; 32],
                rejected_witnesses: vec![nid(5)],
                rejection_reason: 1,
                alternate_paths: vec![],
                requester: nid(3),
                timestamp: now(),
                signature: [0xcc; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::SpilloverResponse(SpilloverResponse {
                original_key: [1; 32],
                alternate_witnesses: vec![nid(5), nid(6)],
                path_proofs: vec![],
                consensus: 2,
                responder: nid(4),
                timestamp: now(),
                signature: [0xdd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::CrossPathValidation(CrossPathValidation {
                key: [1; 32],
                path_responses: vec![],
                witness_ring: vec![nid(1)],
                requester: nid(3),
                timestamp: now(),
                signature: [0xee; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::CrossPathResult(CrossPathResult {
                key: [1; 32],
                consensus_reached: true,
                agreed_witnesses: vec![nid(1), nid(2)],
                conflicting_witnesses: vec![],
                validator: nid(3),
                timestamp: now(),
                signature: [0xff; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::ConnectivityAnnounce(ConnectivityAnnounce {
                node_id: nid(1),
                external_addr: quip_core::Address::V4 {
                    ip: [127, 0, 0, 1],
                    port: 4433,
                },
                internal_addr: quip_core::Address::V4 {
                    ip: [10, 0, 0, 1],
                    port: 4433,
                },
                nat_type: crate::nat_wire::NAT_TYPE_OPEN,
                port_preservation: true,
                relay_capable: false,
                capacity: 0,
                timestamp: now(),
                signature: [0xaa; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::CandidateAnnounce(CandidateAnnounce {
                node_id: nid(1),
                candidates: vec![],
                session_id: [0x11; 16],
                timestamp: now(),
                signature: [0xbb; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::RelayDiscovery(RelayDiscovery {
                requester: nid(1),
                target: nid(2),
                max_hops: 2,
                timestamp: now(),
                signature: [0xcc; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::RelayResponse(RelayResponse {
                request_id: [0x11; 16],
                target: nid(2),
                requester: nid(1),
                relays: vec![],
                timestamp: now(),
                signature: [0xdd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftPreprepare(BftPreprepare {
                ring_id: [1; 32],
                view: 0,
                sequence: 0,
                operation: crate::bft::Operation {
                    kind: String::from("key_rotation"),
                    subject: vec![0x11; 32],
                    body: CborValue::Int(1),
                },
                digest: [0xab; 32],
                primary_sig: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftPrepare(BftPrepare {
                ring_id: [1; 32],
                view: 0,
                sequence: 0,
                digest: [0xab; 32],
                witness_sig: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftPrecommit(BftPrecommit {
                ring_id: [1; 32],
                view: 0,
                sequence: 0,
                digest: [0xab; 32],
                witness_sig: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftCommit(BftCommit {
                ring_id: [1; 32],
                view: 0,
                sequence: 0,
                digest: [0xab; 32],
                witness_sig: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftViewChange(BftViewChange {
                ring_id: [1; 32],
                new_view: 1,
                last_sequence: 0,
                prepared_digests: vec![],
                checkpoint_digest: [0; 32],
                witness_sig: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftNewView(BftNewView {
                ring_id: [1; 32],
                view: 1,
                view_change_messages: vec![],
                prepared_messages: vec![],
                checkpoint_messages: vec![],
                primary_sig: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftCheckpoint(BftCheckpoint {
                ring_id: [1; 32],
                sequence: 100,
                state_digest: [0xab; 32],
                witness_sig: [0xcd; 64],
            }),
            Tier::Ctrl,
        );
        assert_roundtrip(
            Message::BftStateTransfer(BftStateTransfer {
                ring_id: [1; 32],
                checkpoint_sequence: 100,
                state: vec![1, 2, 3],
                checkpoint_digest: [0xab; 32],
                ring_signature: quip_core::messages::RingSignature::Individual(
                    quip_core::messages::IndividualRingSig {
                        signatures: vec![[0; 64]; 5],
                        signers: vec![nid(1), nid(2), nid(3), nid(4), nid(5)],
                    },
                ),
            }),
            Tier::Ctrl,
        );

        // SYNC
        assert_roundtrip(
            Message::Get(GetRequest {
                resource_id: b"r".to_vec(),
                their_dvv: Dvv::from_write(nid(1), 1),
            }),
            Tier::Sync,
        );
        assert_roundtrip(
            Message::Set(SetRequest {
                resource_id: b"r".to_vec(),
                new_dvv: Dvv::from_write(nid(1), 2),
                payload: b"p".to_vec(),
                cid: cid(2),
                previous_cid: Some(cid(1)),
                hash_algo: None,
            }),
            Tier::Sync,
        );
        assert_roundtrip(
            Message::Sync(SyncRequest {
                resource_id: b"r".to_vec(),
                their_dvv: Dvv::from_write(nid(1), 3),
                deltas: vec![vec![1, 2, 3]],
            }),
            Tier::Sync,
        );
        assert_roundtrip(
            Message::Pin(PinQuery {
                resource_id: b"r".to_vec(),
                cid: Some(cid(4)),
                ttl_seconds: 3600,
                witness_ring: vec![nid(5)],
            }),
            Tier::Sync,
        );
        assert_roundtrip(
            Message::Unpin(UnpinRequest {
                resource_id: b"r".to_vec(),
                cid: None,
            }),
            Tier::Sync,
        );
        assert_roundtrip(
            Message::QueryPins(QueryPins {
                resource_id: Some(b"r".to_vec()),
                cid: Some(cid(6)),
            }),
            Tier::Sync,
        );
        assert_roundtrip(Message::PinList(PinList { pins: vec![] }), Tier::Sync);
        assert_roundtrip(
            Message::QueryQuarantined(QueryQuarantined {
                resource_id: None,
                cid: Some(cid(7)),
            }),
            Tier::Sync,
        );
        assert_roundtrip(
            Message::FetchRange(FetchRange {
                resource_id: b"r".to_vec(),
                cid: CidOrV1::V1(quip_core::cid::CidV1 {
                    hash_algo: quip_core::cid::HashAlgo::Blake3,
                    digest: [0x11; 32],
                }),
                offset: 0,
                length: 1024,
            }),
            Tier::Sync,
        );
        assert_roundtrip(
            Message::RangeResponse(RangeResponse {
                resource_id: b"r".to_vec(),
                cid: CidOrV1::V1(quip_core::cid::CidV1 {
                    hash_algo: quip_core::cid::HashAlgo::Blake3,
                    digest: [0x11; 32],
                }),
                offset: 0,
                length: 4,
                bytes: b"data".to_vec(),
                proof: vec![0xde, 0xad],
            }),
            Tier::Sync,
        );

        // BULK
        assert_roundtrip(
            Message::SendStart(SendStart {
                resource_id: b"r".to_vec(),
                total_size: 4096,
                hash: vec![0xab; 32],
                cid: cid(8),
                hash_algo: Some(0),
            }),
            Tier::Bulk,
        );
        assert_roundtrip(
            Message::SendChunk(SendChunk {
                resource_id: b"r".to_vec(),
                seq: 0,
                offset: 0,
                bytes: vec![1, 2, 3, 4],
            }),
            Tier::Bulk,
        );
        assert_roundtrip(
            Message::SendComplete(SendComplete {
                resource_id: b"r".to_vec(),
                final_hash: vec![0xcd; 32],
                cid: Some(cid(8)),
            }),
            Tier::Bulk,
        );

        // EVENT
        assert_roundtrip(
            Message::Emit(EmitEvent {
                event_type: "presence".into(),
                payload: CborValue::Int(1),
            }),
            Tier::Event,
        );
        assert_roundtrip(
            Message::PinAnnounce(PinAnnounce {
                resource_id: b"r".to_vec(),
                cid: cid(9),
                ttl_seconds: 7200,
                witness_sig: [0xaa; 64],
            }),
            Tier::Event,
        );
    }

    #[test]
    fn set_on_bulk_is_rejected() {
        let bytes = Message::Set(SetRequest {
            resource_id: b"r".to_vec(),
            new_dvv: Dvv::from_write(nid(1), 1),
            payload: b"p".to_vec(),
            cid: cid(1),
            previous_cid: None,
            hash_algo: None,
        })
        .to_bytes()
        .unwrap();
        assert!(matches!(
            dispatch(&bytes, Tier::Bulk),
            Err(Error::WrongTier { verb: "set", tier: 2 })
        ));
    }

    #[test]
    fn emit_on_ctrl_is_rejected() {
        let bytes = Message::Emit(EmitEvent {
            event_type: "ping".into(),
            payload: CborValue::Null,
        })
        .to_bytes()
        .unwrap();
        assert!(matches!(
            dispatch(&bytes, Tier::Ctrl),
            Err(Error::WrongTier { verb: "emit", tier: 0 })
        ));
    }

    #[test]
    fn send_chunk_on_sync_is_rejected() {
        let bytes = Message::SendChunk(SendChunk {
            resource_id: b"r".to_vec(),
            seq: 0,
            offset: 0,
            bytes: vec![],
        })
        .to_bytes()
        .unwrap();
        assert!(matches!(
            dispatch(&bytes, Tier::Sync),
            Err(Error::WrongTier {
                verb: "send_chunk",
                tier: 1
            })
        ));
    }

    #[test]
    fn resource_announce_on_sync_is_rejected() {
        let bytes = Message::ResourceAnnounce(ResourceAnnounce {
            resource_id: b"r".to_vec(),
            latest_cid: cid(1),
            witness_ring: vec![],
            dht_locations: vec![],
            relay_locations: vec![],
        })
        .to_bytes()
        .unwrap();
        assert!(matches!(
            dispatch(&bytes, Tier::Sync),
            Err(Error::WrongTier {
                verb: "resource_announce",
                tier: 1
            })
        ));
    }

    #[test]
    fn announce_key_on_sync_is_rejected() {
        let bytes = Message::AnnounceKey(KeyClaim {
            node_id: nid(1),
            timestamp: now(),
            dht_id: nid(1),
            signature: [0xcd; 64],
        })
        .to_bytes()
        .unwrap();
        assert!(matches!(
            dispatch(&bytes, Tier::Sync),
            Err(Error::WrongTier {
                verb: "announce_key",
                tier: 1
            })
        ));
    }

    #[test]
    fn register_tcid_on_bulk_is_rejected() {
        let bytes = Message::RegisterTcid(TrustedCidRegistration {
            cid: cid(10),
            app_metadata: vec![],
            owner: nid(1),
            timestamp: now(),
            signature: [0xef; 64],
        })
        .to_bytes()
        .unwrap();
        assert!(matches!(
            dispatch(&bytes, Tier::Bulk),
            Err(Error::WrongTier {
                verb: "register_tcid",
                tier: 2
            })
        ));
    }

    #[test]
    fn governance_verb_requires_governance_capability() {
        let msg = Message::RegisterTcid(TrustedCidRegistration {
            cid: cid(10),
            app_metadata: vec![],
            owner: nid(1),
            timestamp: now(),
            signature: [0xef; 64],
        });
        let baseline = crate::handshake::Capabilities::baseline();
        let with_gov = baseline
            | crate::handshake::Capabilities(crate::handshake::Capabilities::GOVERNANCE);
        assert!(msg.check_capability(baseline).is_err());
        assert!(msg.check_capability(with_gov).is_ok());
    }

    #[test]
    fn announce_key_needs_no_capability() {
        let msg = Message::AnnounceKey(KeyClaim {
            node_id: nid(1),
            timestamp: now(),
            dht_id: nid(1),
            signature: [0xcd; 64],
        });
        assert!(msg.required_capability().is_none());
        assert!(msg
            .check_capability(crate::handshake::Capabilities::baseline())
            .is_ok());
    }

    #[test]
    fn fetch_range_requires_merkle_range_capability() {
        use crate::handshake::Capabilities;
        let msg = Message::FetchRange(FetchRange {
            resource_id: b"r".to_vec(),
            cid: CidOrV1::V1(quip_core::cid::CidV1 {
                hash_algo: quip_core::cid::HashAlgo::Blake3,
                digest: [0x11; 32],
            }),
            offset: 0,
            length: 1024,
        });
        let baseline = Capabilities::baseline();
        let with_merkle = baseline
            | Capabilities(Capabilities::BLAKE3)
            | Capabilities(Capabilities::CID_ADDRESSING)
            | Capabilities(Capabilities::MERKLE_RANGE);
        assert!(msg.check_capability(baseline).is_err());
        assert!(msg.check_capability(with_merkle).is_ok());
    }

    #[test]
    fn unknown_verb_is_rejected() {
        let msg = envelope("not_a_real_verb", vec![CborValue::Int(1)]);
        let bytes = encode(&msg).unwrap();
        match dispatch(&bytes, Tier::Ctrl) {
            Err(Error::UnknownVerb(v)) => assert_eq!(v, "not_a_real_verb"),
            other => panic!("expected UnknownVerb, got {other:?}"),
        }
    }

    #[test]
    fn bad_prefix_is_rejected() {
        let msg = CborValue::Array(vec![
            CborValue::String("wrong-v1".into()),
            CborValue::String("set".into()),
        ]);
        let bytes = encode(&msg).unwrap();
        assert!(matches!(
            dispatch(&bytes, Tier::Sync),
            Err(Error::BadFrame(_))
        ));
    }

    #[test]
    fn garbage_bytes_are_rejected() {
        assert!(dispatch(&[0xff, 0xff, 0xff], Tier::Ctrl).is_err());
    }

    #[test]
    fn verb_matches_the_wire_string() {
        let m = Message::Set(SetRequest {
            resource_id: b"r".to_vec(),
            new_dvv: Dvv::from_write(nid(1), 1),
            payload: b"p".to_vec(),
            cid: cid(1),
            previous_cid: None,
            hash_algo: None,
        });
        let bytes = m.to_bytes().unwrap();
        let v = decode(&bytes).unwrap();
        assert_eq!(verb_of(&v).unwrap(), m.verb());
    }

    #[test]
    fn error_message_roundtrip() {
        let e = ErrorMessage {
            code: ErrorCode::ProfileMismatch,
            message_id: 42,
            text: "no common capabilities".into(),
        };
        let bytes = e.to_bytes().unwrap();
        assert_eq!(ErrorMessage::from_bytes(&bytes).unwrap(), e);
    }

    #[test]
    fn bft_checkpoint_requires_capability() {
        use crate::handshake::Capabilities;
        let msg = Message::BftCheckpoint(BftCheckpoint {
            ring_id: [1; 32],
            sequence: 100,
            state_digest: [0xab; 32],
            witness_sig: [0xcd; 64],
        });
        let baseline = Capabilities::baseline();
        let with_bft = baseline
            | Capabilities(Capabilities::DHT_DISCOVERY)
            | Capabilities(Capabilities::BFT_CHECKPOINT);
        assert!(msg.check_capability(baseline).is_err());
        assert!(msg.check_capability(with_bft).is_ok());
    }

    #[test]
    fn bft_prepare_needs_no_capability() {
        let msg = Message::BftPrepare(BftPrepare {
            ring_id: [1; 32],
            view: 0,
            sequence: 0,
            digest: [0xab; 32],
            witness_sig: [0xcd; 64],
        });
        assert!(msg.required_capability().is_none());
    }
}