//! Coral DHT wire protocol (spec §13.7, §13.8).
//!
//! # Contents
//!
//! - Six top-level messages: [`CoralLookup`], [`LookupResponse`],
//!   [`SpilloverRequest`], [`SpilloverResponse`],
//!   [`CrossPathValidation`], [`CrossPathResult`].
//! - Two inner structures: [`LookupPath`], [`PathProof`].
//! - XOR-distance algorithms: [`xor_distance`], [`compare_by_distance`],
//!   [`select_witness_ring`], [`cross_path_consensus`].
//!
//! # Signing
//!
//! Every message carries an Ed25519 signature over its signing payload,
//! which is the message array with the `signature` element removed
//! (§10.1). [`CrossPathValidation`] embeds signed [`LookupResponse`]
//! values in its `path_responses` field; per §10.1, the outer signature
//! covers the inner messages as encoded on the wire — including the
//! inner signatures. Only the outer `signature` field is stripped.

use crate::codec::{
    as_array, as_bool, as_bytes, as_bytes_n, as_node_id, as_node_ids, as_u64, envelope, fields,
    node_list_to_cbor, verb_of,
};
use crate::error::{Error, Result};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::ToString;
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::dvv::NodeId;
use quip_core::messages::Verifier;
use quip_core::time::Timestamp;

/// A 256-bit lookup key (usually the target `NodeId`).
pub type Key = [u8; 32];

/// A lookup path identifier.
pub type PathId = [u8; 16];

// -------------------------------------------------------------------------
// Inner structures
// -------------------------------------------------------------------------

/// A path through DHT nodes for a single Coral lookup (§13.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupPath {
    /// Path identifier, unique within a lookup.
    pub path_id: PathId,
    /// DHT nodes the path traverses, in order.
    pub nodes: Vec<NodeId>,
    /// Hash of the value expected at the end of the path.
    pub value_hash: [u8; 32],
    /// Time-to-live in seconds.
    pub ttl: u64,
}

impl LookupPath {
    /// Encode to a CBOR map.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(alloc::vec![
            (
                CborValue::String("path_id".to_string()),
                CborValue::Bytes(self.path_id.to_vec()),
            ),
            (
                CborValue::String("nodes".to_string()),
                node_list_to_cbor(&self.nodes),
            ),
            (
                CborValue::String("value_hash".to_string()),
                CborValue::Bytes(self.value_hash.to_vec()),
            ),
            (
                CborValue::String("ttl".to_string()),
                CborValue::Int(self.ttl as i128),
            ),
        ])
    }

    /// Decode from a CBOR map.
    pub fn from_cbor(v: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = v else {
            return Err(Error::BadFrame("LookupPath must be a map"));
        };
        let mut path_id: Option<PathId> = None;
        let mut nodes: Option<Vec<NodeId>> = None;
        let mut value_hash: Option<[u8; 32]> = None;
        let mut ttl: Option<u64> = None;
        for (k, val) in pairs {
            match k {
                CborValue::String(s) if s == "path_id" => path_id = Some(as_bytes_n::<16>(val)?),
                CborValue::String(s) if s == "nodes" => nodes = Some(as_node_ids(val)?),
                CborValue::String(s) if s == "value_hash" => {
                    value_hash = Some(as_bytes_n::<32>(val)?)
                }
                CborValue::String(s) if s == "ttl" => ttl = Some(as_u64(val)?),
                CborValue::String(_) => {
                    return Err(Error::BadFrame("unknown key in LookupPath"))
                }
                _ => return Err(Error::BadFrame("LookupPath keys must be text")),
            }
        }
        Ok(Self {
            path_id: path_id.ok_or(Error::BadFrame("missing path_id"))?,
            nodes: nodes.ok_or(Error::BadFrame("missing nodes"))?,
            value_hash: value_hash.ok_or(Error::BadFrame("missing value_hash"))?,
            ttl: ttl.ok_or(Error::BadFrame("missing ttl"))?,
        })
    }

    /// Encode a list of paths.
    pub fn list_to_cbor(paths: &[LookupPath]) -> CborValue {
        CborValue::Array(paths.iter().map(|p| p.to_cbor()).collect())
    }

    /// Decode a list of paths.
    pub fn list_from_cbor(v: &CborValue) -> Result<Vec<LookupPath>> {
        as_array(v)?.iter().map(LookupPath::from_cbor).collect()
    }
}

/// Cryptographic proof that a path was followed correctly (§13.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathProof {
    /// Path this proof covers.
    pub path_id: PathId,
    /// Signatures from the DHT nodes on the path, in order.
    pub node_signatures: Vec<[u8; 64]>,
    /// Hash of the value found at the end of the path.
    pub value_hash: [u8; 32],
    /// True if the path returned a value; false if it timed out or failed.
    pub responded: bool,
}

impl PathProof {
    /// Encode to a CBOR map.
    pub fn to_cbor(&self) -> CborValue {
        let sigs: Vec<CborValue> = self
            .node_signatures
            .iter()
            .map(|s| CborValue::Bytes(s.to_vec()))
            .collect();
        CborValue::Map(alloc::vec![
            (
                CborValue::String("path_id".to_string()),
                CborValue::Bytes(self.path_id.to_vec()),
            ),
            (
                CborValue::String("node_signatures".to_string()),
                CborValue::Array(sigs),
            ),
            (
                CborValue::String("value_hash".to_string()),
                CborValue::Bytes(self.value_hash.to_vec()),
            ),
            (
                CborValue::String("responded".to_string()),
                CborValue::Bool(self.responded),
            ),
        ])
    }

    /// Decode from a CBOR map.
    pub fn from_cbor(v: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = v else {
            return Err(Error::BadFrame("PathProof must be a map"));
        };
        let mut path_id: Option<PathId> = None;
        let mut node_signatures: Option<Vec<[u8; 64]>> = None;
        let mut value_hash: Option<[u8; 32]> = None;
        let mut responded: Option<bool> = None;
        for (k, val) in pairs {
            match k {
                CborValue::String(s) if s == "path_id" => path_id = Some(as_bytes_n::<16>(val)?),
                CborValue::String(s) if s == "node_signatures" => {
                    let items = as_array(val)?;
                    let mut sigs = Vec::with_capacity(items.len());
                    for item in items {
                        sigs.push(as_bytes_n::<64>(item)?);
                    }
                    node_signatures = Some(sigs);
                }
                CborValue::String(s) if s == "value_hash" => {
                    value_hash = Some(as_bytes_n::<32>(val)?)
                }
                CborValue::String(s) if s == "responded" => responded = Some(as_bool(val)?),
                CborValue::String(_) => {
                    return Err(Error::BadFrame("unknown key in PathProof"))
                }
                _ => return Err(Error::BadFrame("PathProof keys must be text")),
            }
        }
        Ok(Self {
            path_id: path_id.ok_or(Error::BadFrame("missing path_id"))?,
            node_signatures: node_signatures
                .ok_or(Error::BadFrame("missing node_signatures"))?,
            value_hash: value_hash.ok_or(Error::BadFrame("missing value_hash"))?,
            responded: responded.ok_or(Error::BadFrame("missing responded"))?,
        })
    }

    /// Encode a list of proofs.
    pub fn list_to_cbor(proofs: &[PathProof]) -> CborValue {
        CborValue::Array(proofs.iter().map(|p| p.to_cbor()).collect())
    }

    /// Decode a list of proofs.
    pub fn list_from_cbor(v: &CborValue) -> Result<Vec<PathProof>> {
        as_array(v)?.iter().map(PathProof::from_cbor).collect()
    }
}

// -------------------------------------------------------------------------
// coral_lookup
// -------------------------------------------------------------------------

/// `coral_lookup` — request a multi-path DHT lookup (§13.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoralLookup {
    /// Key being looked up.
    pub key: Key,
    /// Independent lookup paths to follow.
    pub lookup_paths: Vec<LookupPath>,
    /// Witness ring being sought.
    pub witness_ring_id: [u8; 32],
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// The requester.
    pub requester: NodeId,
    /// Ed25519 signature by `requester`.
    pub signature: [u8; 64],
}

impl CoralLookup {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "coral_lookup",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                LookupPath::list_to_cbor(&self.lookup_paths),
                CborValue::Bytes(self.witness_ring_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.requester.to_vec()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "coral_lookup" {
            return Err(Error::BadFrame("not a coral_lookup"));
        }
        let f = fields(&v, "coral_lookup")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("coral_lookup arity"));
        }
        Ok(Self {
            key: as_bytes_n::<32>(&f[0])?,
            lookup_paths: LookupPath::list_from_cbor(&f[1])?,
            witness_ring_id: as_bytes_n::<32>(&f[2])?,
            timestamp: Timestamp::from_millis(as_u64(&f[3])?),
            requester: as_node_id(&f[4])?,
            signature: as_bytes_n::<64>(&f[5])?,
        })
    }

    /// Bytes covered by `signature` (§10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "coral_lookup",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                LookupPath::list_to_cbor(&self.lookup_paths),
                CborValue::Bytes(self.witness_ring_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.requester.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `requester`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.requester, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// coral_lookup_response
// -------------------------------------------------------------------------

/// `coral_lookup_response` — a path's lookup result (§13.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LookupResponse {
    /// Key that was looked up.
    pub key: Key,
    /// Values found (opaque to the protocol).
    pub values: Vec<Vec<u8>>,
    /// Cryptographic proof for each path followed.
    pub path_proofs: Vec<PathProof>,
    /// The responder.
    pub responder: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `responder`.
    pub signature: [u8; 64],
}

impl LookupResponse {
    /// Build the CBOR array for this message, signature included.
    ///
    /// Exposed to the enclosing module so `CrossPathValidation` can embed
    /// this message without a byte round-trip. Kept `pub(crate)` because
    /// callers outside this module should use `to_bytes`.
    pub(crate) fn to_cbor(&self) -> CborValue {
        let values: Vec<CborValue> = self
            .values
            .iter()
            .map(|v| CborValue::Bytes(v.clone()))
            .collect();
        envelope(
            "coral_lookup_response",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                CborValue::Array(values),
                PathProof::list_to_cbor(&self.path_proofs),
                CborValue::Bytes(self.responder.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(encode(&self.to_cbor())?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "coral_lookup_response" {
            return Err(Error::BadFrame("not a coral_lookup_response"));
        }
        let f = fields(&v, "coral_lookup_response")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("coral_lookup_response arity"));
        }
        let values: Vec<Vec<u8>> = as_array(&f[1])?
            .iter()
            .map(as_bytes)
            .collect::<Result<_>>()?;
        Ok(Self {
            key: as_bytes_n::<32>(&f[0])?,
            values,
            path_proofs: PathProof::list_from_cbor(&f[2])?,
            responder: as_node_id(&f[3])?,
            timestamp: Timestamp::from_millis(as_u64(&f[4])?),
            signature: as_bytes_n::<64>(&f[5])?,
        })
    }

    /// Bytes covered by `signature`.
    ///
    /// The `path_proofs` field is preserved verbatim (its own internal
    /// signatures are not stripped) per the nested-signature rule in
    /// §10.1.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let values: Vec<CborValue> = self
            .values
            .iter()
            .map(|v| CborValue::Bytes(v.clone()))
            .collect();
        let msg = envelope(
            "coral_lookup_response",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                CborValue::Array(values),
                PathProof::list_to_cbor(&self.path_proofs),
                CborValue::Bytes(self.responder.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `responder`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.responder, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// spillover
// -------------------------------------------------------------------------

/// `spillover` — request a re-lookup when a path misbehaves (§13.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpilloverRequest {
    /// The original lookup key.
    pub original_key: Key,
    /// Witnesses the requester believes were falsely rejected.
    pub rejected_witnesses: Vec<NodeId>,
    /// Reason code (§13.8): 0 = timeout, 1 = invalid signature,
    /// 2 = conflicting claims, 3 = network error.
    pub rejection_reason: u64,
    /// Alternative paths to try.
    pub alternate_paths: Vec<LookupPath>,
    /// The requester.
    pub requester: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `requester`.
    pub signature: [u8; 64],
}

impl SpilloverRequest {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "spillover",
            alloc::vec![
                CborValue::Bytes(self.original_key.to_vec()),
                node_list_to_cbor(&self.rejected_witnesses),
                CborValue::Int(self.rejection_reason as i128),
                LookupPath::list_to_cbor(&self.alternate_paths),
                CborValue::Bytes(self.requester.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "spillover" {
            return Err(Error::BadFrame("not a spillover"));
        }
        let f = fields(&v, "spillover")?;
        if f.len() != 7 {
            return Err(Error::BadFrame("spillover arity"));
        }
        Ok(Self {
            original_key: as_bytes_n::<32>(&f[0])?,
            rejected_witnesses: as_node_ids(&f[1])?,
            rejection_reason: as_u64(&f[2])?,
            alternate_paths: LookupPath::list_from_cbor(&f[3])?,
            requester: as_node_id(&f[4])?,
            timestamp: Timestamp::from_millis(as_u64(&f[5])?),
            signature: as_bytes_n::<64>(&f[6])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "spillover",
            alloc::vec![
                CborValue::Bytes(self.original_key.to_vec()),
                node_list_to_cbor(&self.rejected_witnesses),
                CborValue::Int(self.rejection_reason as i128),
                LookupPath::list_to_cbor(&self.alternate_paths),
                CborValue::Bytes(self.requester.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `requester`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.requester, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// spillover_response
// -------------------------------------------------------------------------

/// `spillover_response` — the result of a spillover lookup (§13.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpilloverResponse {
    /// The original lookup key.
    pub original_key: Key,
    /// Witnesses the responder believes are valid.
    pub alternate_witnesses: Vec<NodeId>,
    /// Cryptographic proofs for the paths followed.
    pub path_proofs: Vec<PathProof>,
    /// Consensus level: 0 = none, 1 = partial, 2 = full.
    pub consensus: u64,
    /// The responder.
    pub responder: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `responder`.
    pub signature: [u8; 64],
}

impl SpilloverResponse {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "spillover_response",
            alloc::vec![
                CborValue::Bytes(self.original_key.to_vec()),
                node_list_to_cbor(&self.alternate_witnesses),
                PathProof::list_to_cbor(&self.path_proofs),
                CborValue::Int(self.consensus as i128),
                CborValue::Bytes(self.responder.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "spillover_response" {
            return Err(Error::BadFrame("not a spillover_response"));
        }
        let f = fields(&v, "spillover_response")?;
        if f.len() != 7 {
            return Err(Error::BadFrame("spillover_response arity"));
        }
        Ok(Self {
            original_key: as_bytes_n::<32>(&f[0])?,
            alternate_witnesses: as_node_ids(&f[1])?,
            path_proofs: PathProof::list_from_cbor(&f[2])?,
            consensus: as_u64(&f[3])?,
            responder: as_node_id(&f[4])?,
            timestamp: Timestamp::from_millis(as_u64(&f[5])?),
            signature: as_bytes_n::<64>(&f[6])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "spillover_response",
            alloc::vec![
                CborValue::Bytes(self.original_key.to_vec()),
                node_list_to_cbor(&self.alternate_witnesses),
                PathProof::list_to_cbor(&self.path_proofs),
                CborValue::Int(self.consensus as i128),
                CborValue::Bytes(self.responder.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `responder`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.responder, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// cross_path_validation
// -------------------------------------------------------------------------

/// `cross_path_validation` — check that multiple paths agree (§13.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossPathValidation {
    /// The lookup key.
    pub key: Key,
    /// Responses from the paths being validated.
    pub path_responses: Vec<LookupResponse>,
    /// The candidate witness ring.
    pub witness_ring: Vec<NodeId>,
    /// The requester.
    pub requester: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `requester`.
    ///
    /// Per §10.1, this covers the `path_responses` field with its inner
    /// signatures intact.
    pub signature: [u8; 64],
}

impl CrossPathValidation {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let responses: Vec<CborValue> = self
            .path_responses
            .iter()
            .map(LookupResponse::to_cbor)
            .collect();
        let msg = envelope(
            "cross_path_validation",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                CborValue::Array(responses),
                node_list_to_cbor(&self.witness_ring),
                CborValue::Bytes(self.requester.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "cross_path_validation" {
            return Err(Error::BadFrame("not a cross_path_validation"));
        }
        let f = fields(&v, "cross_path_validation")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("cross_path_validation arity"));
        }
        let items = as_array(&f[1])?;
        let mut path_responses = Vec::with_capacity(items.len());
        for item in items {
            let inner = encode(item)?;
            path_responses.push(LookupResponse::from_bytes(&inner)?);
        }
        Ok(Self {
            key: as_bytes_n::<32>(&f[0])?,
            path_responses,
            witness_ring: as_node_ids(&f[2])?,
            requester: as_node_id(&f[3])?,
            timestamp: Timestamp::from_millis(as_u64(&f[4])?),
            signature: as_bytes_n::<64>(&f[5])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let responses: Vec<CborValue> = self
            .path_responses
            .iter()
            .map(LookupResponse::to_cbor)
            .collect();
        let msg = envelope(
            "cross_path_validation",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                CborValue::Array(responses),
                node_list_to_cbor(&self.witness_ring),
                CborValue::Bytes(self.requester.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `requester`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.requester, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// cross_path_result
// -------------------------------------------------------------------------

/// `cross_path_result` — the outcome of cross-path validation (§13.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CrossPathResult {
    /// The lookup key.
    pub key: Key,
    /// True if the paths agreed.
    pub consensus_reached: bool,
    /// Witnesses all agreeing paths included.
    pub agreed_witnesses: Vec<NodeId>,
    /// Witnesses present on some paths but not on others.
    pub conflicting_witnesses: Vec<NodeId>,
    /// The validator.
    pub validator: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `validator`.
    pub signature: [u8; 64],
}

impl CrossPathResult {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cross_path_result",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                CborValue::Bool(self.consensus_reached),
                node_list_to_cbor(&self.agreed_witnesses),
                node_list_to_cbor(&self.conflicting_witnesses),
                CborValue::Bytes(self.validator.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "cross_path_result" {
            return Err(Error::BadFrame("not a cross_path_result"));
        }
        let f = fields(&v, "cross_path_result")?;
        if f.len() != 7 {
            return Err(Error::BadFrame("cross_path_result arity"));
        }
        Ok(Self {
            key: as_bytes_n::<32>(&f[0])?,
            consensus_reached: as_bool(&f[1])?,
            agreed_witnesses: as_node_ids(&f[2])?,
            conflicting_witnesses: as_node_ids(&f[3])?,
            validator: as_node_id(&f[4])?,
            timestamp: Timestamp::from_millis(as_u64(&f[5])?),
            signature: as_bytes_n::<64>(&f[6])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "cross_path_result",
            alloc::vec![
                CborValue::Bytes(self.key.to_vec()),
                CborValue::Bool(self.consensus_reached),
                node_list_to_cbor(&self.agreed_witnesses),
                node_list_to_cbor(&self.conflicting_witnesses),
                CborValue::Bytes(self.validator.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `validator`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.validator, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// XOR distance and witness selection (§5.3.2)
// -------------------------------------------------------------------------

/// Compute the Kademlia XOR distance between two 32-byte values.
pub fn xor_distance(a: &NodeId, b: &NodeId) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Compare two NodeIds by their XOR distance from `target`.
pub fn compare_by_distance(target: &NodeId, a: &NodeId, b: &NodeId) -> core::cmp::Ordering {
    xor_distance(target, a).cmp(&xor_distance(target, b))
}

/// Select the `k` closest reachable nodes to `target`.
pub fn select_witness_ring(
    target: &NodeId,
    candidates: &[NodeId],
    reachable: &BTreeSet<NodeId>,
    k: usize,
) -> Vec<NodeId> {
    let mut filtered: Vec<NodeId> = candidates
        .iter()
        .filter(|c| reachable.contains(*c))
        .copied()
        .collect();
    filtered.sort_by(|a, b| compare_by_distance(target, a, b));
    filtered.truncate(k);
    filtered
}

/// Determine consensus across multiple lookup paths (§13.8).
pub fn cross_path_consensus(
    target: &NodeId,
    paths: &[Vec<NodeId>],
    path_threshold: usize,
    agreement_threshold: usize,
) -> Option<Vec<NodeId>> {
    if paths.len() < path_threshold {
        return None;
    }
    let mut counts: BTreeMap<NodeId, usize> = BTreeMap::new();
    for path in paths {
        let mut seen: BTreeSet<NodeId> = BTreeSet::new();
        for n in path {
            if seen.insert(*n) {
                *counts.entry(*n).or_insert(0) += 1;
            }
        }
    }
    let mut consensus: Vec<NodeId> = counts
        .into_iter()
        .filter(|(_, c)| *c >= path_threshold)
        .map(|(n, _)| n)
        .collect();
    if consensus.len() < agreement_threshold {
        return None;
    }
    consensus.sort_by(|a, b| compare_by_distance(target, a, b));
    Some(consensus)
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn key(b: u8) -> Key {
        [b; 32]
    }

    fn path_id(b: u8) -> PathId {
        [b; 16]
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    fn dummy_path(seed: u8) -> LookupPath {
        LookupPath {
            path_id: path_id(seed),
            nodes: vec![nid(seed), nid(seed.wrapping_add(1))],
            value_hash: [seed; 32],
            ttl: 60,
        }
    }

    fn dummy_proof(seed: u8, responded: bool) -> PathProof {
        PathProof {
            path_id: path_id(seed),
            node_signatures: vec![[seed; 64]],
            value_hash: [seed; 32],
            responded,
        }
    }

    // ---- inner structures ----

    #[test]
    fn lookup_path_roundtrip() {
        let p = dummy_path(1);
        let cbor = p.to_cbor();
        assert_eq!(LookupPath::from_cbor(&cbor).unwrap(), p);
    }

    #[test]
    fn lookup_path_rejects_wrong_type() {
        assert!(LookupPath::from_cbor(&CborValue::Int(1)).is_err());
    }

    #[test]
    fn lookup_path_list_roundtrip() {
        let paths = vec![dummy_path(1), dummy_path(2)];
        let cbor = LookupPath::list_to_cbor(&paths);
        assert_eq!(LookupPath::list_from_cbor(&cbor).unwrap(), paths);
    }

    #[test]
    fn path_proof_roundtrip() {
        let p = dummy_proof(3, true);
        let cbor = p.to_cbor();
        assert_eq!(PathProof::from_cbor(&cbor).unwrap(), p);
    }

    #[test]
    fn path_proof_roundtrip_not_responded() {
        let p = dummy_proof(4, false);
        let cbor = p.to_cbor();
        assert_eq!(PathProof::from_cbor(&cbor).unwrap(), p);
    }

    // ---- top-level messages ----

    #[test]
    fn coral_lookup_roundtrip() {
        let m = CoralLookup {
            key: key(1),
            lookup_paths: vec![dummy_path(1), dummy_path(2), dummy_path(3)],
            witness_ring_id: [0x42; 32],
            timestamp: now(),
            requester: nid(7),
            signature: [0xab; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(CoralLookup::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn lookup_response_roundtrip() {
        let m = LookupResponse {
            key: key(1),
            values: vec![vec![1, 2, 3], vec![4, 5]],
            path_proofs: vec![dummy_proof(1, true), dummy_proof(2, false)],
            responder: nid(8),
            timestamp: now(),
            signature: [0xcd; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(LookupResponse::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn spillover_request_roundtrip() {
        let m = SpilloverRequest {
            original_key: key(2),
            rejected_witnesses: vec![nid(3), nid(4)],
            rejection_reason: 1,
            alternate_paths: vec![dummy_path(5)],
            requester: nid(9),
            timestamp: now(),
            signature: [0xef; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(SpilloverRequest::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn spillover_response_roundtrip() {
        let m = SpilloverResponse {
            original_key: key(2),
            alternate_witnesses: vec![nid(3), nid(4), nid(5)],
            path_proofs: vec![dummy_proof(6, true)],
            consensus: 2,
            responder: nid(10),
            timestamp: now(),
            signature: [0x12; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(SpilloverResponse::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn cross_path_validation_roundtrip() {
        let inner = LookupResponse {
            key: key(3),
            values: vec![vec![9]],
            path_proofs: vec![dummy_proof(1, true)],
            responder: nid(11),
            timestamp: now(),
            signature: [0x34; 64],
        };
        let m = CrossPathValidation {
            key: key(3),
            path_responses: vec![inner.clone(), inner],
            witness_ring: vec![nid(1), nid(2), nid(3), nid(4)],
            requester: nid(12),
            timestamp: now(),
            signature: [0x56; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(CrossPathValidation::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn cross_path_result_roundtrip() {
        let m = CrossPathResult {
            key: key(4),
            consensus_reached: true,
            agreed_witnesses: vec![nid(1), nid(2), nid(3)],
            conflicting_witnesses: vec![nid(4)],
            validator: nid(13),
            timestamp: now(),
            signature: [0x78; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(CrossPathResult::from_bytes(&bytes).unwrap(), m);
    }

    // ---- signing payload ----

    #[test]
    fn coral_lookup_signing_payload_excludes_signature() {
        let m = CoralLookup {
            key: key(1),
            lookup_paths: vec![],
            witness_ring_id: [0; 32],
            timestamp: now(),
            requester: nid(7),
            signature: [0xff; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "coral_lookup").unwrap();
        assert_eq!(f.len(), 5, "signature field must be omitted");

        let mut other = m.clone();
        other.signature = [0x00; 64];
        assert_eq!(other.signing_payload().unwrap(), payload);
    }

    #[test]
    fn cross_path_validation_preserves_inner_signatures() {
        let inner = LookupResponse {
            key: key(3),
            values: vec![],
            path_proofs: vec![],
            responder: nid(11),
            timestamp: now(),
            signature: [0xaa; 64],
        };
        let m = CrossPathValidation {
            key: key(3),
            path_responses: vec![inner.clone()],
            witness_ring: vec![],
            requester: nid(12),
            timestamp: now(),
            signature: [0xbb; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "cross_path_validation").unwrap();
        let responses = as_array(&f[1]).unwrap();
        let inner_decoded =
            LookupResponse::from_bytes(&encode(&responses[0]).unwrap()).unwrap();
        assert_eq!(inner_decoded.signature, [0xaa; 64]);
    }

    // ---- XOR distance ----

    #[test]
    fn xor_distance_is_symmetric() {
        let a = nid(0x12);
        let b = nid(0x34);
        assert_eq!(xor_distance(&a, &b), xor_distance(&b, &a));
    }

    #[test]
    fn xor_distance_zero_iff_equal() {
        let a = nid(0x42);
        assert_eq!(xor_distance(&a, &a), [0u8; 32]);
        assert_ne!(xor_distance(&a, &nid(0x43)), [0u8; 32]);
    }

    #[test]
    fn compare_by_distance_orders_by_xor() {
        let target = [0u8; 32];
        let near = nid(0x01);
        let far = nid(0xff);
        assert_eq!(
            compare_by_distance(&target, &near, &far),
            core::cmp::Ordering::Less
        );
        assert_eq!(
            compare_by_distance(&target, &far, &near),
            core::cmp::Ordering::Greater
        );
    }

    // ---- witness selection ----

    #[test]
    fn select_witness_ring_returns_k_closest() {
        let target = [0u8; 32];
        let candidates: Vec<NodeId> = (1u8..=10).map(nid).collect();
        let reachable: BTreeSet<NodeId> = candidates.iter().copied().collect();
        let ring = select_witness_ring(&target, &candidates, &reachable, 7);
        assert_eq!(ring.len(), 7);
        assert_eq!(ring, (1u8..=7).map(nid).collect::<Vec<_>>());
    }

    #[test]
    fn select_witness_ring_filters_unreachable() {
        let target = [0u8; 32];
        let candidates: Vec<NodeId> = (1u8..=10).map(nid).collect();
        let reachable: BTreeSet<NodeId> = vec![nid(3), nid(5), nid(7)].into_iter().collect();
        let ring = select_witness_ring(&target, &candidates, &reachable, 7);
        assert_eq!(ring, vec![nid(3), nid(5), nid(7)]);
    }

    #[test]
    fn select_witness_ring_truncates_to_k() {
        let target = [0u8; 32];
        let candidates: Vec<NodeId> = (1u8..=20).map(nid).collect();
        let reachable: BTreeSet<NodeId> = candidates.iter().copied().collect();
        assert_eq!(
            select_witness_ring(&target, &candidates, &reachable, 4).len(),
            4
        );
    }

    // ---- cross-path consensus ----

    #[test]
    fn cross_path_consensus_two_of_three() {
        let target = [0u8; 32];
        let w = |b: u8| nid(b);
        let paths = vec![
            vec![w(1), w(2), w(3), w(4), w(5)],
            vec![w(1), w(2), w(3), w(4), w(5)],
            vec![w(6), w(7), w(8), w(9), w(10)],
        ];
        let result = cross_path_consensus(&target, &paths, 2, 3).unwrap();
        assert_eq!(result, vec![w(1), w(2), w(3), w(4), w(5)]);
    }

    #[test]
    fn cross_path_consensus_returns_none_below_agreement() {
        let target = [0u8; 32];
        let paths = vec![
            vec![nid(1), nid(2)],
            vec![nid(3), nid(4)],
            vec![nid(5), nid(6)],
        ];
        assert!(cross_path_consensus(&target, &paths, 2, 3).is_none());
    }

    #[test]
    fn cross_path_consensus_requires_enough_paths() {
        let target = [0u8; 32];
        let paths = vec![vec![nid(1), nid(2), nid(3)]];
        assert!(cross_path_consensus(&target, &paths, 2, 3).is_none());
    }

    #[test]
    fn cross_path_consensus_single_path_votes_do_not_double_count() {
        let target = [0u8; 32];
        let paths = vec![
            vec![nid(1), nid(1), nid(1), nid(2), nid(3)],
            vec![nid(4), nid(5), nid(6)],
        ];
        // Only nid(1) has any chance of appearing on both paths, and the
        // duplicates within one path count once. With agreement=2, no
        // witness reaches it, so the result is None.
        assert!(cross_path_consensus(&target, &paths, 2, 2).is_none());
    }

    #[test]
    fn cross_path_consensus_sorted_by_distance() {
        let target = [0u8; 32];
        let paths = vec![
            vec![nid(0x40), nid(0x10), nid(0x20)],
            vec![nid(0x40), nid(0x10), nid(0x20)],
        ];
        let result = cross_path_consensus(&target, &paths, 2, 1).unwrap();
        // Sorted ascending by XOR distance from 0: 0x10 < 0x20 < 0x40.
        assert_eq!(result, vec![nid(0x10), nid(0x20), nid(0x40)]);
    }
}