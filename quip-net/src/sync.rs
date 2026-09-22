//! SYNC-plane verbs (T1, spec §14.2).
//!
//! Wire forms (all wrapped as `["quip-v1", verb, ...]` QUIP-CBOR):
//!
//! ```text
//! get    = ["get", resource_id: bytes, their_dvv: DVV]
//! set    = ["set", resource_id, new_dvv, payload, cid,
//!           ?previous_cid: (CIDOrV1 / null), ?hash_algo: uint]
//! sync   = ["sync", resource_id, their_dvv, deltas: [* bytes]]
//! rbsr_sync     = ["rbsr_sync", resource_id, their_dvv,
//!                  ranges: [* Range], fingerprint: Fingerprint, ?cid]
//! rbsr_response = ["rbsr_response", resource_id,
//!                  ranges: [* Range], deltas: [* bytes], ?cid]
//! pin           = ["pin", resource_id, cid, ttl, ?witness_ring]
//! unpin         = ["unpin", resource_id, ?cid]
//! query_pins    = ["query_pins", ?resource_id: (bytes / null), ?cid]
//! pin_list      = ["pin_list", pins: [* PinEntry]]
//! query_quarantined = ["query_quarantined",
//!                      ?resource_id: (bytes / null), ?cid]
//! ```
//!
//! # Nullable positional slots
//!
//! In `set`, `query_pins`, and `query_quarantined`, a `null` in a positional
//! slot means "this filter is absent" and is permitted **only** when a later
//! positional slot in the same message is non-null. A `null` at the last
//! occupied position is NOT RECOMMENDED — senders SHOULD omit the trailing
//! field instead, and receivers SHOULD normalize a trailing `null` to
//! absence. See the CDDL block in spec §14.2 for the canonical wire forms.

use crate::codec::{as_bytes, as_u64, envelope, fields, verb_of};
use crate::error::{Error, Result};
use crate::sync_codec as sc;
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::cid::CidOrV1;
#[allow(unused_imports)]
use quip_core::dvv::cbor as dvv_cbor;
use quip_core::dvv::{Dvv, NodeId};

/// Re-exported range cap (spec: at most 1024 ranges per RBSR message).
pub use quip_core::constants::MAX_RANGES;

/// RBSR fingerprint algorithm identifiers.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum FingerprintAlgo {
    /// XOR of range hashes (MUST implement).
    Xor = 0,
    /// Invertible Bloom Lookup Table (OPTIONAL).
    Iblt = 1,
    /// Merkle tree root (OPTIONAL).
    Merkle = 2,
}

impl FingerprintAlgo {
    /// Parse a wire algorithm id.
    pub fn from_u64(v: u64) -> Result<Self> {
        match v {
            0 => Ok(Self::Xor),
            1 => Ok(Self::Iblt),
            2 => Ok(Self::Merkle),
            _ => Err(Error::BadFrame("unknown fingerprint algo")),
        }
    }
}

/// Fingerprint envelope `[algo: uint, value: bytes]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fingerprint {
    /// Algorithm used.
    pub algo: FingerprintAlgo,
    /// Opaque fingerprint bytes.
    pub value: Vec<u8>,
}

/// A byte range with its content hash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// Start byte offset.
    pub start: u64,
    /// Inclusive end byte offset.
    pub end: u64,
    /// 32-byte hash of `payload[start..=end]`.
    pub hash: [u8; 32],
}

/// `get = ["get", resource_id: bytes, their_dvv: DVV]`.
#[derive(Clone, Debug, PartialEq)]
pub struct GetRequest {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Requestor's current DVV for the resource.
    pub their_dvv: Dvv,
}

/// `set = ["set", resource_id, new_dvv, payload, cid, ?previous_cid, ?hash_algo]`.
///
/// `previous_cid` may be encoded as `null` when the sender wants to signal
/// `hash_algo` without a prior CID (first write). See the module doc.
#[derive(Clone, Debug, PartialEq)]
pub struct SetRequest {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// DVV after applying this write.
    pub new_dvv: Dvv,
    /// Raw payload bytes.
    pub payload: Vec<u8>,
    /// CID of `payload`.
    pub cid: CidOrV1,
    /// Previous CID (optimistic concurrency), if known.
    pub previous_cid: Option<CidOrV1>,
    /// Hash algorithm id (0 = SHA-256 default; ignored for CIDv1).
    pub hash_algo: Option<u64>,
}

/// `sync = ["sync", resource_id, their_dvv, deltas: [* bytes]]`.
#[derive(Clone, Debug, PartialEq)]
pub struct SyncRequest {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Requestor's current DVV.
    pub their_dvv: Dvv,
    /// Opaque DVV deltas.
    pub deltas: Vec<Vec<u8>>,
}

/// Short alias for a sync reply.
pub type SyncResponse = SyncRequest;

/// `rbsr_sync` request envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct RbsrRequest {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Requestor's current DVV.
    pub their_dvv: Dvv,
    /// Range hashes covered by `fingerprint`.
    pub ranges: Vec<Range>,
    /// Set fingerprint.
    pub fingerprint: Fingerprint,
    /// Optional CID hint for the full resource.
    pub cid: Option<CidOrV1>,
}

/// `rbsr_response` envelope.
#[derive(Clone, Debug, PartialEq)]
pub struct RbsrResponse {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Ranges the responder disagrees on / wants.
    pub ranges: Vec<Range>,
    /// Missing payload slices.
    pub deltas: Vec<Vec<u8>>,
    /// Optional CID hint.
    pub cid: Option<CidOrV1>,
}

/// `pin = ["pin", resource_id, cid, ttl, ?witness_ring]`.
///
/// `PinQuery.cid` is `None` only for the filter-only shape of `query_pins`;
/// on the wire `pin` always carries a CID. `witness_ring` is optional.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinQuery {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// CID to pin (None = filter-only query).
    pub cid: Option<CidOrV1>,
    /// TTL in seconds (0 = default 7 days).
    pub ttl_seconds: u64,
    /// Optional witness ring accompanying the pin.
    pub witness_ring: Vec<NodeId>,
}

/// `unpin = ["unpin", resource_id, ?cid]`; absent cid = unpin all versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnpinRequest {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// CID to release, or None for all versions.
    pub cid: Option<CidOrV1>,
}

/// `query_pins = ["query_pins", ?resource_id: (bytes / null), ?cid]`.
///
/// Both fields are optional; a `null` in the `resource_id` slot is used to
/// signal "no resource filter" when a `cid` filter is still supplied.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct QueryPins {
    /// Optional resource name filter (`None` = no filter).
    pub resource_id: Option<Vec<u8>>,
    /// Optional version filter.
    pub cid: Option<CidOrV1>,
}

/// `pin_list = ["pin_list", pins: [* PinEntry]]`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PinList {
    /// Pins in the response (remaining TTL per `PinEntry.ttl`).
    pub pins: Vec<quip_core::messages::PinEntry>,
}

/// `query_quarantined = ["query_quarantined",
///                     ?resource_id: (bytes / null), ?cid]`
/// (spec §14.2 governance queries, OPTIONAL).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct QueryQuarantined {
    /// Optional resource name filter (`None` = no filter).
    pub resource_id: Option<Vec<u8>>,
    /// Optional version filter.
    pub cid: Option<CidOrV1>,
}

/// XOR fingerprint accumulator (algo 0).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct XorFingerprint(pub [u8; 32]);

impl XorFingerprint {
    /// Fold one 32-byte range hash in.
    pub fn absorb(&mut self, hash: &[u8; 32]) {
        for (a, b) in self.0.iter_mut().zip(hash.iter()) {
            *a ^= *b;
        }
    }
    /// Finish as a [`Fingerprint`].
    pub fn finish(&self) -> Fingerprint {
        Fingerprint {
            algo: FingerprintAlgo::Xor,
            value: self.0.to_vec(),
        }
    }
}

/// Stateful RBSR reconciler: tracks advertised ranges, finds missing ones.
#[derive(Clone, Debug, Default)]
pub struct RbsrReconciler {
    have: Vec<Range>,
    want: Vec<Range>,
}

impl RbsrReconciler {
    /// Create an empty reconciler.
    pub fn new() -> Self {
        Self::default()
    }
    /// Record locally held ranges.
    pub fn advertise(&mut self, ranges: Vec<Range>) {
        self.have = ranges;
    }
    /// Compare a remote fingerprint; queue ranges whose hash differs.
    pub fn reconcile(&mut self, remote: &[Range]) -> Vec<Range> {
        let mut missing = Vec::new();
        for r in remote {
            let same = self
                .have
                .iter()
                .any(|h| h.start == r.start && h.end == r.end && h.hash == r.hash);
            if !same {
                missing.push(r.clone());
            }
        }
        self.want = missing.clone();
        missing
    }
    /// Ranges currently wanted.
    pub fn wanted(&self) -> &[Range] {
        &self.want
    }
}

impl GetRequest {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "get",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                sc::dvv_field(&self.their_dvv),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "get" {
            return Err(Error::BadFrame("not a get"));
        }
        let f = fields(&v, "get")?;
        if f.len() != 2 {
            return Err(Error::BadFrame("get arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            their_dvv: sc::dvv_from(&f[1])?,
        })
    }
}

impl SetRequest {
    /// Encode to QUIP-CBOR bytes.
    ///
    /// `previous_cid` is emitted as `null` when `hash_algo` is present but
    /// `previous_cid` is absent, per the spec's nullable-slot rule. When both
    /// are absent the trailing fields are omitted entirely.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = alloc::vec![
            CborValue::Bytes(self.resource_id.clone()),
            sc::dvv_field(&self.new_dvv),
            CborValue::Bytes(self.payload.clone()),
            self.cid.to_cbor(),
        ];
        match (&self.previous_cid, self.hash_algo) {
            (None, None) => {}
            (prev, algo) => {
                f.push(sc::opt_cid_to_cbor(prev));
                if let Some(a) = algo {
                    f.push(CborValue::Int(a as i128));
                }
            }
        }
        Ok(encode(&envelope("set", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    ///
    /// Accepts `null` in the `previous_cid` slot (see module doc).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "set" {
            return Err(Error::BadFrame("not a set"));
        }
        let f = fields(&v, "set")?;
        if f.len() < 4 || f.len() > 6 {
            return Err(Error::BadFrame("set arity"));
        }
        let mut previous_cid = None;
        let mut hash_algo = None;
        if f.len() >= 5 {
            previous_cid = sc::opt_cid_from_cbor(&f[4])?;
        }
        if f.len() == 6 {
            hash_algo = Some(as_u64(&f[5])?);
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            new_dvv: sc::dvv_from(&f[1])?,
            payload: as_bytes(&f[2])?,
            cid: CidOrV1::from_cbor(&f[3])?,
            previous_cid,
            hash_algo,
        })
    }
}

impl SyncRequest {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let deltas = CborValue::Array(
            self.deltas
                .iter()
                .map(|d| CborValue::Bytes(d.clone()))
                .collect(),
        );
        let msg = envelope(
            "sync",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                sc::dvv_field(&self.their_dvv),
                deltas,
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "sync" {
            return Err(Error::BadFrame("not a sync"));
        }
        let f = fields(&v, "sync")?;
        if f.len() != 3 {
            return Err(Error::BadFrame("sync arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            their_dvv: sc::dvv_from(&f[1])?,
            deltas: sc::bytes_list(&f[2])?,
        })
    }
}

impl RbsrRequest {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = alloc::vec![
            CborValue::Bytes(self.resource_id.clone()),
            sc::dvv_field(&self.their_dvv),
            sc::ranges_to_cbor(&self.ranges),
            sc::fingerprint_to_cbor(&self.fingerprint),
        ];
        if let Some(cid) = &self.cid {
            f.push(cid.to_cbor());
        }
        Ok(encode(&envelope("rbsr_sync", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "rbsr_sync" {
            return Err(Error::BadFrame("not an rbsr_sync"));
        }
        let f = fields(&v, "rbsr_sync")?;
        if f.len() != 4 && f.len() != 5 {
            return Err(Error::BadFrame("rbsr_sync arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            their_dvv: sc::dvv_from(&f[1])?,
            ranges: sc::ranges_from_cbor(&f[2])?,
            fingerprint: sc::fingerprint_from_cbor(&f[3])?,
            cid: if f.len() == 5 {
                Some(CidOrV1::from_cbor(&f[4])?)
            } else {
                None
            },
        })
    }
}

impl RbsrResponse {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let deltas = CborValue::Array(
            self.deltas
                .iter()
                .map(|d| CborValue::Bytes(d.clone()))
                .collect(),
        );
        let mut f = alloc::vec![
            CborValue::Bytes(self.resource_id.clone()),
            sc::ranges_to_cbor(&self.ranges),
            deltas,
        ];
        if let Some(cid) = &self.cid {
            f.push(cid.to_cbor());
        }
        Ok(encode(&envelope("rbsr_response", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "rbsr_response" {
            return Err(Error::BadFrame("not an rbsr_response"));
        }
        let f = fields(&v, "rbsr_response")?;
        if f.len() != 3 && f.len() != 4 {
            return Err(Error::BadFrame("rbsr_response arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            ranges: sc::ranges_from_cbor(&f[1])?,
            deltas: sc::bytes_list(&f[2])?,
            cid: if f.len() == 4 {
                Some(CidOrV1::from_cbor(&f[3])?)
            } else {
                None
            },
        })
    }
}

impl PinQuery {
    /// Encode a `pin` verb (`cid` required on the wire).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let cid = self
            .cid
            .as_ref()
            .ok_or(Error::BadFrame("pin requires a cid"))?;
        let mut f = alloc::vec![
            CborValue::Bytes(self.resource_id.clone()),
            cid.to_cbor(),
            CborValue::Int(self.ttl_seconds as i128),
        ];
        if !self.witness_ring.is_empty() {
            f.push(sc::node_list_to_cbor(&self.witness_ring));
        }
        Ok(encode(&envelope("pin", f))?)
    }

    /// Decode a `pin` verb.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "pin" {
            return Err(Error::BadFrame("not a pin"));
        }
        let f = fields(&v, "pin")?;
        if f.len() != 3 && f.len() != 4 {
            return Err(Error::BadFrame("pin arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            cid: Some(CidOrV1::from_cbor(&f[1])?),
            ttl_seconds: as_u64(&f[2])?,
            witness_ring: if f.len() == 4 {
                sc::node_list(&f[3])?
            } else {
                Vec::new()
            },
        })
    }
}

impl UnpinRequest {
    /// Encode (trailing `cid` omitted when `None`).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = alloc::vec![CborValue::Bytes(self.resource_id.clone())];
        if let Some(cid) = &self.cid {
            f.push(cid.to_cbor());
        }
        Ok(encode(&envelope("unpin", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "unpin" {
            return Err(Error::BadFrame("not an unpin"));
        }
        let f = fields(&v, "unpin")?;
        if f.len() != 1 && f.len() != 2 {
            return Err(Error::BadFrame("unpin arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            cid: if f.len() == 2 {
                Some(CidOrV1::from_cbor(&f[1])?)
            } else {
                None
            },
        })
    }
}

impl QueryPins {
    /// Encode.
    ///
    /// Four canonical wire shapes (see module doc):
    /// - `(None, None)` → `["query_pins"]`
    /// - `(Some(rid), None)` → `["query_pins", rid]`
    /// - `(Some(rid), Some(cid))` → `["query_pins", rid, cid]`
    /// - `(None, Some(cid))` → `["query_pins", null, cid]`
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = Vec::new();
        match (&self.resource_id, &self.cid) {
            (None, None) => {}
            (Some(rid), None) => f.push(CborValue::Bytes(rid.clone())),
            (Some(rid), Some(cid)) => {
                f.push(CborValue::Bytes(rid.clone()));
                f.push(cid.to_cbor());
            }
            (None, Some(cid)) => {
                f.push(CborValue::Null);
                f.push(cid.to_cbor());
            }
        }
        Ok(encode(&envelope("query_pins", f))?)
    }

    /// Decode.
    ///
    /// Accepts the four canonical wire shapes plus a trailing `null` in the
    /// `cid` slot (which the spec marks NOT RECOMMENDED but permits); a
    /// trailing `null` is normalized to absence.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "query_pins" {
            return Err(Error::BadFrame("not a query_pins"));
        }
        let f = fields(&v, "query_pins")?;
        if f.len() > 2 {
            return Err(Error::BadFrame("query_pins arity"));
        }
        let mut out = Self::default();
        if !f.is_empty() {
            out.resource_id = sc::opt_bytes(&f[0])?;
        }
        if f.len() == 2 {
            out.cid = sc::opt_cid_from_cbor(&f[1])?;
        }
        Ok(out)
    }
}

impl PinList {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let pins = CborValue::Array(self.pins.iter().map(|p| p.to_cbor()).collect());
        Ok(encode(&envelope("pin_list", alloc::vec![pins]))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "pin_list" {
            return Err(Error::BadFrame("not a pin_list"));
        }
        let f = fields(&v, "pin_list")?;
        if f.len() != 1 {
            return Err(Error::BadFrame("pin_list arity"));
        }
        let CborValue::Array(items) = &f[0] else {
            return Err(Error::BadFrame("pins must be an array"));
        };
        let mut pins = Vec::with_capacity(items.len());
        for item in items {
            pins.push(quip_core::messages::PinEntry::from_cbor(item).map_err(Error::Core)?);
        }
        Ok(Self { pins })
    }

    /// Build a `pin_list` reply from held pins at `now`.
    pub fn from_records(
        records: &[quip_storage::PinRecord],
        now: quip_core::time::Timestamp,
    ) -> Self {
        Self {
            pins: records.iter().map(|r| r.to_entry(now)).collect(),
        }
    }
}

impl QueryQuarantined {
    /// Encode.
    ///
    /// Same four canonical wire shapes as [`QueryPins::to_bytes`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = Vec::new();
        match (&self.resource_id, &self.cid) {
            (None, None) => {}
            (Some(rid), None) => f.push(CborValue::Bytes(rid.clone())),
            (Some(rid), Some(cid)) => {
                f.push(CborValue::Bytes(rid.clone()));
                f.push(cid.to_cbor());
            }
            (None, Some(cid)) => {
                f.push(CborValue::Null);
                f.push(cid.to_cbor());
            }
        }
        Ok(encode(&envelope("query_quarantined", f))?)
    }

    /// Decode.
    ///
    /// Same acceptance rules as [`QueryPins::from_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "query_quarantined" {
            return Err(Error::BadFrame("not a query_quarantined"));
        }
        let f = fields(&v, "query_quarantined")?;
        if f.len() > 2 {
            return Err(Error::BadFrame("query_quarantined arity"));
        }
        let mut out = Self::default();
        if !f.is_empty() {
            out.resource_id = sc::opt_bytes(&f[0])?;
        }
        if f.len() == 2 {
            out.cid = sc::opt_cid_from_cbor(&f[1])?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::cid::Cid;
    use quip_core::dvv::NodeId;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }
    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn get_roundtrip() {
        let g = GetRequest {
            resource_id: b"res".to_vec(),
            their_dvv: Dvv::from_write(nid(1), 3),
        };
        let bytes = g.to_bytes().unwrap();
        let back = GetRequest::from_bytes(&bytes).unwrap();
        assert_eq!(back, g);
    }

    #[test]
    fn set_roundtrip_full() {
        let s = SetRequest {
            resource_id: b"r".to_vec(),
            new_dvv: Dvv::from_write(nid(1), 1),
            payload: b"payload".to_vec(),
            cid: cid(2),
            previous_cid: Some(cid(1)),
            hash_algo: Some(0),
        };
        let bytes = s.to_bytes().unwrap();
        let back = SetRequest::from_bytes(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn set_roundtrip_minimal() {
        let s = SetRequest {
            resource_id: b"r".to_vec(),
            new_dvv: Dvv::from_write(nid(1), 1),
            payload: b"payload".to_vec(),
            cid: cid(2),
            previous_cid: None,
            hash_algo: None,
        };
        let bytes = s.to_bytes().unwrap();
        let back = SetRequest::from_bytes(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn set_hash_algo_without_previous_cid_uses_null_slot() {
        // Spec: `["set", rid, dvv, payload, cid, null, hash_algo]`.
        let s = SetRequest {
            resource_id: b"r".to_vec(),
            new_dvv: Dvv::from_write(nid(1), 1),
            payload: b"p".to_vec(),
            cid: cid(2),
            previous_cid: None,
            hash_algo: Some(1),
        };
        let bytes = s.to_bytes().unwrap();
        let v = decode(&bytes).unwrap();
        let CborValue::Array(arr) = &v else { panic!("expected array") };
        // ["quip-v1","set", rid, dvv, payload, cid, null, 1]
        assert_eq!(arr.len(), 8);
        assert_eq!(arr[6], CborValue::Null);
        assert_eq!(arr[7], CborValue::Int(1));
        let back = SetRequest::from_bytes(&bytes).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn pin_with_witness_ring() {
        let p = PinQuery {
            resource_id: b"doc".to_vec(),
            cid: Some(cid(5)),
            ttl_seconds: 7200,
            witness_ring: alloc::vec![nid(1), nid(2)],
        };
        let bytes = p.to_bytes().unwrap();
        let back = PinQuery::from_bytes(&bytes).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn pin_without_cid_errors() {
        let p = PinQuery {
            resource_id: b"doc".to_vec(),
            cid: None,
            ttl_seconds: 7200,
            witness_ring: Vec::new(),
        };
        assert!(p.to_bytes().is_err());
    }

    #[test]
    fn query_pins_arity_variants() {
        // (None, None)
        let none = QueryPins::default();
        assert_eq!(QueryPins::from_bytes(&none.to_bytes().unwrap()).unwrap(), none);

        // (Some, None)
        let rid_only = QueryPins {
            resource_id: Some(b"r".to_vec()),
            cid: None,
        };
        assert_eq!(
            QueryPins::from_bytes(&rid_only.to_bytes().unwrap()).unwrap(),
            rid_only
        );

        // (Some, Some)
        let both = QueryPins {
            resource_id: Some(b"r".to_vec()),
            cid: Some(cid(1)),
        };
        assert_eq!(QueryPins::from_bytes(&both.to_bytes().unwrap()).unwrap(), both);

        // (None, Some) — nullable resource_id slot
        let cid_only = QueryPins {
            resource_id: None,
            cid: Some(cid(1)),
        };
        let bytes = cid_only.to_bytes().unwrap();
        let v = decode(&bytes).unwrap();
        let CborValue::Array(arr) = &v else { panic!("expected array") };
        // ["quip-v1","query_pins", null, cid]
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[2], CborValue::Null);
        assert_eq!(QueryPins::from_bytes(&bytes).unwrap(), cid_only);
    }

    #[test]
    fn query_pins_trailing_null_cid_normalized_to_absence() {
        // Forge `["quip-v1","query_pins", rid, null]` — non-canonical but
        // accepted per spec ("receivers SHOULD normalize").
        let msg = envelope(
            "query_pins",
            alloc::vec![
                CborValue::Bytes(b"r".to_vec()),
                CborValue::Null,
            ],
        );
        let bytes = encode(&msg).unwrap();
        let back = QueryPins::from_bytes(&bytes).unwrap();
        assert_eq!(back.resource_id, Some(b"r".to_vec()));
        assert_eq!(back.cid, None);
    }

    #[test]
    fn query_pins_null_resource_id_only_is_accepted_and_normalized() {
        // `["quip-v1","query_pins", null]` — a trailing null in the
        // resource_id slot. Spec marks this NOT RECOMMENDED but permits
        // reception. We normalize to (None, None).
        let msg = envelope("query_pins", alloc::vec![CborValue::Null]);
        let bytes = encode(&msg).unwrap();
        let back = QueryPins::from_bytes(&bytes).unwrap();
        assert_eq!(back, QueryPins::default());
    }

    #[test]
    fn query_quarantined_arity_variants() {
        let none = QueryQuarantined::default();
        assert_eq!(
            QueryQuarantined::from_bytes(&none.to_bytes().unwrap()).unwrap(),
            none
        );

        let rid_only = QueryQuarantined {
            resource_id: Some(b"r".to_vec()),
            cid: None,
        };
        assert_eq!(
            QueryQuarantined::from_bytes(&rid_only.to_bytes().unwrap()).unwrap(),
            rid_only
        );

        let both = QueryQuarantined {
            resource_id: Some(b"r".to_vec()),
            cid: Some(cid(1)),
        };
        assert_eq!(
            QueryQuarantined::from_bytes(&both.to_bytes().unwrap()).unwrap(),
            both
        );

        let cid_only = QueryQuarantined {
            resource_id: None,
            cid: Some(cid(1)),
        };
        let bytes = cid_only.to_bytes().unwrap();
        let v = decode(&bytes).unwrap();
        let CborValue::Array(arr) = &v else { panic!("expected array") };
        assert_eq!(arr.len(), 4);
        assert_eq!(arr[2], CborValue::Null);
        assert_eq!(
            QueryQuarantined::from_bytes(&bytes).unwrap(),
            cid_only
        );
    }

    #[test]
    fn query_pins_rejects_more_than_two_fields() {
        let msg = envelope(
            "query_pins",
            alloc::vec![
                CborValue::Bytes(b"r".to_vec()),
                cid(1).to_cbor(),
                CborValue::Null,
            ],
        );
        let bytes = encode(&msg).unwrap();
        assert!(QueryPins::from_bytes(&bytes).is_err());
    }

    #[test]
    fn pin_list_roundtrip() {
        let entry = quip_core::messages::PinEntry {
            resource_id: b"a".to_vec(),
            cid: cid(1),
            pinned_at: quip_core::time::Timestamp::from_millis(1_000),
            ttl_seconds: 600,
            ref_count: 1,
            local: true,
        };
        let pl = PinList {
            pins: alloc::vec![entry.clone()],
        };
        let bytes = pl.to_bytes().unwrap();
        let back = PinList::from_bytes(&bytes).unwrap();
        assert_eq!(back.pins.len(), 1);
        assert_eq!(back.pins[0], entry);
    }
}