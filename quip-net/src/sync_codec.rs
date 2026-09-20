//! SYNC codec helpers (internal).
//!
//! Range / fingerprint shapes (§14.2):
//!
//! ```text
//! Range       = [start: uint, end: uint, hash: bytes .size 32]
//! Fingerprint = [algo: uint, value: bytes]
//! ```
use crate::codec::{as_bytes, as_u64};
use crate::error::{Error, Result};
use crate::sync::{Fingerprint, FingerprintAlgo, Range};
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::cid::CidOrV1;
use quip_core::dvv::NodeId;

/// Encode a range triple.
pub fn range_to_cbor(r: &Range) -> CborValue {
    CborValue::Array(alloc::vec![
        CborValue::Int(r.start as i128),
        CborValue::Int(r.end as i128),
        CborValue::Bytes(r.hash.to_vec()),
    ])
}

/// Decode a range triple.
pub fn range_from_cbor(v: &CborValue) -> Result<Range> {
    let CborValue::Array(items) = v else {
        return Err(Error::BadFrame("range must be an array"));
    };
    if items.len() != 3 {
        return Err(Error::BadFrame("range arity"));
    }
    let hash = as_bytes(&items[2])?;
    if hash.len() != 32 {
        return Err(Error::BadFrame("range hash must be 32 bytes"));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&hash);
    Ok(Range { start: as_u64(&items[0])?, end: as_u64(&items[1])?, hash: arr })
}

/// Encode a `[* Range]` list.
pub fn ranges_to_cbor(ranges: &[Range]) -> CborValue {
    CborValue::Array(ranges.iter().map(range_to_cbor).collect())
}

/// Decode a `[* Range]` list, enforcing the §3.1 `MAX_RANGES = 1024` cap.
pub fn ranges_from_cbor(v: &CborValue) -> Result<Vec<Range>> {
    let CborValue::Array(items) = v else {
        return Err(Error::BadFrame("ranges must be an array"));
    };
    if items.len() > crate::sync::MAX_RANGES {
        return Err(Error::TooLarge { size: items.len(), max: crate::sync::MAX_RANGES });
    }
    items.iter().map(range_from_cbor).collect()
}

/// Encode a fingerprint pair.
pub fn fingerprint_to_cbor(f: &Fingerprint) -> CborValue {
    CborValue::Array(alloc::vec![
        CborValue::Int(f.algo as u64 as i128),
        CborValue::Bytes(f.value.clone()),
    ])
}

/// Decode a fingerprint pair.
pub fn fingerprint_from_cbor(v: &CborValue) -> Result<Fingerprint> {
    let CborValue::Array(items) = v else {
        return Err(Error::BadFrame("fingerprint must be an array"));
    };
    if items.len() != 2 {
        return Err(Error::BadFrame("fingerprint arity"));
    }
    Ok(Fingerprint { algo: FingerprintAlgo::from_u64(as_u64(&items[0])?)?, value: as_bytes(&items[1])? })
}

/// Encode an optional CID.
///
/// `None` is encoded as `Null` on the wire for `rbsr_*` tails; the
/// `pin`/`unpin`/`query_pins` verbs omit trailing fields instead (see
/// `sync.rs` codecs).
pub fn opt_cid_to_cbor(cid: &Option<CidOrV1>) -> CborValue {
    match cid {
        Some(c) => c.to_cbor(),
        None => CborValue::Null,
    }
}

/// Decode an optional CID.
pub fn opt_cid_from_cbor(v: &CborValue) -> Result<Option<CidOrV1>> {
    match v {
        CborValue::Null => Ok(None),
        other => Ok(Some(CidOrV1::from_cbor(other)?)),
    }
}

/// Collect a `[* bytes]` array.
pub fn bytes_list(v: &CborValue) -> Result<Vec<Vec<u8>>> {
    let CborValue::Array(items) = v else {
        return Err(Error::BadFrame("expected array"));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(as_bytes(item)?);
    }
    Ok(out)
}

/// Collect a `[* NodeId]` array.
pub fn node_list(v: &CborValue) -> Result<Vec<NodeId>> {
    let CborValue::Array(items) = v else {
        return Err(Error::BadFrame("expected node list"));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let b = as_bytes(item)?;
        if b.len() != 32 {
            return Err(Error::BadFrame("NodeId must be 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&b);
        out.push(arr);
    }
    Ok(out)
}

/// Encode a `[* NodeId]` array.
pub fn node_list_to_cbor(nodes: &[NodeId]) -> CborValue {
    CborValue::Array(nodes.iter().map(|n| CborValue::Bytes(n.to_vec())).collect())
}

/// Encode an optional `bytes` field (`Null` → `None`).
pub fn opt_bytes(v: &CborValue) -> Result<Option<Vec<u8>>> {
    match v {
        CborValue::Null => Ok(None),
        CborValue::Bytes(b) => Ok(Some(b.clone())),
        _ => Err(Error::BadFrame("expected bytes or null")),
    }
}

use quip_core::dvv::cbor as dvv_cbor;
use quip_core::dvv::Dvv;

/// Encode a DVV field for the `get`/`set`/`sync`/`rbsr_sync` verbs.
pub fn dvv_field(dvv: &Dvv) -> CborValue {
    dvv_cbor::to_cbor(dvv)
}

/// Decode a DVV field.
pub fn dvv_from(v: &CborValue) -> Result<Dvv> {
    Ok(dvv_cbor::from_cbor(v)?)
}
