//! Codec helpers shared by verb envelopes.

use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::dvv::NodeId;

/// Extract the verb string from a `["quip-v1", verb, ...]` envelope.
pub fn verb_of(value: &CborValue) -> Result<&str> {
    let CborValue::Array(items) = value else {
        return Err(Error::BadFrame("message must be an array"));
    };
    if items.len() < 2 {
        return Err(Error::BadFrame("message too short"));
    }
    match (&items[0], &items[1]) {
        (CborValue::String(p), CborValue::String(v)) if p == "quip-v1" => Ok(v.as_str()),
        _ => Err(Error::BadFrame("bad prefix or verb")),
    }
}

/// Build a `["quip-v1", verb, ...fields]` envelope.
pub fn envelope(verb: &str, fields: Vec<CborValue>) -> CborValue {
    let mut out = Vec::with_capacity(fields.len() + 2);
    out.push(CborValue::String(alloc::string::ToString::to_string("quip-v1")));
    out.push(CborValue::String(alloc::string::ToString::to_string(verb)));
    out.extend(fields);
    CborValue::Array(out)
}

/// Trailing fields after the prefix.
pub fn fields<'a>(value: &'a CborValue, verb: &str) -> Result<&'a [CborValue]> {
    let CborValue::Array(items) = value else {
        return Err(Error::BadFrame("message must be an array"));
    };
    if items.len() < 2 {
        return Err(Error::BadFrame("message too short"));
    }
    match (&items[0], &items[1]) {
        (CborValue::String(p), CborValue::String(v)) if p == "quip-v1" && v == verb => {
            Ok(&items[2..])
        }
        _ => Err(Error::BadFrame("wrong prefix or verb")),
    }
}

/// Extract bytes field.
pub fn as_bytes(v: &CborValue) -> Result<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Ok(b.clone()),
        _ => Err(Error::BadFrame("expected bytes")),
    }
}

/// Extract u64 field.
pub fn as_u64(v: &CborValue) -> Result<u64> {
    match v {
        CborValue::Int(n) if *n >= 0 && *n <= u64::MAX as i128 => Ok(*n as u64),
        _ => Err(Error::BadFrame("expected uint")),
    }
}

/// Extract a CBOR boolean.
pub fn as_bool(v: &CborValue) -> Result<bool> {
    match v {
        CborValue::Bool(b) => Ok(*b),
        _ => Err(Error::BadFrame("expected a boolean")),
    }
}

/// Borrow a CBOR array as a slice.
pub fn as_array(v: &CborValue) -> Result<&[CborValue]> {
    match v {
        CborValue::Array(items) => Ok(items.as_slice()),
        _ => Err(Error::BadFrame("expected an array")),
    }
}

/// Read a fixed-size byte string.
pub fn as_bytes_n<const N: usize>(v: &CborValue) -> Result<[u8; N]> {
    let bytes = as_bytes(v)?;
    if bytes.len() != N {
        return Err(Error::BadFrame("wrong byte string length"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Read a 32-byte `NodeId`.
pub fn as_node_id(v: &CborValue) -> Result<NodeId> {
    as_bytes_n::<32>(v)
}

/// Read an array of 32-byte `NodeId`s.
pub fn as_node_ids(v: &CborValue) -> Result<Vec<NodeId>> {
    as_array(v)?.iter().map(as_node_id).collect()
}

/// Encode a list of `NodeId`s.
pub fn node_list_to_cbor(nodes: &[NodeId]) -> CborValue {
    CborValue::Array(nodes.iter().map(|n| CborValue::Bytes(n.to_vec())).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn as_bool_accepts_bool() {
        assert!(as_bool(&CborValue::Bool(true)).unwrap());
        assert!(!as_bool(&CborValue::Bool(false)).unwrap());
        assert!(as_bool(&CborValue::Int(1)).is_err());
    }

    #[test]
    fn as_array_borrows_slice() {
        let v = CborValue::Array(vec![CborValue::Int(1), CborValue::Int(2)]);
        assert_eq!(as_array(&v).unwrap().len(), 2);
        assert!(as_array(&CborValue::Int(1)).is_err());
    }

    #[test]
    fn as_bytes_n_enforces_length() {
        let v = CborValue::Bytes(vec![0xab; 32]);
        let out: [u8; 32] = as_bytes_n(&v).unwrap();
        assert_eq!(out[0], 0xab);
        assert!(as_bytes_n::<16>(&v).is_err());
    }

    #[test]
    fn node_id_roundtrip() {
        let v = CborValue::Bytes(nid(7).to_vec());
        assert_eq!(as_node_id(&v).unwrap(), nid(7));
    }

    #[test]
    fn node_list_roundtrip() {
        let nodes = vec![nid(1), nid(2), nid(3)];
        let v = node_list_to_cbor(&nodes);
        assert_eq!(as_node_ids(&v).unwrap(), nodes);
    }
}