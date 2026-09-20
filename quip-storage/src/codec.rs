//! Internal CBOR helpers for the storage record codecs.
//!
//! Records are encoded with the canonical QUIP-CBOR codec in `quip-core`. Parsing
//! here is strict, like the message codecs in `quip-core`: unknown keys are
//! rejected so that a newer writer cannot be silently misread.

use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::dvv::NodeId;
use quip_core::Error as CoreError;

/// Wrap a static message as a `quip-core` encoding error.
pub(crate) fn bad(message: &'static str) -> Error {
    Error::Core(CoreError::BadEncoding(message))
}

/// Parse a CBOR map into a lookup keyed by text key, rejecting keys outside
/// `allowed` and duplicate keys.
pub(crate) fn parse_map<'a>(
    value: &'a CborValue,
    allowed: &[&str],
) -> Result<BTreeMap<&'a str, &'a CborValue>> {
    let CborValue::Map(pairs) = value else {
        return Err(bad("record must be a CBOR map"));
    };
    let mut out: BTreeMap<&'a str, &'a CborValue> = BTreeMap::new();
    for (k, v) in pairs {
        let CborValue::String(key) = k else {
            return Err(bad("record keys must be text strings"));
        };
        if !allowed.contains(&key.as_str()) {
            return Err(bad("unknown key in record"));
        }
        if out.insert(key.as_str(), v).is_some() {
            return Err(bad("duplicate key in record"));
        }
    }
    Ok(out)
}

/// Fetch a required key, reporting `missing` when absent.
pub(crate) fn expect_key<'a>(
    map: &BTreeMap<&'a str, &'a CborValue>,
    key: &str,
    missing: &'static str,
) -> Result<&'a CborValue> {
    map.get(key).copied().ok_or_else(|| bad(missing))
}

/// Fetch an optional key.
pub(crate) fn optional_key<'a>(
    map: &BTreeMap<&'a str, &'a CborValue>,
    key: &str,
) -> Option<&'a CborValue> {
    map.get(key).copied()
}

/// Read a non-negative integer as `u64`.
pub(crate) fn as_u64(value: &CborValue) -> Result<u64> {
    match value {
        CborValue::Int(n) if *n >= 0 && *n <= u64::MAX as i128 => Ok(*n as u64),
        CborValue::Int(_) => Err(bad("integer out of u64 range")),
        _ => Err(bad("expected a non-negative integer")),
    }
}

/// Read a boolean.
pub(crate) fn as_bool(value: &CborValue) -> Result<bool> {
    match value {
        CborValue::Bool(b) => Ok(*b),
        _ => Err(bad("expected a boolean")),
    }
}

/// Read a byte string.
pub(crate) fn as_bytes(value: &CborValue) -> Result<Vec<u8>> {
    match value {
        CborValue::Bytes(b) => Ok(b.clone()),
        _ => Err(bad("expected a byte string")),
    }
}

/// Read a 32-byte `NodeId`.
pub(crate) fn as_node_id(value: &CborValue) -> Result<NodeId> {
    let bytes = as_bytes(value)?;
    if bytes.len() != 32 {
        return Err(Error::Core(CoreError::InvalidDigestLength(bytes.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Read an array of 32-byte `NodeId`s.
pub(crate) fn as_node_ids(value: &CborValue) -> Result<Vec<NodeId>> {
    as_array(value)?.iter().map(as_node_id).collect()
}

/// Read an array.
pub(crate) fn as_array(value: &CborValue) -> Result<&[CborValue]> {
    match value {
        CborValue::Array(items) => Ok(items.as_slice()),
        _ => Err(bad("expected a CBOR array")),
    }
}

/// Read a timestamp (milliseconds as u64).
pub(crate) fn as_timestamp(value: &CborValue) -> Result<quip_core::time::Timestamp> {
    Ok(quip_core::time::Timestamp::from_millis(as_u64(value)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn unknown_key_rejected() {
        let value = CborValue::Map(vec![(
            CborValue::String("nope".into()),
            CborValue::Int(1),
        )]);
        assert!(matches!(parse_map(&value, &["ok"]), Err(Error::Core(_))));
    }

    #[test]
    fn duplicate_key_rejected() {
        let value = CborValue::Map(vec![
            (CborValue::String("a".into()), CborValue::Int(1)),
            (CborValue::String("a".into()), CborValue::Int(2)),
        ]);
        assert!(parse_map(&value, &["a"]).is_err());
    }

    #[test]
    fn negative_integer_rejected() {
        assert!(as_u64(&CborValue::Int(-1)).is_err());
        assert_eq!(as_u64(&CborValue::Int(7)).unwrap(), 7);
    }

    #[test]
    fn node_id_length_enforced() {
        assert!(as_node_id(&CborValue::Bytes(vec![0u8; 31])).is_err());
        assert!(as_node_id(&CborValue::Bytes(vec![0u8; 32])).is_ok());
    }
}