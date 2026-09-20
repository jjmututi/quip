//! DVV <-> CBOR.
//!
//! CDDL from spec §5.2:
//!
//! ```text
//! DVV = {
//!   ? 1: Dot,
//!   ? 2: Deps,
//!   ? 3: [* NodeId],
//!   ? 4: CIDOrV1
//! }
//! Dot  = [writer: NodeId, counter: uint, ? cid: CIDOrV1]
//! Deps = { * NodeId => counter: uint }
//! ```
//!
//! Unknown keys are rejected (closed CDDL).

use super::types::{Dot, Dvv, NodeId};
use crate::cbor::{decode, encode, CborValue};
use crate::cid::CidOrV1;
use crate::error::{Error, Result};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// Serialize to a [`CborValue`].
pub fn to_cbor(dvv: &Dvv) -> CborValue {
    let mut pairs: Vec<(CborValue, CborValue)> = Vec::new();

    if let Some(dot) = &dvv.dot {
        pairs.push((CborValue::Int(1), dot_to_cbor(dot)));
    }
    if !dvv.deps.is_empty() {
        let mut deps: Vec<(CborValue, CborValue)> = Vec::with_capacity(dvv.deps.len());
        for (w, c) in &dvv.deps {
            deps.push((CborValue::Bytes(w.to_vec()), CborValue::Int(*c as i128)));
        }
        pairs.push((CborValue::Int(2), CborValue::Map(deps)));
    }
    if !dvv.pruned.is_empty() {
        let list: Vec<CborValue> = dvv
            .pruned
            .iter()
            .map(|w| CborValue::Bytes(w.to_vec()))
            .collect();
        pairs.push((CborValue::Int(3), CborValue::Array(list)));
    }
    if let Some(cid) = &dvv.cid {
        pairs.push((CborValue::Int(4), cid.to_cbor()));
    }

    CborValue::Map(pairs)
}

fn dot_to_cbor(dot: &Dot) -> CborValue {
    CborValue::Array(alloc::vec![
        CborValue::Bytes(dot.writer.to_vec()),
        CborValue::Int(dot.counter as i128),
    ])
}

/// Deserialize from a [`CborValue`].
pub fn from_cbor(value: &CborValue) -> Result<Dvv> {
    let CborValue::Map(pairs) = value else {
        return Err(Error::BadEncoding("DVV must be a CBOR map"));
    };
    let mut dvv = Dvv::new();
    for (k, v) in pairs {
        match k {
            CborValue::Int(1) => dvv.dot = Some(parse_dot(v)?),
            CborValue::Int(2) => dvv.deps = parse_deps(v)?,
            CborValue::Int(3) => dvv.pruned = parse_pruned(v)?,
            CborValue::Int(4) => dvv.cid = Some(CidOrV1::from_cbor(v)?),
            CborValue::Int(_) => return Err(Error::BadEncoding("unknown DVV key")),
            _ => return Err(Error::BadEncoding("DVV keys must be integers")),
        }
    }
    Ok(dvv)
}

fn parse_dot(value: &CborValue) -> Result<Dot> {
    let CborValue::Array(arr) = value else {
        return Err(Error::BadEncoding("dot must be an array"));
    };
    if arr.len() < 2 || arr.len() > 3 {
        return Err(Error::BadEncoding("dot array must have 2 or 3 elements"));
    }
    let writer = extract_node_id(&arr[0])?;
    let counter = extract_u64(&arr[1])?;
    Ok(Dot::new(writer, counter))
}

fn parse_deps(value: &CborValue) -> Result<BTreeMap<NodeId, u64>> {
    let CborValue::Map(pairs) = value else {
        return Err(Error::BadEncoding("deps must be a CBOR map"));
    };
    let mut deps = BTreeMap::new();
    for (k, v) in pairs {
        deps.insert(extract_node_id(k)?, extract_u64(v)?);
    }
    Ok(deps)
}

fn parse_pruned(value: &CborValue) -> Result<BTreeSet<NodeId>> {
    let CborValue::Array(arr) = value else {
        return Err(Error::BadEncoding("pruned must be a CBOR array"));
    };
    let mut set = BTreeSet::new();
    for item in arr {
        set.insert(extract_node_id(item)?);
    }
    Ok(set)
}

fn extract_node_id(value: &CborValue) -> Result<NodeId> {
    match value {
        CborValue::Bytes(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Ok(a)
        }
        CborValue::Bytes(b) => Err(Error::InvalidDigestLength(b.len())),
        _ => Err(Error::BadEncoding("NodeId must be 32 bytes")),
    }
}

fn extract_u64(value: &CborValue) -> Result<u64> {
    match value {
        CborValue::Int(n) if *n >= 0 && *n <= u64::MAX as i128 => Ok(*n as u64),
        CborValue::Int(_) => Err(Error::BadEncoding("counter out of u64 range")),
        _ => Err(Error::BadEncoding("counter must be a non-negative integer")),
    }
}

/// Serialize to canonical CBOR bytes.
pub fn to_bytes(dvv: &Dvv) -> Result<Vec<u8>> {
    encode(&to_cbor(dvv))
}

/// Deserialize from canonical CBOR bytes.
pub fn from_bytes(bytes: &[u8]) -> Result<Dvv> {
    from_cbor(&decode(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn roundtrip_full() {
        let mut d = Dvv::new();
        d.deps.insert(id(1), 5);
        d.deps.insert(id(2), 7);
        d.pruned.insert(id(3));
        d.dot = Some(Dot::new(id(2), 7));
        d.cid = Some(CidOrV1::V1(crate::cid::CidV1 {
            hash_algo: crate::cid::HashAlgo::Sha256,
            digest: [0xcd; 32],
        }));

        let bytes = to_bytes(&d).unwrap();
        let back = from_bytes(&bytes).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn absent_dot_omits_key_1() {
        let d = Dvv::new();
        let CborValue::Map(pairs) = to_cbor(&d) else {
            panic!("expected map");
        };
        assert!(pairs.iter().all(|(k, _)| k != &CborValue::Int(1)));
    }

    #[test]
    fn unknown_key_rejected() {
        let cbor = CborValue::Map(alloc::vec![(CborValue::Int(99), CborValue::Null)]);
        assert!(matches!(from_cbor(&cbor), Err(Error::BadEncoding(_))));
    }

    #[test]
    fn pruned_preserved_through_roundtrip() {
        let mut d = Dvv::new();
        d.deps.insert(id(1), 5);
        d.pruned.insert(id(2));
        d.pruned.insert(id(3));
        let bytes = to_bytes(&d).unwrap();
        let back = from_bytes(&bytes).unwrap();
        assert_eq!(back.pruned.len(), 2);
        assert!(back.pruned.contains(&id(2)));
        assert!(back.pruned.contains(&id(3)));
    }
}