//! `query` verb (spec §14.1).
//!
//! ```text
//! query_key       = [ "quip-v1", "query", "key", NodeId ]
//! query_witnesses = [ "quip-v1", "query", "witnesses", NodeId ]
//! ```
//!
//! Two shapes share the verb string `"query"`; they are discriminated by
//! a leading `"key"` or `"witnesses"` string, so the `fields()` slice
//! after the prefix has length 2.

use crate::codec::{as_bytes, envelope, fields, verb_of};
use crate::error::{Error, Result};
use alloc::string::ToString;
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::dvv::NodeId;

/// A `query` request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query {
    /// `["quip-v1", "query", "key", NodeId]` — request the Key Claim
    /// for a NodeId.
    Key(NodeId),
    /// `["quip-v1", "query", "witnesses", NodeId]` — request the
    /// witness ring for a NodeId.
    Witnesses(NodeId),
}

impl Query {
    /// The discriminating sub-verb (`"key"` or `"witnesses"`).
    pub fn kind(&self) -> &'static str {
        match self {
            Query::Key(_) => "key",
            Query::Witnesses(_) => "witnesses",
        }
    }

    /// The NodeId being queried.
    pub fn target(&self) -> &NodeId {
        match self {
            Query::Key(n) | Query::Witnesses(n) => n,
        }
    }

    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let (kind, node) = match self {
            Query::Key(n) => ("key", n),
            Query::Witnesses(n) => ("witnesses", n),
        };
        let msg = envelope(
            "query",
            alloc::vec![
                CborValue::String(kind.to_string()),
                CborValue::Bytes(node.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "query" {
            return Err(Error::BadFrame("not a query"));
        }
        let f = fields(&v, "query")?;
        if f.len() != 2 {
            return Err(Error::BadFrame("query arity"));
        }
        let kind = match &f[0] {
            CborValue::String(s) => s.as_str(),
            _ => return Err(Error::BadFrame("query kind must be text")),
        };
        let raw = as_bytes(&f[1])?;
        if raw.len() != 32 {
            return Err(Error::BadFrame("query NodeId must be 32 bytes"));
        }
        let mut n = [0u8; 32];
        n.copy_from_slice(&raw);
        match kind {
            "key" => Ok(Query::Key(n)),
            "witnesses" => Ok(Query::Witnesses(n)),
            _ => Err(Error::BadFrame("unknown query kind")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn key_roundtrip() {
        let q = Query::Key(nid(1));
        let bytes = q.to_bytes().unwrap();
        assert_eq!(Query::from_bytes(&bytes).unwrap(), q);
    }

    #[test]
    fn witnesses_roundtrip() {
        let q = Query::Witnesses(nid(2));
        let bytes = q.to_bytes().unwrap();
        assert_eq!(Query::from_bytes(&bytes).unwrap(), q);
    }

    #[test]
    fn wrong_verb_rejected() {
        let msg = envelope("query_pins", alloc::vec![]);
        let bytes = encode(&msg).unwrap();
        assert!(Query::from_bytes(&bytes).is_err());
    }

    #[test]
    fn unknown_kind_rejected() {
        let msg = envelope(
            "query",
            alloc::vec![
                CborValue::String("bogus".into()),
                CborValue::Bytes(vec![0u8; 32]),
            ],
        );
        let bytes = encode(&msg).unwrap();
        assert!(Query::from_bytes(&bytes).is_err());
    }

    #[test]
    fn short_node_id_rejected() {
        let msg = envelope(
            "query",
            alloc::vec![
                CborValue::String("key".into()),
                CborValue::Bytes(vec![0u8; 31]),
            ],
        );
        let bytes = encode(&msg).unwrap();
        assert!(Query::from_bytes(&bytes).is_err());
    }
}