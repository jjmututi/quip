//! Resource discovery verbs (spec §14.5).
//!
//! Wire forms (all wrapped as `["quip-v1", verb, ...]` QUIP-CBOR):
//!
//! ```text
//! query_resource    = ["query_resource", resource_id: bytes, ?cid: CIDOrV1]
//! resource_announce = ["resource_announce", resource_id: bytes,
//!                      latest_cid: CIDOrV1, witness_ring: [* NodeId],
//!                      dht_locations: [* NodeId],
//!                      relay_locations: [* NodeId]]
//! ```
//!
//! `resource_announce` carries no timestamp and no DVV: freshness is a
//! property of the DHT record that stores it, not of the wire message
//! itself. `quip-storage::directory::ResourceAnnouncement` layers a local
//! `received_at` on top of these five wire fields.

use crate::codec::{as_bytes, envelope, fields, verb_of};
use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::cid::CidOrV1;
use quip_core::dvv::NodeId;

/// `query_resource = ["query_resource", resource_id: bytes, ?cid: CIDOrV1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryResource {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Optional version filter.
    pub cid: Option<CidOrV1>,
}

impl QueryResource {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut f = alloc::vec![CborValue::Bytes(self.resource_id.clone())];
        if let Some(cid) = &self.cid {
            f.push(cid.to_cbor());
        }
        Ok(encode(&envelope("query_resource", f))?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "query_resource" {
            return Err(Error::BadFrame("not a query_resource"));
        }
        let f = fields(&v, "query_resource")?;
        if f.is_empty() || f.len() > 2 {
            return Err(Error::BadFrame("query_resource arity"));
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

/// `resource_announce` gossip (T0 CTRL, spec §14.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceAnnounce {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Current CID (raw or CIDv1) of the resource.
    pub latest_cid: CidOrV1,
    /// Witness ring for this resource.
    pub witness_ring: Vec<NodeId>,
    /// DHT nodes that can serve the resource.
    pub dht_locations: Vec<NodeId>,
    /// Relay nodes that can serve the resource (for NATed hosts).
    pub relay_locations: Vec<NodeId>,
}

impl ResourceAnnounce {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "resource_announce",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                self.latest_cid.to_cbor(),
                node_list_to_cbor(&self.witness_ring),
                node_list_to_cbor(&self.dht_locations),
                node_list_to_cbor(&self.relay_locations),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "resource_announce" {
            return Err(Error::BadFrame("not a resource_announce"));
        }
        let f = fields(&v, "resource_announce")?;
        if f.len() != 5 {
            return Err(Error::BadFrame("resource_announce arity"));
        }
        Ok(Self {
            resource_id: as_bytes(&f[0])?,
            latest_cid: CidOrV1::from_cbor(&f[1])?,
            witness_ring: node_list_from_cbor(&f[2])?,
            dht_locations: node_list_from_cbor(&f[3])?,
            relay_locations: node_list_from_cbor(&f[4])?,
        })
    }
}

// -------------------------------------------------------------------------
// Local NodeId list helpers.
//
// `sync_codec` has identical helpers, but they live in the SYNC plane and
// this is CTRL. Keeping them local avoids a cross-tier import for what is
// ultimately a wire-shape concern.
// -------------------------------------------------------------------------

fn node_list_to_cbor(nodes: &[NodeId]) -> CborValue {
    CborValue::Array(nodes.iter().map(|n| CborValue::Bytes(n.to_vec())).collect())
}

fn node_list_from_cbor(v: &CborValue) -> Result<Vec<NodeId>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::cid::Cid;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn query_resource_no_cid() {
        let q = QueryResource {
            resource_id: b"profile".to_vec(),
            cid: None,
        };
        let bytes = q.to_bytes().unwrap();
        assert_eq!(QueryResource::from_bytes(&bytes).unwrap(), q);
    }

    #[test]
    fn query_resource_with_cid() {
        let q = QueryResource {
            resource_id: b"profile".to_vec(),
            cid: Some(cid(1)),
        };
        let bytes = q.to_bytes().unwrap();
        assert_eq!(QueryResource::from_bytes(&bytes).unwrap(), q);
    }

    #[test]
    fn query_resource_rejects_wrong_verb() {
        let bytes = encode(&envelope("resource_announce", alloc::vec![])).unwrap();
        assert!(QueryResource::from_bytes(&bytes).is_err());
    }

    #[test]
    fn query_resource_rejects_overlong_arity() {
        let bytes = encode(&envelope(
            "query_resource",
            alloc::vec![
                CborValue::Bytes(b"r".to_vec()),
                cid(1).to_cbor(),
                CborValue::Null,
            ],
        ))
        .unwrap();
        assert!(QueryResource::from_bytes(&bytes).is_err());
    }

    #[test]
    fn resource_announce_roundtrip_full() {
        let ra = ResourceAnnounce {
            resource_id: b"doc".to_vec(),
            latest_cid: cid(9),
            witness_ring: alloc::vec![nid(1), nid(2), nid(3)],
            dht_locations: alloc::vec![nid(4), nid(5)],
            relay_locations: alloc::vec![nid(6)],
        };
        let bytes = ra.to_bytes().unwrap();
        assert_eq!(ResourceAnnounce::from_bytes(&bytes).unwrap(), ra);
    }

    #[test]
    fn resource_announce_roundtrip_all_empty_lists() {
        // A resource hosted directly, with no ring and no relays.
        let ra = ResourceAnnounce {
            resource_id: b"local-only".to_vec(),
            latest_cid: cid(7),
            witness_ring: alloc::vec![],
            dht_locations: alloc::vec![],
            relay_locations: alloc::vec![],
        };
        let bytes = ra.to_bytes().unwrap();
        assert_eq!(ResourceAnnounce::from_bytes(&bytes).unwrap(), ra);
    }

    #[test]
    fn resource_announce_wire_shape_is_five_fields() {
        // Locks in the §14.5 CDDL: exactly five fields after the verb,
        // with `latest_cid` at index 2 of the array (index 1 after the
        // verb prefix is stripped by `fields`).
        let ra = ResourceAnnounce {
            resource_id: b"r".to_vec(),
            latest_cid: cid(1),
            witness_ring: alloc::vec![nid(2)],
            dht_locations: alloc::vec![nid(3)],
            relay_locations: alloc::vec![nid(4)],
        };
        let bytes = ra.to_bytes().unwrap();
        let v = decode(&bytes).unwrap();
        let CborValue::Array(arr) = &v else { panic!("expected array") };
        // ["quip-v1", "resource_announce", rid, cid, ring, dht, relay]
        assert_eq!(arr.len(), 7);
        assert_eq!(arr[0], CborValue::String("quip-v1".into()));
        assert_eq!(arr[1], CborValue::String("resource_announce".into()));
        assert!(matches!(&arr[2], CborValue::Bytes(_)));
        assert!(matches!(&arr[3], CborValue::Bytes(_)));       // raw CID
        assert!(matches!(&arr[4], CborValue::Array(_)));        // ring
        assert!(matches!(&arr[5], CborValue::Array(_)));        // dht
        assert!(matches!(&arr[6], CborValue::Array(_)));        // relay
    }

    #[test]
    fn resource_announce_rejects_wrong_arity() {
        // Four fields instead of five.
        let bytes = encode(&envelope(
            "resource_announce",
            alloc::vec![
                CborValue::Bytes(b"r".to_vec()),
                cid(1).to_cbor(),
                CborValue::Array(alloc::vec![]),
                CborValue::Array(alloc::vec![]),
            ],
        ))
        .unwrap();
        assert!(ResourceAnnounce::from_bytes(&bytes).is_err());
    }

    #[test]
    fn resource_announce_rejects_non_32_byte_node_id() {
        let short = CborValue::Array(alloc::vec![CborValue::Bytes(alloc::vec![0u8; 31])]);
        let bytes = encode(&envelope(
            "resource_announce",
            alloc::vec![
                CborValue::Bytes(b"r".to_vec()),
                cid(1).to_cbor(),
                short.clone(),
                CborValue::Array(alloc::vec![]),
                CborValue::Array(alloc::vec![]),
            ],
        ))
        .unwrap();
        assert!(ResourceAnnounce::from_bytes(&bytes).is_err());
    }
}