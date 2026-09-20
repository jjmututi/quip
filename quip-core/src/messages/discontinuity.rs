//! `Discontinuity` — spec §5.3.5.
//!
//! ```text
//! ["quip-v1", "identity_discontinuity", old_NodeId, new_NodeId,
//!  timestamp, export_token, signature]
//! ```
//!
//! A permanent break in the rotation chain. Unlike [`super::KeyRotation`],
//! `Discontinuity` carries no transfer of `KT_VERIFIED` status; the old
//! NodeId is tombstoned and the new identity is unrelated.

use super::verifier::Verifier;
use super::{
    expect_len, extract_bytes, extract_node_id, extract_sig64, extract_timestamp, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::constants::VERB_IDENTITY_DISCONTINUITY;
use crate::dvv::NodeId;
use crate::error::Result;
use crate::time::Timestamp;
use alloc::vec;
use alloc::vec::Vec;

/// A permanent break of a rotation chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Discontinuity {
    /// The old NodeId being retired.
    pub old_node_id: NodeId,
    /// The new NodeId.
    pub new_node_id: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Optional data-portability proof. Zero length if absent.
    pub export_token: Vec<u8>,
    /// Ed25519 signature by `old_node_id`.
    pub signature: [u8; 64],
}

impl Discontinuity {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_IDENTITY_DISCONTINUITY,
            vec![
                CborValue::Bytes(self.old_node_id.to_vec()),
                CborValue::Bytes(self.new_node_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.export_token.clone()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_IDENTITY_DISCONTINUITY)?;
        expect_len(fields, 5)?;
        Ok(Self {
            old_node_id: extract_node_id(&fields[0])?,
            new_node_id: extract_node_id(&fields[1])?,
            timestamp: extract_timestamp(&fields[2])?,
            export_token: extract_bytes(&fields[3])?,
            signature: extract_sig64(&fields[4])?,
        })
    }

    /// Bytes covered by `signature`, per the QUIP signing convention
    /// (draft-mututi-quip-03 §10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_IDENTITY_DISCONTINUITY,
            vec![
                CborValue::Bytes(self.old_node_id.to_vec()),
                CborValue::Bytes(self.new_node_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.export_token.clone()),
            ],
        ))
    }

    /// Verify the signature against the **old** NodeId.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.old_node_id, &payload, &self.signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn roundtrip() {
        let d = Discontinuity {
            old_node_id: nid(1),
            new_node_id: nid(2),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            export_token: alloc::vec![1, 2, 3, 4],
            signature: [0xee; 64],
        };
        let back = Discontinuity::from_cbor(&d.to_cbor()).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn roundtrip_empty_export_token() {
        let d = Discontinuity {
            old_node_id: nid(1),
            new_node_id: nid(2),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            export_token: alloc::vec![],
            signature: [0xee; 64],
        };
        let back = Discontinuity::from_cbor(&d.to_cbor()).unwrap();
        assert_eq!(back, d);
    }
}