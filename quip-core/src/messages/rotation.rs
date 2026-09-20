//! `KeyRotation` — spec §5.3.5.

use super::verifier::Verifier;
use super::{expect_len, extract_node_id, extract_sig64, extract_timestamp, unwrap, wrap};
use crate::cbor::{encode, CborValue};
use crate::constants::VERB_ROTATION;
use crate::dvv::NodeId;
use crate::error::Result;
use crate::time::Timestamp;
use alloc::vec;
use alloc::vec::Vec;

/// Signed rotation from one NodeId to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyRotation {
    /// Previous NodeId.
    pub old_node_id: NodeId,
    /// New NodeId.
    pub new_node_id: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `old_node_id`.
    pub signature: [u8; 64],
}

impl KeyRotation {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_ROTATION,
            vec![
                CborValue::Bytes(self.old_node_id.to_vec()),
                CborValue::Bytes(self.new_node_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_ROTATION)?;
        expect_len(fields, 4)?;
        Ok(Self {
            old_node_id: extract_node_id(&fields[0])?,
            new_node_id: extract_node_id(&fields[1])?,
            timestamp: extract_timestamp(&fields[2])?,
            signature: extract_sig64(&fields[3])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_ROTATION,
            vec![
                CborValue::Bytes(self.old_node_id.to_vec()),
                CborValue::Bytes(self.new_node_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        ))
    }

    /// Verify the rotation is signed by the **old** key.
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
        let r = KeyRotation {
            old_node_id: nid(1),
            new_node_id: nid(2),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            signature: [0xcd; 64],
        };
        let back = KeyRotation::from_cbor(&r.to_cbor()).unwrap();
        assert_eq!(back, r);
    }
}