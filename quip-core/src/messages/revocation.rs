//! `RevocationNotice` — spec §6.

use super::verifier::Verifier;
use super::{
    expect_len, extract_bytes, extract_node_id, extract_sig64, extract_timestamp, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::constants::VERB_REVOCATION;
use crate::dvv::NodeId;
use crate::error::Result;
use crate::time::Timestamp;
use alloc::vec;
use alloc::vec::Vec;

/// Gossip-propagated accusation against a NodeId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationNotice {
    /// Accused NodeId.
    pub violator: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Application-defined evidence blob.
    pub evidence: Vec<u8>,
    /// Accusing peer.
    pub reporter: NodeId,
    /// Ed25519 signature by `reporter`.
    pub signature: [u8; 64],
}

impl RevocationNotice {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_REVOCATION,
            vec![
                CborValue::Bytes(self.violator.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.evidence.clone()),
                CborValue::Bytes(self.reporter.to_vec()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_REVOCATION)?;
        expect_len(fields, 5)?;
        Ok(Self {
            violator: extract_node_id(&fields[0])?,
            timestamp: extract_timestamp(&fields[1])?,
            evidence: extract_bytes(&fields[2])?,
            reporter: extract_node_id(&fields[3])?,
            signature: extract_sig64(&fields[4])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_REVOCATION,
            vec![
                CborValue::Bytes(self.violator.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.evidence.clone()),
                CborValue::Bytes(self.reporter.to_vec()),
            ],
        ))
    }

    /// Verify the reporter's signature.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.reporter, &payload, &self.signature))
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
        let r = RevocationNotice {
            violator: nid(1),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            evidence: alloc::vec![1, 2, 3],
            reporter: nid(2),
            signature: [0xaa; 64],
        };
        let back = RevocationNotice::from_cbor(&r.to_cbor()).unwrap();
        assert_eq!(back, r);
    }
}