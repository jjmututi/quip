//! `WitnessStatement` — spec §5.3.3.

use super::verifier::Verifier;
use super::{
    expect_len, extract_node_id, extract_ring_id, extract_sig64, extract_timestamp, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::constants::VERB_WITNESS;
use crate::dvv::NodeId;
use crate::error::Result;
use crate::time::Timestamp;
use alloc::vec;
use alloc::vec::Vec;

/// Corroboration of a `KeyClaim` by a single witness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessStatement {
    /// Subject NodeId.
    pub subject: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Timestamp after which this statement is stale.
    pub valid_until: Timestamp,
    /// DHT ring identifier.
    pub ring_id: [u8; 32],
    /// Witness NodeId.
    pub witness: NodeId,
    /// Ed25519 signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl WitnessStatement {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_WITNESS,
            vec![
                CborValue::Bytes(self.subject.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Int(self.valid_until.as_millis() as i128),
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Bytes(self.witness.to_vec()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_WITNESS)?;
        expect_len(fields, 6)?;
        Ok(Self {
            subject: extract_node_id(&fields[0])?,
            timestamp: extract_timestamp(&fields[1])?,
            valid_until: extract_timestamp(&fields[2])?,
            ring_id: extract_ring_id(&fields[3])?,
            witness: extract_node_id(&fields[4])?,
            signature: extract_sig64(&fields[5])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_WITNESS,
            vec![
                CborValue::Bytes(self.subject.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Int(self.valid_until.as_millis() as i128),
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Bytes(self.witness.to_vec()),
            ],
        ))
    }

    /// Verify the witness signature.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.witness, &payload, &self.signature))
    }

    /// True if `valid_until` is strictly after `now`.
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        self.valid_until > now
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
        let w = WitnessStatement {
            subject: nid(1),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            valid_until: Timestamp::from_millis(1_700_086_400_000),
            ring_id: [0x42; 32],
            witness: nid(2),
            signature: [0xab; 64],
        };
        let back = WitnessStatement::from_cbor(&w.to_cbor()).unwrap();
        assert_eq!(back, w);
    }
}