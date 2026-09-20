//! `KeyClaim` — spec §5.1.

use super::verifier::Verifier;
use super::{expect_len, extract_node_id, extract_sig64, extract_timestamp, unwrap, wrap};
use crate::cbor::{encode, CborValue};
use crate::constants::VERB_KEY_CLAIM;
use crate::dvv::NodeId;
use crate::error::{Error, Result};
use crate::time::Timestamp;
use alloc::vec;
use alloc::vec::Vec;

/// Self-signed assertion of a NodeId.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyClaim {
    /// Claimed NodeId.
    pub node_id: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// DHT node ID. Spec requires this to equal `node_id`.
    pub dht_id: NodeId,
    /// Ed25519 signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl KeyClaim {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_KEY_CLAIM,
            vec![
                CborValue::Bytes(self.node_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.dht_id.to_vec()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_KEY_CLAIM)?;
        expect_len(fields, 4)?;
        let node_id = extract_node_id(&fields[0])?;
        let timestamp = extract_timestamp(&fields[1])?;
        let dht_id = extract_node_id(&fields[2])?;
        let signature = extract_sig64(&fields[3])?;
        if dht_id != node_id {
            return Err(Error::BadEncoding("KeyClaim dht_id must equal node_id"));
        }
        Ok(Self {
            node_id,
            timestamp,
            dht_id,
            signature,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_KEY_CLAIM,
            vec![
                CborValue::Bytes(self.node_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.dht_id.to_vec()),
            ],
        ))
    }

    /// Verify the self-signature.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.node_id, &payload, &self.signature))
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
        let claim = KeyClaim {
            node_id: nid(1),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            dht_id: nid(1),
            signature: [0xcd; 64],
        };
        let back = KeyClaim::from_cbor(&claim.to_cbor()).unwrap();
        assert_eq!(back, claim);
    }

    #[test]
    fn dht_id_mismatch_rejected() {
        let cbor = wrap(
            VERB_KEY_CLAIM,
            vec![
                CborValue::Bytes(nid(1).to_vec()),
                CborValue::Int(0),
                CborValue::Bytes(nid(2).to_vec()),
                CborValue::Bytes(vec![0u8; 64]),
            ],
        );
        assert!(matches!(KeyClaim::from_cbor(&cbor), Err(Error::BadEncoding(_))));
    }
}