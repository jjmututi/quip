//! `TrustedCidRegistration` — spec §7.1.

use super::verifier::Verifier;
use super::{
    expect_len, extract_metadata, extract_node_id, extract_sig64, extract_timestamp,
    metadata_to_cbor, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::cid::CidOrV1;
use crate::constants::VERB_REGISTER_TCID;
use crate::dvv::NodeId;
use crate::error::Result;
use crate::time::Timestamp;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Registration of a CID as the reference for a work.
#[derive(Clone, Debug, PartialEq)]
pub struct TrustedCidRegistration {
    /// Cryptographic CID of the content.
    pub cid: CidOrV1,
    /// Application-defined metadata.
    pub app_metadata: Vec<(String, CborValue)>,
    /// Owner or authorized agent.
    pub owner: NodeId,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `owner`.
    pub signature: [u8; 64],
}

impl TrustedCidRegistration {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_REGISTER_TCID,
            vec![
                self.cid.to_cbor(),
                metadata_to_cbor(&self.app_metadata),
                CborValue::Bytes(self.owner.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_REGISTER_TCID)?;
        expect_len(fields, 5)?;
        Ok(Self {
            cid: CidOrV1::from_cbor(&fields[0])?,
            app_metadata: extract_metadata(&fields[1])?,
            owner: extract_node_id(&fields[2])?,
            timestamp: extract_timestamp(&fields[3])?,
            signature: extract_sig64(&fields[4])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_REGISTER_TCID,
            vec![
                self.cid.to_cbor(),
                metadata_to_cbor(&self.app_metadata),
                CborValue::Bytes(self.owner.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        ))
    }

    /// Verify the owner's signature.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.owner, &payload, &self.signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::Cid;
    use alloc::string::ToString; 

    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn roundtrip() {
        let r = TrustedCidRegistration {
            cid: CidOrV1::Raw(Cid([0x11; 32])),
            app_metadata: alloc::vec![(
                "title".to_string(),
                CborValue::String("Example".into())
            )],
            owner: nid(1),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            signature: [0xef; 64],
        };
        let back = TrustedCidRegistration::from_cbor(&r.to_cbor()).unwrap();
        assert_eq!(back, r);
    }
}