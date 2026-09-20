//! `DerivativeLink` — spec §7.3.

use super::verifier::Verifier;
use super::{
    expect_len, extract_metadata, extract_node_id, extract_sig64, extract_text,
    extract_timestamp, metadata_to_cbor, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::cid::CidOrV1;
use crate::constants::VERB_DERIVATIVE_LINK;
use crate::dvv::NodeId;
use crate::error::Result;
use crate::time::Timestamp;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// A link from a derivative CID to a Trusted CID.
#[derive(Clone, Debug, PartialEq)]
pub struct DerivativeLink {
    /// The Trusted CID.
    pub trusted_cid: CidOrV1,
    /// The derivative CID.
    pub derivative_cid: CidOrV1,
    /// Application-defined evidence.
    pub app_data: Vec<(String, CborValue)>,
    /// Application-defined link type, e.g. `"perceptual_hash"` or `"manual"`.
    pub link_type: String,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Reporter NodeId.
    pub reporter: NodeId,
    /// Ed25519 signature by `reporter`.
    pub signature: [u8; 64],
}

impl DerivativeLink {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_DERIVATIVE_LINK,
            vec![
                self.trusted_cid.to_cbor(),
                self.derivative_cid.to_cbor(),
                metadata_to_cbor(&self.app_data),
                CborValue::String(self.link_type.clone()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.reporter.to_vec()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_DERIVATIVE_LINK)?;
        expect_len(fields, 7)?;
        Ok(Self {
            trusted_cid: CidOrV1::from_cbor(&fields[0])?,
            derivative_cid: CidOrV1::from_cbor(&fields[1])?,
            app_data: extract_metadata(&fields[2])?,
            link_type: extract_text(&fields[3])?,
            timestamp: extract_timestamp(&fields[4])?,
            reporter: extract_node_id(&fields[5])?,
            signature: extract_sig64(&fields[6])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_DERIVATIVE_LINK,
            vec![
                self.trusted_cid.to_cbor(),
                self.derivative_cid.to_cbor(),
                metadata_to_cbor(&self.app_data),
                CborValue::String(self.link_type.clone()),
                CborValue::Int(self.timestamp.as_millis() as i128),
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
    use crate::cid::Cid;
    use alloc::string::ToString;

    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn roundtrip() {
        let d = DerivativeLink {
            trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
            derivative_cid: CidOrV1::Raw(Cid([0x22; 32])),
            app_data: alloc::vec![("phash".to_string(), CborValue::Int(42))],
            link_type: "perceptual_hash".to_string(),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            reporter: nid(1),
            signature: [0xcc; 64],
        };
        let back = DerivativeLink::from_cbor(&d.to_cbor()).unwrap();
        assert_eq!(back, d);
    }
}