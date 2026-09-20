//! `QuarantineRequest` and `UnquarantineRequest` — spec §7.2.
//!
//! These are the *request* half of the quarantine mechanism. A
//! `QuarantineRequest` is submitted by a requestor (typically the owner
//! of a Trusted CID, or a delegate) and validated by the witness ring.
//! The witness ring's approval produces a [`super::QuarantineNotice`],
//! which is the message peers act on.
//!
//! ```text
//! ["quip-v1", "quarantine", trusted_cid, affected_cids, reason,
//!  app_data, timestamp, requestor, signature]
//! ["quip-v1", "unquarantine", trusted_cid, affected_cids, reason,
//!  timestamp, requestor, signature]
//! ```

use super::verifier::Verifier;
use super::{
    expect_len, extract_metadata, extract_node_id, extract_sig64, extract_text,
    extract_timestamp, metadata_to_cbor, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::cid::CidOrV1;
use crate::constants::{VERB_QUARANTINE, VERB_UNQUARANTINE};
use crate::dvv::NodeId;
use crate::error::{Error, Result};
use crate::time::Timestamp;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

// -------------------------------------------------------------------------
// QuarantineRequest
// -------------------------------------------------------------------------

/// A request to place one or more CIDs under quarantine.
#[derive(Clone, Debug, PartialEq)]
pub struct QuarantineRequest {
    /// The Trusted CID the request concerns.
    pub trusted_cid: CidOrV1,
    /// CIDs to quarantine.
    pub affected_cids: Vec<CidOrV1>,
    /// Application-defined reason.
    pub reason: String,
    /// Application-defined evidence.
    pub app_data: Vec<(String, CborValue)>,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// The requestor.
    pub requestor: NodeId,
    /// Ed25519 signature by `requestor`.
    pub signature: [u8; 64],
}

impl QuarantineRequest {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        let affected: Vec<CborValue> = self.affected_cids.iter().map(|c| c.to_cbor()).collect();
        wrap(
            VERB_QUARANTINE,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Array(affected),
                CborValue::String(self.reason.clone()),
                metadata_to_cbor(&self.app_data),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.requestor.to_vec()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_QUARANTINE)?;
        expect_len(fields, 7)?;
        Ok(Self {
            trusted_cid: CidOrV1::from_cbor(&fields[0])?,
            affected_cids: parse_cid_array(&fields[1])?,
            reason: extract_text(&fields[2])?,
            app_data: extract_metadata(&fields[3])?,
            timestamp: extract_timestamp(&fields[4])?,
            requestor: extract_node_id(&fields[5])?,
            signature: extract_sig64(&fields[6])?,
        })
    }

    /// Bytes covered by `signature`, per the QUIP signing convention
    /// (draft-mututi-quip-03 §10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let affected: Vec<CborValue> = self.affected_cids.iter().map(|c| c.to_cbor()).collect();
        encode(&wrap(
            VERB_QUARANTINE,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Array(affected),
                CborValue::String(self.reason.clone()),
                metadata_to_cbor(&self.app_data),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.requestor.to_vec()),
            ],
        ))
    }

    /// Verify the requestor's signature.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.requestor, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// UnquarantineRequest
// -------------------------------------------------------------------------

/// A request to lift a quarantine.
#[derive(Clone, Debug, PartialEq)]
pub struct UnquarantineRequest {
    /// The Trusted CID the request concerns.
    pub trusted_cid: CidOrV1,
    /// CIDs to unquarantine.
    pub affected_cids: Vec<CidOrV1>,
    /// Application-defined reason.
    pub reason: String,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// The requestor.
    pub requestor: NodeId,
    /// Ed25519 signature by `requestor`.
    pub signature: [u8; 64],
}

impl UnquarantineRequest {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        let affected: Vec<CborValue> = self.affected_cids.iter().map(|c| c.to_cbor()).collect();
        wrap(
            VERB_UNQUARANTINE,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Array(affected),
                CborValue::String(self.reason.clone()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.requestor.to_vec()),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_UNQUARANTINE)?;
        expect_len(fields, 6)?;
        Ok(Self {
            trusted_cid: CidOrV1::from_cbor(&fields[0])?,
            affected_cids: parse_cid_array(&fields[1])?,
            reason: extract_text(&fields[2])?,
            timestamp: extract_timestamp(&fields[3])?,
            requestor: extract_node_id(&fields[4])?,
            signature: extract_sig64(&fields[5])?,
        })
    }

    /// Bytes covered by `signature`, per the QUIP signing convention
    /// (draft-mututi-quip-03 §10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let affected: Vec<CborValue> = self.affected_cids.iter().map(|c| c.to_cbor()).collect();
        encode(&wrap(
            VERB_UNQUARANTINE,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Array(affected),
                CborValue::String(self.reason.clone()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.requestor.to_vec()),
            ],
        ))
    }

    /// Verify the requestor's signature.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.requestor, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// Shared helper
// -------------------------------------------------------------------------

fn parse_cid_array(value: &CborValue) -> Result<Vec<CidOrV1>> {
    let CborValue::Array(items) = value else {
        return Err(Error::BadEncoding("affected_cids must be an array"));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(CidOrV1::from_cbor(item)?);
    }
    Ok(out)
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
    fn quarantine_request_roundtrip() {
        let q = QuarantineRequest {
            trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
            affected_cids: alloc::vec![CidOrV1::Raw(Cid([0x22; 32]))],
            reason: "DMCA".into(),
            app_data: alloc::vec![("notice_id".to_string(), CborValue::String("N-1".into()))],
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            requestor: nid(1),
            signature: [0xaa; 64],
        };
        let back = QuarantineRequest::from_cbor(&q.to_cbor()).unwrap();
        assert_eq!(back, q);
    }

    #[test]
    fn unquarantine_request_roundtrip() {
        let u = UnquarantineRequest {
            trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
            affected_cids: alloc::vec![CidOrV1::Raw(Cid([0x22; 32]))],
            reason: "error".into(),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            requestor: nid(1),
            signature: [0xbb; 64],
        };
        let back = UnquarantineRequest::from_cbor(&u.to_cbor()).unwrap();
        assert_eq!(back, u);
    }
}