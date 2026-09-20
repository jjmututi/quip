//! `QuarantineNotice` — spec §7.2.

use super::ring_signature::RingSignature;
use super::verifier::Verifier;
use super::{expect_len, extract_text, extract_timestamp, unwrap, wrap};
use crate::cbor::{encode, CborValue};
use crate::cid::CidOrV1;
use crate::constants::VERB_QUARANTINE_NOTICE;
use crate::error::{Error, Result};
use crate::time::Timestamp;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// Witness-ring–validated quarantine declaration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuarantineNotice {
    /// Trusted CID this notice applies to.
    pub trusted_cid: CidOrV1,
    /// CIDs affected by this notice.
    pub affected_cids: Vec<CidOrV1>,
    /// Human-readable reason.
    pub reason: String,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Unix milliseconds. 0 means permanent.
    pub valid_until: Timestamp,
    /// Ring signature (5 of 7).
    pub ring_signature: RingSignature,
}

impl QuarantineNotice {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        let affected: Vec<CborValue> = self.affected_cids.iter().map(|c| c.to_cbor()).collect();
        wrap(
            VERB_QUARANTINE_NOTICE,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Array(affected),
                CborValue::String(self.reason.clone()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Int(self.valid_until.as_millis() as i128),
                self.ring_signature.to_cbor(),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_QUARANTINE_NOTICE)?;
        expect_len(fields, 6)?;
        let trusted_cid = CidOrV1::from_cbor(&fields[0])?;
        let CborValue::Array(affected) = &fields[1] else {
            return Err(Error::BadEncoding("affected_cids must be an array"));
        };
        let mut affected_cids = Vec::with_capacity(affected.len());
        for item in affected {
            affected_cids.push(CidOrV1::from_cbor(item)?);
        }
        Ok(Self {
            trusted_cid,
            affected_cids,
            reason: extract_text(&fields[2])?,
            timestamp: extract_timestamp(&fields[3])?,
            valid_until: extract_timestamp(&fields[4])?,
            ring_signature: RingSignature::from_cbor(&fields[5])?,
        })
    }

    /// Bytes covered by `ring_signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let affected: Vec<CborValue> = self.affected_cids.iter().map(|c| c.to_cbor()).collect();
        encode(&wrap(
            VERB_QUARANTINE_NOTICE,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Array(affected),
                CborValue::String(self.reason.clone()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Int(self.valid_until.as_millis() as i128),
            ],
        ))
    }

    /// True if `valid_until` is zero (permanent) or after `now`.
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        self.valid_until.as_millis() == 0 || self.valid_until > now
    }

    /// Verify the ring signature over this notice.
    ///
    /// FROST variants require the group public key — use
    /// `self.ring_signature.verify_frost(&payload, &group_pk, v)` directly.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        self.ring_signature.verify(&payload, v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::Cid;
    use crate::dvv::NodeId;
    use crate::messages::ring_signature::IndividualRingSig;

    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn roundtrip() {
        let n = QuarantineNotice {
            trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
            affected_cids: vec![CidOrV1::Raw(Cid([0x22; 32]))],
            reason: "RtBF".into(),
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            valid_until: Timestamp::from_millis(0),
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0xaa; 64]],
                signers: vec![nid(1)],
            }),
        };
        let back = QuarantineNotice::from_cbor(&n.to_cbor()).unwrap();
        assert_eq!(back, n);
    }
}