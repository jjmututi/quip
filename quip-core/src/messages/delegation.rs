//! `DelegationCertificate` — spec §7.1.

use super::verifier::Verifier;
use super::{
    expect_len, extract_node_id, extract_sig64, extract_timestamp, extract_u64, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::cid::CidOrV1;
use crate::constants::VERB_DELEGATION;
use crate::dvv::NodeId;
use crate::error::Result;
use crate::time::Timestamp;
use alloc::vec;
use alloc::vec::Vec;

/// Delegation of governance authority over a Trusted CID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationCertificate {
    /// Trusted CID the delegation covers.
    pub trusted_cid: CidOrV1,
    /// Delegate.
    pub delegate: NodeId,
    /// Application-defined permission bits.
    pub permissions: u64,
    /// Unix milliseconds.
    pub valid_from: Timestamp,
    /// Unix milliseconds.
    pub valid_until: Timestamp,
    /// Ed25519 signature by the tCID's owner.
    pub owner_signature: [u8; 64],
}

impl DelegationCertificate {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_DELEGATION,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Bytes(self.delegate.to_vec()),
                CborValue::Int(self.permissions as i128),
                CborValue::Int(self.valid_from.as_millis() as i128),
                CborValue::Int(self.valid_until.as_millis() as i128),
                CborValue::Bytes(self.owner_signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_DELEGATION)?;
        expect_len(fields, 6)?;
        Ok(Self {
            trusted_cid: CidOrV1::from_cbor(&fields[0])?,
            delegate: extract_node_id(&fields[1])?,
            permissions: extract_u64(&fields[2])?,
            valid_from: extract_timestamp(&fields[3])?,
            valid_until: extract_timestamp(&fields[4])?,
            owner_signature: extract_sig64(&fields[5])?,
        })
    }

    /// Bytes covered by `owner_signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_DELEGATION,
            vec![
                self.trusted_cid.to_cbor(),
                CborValue::Bytes(self.delegate.to_vec()),
                CborValue::Int(self.permissions as i128),
                CborValue::Int(self.valid_from.as_millis() as i128),
                CborValue::Int(self.valid_until.as_millis() as i128),
            ],
        ))
    }

    /// Verify the owner's signature using the supplied owner NodeId.
    ///
    /// The certificate does not carry the owner field; callers must supply
    /// it from the corresponding [`super::TrustedCidRegistration`].
    pub fn verify(&self, owner: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(owner, &payload, &self.owner_signature))
    }

    /// True if `now` is within `[valid_from, valid_until)`.
    pub fn is_valid_at(&self, now: Timestamp) -> bool {
        now >= self.valid_from && now < self.valid_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::Cid;

    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn roundtrip() {
        let d = DelegationCertificate {
            trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
            delegate: nid(2),
            permissions: 0b1011,
            valid_from: Timestamp::from_millis(1_700_000_000_000),
            valid_until: Timestamp::from_millis(1_700_086_400_000),
            owner_signature: [0xdd; 64],
        };
        let back = DelegationCertificate::from_cbor(&d.to_cbor()).unwrap();
        assert_eq!(back, d);
    }
}