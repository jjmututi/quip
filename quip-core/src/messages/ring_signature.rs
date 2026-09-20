//! Ring signature aggregate (spec §5.3.4).

use super::verifier::Verifier;
use super::{extract_bytes, extract_node_id, extract_sig64};
use crate::cbor::CborValue;
use crate::constants::QUORUM;
use crate::dvv::NodeId;
use crate::error::{Error, Result};
use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;

/// A ring signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RingSignature {
    /// Collection of individual Ed25519 signatures.
    Individual(IndividualRingSig),
    /// FROST aggregate signature.
    Frost(FrostRingSig),
}

/// Individual Ed25519 signatures from distinct witnesses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndividualRingSig {
    /// 64-byte signatures in canonical NodeId order.
    pub signatures: Vec<[u8; 64]>,
    /// Signer NodeIds, same order as `signatures`.
    pub signers: Vec<NodeId>,
}

/// FROST aggregate signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrostRingSig {
    /// FROST aggregate signature bytes.
    pub aggregate: Vec<u8>,
    /// Signing participants (NodeIds).
    pub participants: Vec<NodeId>,
    /// FROST commitment.
    pub commitment: Vec<u8>,
}

impl RingSignature {
    /// Number of witnesses contributing.
    pub fn signer_count(&self) -> usize {
        match self {
            RingSignature::Individual(s) => s.signers.len(),
            RingSignature::Frost(s) => s.participants.len(),
        }
    }

    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        match self {
            RingSignature::Individual(s) => s.to_cbor(),
            RingSignature::Frost(s) => s.to_cbor(),
        }
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = value else {
            return Err(Error::BadEncoding("RingSignature must be a map"));
        };
        let ty = pairs
            .iter()
            .find_map(|(k, v)| match (k, v) {
                (CborValue::String(s), CborValue::String(t)) if s == "type" => Some(t.clone()),
                _ => None,
            })
            .ok_or(Error::BadEncoding("RingSignature missing `type`"))?;

        match ty.as_str() {
            "individual" => Ok(RingSignature::Individual(IndividualRingSig::from_cbor(value)?)),
            "frost" => Ok(RingSignature::Frost(FrostRingSig::from_cbor(value)?)),
            _ => Err(Error::BadEncoding("unknown RingSignature type")),
        }
    }

    /// Verify an Individual ring signature over `message`.
    ///
    /// FROST variants return [`Error::BadEncoding`] — use
    /// [`Self::verify_frost`] with the group public key instead.
    pub fn verify(&self, message: &[u8], v: &impl Verifier) -> Result<bool> {
        match self {
            RingSignature::Individual(sig) => {
                if sig.signatures.len() != sig.signers.len() {
                    return Ok(false);
                }
                if sig.signatures.len() < QUORUM {
                    return Ok(false);
                }
                // Distinct signers check.
                let mut seen = BTreeSet::new();
                for pk in &sig.signers {
                    if !seen.insert(*pk) {
                        return Ok(false);
                    }
                }
                for (pk, s) in sig.signers.iter().zip(sig.signatures.iter()) {
                    if !v.verify_ed25519(pk, message, s) {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            RingSignature::Frost(_) => Err(Error::BadEncoding(
                "FROST ring signatures require the group public key; \
                 use verify_frost",
            )),
        }
    }

    /// Verify a FROST ring signature against the group public key.
    pub fn verify_frost(
        &self,
        message: &[u8],
        group_public_key: &[u8; 32],
        v: &impl Verifier,
    ) -> Result<bool> {
        match self {
            RingSignature::Frost(sig) => {
                if sig.participants.len() < QUORUM {
                    return Ok(false);
                }
                if sig.aggregate.len() != 64 {
                    return Ok(false);
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(&sig.aggregate);
                Ok(v.verify_ed25519(group_public_key, message, &arr))
            }
            RingSignature::Individual(_) => Err(Error::BadEncoding(
                "verify_frost called on an Individual signature",
            )),
        }
    }
}

impl IndividualRingSig {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        let sigs: Vec<CborValue> = self
            .signatures
            .iter()
            .map(|s| CborValue::Bytes(s.to_vec()))
            .collect();
        let signers: Vec<CborValue> = self
            .signers
            .iter()
            .map(|n| CborValue::Bytes(n.to_vec()))
            .collect();
        CborValue::Map(alloc::vec![
            (
                CborValue::String("type".to_string()),
                CborValue::String("individual".to_string())
            ),
            (CborValue::String("signatures".to_string()), CborValue::Array(sigs)),
            (CborValue::String("signers".to_string()), CborValue::Array(signers)),
        ])
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = value else {
            return Err(Error::BadEncoding("IndividualRingSig must be a map"));
        };
        let mut signatures = None;
        let mut signers = None;
        for (k, v) in pairs {
            match k {
                CborValue::String(s) if s == "type" => {
                    if let CborValue::String(t) = v {
                        if t != "individual" {
                            return Err(Error::BadEncoding("wrong type discriminator"));
                        }
                    } else {
                        return Err(Error::BadEncoding("type must be text"));
                    }
                }
                CborValue::String(s) if s == "signatures" => {
                    let CborValue::Array(arr) = v else {
                        return Err(Error::BadEncoding("signatures must be an array"));
                    };
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        out.push(extract_sig64(item)?);
                    }
                    signatures = Some(out);
                }
                CborValue::String(s) if s == "signers" => {
                    let CborValue::Array(arr) = v else {
                        return Err(Error::BadEncoding("signers must be an array"));
                    };
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        out.push(extract_node_id(item)?);
                    }
                    signers = Some(out);
                }
                _ => return Err(Error::BadEncoding("unknown key in IndividualRingSig")),
            }
        }
        let signatures = signatures.ok_or(Error::BadEncoding("missing signatures"))?;
        let signers = signers.ok_or(Error::BadEncoding("missing signers"))?;
        if signatures.len() != signers.len() {
            return Err(Error::BadEncoding("signatures/signers length mismatch"));
        }
        Ok(IndividualRingSig { signatures, signers })
    }
}

impl FrostRingSig {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        let participants: Vec<CborValue> = self
            .participants
            .iter()
            .map(|n| CborValue::Bytes(n.to_vec()))
            .collect();
        CborValue::Map(alloc::vec![
            (
                CborValue::String("type".to_string()),
                CborValue::String("frost".to_string())
            ),
            (
                CborValue::String("aggregate".to_string()),
                CborValue::Bytes(self.aggregate.clone())
            ),
            (
                CborValue::String("participants".to_string()),
                CborValue::Array(participants)
            ),
            (
                CborValue::String("commitment".to_string()),
                CborValue::Bytes(self.commitment.clone())
            ),
        ])
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = value else {
            return Err(Error::BadEncoding("FrostRingSig must be a map"));
        };
        let mut aggregate = None;
        let mut participants = None;
        let mut commitment = None;
        for (k, v) in pairs {
            match k {
                CborValue::String(s) if s == "type" => {
                    if let CborValue::String(t) = v {
                        if t != "frost" {
                            return Err(Error::BadEncoding("wrong type discriminator"));
                        }
                    } else {
                        return Err(Error::BadEncoding("type must be text"));
                    }
                }
                CborValue::String(s) if s == "aggregate" => aggregate = Some(extract_bytes(v)?),
                CborValue::String(s) if s == "participants" => {
                    let CborValue::Array(arr) = v else {
                        return Err(Error::BadEncoding("participants must be an array"));
                    };
                    let mut out = Vec::with_capacity(arr.len());
                    for item in arr {
                        out.push(extract_node_id(item)?);
                    }
                    participants = Some(out);
                }
                CborValue::String(s) if s == "commitment" => commitment = Some(extract_bytes(v)?),
                _ => return Err(Error::BadEncoding("unknown key in FrostRingSig")),
            }
        }
        Ok(FrostRingSig {
            aggregate: aggregate.ok_or(Error::BadEncoding("missing aggregate"))?,
            participants: participants.ok_or(Error::BadEncoding("missing participants"))?,
            commitment: commitment.ok_or(Error::BadEncoding("missing commitment"))?,
        })
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
    fn individual_roundtrip() {
        let sig = IndividualRingSig {
            signatures: alloc::vec![[0xaa; 64], [0xbb; 64]],
            signers: alloc::vec![nid(1), nid(2)],
        };
        let v = RingSignature::Individual(sig);
        let back = RingSignature::from_cbor(&v.to_cbor()).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn frost_roundtrip() {
        let sig = FrostRingSig {
            aggregate: alloc::vec![0x01, 0x02],
            participants: alloc::vec![nid(1)],
            commitment: alloc::vec![0x03],
        };
        let v = RingSignature::Frost(sig);
        let back = RingSignature::from_cbor(&v.to_cbor()).unwrap();
        assert_eq!(back, v);
    }
}