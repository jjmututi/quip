//! Content Identifiers.

use crate::cbor::CborValue;
use crate::error::{Error, Result};
use alloc::string::ToString;
use alloc::vec;

/// Hash algorithm identifier.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum HashAlgo {
    /// SHA-256. Mandatory to implement.
    Sha256 = 0,
    /// BLAKE3. Optional.
    Blake3 = 1,
}

impl HashAlgo {
    /// Parse from the wire representation.
    pub fn from_u64(v: u64) -> Result<Self> {
        match v {
            0 => Ok(HashAlgo::Sha256),
            1 => Ok(HashAlgo::Blake3),
            other => Err(Error::UnknownHashAlgo(other)),
        }
    }

    /// Wire representation.
    pub fn as_u64(self) -> u64 {
        self as u64
    }
}

/// Raw content identifier: 32-byte digest, algorithm implied by handshake.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Cid(pub [u8; 32]);

impl Cid {
    /// Construct from a digest.
    pub const fn new(digest: [u8; 32]) -> Self {
        Cid(digest)
    }

    /// Borrow the digest.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to a tagged [`CidV1`] using the given algorithm.
    pub const fn with_algo(self, algo: HashAlgo) -> CidV1 {
        CidV1 {
            hash_algo: algo,
            digest: self.0,
        }
    }

    /// Encode as a CBOR byte string.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Bytes(self.0.to_vec())
    }

    /// Decode from a CBOR byte string of exactly 32 bytes.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        match value {
            CborValue::Bytes(b) if b.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(b);
                Ok(Cid(arr))
            }
            CborValue::Bytes(b) => Err(Error::InvalidDigestLength(b.len())),
            _ => Err(Error::BadEncoding("CID must be a 32-byte byte string")),
        }
    }
}

/// Tagged content identifier carrying its hash algorithm.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct CidV1 {
    /// Hash algorithm.
    pub hash_algo: HashAlgo,
    /// 32-byte digest.
    pub digest: [u8; 32],
}

impl CidV1 {
    /// Encode as a CBOR map `{hash_algo, digest}`.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (
                CborValue::String("hash_algo".to_string()),
                CborValue::Int(self.hash_algo.as_u64() as i128),
            ),
            (
                CborValue::String("digest".to_string()),
                CborValue::Bytes(self.digest.to_vec()),
            ),
        ])
    }

    /// Decode from a CBOR map.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = value else {
            return Err(Error::BadEncoding("CIDv1 must be a CBOR map"));
        };
        let mut hash_algo = None;
        let mut digest = None;
        for (k, v) in pairs {
            match k {
                CborValue::String(s) if s == "hash_algo" => {
                    let CborValue::Int(n) = v else {
                        return Err(Error::BadEncoding("hash_algo must be an integer"));
                    };
                    if *n < 0 {
                        return Err(Error::UnknownHashAlgo(*n as u64));
                    }
                    hash_algo = Some(HashAlgo::from_u64(*n as u64)?);
                }
                CborValue::String(s) if s == "digest" => {
                    let CborValue::Bytes(b) = v else {
                        return Err(Error::BadEncoding("digest must be a byte string"));
                    };
                    if b.len() != 32 {
                        return Err(Error::InvalidDigestLength(b.len()));
                    }
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(b);
                    digest = Some(arr);
                }
                _ => return Err(Error::BadEncoding("unknown key in CIDv1")),
            }
        }
        let hash_algo = hash_algo.ok_or(Error::BadEncoding("CIDv1 missing hash_algo"))?;
        let digest = digest.ok_or(Error::BadEncoding("CIDv1 missing digest"))?;
        Ok(CidV1 { hash_algo, digest })
    }
}

/// Union of raw and tagged CIDs.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CidOrV1 {
    /// Raw 32-byte digest.
    Raw(Cid),
    /// Tagged identifier.
    V1(CidV1),
}

impl CidOrV1 {
    /// Return the digest regardless of variant.
    pub const fn digest(&self) -> &[u8; 32] {
        match self {
            CidOrV1::Raw(c) => &c.0,
            CidOrV1::V1(v) => &v.digest,
        }
    }

    /// Return the algorithm if tagged, `None` if raw.
    pub const fn algo(&self) -> Option<HashAlgo> {
        match self {
            CidOrV1::Raw(_) => None,
            CidOrV1::V1(v) => Some(v.hash_algo),
        }
    }

    /// Encode to CBOR. Raw CIDs are byte strings; tagged CIDs are maps.
    pub fn to_cbor(&self) -> CborValue {
        match self {
            CidOrV1::Raw(c) => c.to_cbor(),
            CidOrV1::V1(v) => v.to_cbor(),
        }
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        match value {
            CborValue::Bytes(_) => Ok(CidOrV1::Raw(Cid::from_cbor(value)?)),
            CborValue::Map(_) => Ok(CidOrV1::V1(CidV1::from_cbor(value)?)),
            _ => Err(Error::BadEncoding("CIDOrV1 must be bytes or map")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_cid_roundtrip() {
        let c = Cid([0xab; 32]);
        let v = c.to_cbor();
        assert_eq!(Cid::from_cbor(&v).unwrap(), c);
    }

    #[test]
    fn cidv1_roundtrip() {
        let c = CidV1 {
            hash_algo: HashAlgo::Blake3,
            digest: [0x42; 32],
        };
        let v = c.to_cbor();
        assert_eq!(CidV1::from_cbor(&v).unwrap(), c);
    }

    #[test]
    fn cid_or_v1_distinguishes_variants() {
        let raw = CidOrV1::Raw(Cid([0u8; 32]));
        let tagged = CidOrV1::V1(CidV1 {
            hash_algo: HashAlgo::Sha256,
            digest: [0u8; 32],
        });
        assert!(matches!(
            CidOrV1::from_cbor(&raw.to_cbor()).unwrap(),
            CidOrV1::Raw(_)
        ));
        assert!(matches!(
            CidOrV1::from_cbor(&tagged.to_cbor()).unwrap(),
            CidOrV1::V1(_)
        ));
    }
}