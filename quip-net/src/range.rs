//! Merkle range fetching (spec §8.2).
//!
//! Two verbs, both on T1:
//!
//! - `fetch_range` requests a byte range from an immutable BLAKE3
//!   resource.
//! - `range_response` returns the slice, a bao-encoded proof, and the
//!   echoed request parameters.
//!
//! # Wire form
//!
//! ```text
//! fetch_range    = ["quip-v1", "fetch_range", resource_id, cid, offset, length]
//! range_response = ["quip-v1", "range_response", resource_id, cid,
//!                   offset, length, bytes, proof]
//! ```
//!
//! Neither message is signed. The proof itself is the cryptographic
//! guarantee; the response's identity is established by the connection
//! and by the CID matching the payload.
//!
//! # Proof format
//!
//! `proof` is the byte stream produced by BLAKE3's verified streaming
//! encoder for `payload[offset..offset+length]`. In Rust, that is
//! [`bao::encode::SliceExtractor`]'s output. The client verifies it with
//! [`bao::decode::SliceDecoder`] and checks that the verified slice
//! equals `bytes`.
//!
//! # Message size constraint
//!
//! The spec allows `length` up to [`MAX_RANGE_LENGTH`] (1 MiB), but a
//! QUIP message is capped at [`MAX_MESSAGE_SIZE`] (64 KiB). A
//! `range_response` carries both the slice (`bytes`) and a bao-encoded
//! stream (`proof`) that is roughly the same size, so the effective cap
//! is much smaller than either nominal limit.
//!
//! [`MAX_RANGE_IN_SINGLE_RESPONSE`] is the largest `length` this crate
//! will serve in one response, derived from [`MAX_MESSAGE_SIZE`] with a
//! 1 KiB reserve for CBOR and field overhead. Callers negotiating
//! `max_range_length` with a peer SHOULD cap it at this value; callers
//! that need larger ranges MUST split the request across multiple
//! `fetch_range` calls.
//!
//! [`MAX_RANGE_LENGTH`]: quip_core::constants::MAX_RANGE_LENGTH
//!
//! # BLAKE3 only
//!
//! Range fetching is only defined for BLAKE3 CIDs. The codec does not
//! enforce this — it carries any [`CidOrV1`]. The server and client
//! helpers check the algorithm; see [`is_blake3`].

use crate::codec::{as_u64, envelope, fields, verb_of};
use crate::constants::MAX_MESSAGE_SIZE;
use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::cid::{CidOrV1, HashAlgo};

/// Largest `length` we will serve in a single [`RangeResponse`].
pub const MAX_RANGE_IN_SINGLE_RESPONSE: u64 = (MAX_MESSAGE_SIZE as u64 - 1024) / 2;

/// True if `cid` is a BLAKE3 identifier.
pub fn is_blake3(cid: &CidOrV1, negotiated: HashAlgo) -> bool {
    cid.algo().unwrap_or(negotiated) == HashAlgo::Blake3
}

// -------------------------------------------------------------------------
// fetch_range
// -------------------------------------------------------------------------

/// `fetch_range` — request a byte range (§8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRange {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// BLAKE3 CID of the resource.
    pub cid: CidOrV1,
    /// Byte offset within the resource.
    pub offset: u64,
    /// Byte length; must be non-zero and at most the peer's advertised
    /// `max_range_length`.
    pub length: u64,
}

impl FetchRange {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "fetch_range",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                self.cid.to_cbor(),
                CborValue::Int(self.offset as i128),
                CborValue::Int(self.length as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "fetch_range" {
            return Err(Error::BadFrame("not a fetch_range"));
        }
        let f = fields(&v, "fetch_range")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("fetch_range arity"));
        }
        let length = as_u64(&f[3])?;
        if length == 0 {
            return Err(Error::RangeInvalid("fetch_range length must be non-zero"));
        }
        Ok(Self {
            resource_id: crate::codec::as_bytes(&f[0])?,
            cid: CidOrV1::from_cbor(&f[1])?,
            offset: as_u64(&f[2])?,
            length,
        })
    }

    /// Validate against a negotiated `max_range_length`.
    pub fn check_length(&self, max_range_length: u64) -> Result<()> {
        if self.length > max_range_length {
            return Err(Error::RangeInvalid(
                "fetch_range length exceeds negotiated maximum",
            ));
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------
// range_response
// -------------------------------------------------------------------------

/// `range_response` — a range fetch's reply (§8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeResponse {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// The CID from the request.
    pub cid: CidOrV1,
    /// Byte offset from the request.
    pub offset: u64,
    /// Byte length from the request.
    pub length: u64,
    /// The raw slice.
    pub bytes: Vec<u8>,
    /// The bao-encoded proof.
    pub proof: Vec<u8>,
}

impl RangeResponse {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "range_response",
            alloc::vec![
                CborValue::Bytes(self.resource_id.clone()),
                self.cid.to_cbor(),
                CborValue::Int(self.offset as i128),
                CborValue::Int(self.length as i128),
                CborValue::Bytes(self.bytes.clone()),
                CborValue::Bytes(self.proof.clone()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "range_response" {
            return Err(Error::BadFrame("not a range_response"));
        }
        let f = fields(&v, "range_response")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("range_response arity"));
        }
        let offset = as_u64(&f[2])?;
        let length = as_u64(&f[3])?;
        let slice = crate::codec::as_bytes(&f[4])?;
        if slice.len() as u64 != length {
            return Err(Error::RangeInvalid(
                "range_response byte count does not match length",
            ));
        }
        Ok(Self {
            resource_id: crate::codec::as_bytes(&f[0])?,
            cid: CidOrV1::from_cbor(&f[1])?,
            offset,
            length,
            bytes: slice,
            proof: crate::codec::as_bytes(&f[5])?,
        })
    }
}

// -------------------------------------------------------------------------
// bao-backed helpers
// -------------------------------------------------------------------------

/// Server-side proof generation and client-side proof verification.
#[cfg(feature = "crypto")]
pub mod bao_support {
    use super::*;
    use crate::error::{Error, Result};
    use alloc::format;
    use alloc::vec::Vec;
    use std::io::{Cursor, Read};

    /// Build a proof for `payload[offset..offset+length]`.
    ///
    /// Returns a `(slice, proof)` pair suitable for [`RangeResponse`]. The
    /// `slice` is the raw bytes; the `proof` is a bao-encoded stream that
    /// a client can feed to [`verify_response`].
    ///
    /// # Cost
    ///
    /// Encodes the entire payload on every call, which is O(n) in the
    /// resource size. The spec (§8.2) permits this and suggests caching
    /// the encoded stream alongside the blob for production deployments.
    pub fn extract_proof(
        payload: &[u8],
        offset: u64,
        length: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if length == 0 {
            return Err(Error::RangeInvalid("range length must be non-zero"));
        }
        if length > MAX_RANGE_IN_SINGLE_RESPONSE {
            return Err(Error::RangeInvalid(
                "range length exceeds single-response cap",
            ));
        }
        let end = offset
            .checked_add(length)
            .ok_or(Error::RangeInvalid("range offset + length overflows"))?;
        if end > payload.len() as u64 {
            return Err(Error::RangeInvalid("range extends past the resource"));
        }

        let slice = payload[offset as usize..end as usize].to_vec();

        // bao's SliceExtractor reads from the *encoded* stream, not the
        // raw bytes: the encoding begins with an 8-byte length prefix
        // that the extractor uses to plan its walk.
        let (encoded, _root_hash) = ::bao::encode::encode(payload);

        let mut extractor =
            ::bao::encode::SliceExtractor::new(Cursor::new(encoded), offset, length);
        let mut proof = Vec::with_capacity(slice.len() + 512);
        extractor
            .read_to_end(&mut proof)
            .map_err(|e| Error::Transport(format!("bao extract: {e}")))?;

        let overhead_estimate = 512usize;
        if slice.len() + proof.len() + overhead_estimate > MAX_MESSAGE_SIZE {
            return Err(Error::RangeInvalid(
                "range response exceeds MAX_MESSAGE_SIZE",
            ));
        }

        Ok((slice, proof))
    }

    /// Verify a [`RangeResponse`] against the expected CID.
    pub fn verify_response(resp: &RangeResponse, negotiated: HashAlgo) -> Result<()> {
        if !super::is_blake3(&resp.cid, negotiated) {
            return Err(Error::RangeInvalid("range_response CID is not BLAKE3"));
        }

        let digest: [u8; 32] = *resp.cid.digest();
        let hash: ::bao::Hash = digest.into();

        let mut decoder = ::bao::decode::SliceDecoder::new(
            Cursor::new(&resp.proof[..]),
            &hash,
            resp.offset,
            resp.length,
        );

        let mut verified = Vec::with_capacity(resp.length as usize);
        decoder
            .read_to_end(&mut verified)
            .map_err(|_| Error::ProofInvalid("bao verification failed"))?;

        if verified != resp.bytes {
            return Err(Error::ProofInvalid(
                "verified slice does not match response bytes",
            ));
        }
        Ok(())
    }

    /// Convenience: verify a slice and return it.
    pub fn verified_slice(resp: &RangeResponse, negotiated: HashAlgo) -> Result<Vec<u8>> {
        verify_response(resp, negotiated)?;
        Ok(resp.bytes.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn cid_blake3(payload: &[u8]) -> CidOrV1 {
        let hash = ::blake3::hash(payload);
        CidOrV1::V1(quip_core::cid::CidV1 {
            hash_algo: HashAlgo::Blake3,
            digest: *hash.as_bytes(),
        })
    }

    fn cid_sha256(payload: &[u8]) -> CidOrV1 {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(payload);
        let out = hasher.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&out);
        CidOrV1::V1(quip_core::cid::CidV1 {
            hash_algo: HashAlgo::Sha256,
            digest: arr,
        })
    }

    // ---- codec ----

    #[test]
    fn fetch_range_roundtrip() {
        let m = FetchRange {
            resource_id: b"video".to_vec(),
            cid: cid_blake3(b"payload"),
            offset: 1024,
            length: 512,
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(FetchRange::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn fetch_range_rejects_zero_length() {
        let m = FetchRange {
            resource_id: b"v".to_vec(),
            cid: cid_blake3(b"p"),
            offset: 0,
            length: 0,
        };
        let bytes = m.to_bytes().unwrap();
        assert!(FetchRange::from_bytes(&bytes).is_err());
    }

    #[test]
    fn fetch_range_check_length() {
        let m = FetchRange {
            resource_id: vec![],
            cid: cid_blake3(b"p"),
            offset: 0,
            length: 1024,
        };
        assert!(m.check_length(1024).is_ok());
        assert!(m.check_length(512).is_err());
    }

    #[test]
    fn range_response_roundtrip() {
        let m = RangeResponse {
            resource_id: b"video".to_vec(),
            cid: cid_blake3(b"payload"),
            offset: 0,
            length: 4,
            bytes: b"data".to_vec(),
            proof: vec![0xde, 0xad, 0xbe, 0xef],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(RangeResponse::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn range_response_rejects_byte_count_mismatch() {
        let msg = envelope(
            "range_response",
            alloc::vec![
                CborValue::Bytes(vec![]),
                cid_blake3(b"p").to_cbor(),
                CborValue::Int(0),
                CborValue::Int(100),
                CborValue::Bytes(vec![1, 2, 3]),
                CborValue::Bytes(vec![]),
            ],
        );
        let bytes = encode(&msg).unwrap();
        assert!(RangeResponse::from_bytes(&bytes).is_err());
    }

    #[test]
    fn is_blake3_detects_algorithm() {
        let payload = b"payload";
        assert!(is_blake3(&cid_blake3(payload), HashAlgo::Sha256));
        assert!(!is_blake3(&cid_sha256(payload), HashAlgo::Blake3));
        let raw = CidOrV1::Raw(quip_core::cid::Cid([0u8; 32]));
        assert!(is_blake3(&raw, HashAlgo::Blake3));
        assert!(!is_blake3(&raw, HashAlgo::Sha256));
    }

    // ---- bao helpers (crypto feature only) ----

    #[cfg(feature = "crypto")]
    mod bao_tests {
        use super::*;
        use crate::range::bao_support::{extract_proof, verified_slice, verify_response};

        #[test]
        fn extract_and_verify_chunk_aligned_range() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4 * 1024).collect();
            let cid = cid_blake3(&payload);

            let (slice, proof) = extract_proof(&payload, 1024, 1024).unwrap();
            assert_eq!(slice, payload[1024..2048].to_vec());

            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 1024,
                length: 1024,
                bytes: slice,
                proof,
            };
            verify_response(&resp, HashAlgo::Blake3).unwrap();
        }

        #[test]
        fn extract_and_verify_unaligned_range() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4 * 1024).collect();
            let cid = cid_blake3(&payload);

            let (slice, proof) = extract_proof(&payload, 1234, 500).unwrap();
            assert_eq!(slice, payload[1234..1734].to_vec());

            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 1234,
                length: 500,
                bytes: slice,
                proof,
            };
            verify_response(&resp, HashAlgo::Blake3).unwrap();
        }

        #[test]
        fn extract_and_verify_single_byte() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);

            let (slice, proof) = extract_proof(&payload, 2000, 1).unwrap();
            assert_eq!(slice, vec![payload[2000]]);

            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 2000,
                length: 1,
                bytes: slice,
                proof,
            };
            verify_response(&resp, HashAlgo::Blake3).unwrap();
        }

        #[test]
        fn extract_and_verify_whole_resource() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(8 * 1024).collect();
            let cid = cid_blake3(&payload);

            let (slice, proof) = extract_proof(&payload, 0, payload.len() as u64).unwrap();
            assert_eq!(slice, payload);

            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 0,
                length: payload.len() as u64,
                bytes: slice,
                proof,
            };
            verify_response(&resp, HashAlgo::Blake3).unwrap();
        }

        #[test]
        fn verify_rejects_tampered_proof() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);

            let (slice, mut proof) = extract_proof(&payload, 100, 200).unwrap();
            let mid = proof.len() / 2;
            proof[mid] ^= 0xff;

            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 100,
                length: 200,
                bytes: slice,
                proof,
            };
            assert!(verify_response(&resp, HashAlgo::Blake3).is_err());
        }

        #[test]
        fn verify_rejects_tampered_bytes() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);

            let (mut slice, proof) = extract_proof(&payload, 100, 200).unwrap();
            slice[0] ^= 0xff;

            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 100,
                length: 200,
                bytes: slice,
                proof,
            };
            assert!(verify_response(&resp, HashAlgo::Blake3).is_err());
        }

        #[test]
        fn verify_rejects_wrong_cid() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let other: Vec<u8> = (0u8..=255).cycle().take(4097).collect();

            let (slice, proof) = extract_proof(&payload, 0, 100).unwrap();

            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid: cid_blake3(&other),
                offset: 0,
                length: 100,
                bytes: slice,
                proof,
            };
            assert!(verify_response(&resp, HashAlgo::Blake3).is_err());
        }

        #[test]
        fn extract_rejects_out_of_bounds() {
            let payload: Vec<u8> = vec![0; 1024];
            assert!(extract_proof(&payload, 1000, 100).is_err());
            assert!(extract_proof(&payload, 2048, 1).is_err());
        }

        #[test]
        fn extract_rejects_zero_length() {
            let payload: Vec<u8> = vec![0; 1024];
            assert!(extract_proof(&payload, 0, 0).is_err());
        }

        #[test]
        fn extract_rejects_over_cap() {
            let payload: Vec<u8> = vec![0; MAX_RANGE_IN_SINGLE_RESPONSE as usize + 10];
            assert!(extract_proof(&payload, 0, MAX_RANGE_IN_SINGLE_RESPONSE + 1).is_err());
        }

        #[test]
        fn verify_rejects_non_blake3_cid() {
            let payload: Vec<u8> = vec![0; 1024];
            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid: cid_sha256(&payload),
                offset: 0,
                length: 4,
                bytes: vec![0, 0, 0, 0],
                proof: vec![],
            };
            assert!(verify_response(&resp, HashAlgo::Blake3).is_err());
        }

        #[test]
        fn verified_slice_returns_bytes() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
            let cid = cid_blake3(&payload);
            let (slice, proof) = extract_proof(&payload, 500, 100).unwrap();
            let resp = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 500,
                length: 100,
                bytes: slice.clone(),
                proof,
            };
            let out = verified_slice(&resp, HashAlgo::Blake3).unwrap();
            assert_eq!(out, slice);
        }
    }
}