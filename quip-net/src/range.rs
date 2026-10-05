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
//! `fetch_range` calls — [`split_range`] computes those calls.
//!
//! [`MAX_RANGE_LENGTH`]: quip_core::constants::MAX_RANGE_LENGTH
//!
//! # BLAKE3 only
//!
//! Range fetching is only defined for BLAKE3 CIDs. The codec does not
//! enforce this — it carries any [`CidOrV1`]. The server and client
//! helpers check the algorithm; see [`is_blake3`].
//!
//! # Quarantine and the responder
//!
//! A responder that supports the governance primitive MUST NOT serve a
//! quarantined CID via `range_response`, even when the requester knows
//! the CID (§8.2, §19.3), and MUST reject a length above the peer's
//! negotiated `max_range_length` with `E_RANGE_INVALID`.
//! [`bao_support::RangeResponder`] is the entry point that enforces
//! both, and a governance-supporting responder SHOULD use it.

use crate::codec::{as_u64, envelope, fields, verb_of};
use crate::constants::MAX_MESSAGE_SIZE;
use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::cid::{CidOrV1, HashAlgo};
use quip_core::time::Timestamp;

/// Largest `length` we will serve in a single [`RangeResponse`].
///
/// The `bao` chunk tree cache lives in
/// [`crate::bao_cache`].
pub const MAX_RANGE_IN_SINGLE_RESPONSE: u64 = (MAX_MESSAGE_SIZE as u64 - 1024) / 2;

/// True if `cid` is a BLAKE3 identifier.
pub fn is_blake3(cid: &CidOrV1, negotiated: HashAlgo) -> bool {
    cid.algo().unwrap_or(negotiated) == HashAlgo::Blake3
}

// -------------------------------------------------------------------------
// Range splitting (§19.4)
// -------------------------------------------------------------------------

/// Split a large range into sub-ranges each within `max_per_request`.
///
/// §19.4 asks implementations to bound a single response's size; a caller
/// that wants more than [`MAX_RANGE_IN_SINGLE_RESPONSE`] bytes issues
/// multiple `fetch_range` requests and concatenates the responses. This
/// returns the `(offset, length)` pairs for those requests.
///
/// Returns an error if `length` is zero or `max_per_request` is zero.
pub fn split_range(
    offset: u64,
    length: u64,
    max_per_request: u64,
) -> Result<Vec<(u64, u64)>> {
    if length == 0 {
        return Err(Error::RangeInvalid("range length must be non-zero"));
    }
    if max_per_request == 0 {
        return Err(Error::RangeInvalid("max_per_request must be non-zero"));
    }
    let mut out = Vec::new();
    let mut remaining = length;
    let mut cursor = offset;
    while remaining > 0 {
        let this = remaining.min(max_per_request);
        out.push((cursor, this));
        cursor = cursor.saturating_add(this);
        remaining -= this;
    }
    Ok(out)
}

// -------------------------------------------------------------------------
// Quarantine policy (§8.2, §19.3)
// -------------------------------------------------------------------------

/// The quarantine policy a responder applies before serving a range.
///
/// §8.2: "A quarantined CID **MUST NOT** be served via `range_response`,
/// even if the requester knows the exact CID. Implementations **SHOULD**
/// reject such requests with E_QUARANTINED." §A.4 adds that a responder
/// **MUST** apply "the same quarantine policy to range responses as to
/// whole-resource reads".
///
/// This trait is that boundary. It follows the `DhtClient` pattern in
/// `nat_driver`: `quip-net` defines the interface and the caller supplies
/// the state. It is implemented for
/// [`quip_storage::QuarantineStore`], the same store
/// [`quip_storage::QuipStore`] consults for whole-resource
/// reads, so the two cannot disagree.
///
/// [`NoQuarantine`] is for callers that do not support the governance
/// primitive, which §A.4 makes the condition for the requirement.
pub trait QuarantineCheck {
    /// True if `cid` must not be served at `now`.
    ///
    /// `now` is an argument rather than a clock read because notices
    /// expire: `QuarantineStore` treats `valid_until == 0` as permanent
    /// and any other value as a deadline.
    fn is_quarantined(&self, cid: &CidOrV1, now: Timestamp) -> bool;
}

impl QuarantineCheck for quip_storage::QuarantineStore {
    fn is_quarantined(&self, cid: &CidOrV1, now: Timestamp) -> bool {
        quip_storage::QuarantineStore::is_quarantined(self, cid, now)
    }
}

/// A [`QuarantineCheck`] that quarantines nothing.
///
/// For deployments that do not support the governance primitive, which is
/// the condition §A.4 attaches to the requirement. A responder that *does*
/// support it must use [`quip_storage::QuarantineStore`], not this.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NoQuarantine;

impl QuarantineCheck for NoQuarantine {
    fn is_quarantined(&self, _cid: &CidOrV1, _now: Timestamp) -> bool {
        false
    }
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
    use crate::bao_cache::BaoCache;
    use crate::error::{Error, Result};
    use alloc::format;
    use alloc::vec::Vec;
    use std::io::{Cursor, Read};

    /// Bytes reserved for CBOR and field overhead when checking a
    /// response against [`MAX_MESSAGE_SIZE`].
    const RESPONSE_OVERHEAD: usize = 512;

    /// Validate a range against `payload` and the single-response cap.
    ///
    /// Returns the half-open `[start, end)` byte interval. Shared by
    /// [`extract_proof`] and [`extract_proof_cached`] so that the cached
    /// and uncached paths reject exactly the same inputs.
    fn checked_range(payload: &[u8], offset: u64, length: u64) -> Result<(usize, usize)> {
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
        Ok((offset as usize, end as usize))
    }

    /// A proof produced by [`extract_proof_cached`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ExtractedProof {
        /// The raw payload bytes for the requested range.
        pub slice: Vec<u8>,
        /// The bao-encoded slice, ready for a [`RangeResponse`].
        pub proof: Vec<u8>,
        /// True if the chunk tree was not cached and had to be built on
        /// this call.
        ///
        /// §8.2 says a responder that recomputes **SHOULD** rate-limit
        /// such requests. This flag is the signal for that decision;
        /// `RateLimiter::check_at_most` is the intended tool.
        pub recomputed: bool,
    }

    /// Build a proof for `payload[offset..offset+length]`.
    ///
    /// Returns a `(slice, proof)` pair suitable for [`RangeResponse`]. The
    /// `slice` is the raw bytes; the `proof` is a bao-encoded stream that
    /// a client can feed to [`verify_response`].
    ///
    /// # Cost
    ///
    /// Encodes the entire payload on every call, which is O(n) in the
    /// resource size. This is the "recompute on demand" path that §8.2
    /// permits. [`extract_proof_cached`] is the caching path §8.2 prefers
    /// and produces byte-identical proofs.
    pub fn extract_proof(
        payload: &[u8],
        offset: u64,
        length: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let (start, end) = checked_range(payload, offset, length)?;

        let slice = payload[start..end].to_vec();

        // bao's SliceExtractor reads from the *encoded* stream, not the
        // raw bytes: the encoding begins with an 8-byte length prefix
        // that the extractor uses to plan its walk.
        let (encoded, _root_hash) = ::bao::encode::encode(payload);

        let mut extractor =
            ::bao::encode::SliceExtractor::new(Cursor::new(encoded), offset, length);
        let mut proof = Vec::with_capacity(slice.len() + RESPONSE_OVERHEAD);
        extractor
            .read_to_end(&mut proof)
            .map_err(|e| Error::Transport(format!("bao extract: {e}")))?;

        if slice.len() + proof.len() + RESPONSE_OVERHEAD > MAX_MESSAGE_SIZE {
            return Err(Error::RangeInvalid(
                "range response exceeds MAX_MESSAGE_SIZE",
            ));
        }

        Ok((slice, proof))
    }

    /// Build a proof using a cached chunk tree, per §8.2 (M7).
    ///
    /// On a hit the tree is reused and the call costs
    /// `O(log(resource_size))`. On a miss the tree is built once, at
    /// `O(payload.len())`, and cached, so the next request for the same
    /// resource is a hit — the behaviour §8.2 asks for when it says a
    /// responder **SHOULD** "cache the tree after the first
    /// recomputation".
    ///
    /// A tree too large for the cache is not an error: the call falls back
    /// to [`extract_proof`], so wiring a cache never makes a responder
    /// serve less than it would have without one.
    ///
    /// # Trust boundary
    ///
    /// `payload` must be the bytes addressed by `cid`, for the reason
    /// documented on [`BaoCache`]: re-hashing per request would cost the
    /// `O(n)` this function exists to avoid. The digest is checked when
    /// the tree is built, so a mismatch is an error on a miss; on a hit
    /// the caller's assertion is taken as given.
    pub fn extract_proof_cached(
        cache: &mut BaoCache,
        cid: &CidOrV1,
        payload: &[u8],
        offset: u64,
        length: u64,
        negotiated: HashAlgo,
        now: Timestamp,
    ) -> Result<ExtractedProof> {
        if !super::is_blake3(cid, negotiated) {
            return Err(Error::RangeInvalid("range CID is not BLAKE3"));
        }
        let (start, end) = checked_range(payload, offset, length)?;

        // A hit requires the digest and the payload length to agree.
        let mut recomputed = false;
        if cache.get(cid, payload.len() as u64, now).is_none() {
            recomputed = true;
            // `Ok(false)` means the tree was declined as oversized, which
            // the fallback below handles.
            cache.insert(cid, payload, now)?;
        }

        let outboard = match cache.peek(cid) {
            Some(entry) => entry.outboard(),
            None => {
                let (slice, proof) = extract_proof(payload, offset, length)?;
                return Ok(ExtractedProof {
                    slice,
                    proof,
                    recomputed,
                });
            }
        };

        let slice = payload[start..end].to_vec();
        let mut extractor = ::bao::encode::SliceExtractor::new_outboard(
            Cursor::new(payload),
            Cursor::new(outboard),
            offset,
            length,
        );
        let mut proof = Vec::with_capacity(slice.len() + RESPONSE_OVERHEAD);
        extractor
            .read_to_end(&mut proof)
            .map_err(|e| Error::Transport(format!("bao extract: {e}")))?;

        if slice.len() + proof.len() + RESPONSE_OVERHEAD > MAX_MESSAGE_SIZE {
            return Err(Error::RangeInvalid(
                "range response exceeds MAX_MESSAGE_SIZE",
            ));
        }

        Ok(ExtractedProof {
            slice,
            proof,
            recomputed,
        })
    }

    /// Serve a range, applying the quarantine policy first (§8.2, §19.3).
    ///
    /// This is the entry point a responder should call. It consults
    /// `quarantine` before touching the cache, so a quarantined CID is
    /// neither served nor given a chunk tree, and it fails with
    /// [`quip_core::ErrorCode::Quarantined`]
    /// (0x10) as §8.2 recommends.
    ///
    /// [`extract_proof_cached`] is the same operation without the policy.
    /// A responder that supports the governance primitive **MUST NOT**
    /// call it directly: §8.2 makes the quarantine check mandatory, not
    /// optional.
    #[allow(clippy::too_many_arguments)]
    pub fn serve_range<Q: QuarantineCheck>(
        cache: &mut BaoCache,
        quarantine: &Q,
        cid: &CidOrV1,
        payload: &[u8],
        offset: u64,
        length: u64,
        negotiated: HashAlgo,
        now: Timestamp,
    ) -> Result<ExtractedProof> {
        if quarantine.is_quarantined(cid, now) {
            return Err(Error::Storage(quip_storage::Error::Quarantined));
        }
        extract_proof_cached(cache, cid, payload, offset, length, negotiated, now)
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

    // ---------------------------------------------------------------------
    // RangeResponder — cache + quarantine + negotiated cap (M7)
    // ---------------------------------------------------------------------

    /// A responder that serves byte ranges subject to three policies.
    ///
    /// The three belong together because they are the three things a
    /// responder must consult before building a `range_response`:
    ///
    /// - §8.2 requires the quarantine check on a range request.
    /// - §8.2 requires rejecting a length above the negotiated cap with
    ///   `E_RANGE_INVALID`.
    /// - §A.4 requires caching the chunk tree when possible.
    ///
    /// `max_range_length` is the peer's negotiated maximum, from the
    /// handshake extension `max_range_length` (0x0C). A caller that did
    /// not negotiate one SHOULD pass
    /// [`MAX_RANGE_IN_SINGLE_RESPONSE`].
    ///
    /// A responder that supports the governance primitive **MUST** use
    /// this type (or [`serve_range`]) rather than calling
    /// [`extract_proof_cached`] directly, because §8.2 makes the
    /// quarantine check mandatory.
    pub struct RangeResponder<'a, Q: QuarantineCheck> {
        cache: &'a mut BaoCache,
        quarantine: &'a Q,
        max_range_length: u64,
    }

    impl<'a, Q: QuarantineCheck> RangeResponder<'a, Q> {
        /// Build a responder.
        pub fn new(
            cache: &'a mut BaoCache,
            quarantine: &'a Q,
            max_range_length: u64,
        ) -> Self {
            Self {
                cache,
                quarantine,
                max_range_length,
            }
        }

        /// The maximum length the responder will serve, which is the
        /// smaller of the negotiated cap and the single-response cap.
        pub fn effective_max_range_length(&self) -> u64 {
            self.max_range_length
                .min(super::MAX_RANGE_IN_SINGLE_RESPONSE)
        }

        /// Serve a range request.
        ///
        /// Checks, in order:
        /// 1. The requested length against the negotiated and
        ///    single-response caps (§8.2).
        /// 2. The quarantine policy (§8.2, §19.3).
        /// 3. The cached chunk tree for a hit; recomputes on a miss
        ///    (§A.4).
        pub fn serve(
            &mut self,
            request: &super::FetchRange,
            payload: &[u8],
            negotiated: HashAlgo,
            now: Timestamp,
        ) -> Result<ExtractedProof> {
            request.check_length(self.effective_max_range_length())?;
            if self.quarantine.is_quarantined(&request.cid, now) {
                return Err(Error::Storage(quip_storage::Error::Quarantined));
            }
            extract_proof_cached(
                self.cache,
                &request.cid,
                payload,
                request.offset,
                request.length,
                negotiated,
                now,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quip_core::messages::{IndividualRingSig, QuarantineNotice, RingSignature};
    use quip_storage::QuarantineStore;

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

    // ---- split_range (§19.4) ----

    #[test]
    fn split_range_covers_the_whole_span() {
        let parts = split_range(0, 100, 32).unwrap();
        assert_eq!(parts, vec![(0, 32), (32, 32), (64, 32), (96, 4)]);
        let total: u64 = parts.iter().map(|(_, len)| len).sum();
        assert_eq!(total, 100);
    }

    #[test]
    fn split_range_single_part_when_it_fits() {
        let parts = split_range(500, 100, 1024).unwrap();
        assert_eq!(parts, vec![(500, 100)]);
    }

    #[test]
    fn split_range_respects_the_offset() {
        let parts = split_range(1000, 70, 30).unwrap();
        assert_eq!(parts, vec![(1000, 30), (1030, 30), (1060, 10)]);
    }

    #[test]
    fn split_range_rejects_zero_length() {
        assert!(split_range(0, 0, 32).is_err());
    }

    #[test]
    fn split_range_rejects_zero_max_per_request() {
        assert!(split_range(0, 100, 0).is_err());
    }

    // ---- quarantine policy (§8.2, §19.3) ----

    fn raw_cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(quip_core::cid::Cid([b; 32]))
    }

    fn notice(tcid: u8, affected: &[u8], valid_until_ms: u64) -> QuarantineNotice {
        QuarantineNotice {
            trusted_cid: raw_cid(tcid),
            affected_cids: affected.iter().map(|&b| raw_cid(b)).collect(),
            reason: "dmca".into(),
            timestamp: Timestamp::from_millis(1_000),
            valid_until: Timestamp::from_millis(valid_until_ms),
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0xaa; 64]],
                signers: vec![[0x01; 32]],
            }),
        }
    }

    #[test]
    fn no_quarantine_never_quarantines() {
        let q = NoQuarantine;
        assert!(!q.is_quarantined(&raw_cid(1), Timestamp::from_millis(0)));
        assert!(!q.is_quarantined(&raw_cid(1), Timestamp::from_millis(u64::MAX)));
    }

    #[test]
    fn quarantine_store_impl_matches_storage() {
        // The point of the impl is that `quip-net` and `QuipStore` cannot
        // disagree about what is quarantined. Delegate, do not reimplement.
        let mut store = QuarantineStore::new();
        let target = raw_cid(1);
        let t0 = Timestamp::from_millis(2_000);

        assert!(!store.is_quarantined(&target, t0));
        assert!(!QuarantineCheck::is_quarantined(&store, &target, t0));

        store.add_notice(notice(1, &[2], 0), t0).unwrap();

        assert!(store.is_quarantined(&target, t0));
        assert!(QuarantineCheck::is_quarantined(&store, &target, t0));
        // An affected CID is covered too, not just the trusted CID.
        assert!(QuarantineCheck::is_quarantined(&store, &raw_cid(2), t0));
        // An unrelated CID is not.
        assert!(!QuarantineCheck::is_quarantined(&store, &raw_cid(9), t0));
    }

    #[test]
    fn quarantine_check_honours_expiry() {
        let mut store = QuarantineStore::new();
        let target = raw_cid(1);
        let t0 = Timestamp::from_millis(2_000);

        // Valid until t0 + 1000 ms.
        store.add_notice(notice(1, &[], 3_000), t0).unwrap();

        assert!(QuarantineCheck::is_quarantined(&store, &target, t0));
        assert!(!QuarantineCheck::is_quarantined(
            &store,
            &target,
            Timestamp::from_millis(3_000)
        ));
    }

    // ---- bao helpers (crypto feature only) ----

    #[cfg(feature = "crypto")]
    mod bao_tests {
        use super::*;
        use crate::bao_cache::BaoCache;
        use crate::range::bao_support::{
            extract_proof, extract_proof_cached, verified_slice, verify_response, ExtractedProof,
            RangeResponder,
        };

        fn now() -> Timestamp {
            Timestamp::from_millis(1_700_000_000_000)
        }

        fn response(cid: CidOrV1, offset: u64, length: u64, out: ExtractedProof) -> RangeResponse {
            RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset,
                length,
                bytes: out.slice,
                proof: out.proof,
            }
        }

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

        // ---- cached path (§8.2, M7) ----

        #[test]
        fn cached_proof_verifies_with_the_unchanged_verifier() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();

            let out =
                extract_proof_cached(&mut cache, &cid, &payload, 100, 200, HashAlgo::Blake3, now())
                    .unwrap();

            // The client side is untouched by this milestone: the same
            // verifier that accepted the uncached proofs must accept this.
            let resp = response(cid, 100, 200, out);
            let verified = verified_slice(&resp, HashAlgo::Blake3).unwrap();
            assert_eq!(verified, payload[100..300].to_vec());
        }

        #[test]
        fn cached_and_uncached_proofs_are_byte_identical() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();

            let (uncached_slice, uncached_proof) = extract_proof(&payload, 1234, 500).unwrap();
            let cached = extract_proof_cached(
                &mut cache,
                &cid,
                &payload,
                1234,
                500,
                HashAlgo::Blake3,
                now(),
            )
            .unwrap();

            assert_eq!(cached.slice, uncached_slice);
            assert_eq!(cached.proof, uncached_proof, "wire bytes must not move");
        }

        #[test]
        fn second_request_for_a_resource_is_a_cache_hit() {
            let payload: Vec<u8> = vec![9; 4096];
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();

            let first =
                extract_proof_cached(&mut cache, &cid, &payload, 0, 256, HashAlgo::Blake3, now())
                    .unwrap();
            assert!(first.recomputed, "first request must build the tree");

            let second = extract_proof_cached(
                &mut cache,
                &cid,
                &payload,
                1024,
                256,
                HashAlgo::Blake3,
                now(),
            )
            .unwrap();
            assert!(!second.recomputed, "second request must reuse the tree");

            let stats = cache.stats();
            assert_eq!(stats.hits, 1);
            assert_eq!(stats.misses, 1);
            assert_eq!(stats.entries, 1);
        }

        #[test]
        fn cached_path_matches_uncached_across_chunk_boundaries() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();

            let cases: [(u64, u64); 5] =
                [(0, 1), (1023, 2), (1024, 1024), (2048, 2048), (4095, 1)];
            for (offset, length) in cases {
                let (expected_slice, expected_proof) =
                    extract_proof(&payload, offset, length).unwrap();
                let got = extract_proof_cached(
                    &mut cache,
                    &cid,
                    &payload,
                    offset,
                    length,
                    HashAlgo::Blake3,
                    now(),
                )
                .unwrap();
                assert_eq!(got.slice, expected_slice, "slice at {offset}+{length}");
                assert_eq!(got.proof, expected_proof, "proof at {offset}+{length}");
            }
        }

        #[test]
        fn cached_path_rejects_the_same_inputs_as_uncached() {
            let payload: Vec<u8> = vec![3; 1024];
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();

            let cases: [(u64, u64); 4] = [
                (0, 0),                                // zero length
                (1000, 100),                           // extends past the resource
                (1024, 1),                             // starts at the end
                (0, MAX_RANGE_IN_SINGLE_RESPONSE + 1), // over the single-response cap
            ];
            for (offset, length) in cases {
                let uncached = extract_proof(&payload, offset, length).is_err();
                let cached = extract_proof_cached(
                    &mut cache,
                    &cid,
                    &payload,
                    offset,
                    length,
                    HashAlgo::Blake3,
                    now(),
                )
                .is_err();
                assert!(uncached, "uncached should reject {offset}+{length}");
                assert_eq!(cached, uncached, "paths disagree on {offset}+{length}");
            }

            // A SHA-256 CID is not range-fetchable.
            let sha = cid_sha256(&payload);
            assert!(extract_proof_cached(
                &mut cache,
                &sha,
                &payload,
                0,
                32,
                HashAlgo::Sha256,
                now(),
            )
            .is_err());
            assert!(cache.is_empty(), "a rejected request must not populate");
        }

        #[test]
        fn cached_path_errors_when_the_payload_does_not_match_the_cid() {
            let payload: Vec<u8> = vec![4; 4096];
            let other: Vec<u8> = vec![5; 4096];
            let mut cache = BaoCache::new();

            // On a miss the tree is built for `cid`, so a payload that does
            // not hash to it cannot be cached or served.
            let err = extract_proof_cached(
                &mut cache,
                &cid_blake3(&other),
                &payload,
                0,
                64,
                HashAlgo::Blake3,
                now(),
            )
            .unwrap_err();
            assert!(matches!(err, Error::ProofInvalid(_)), "got {err:?}");
            assert!(cache.is_empty());
        }

        #[test]
        fn oversized_tree_falls_back_and_still_verifies() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);
            // A cache that cannot hold anything: every tree is declined.
            let mut cache = BaoCache::with_limits(4, 1, 1);

            let out =
                extract_proof_cached(&mut cache, &cid, &payload, 0, 128, HashAlgo::Blake3, now())
                    .unwrap();
            assert!(out.recomputed);
            assert!(cache.is_empty(), "nothing should have been cached");

            let resp = response(cid, 0, 128, out);
            assert_eq!(
                verified_slice(&resp, HashAlgo::Blake3).unwrap(),
                payload[0..128].to_vec()
            );
        }

        #[test]
        fn an_evicted_tree_is_rebuilt_and_still_verifies() {
            let small: Vec<u8> = vec![1; 4096];
            let big: Vec<u8> = vec![2; 256 * 1024];
            let small_cid = cid_blake3(&small);
            let big_cid = cid_blake3(&big);

            // A budget that holds the large tree and nothing else.
            let big_tree = ::bao::encode::outboard_size(big.len() as u64) as usize;
            let mut cache = BaoCache::with_limits(8, big_tree, big_tree);

            let first = extract_proof_cached(
                &mut cache,
                &small_cid,
                &small,
                0,
                64,
                HashAlgo::Blake3,
                now(),
            )
            .unwrap();
            assert!(first.recomputed);
            assert!(cache.contains(&small_cid));

            // The larger resource evicts the smaller one.
            let _ = extract_proof_cached(
                &mut cache,
                &big_cid,
                &big,
                0,
                64,
                HashAlgo::Blake3,
                now(),
            )
            .unwrap();
            assert!(!cache.contains(&small_cid), "small tree should be evicted");

            // Re-requesting the small resource rebuilds it; the proof still
            // verifies.
            let again = extract_proof_cached(
                &mut cache,
                &small_cid,
                &small,
                0,
                64,
                HashAlgo::Blake3,
                now(),
            )
            .unwrap();
            assert!(again.recomputed, "an evicted tree must be rebuilt");

            let resp = response(small_cid, 0, 64, again);
            assert_eq!(
                verified_slice(&resp, HashAlgo::Blake3).unwrap(),
                small[0..64].to_vec()
            );
        }

        #[test]
        fn cached_path_serves_the_whole_payload_from_a_hit() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(2048).collect();
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();

            // Warm the cache, then take the whole resource from the hit.
            let _ =
                extract_proof_cached(&mut cache, &cid, &payload, 0, 1, HashAlgo::Blake3, now())
                    .unwrap();
            let out = extract_proof_cached(
                &mut cache,
                &cid,
                &payload,
                0,
                2048,
                HashAlgo::Blake3,
                now(),
            )
            .unwrap();

            assert!(!out.recomputed);
            assert_eq!(out.slice, payload);

            let resp = response(cid, 0, 2048, out);
            assert!(verify_response(&resp, HashAlgo::Blake3).is_ok());
        }

        // ---- RangeResponder (§8.2, §19.3, M7) ----

        #[test]
        fn responder_enforces_the_negotiated_cap() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();
            let q = NoQuarantine;
            // A tight cap, far below MAX_RANGE_IN_SINGLE_RESPONSE.
            let mut resp = RangeResponder::new(&mut cache, &q, 100);

            let req = FetchRange {
                resource_id: b"r".to_vec(),
                cid,
                offset: 0,
                length: 200,
            };
            let err = resp
                .serve(&req, &payload, HashAlgo::Blake3, now())
                .unwrap_err();
            assert!(matches!(err, Error::RangeInvalid(_)), "got {err:?}");
            assert!(cache.is_empty(), "a rejected request must not populate");
        }

        #[test]
        fn responder_checks_quarantine_before_serving() {
            struct AlwaysQuarantined;
            impl QuarantineCheck for AlwaysQuarantined {
                fn is_quarantined(&self, _: &CidOrV1, _: Timestamp) -> bool {
                    true
                }
            }

            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();
            let q = AlwaysQuarantined;
            let mut resp =
                RangeResponder::new(&mut cache, &q, MAX_RANGE_IN_SINGLE_RESPONSE);

            let req = FetchRange {
                resource_id: b"r".to_vec(),
                cid,
                offset: 0,
                length: 64,
            };
            let err = resp
                .serve(&req, &payload, HashAlgo::Blake3, now())
                .unwrap_err();
            assert!(
                matches!(err, Error::Storage(quip_storage::Error::Quarantined)),
                "got {err:?}"
            );
            assert!(cache.is_empty(), "a rejected request must not populate");
        }

        #[test]
        fn responder_serves_a_valid_request() {
            let payload: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
            let cid = cid_blake3(&payload);
            let mut cache = BaoCache::new();
            let q = NoQuarantine;
            let mut resp =
                RangeResponder::new(&mut cache, &q, MAX_RANGE_IN_SINGLE_RESPONSE);

            let req = FetchRange {
                resource_id: b"r".to_vec(),
                cid,
                offset: 100,
                length: 200,
            };
            let out = resp
                .serve(&req, &payload, HashAlgo::Blake3, now())
                .unwrap();
            assert_eq!(out.slice, payload[100..300].to_vec());

            let r = RangeResponse {
                resource_id: b"r".to_vec(),
                cid,
                offset: 100,
                length: 200,
                bytes: out.slice,
                proof: out.proof,
            };
            assert!(verify_response(&r, HashAlgo::Blake3).is_ok());
        }

        #[test]
        fn responder_effective_cap_is_the_smaller_of_the_two() {
            let mut cache = BaoCache::new();
            let q = NoQuarantine;

            let small = RangeResponder::new(&mut cache, &q, 100);
            assert_eq!(small.effective_max_range_length(), 100);

            let large = RangeResponder::new(&mut cache, &q, u64::MAX);
            assert_eq!(
                large.effective_max_range_length(),
                MAX_RANGE_IN_SINGLE_RESPONSE
            );
        }
    }
}