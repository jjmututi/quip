//! Content hashing.
//!
//! `quip-storage` deliberately has no hashing dependency: like `quip-core`'s
//! [`quip_core::messages::Verifier`] trait for Ed25519, the digest
//! algorithm is supplied by the application. A `std` application would
//! typically wrap `sha2`/`blake3` behind [`ContentHasher`] (spec App. A.3).
//!
//! Two algorithms are defined by the protocol: SHA-256 (mandatory) and BLAKE3
//! (optional). Both produce 32-byte digests, which is why a raw
//! [`Cid`] is exactly 32 bytes.

use crate::error::{Error, Result};
use quip_core::cid::{Cid, CidOrV1, HashAlgo};
use quip_core::Error as CoreError;

/// A pluggable content digest provider.
pub trait ContentHasher {
    /// Digest `payload` with `algo`, or `None` if this implementation does not
    /// support that algorithm (for example a SHA-256-only build asked for BLAKE3).
    fn digest(&self, algo: HashAlgo, payload: &[u8]) -> Option<[u8; 32]>;
}

/// Compute the digest of `payload` and wrap it as a raw [`Cid`].
///
/// # Errors
///
/// [`Error::Core`] wrapping [`CoreError::UnknownHashAlgo`] when the hasher does
/// not implement `algo`.
pub fn compute_cid(algo: HashAlgo, payload: &[u8], hasher: &impl ContentHasher) -> Result<Cid> {
    let digest = hasher
        .digest(algo, payload)
        .ok_or_else(|| Error::Core(CoreError::UnknownHashAlgo(algo.as_u64())))?;
    Ok(Cid::new(digest))
}

/// Verify that `payload` hashes to `cid`.
///
/// For a tagged [`CidOrV1::V1`] the algorithm is taken from the CID itself and
/// `negotiated` is ignored (spec §8.1). For a raw [`CidOrV1::Raw`] the algorithm
/// comes from the connection's `hash_algo` handshake extension, which the caller
/// passes as `negotiated` (spec §8: *"Receivers MUST verify that the hash of the
/// received payload matches the CID using the algorithm indicated in the
/// handshake"*).
///
/// # Errors
///
/// [`Error::CidMismatch`] when the digest differs, or [`Error::Core`] when the
/// algorithm is unsupported by `hasher`.
pub fn verify_content(
    cid: &CidOrV1,
    payload: &[u8],
    negotiated: HashAlgo,
    hasher: &impl ContentHasher,
) -> Result<()> {
    let algo = cid.algo().unwrap_or(negotiated);
    let computed = compute_cid(algo, payload, hasher)?;
    if computed.as_bytes() == cid.digest() {
        Ok(())
    } else {
        Err(Error::CidMismatch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fake hasher: digest = XOR-fold of the payload, seeded per algorithm.
    struct Fake;

    impl ContentHasher for Fake {
        fn digest(&self, algo: HashAlgo, payload: &[u8]) -> Option<[u8; 32]> {
            let seed = match algo {
                HashAlgo::Sha256 => 0x11,
                HashAlgo::Blake3 => 0x22,
            };
            let mut out = [0u8; 32];
            for (i, b) in payload.iter().enumerate() {
                out[i % 32] ^= b ^ seed;
            }
            Some(out)
        }
    }

    /// Supports SHA-256 only, to exercise the unsupported-algorithm path.
    struct ShaOnly;

    impl ContentHasher for ShaOnly {
        fn digest(&self, algo: HashAlgo, payload: &[u8]) -> Option<[u8; 32]> {
            match algo {
                HashAlgo::Sha256 => Fake.digest(algo, payload),
                HashAlgo::Blake3 => None,
            }
        }
    }

    #[test]
    fn compute_is_deterministic() {
        let a = compute_cid(HashAlgo::Sha256, b"payload", &Fake).unwrap();
        let b = compute_cid(HashAlgo::Sha256, b"payload", &Fake).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn algorithm_is_part_of_the_digest() {
        let sha = compute_cid(HashAlgo::Sha256, b"payload", &Fake).unwrap();
        let blake3 = compute_cid(HashAlgo::Blake3, b"payload", &Fake).unwrap();
        assert_ne!(sha, blake3);
    }

    #[test]
    fn verify_accepts_matching_digest() {
        let cid = CidOrV1::V1(compute_cid(HashAlgo::Blake3, b"x", &Fake).unwrap().with_algo(HashAlgo::Blake3));
        assert!(verify_content(&cid, b"x", HashAlgo::Sha256, &Fake).is_ok());
        assert!(matches!(
            verify_content(&cid, b"y", HashAlgo::Sha256, &Fake),
            Err(Error::CidMismatch)
        ));
    }

    #[test]
    fn verify_honours_negotiated_algorithm_for_raw_cids() {
        let raw = CidOrV1::Raw(compute_cid(HashAlgo::Sha256, b"x", &Fake).unwrap());
        assert!(verify_content(&raw, b"x", HashAlgo::Sha256, &Fake).is_ok());
        // Same bytes, different negotiated algorithm → different digest.
        assert!(matches!(
            verify_content(&raw, b"x", HashAlgo::Blake3, &Fake),
            Err(Error::CidMismatch)
        ));
    }

    #[test]
    fn unsupported_algorithm_reports_unknown_hash_algo() {
        let err = compute_cid(HashAlgo::Blake3, &[1, 2, 3], &ShaOnly).unwrap_err();
        assert!(matches!(
            err,
            Error::Core(CoreError::UnknownHashAlgo(1))
        ));
    }
}