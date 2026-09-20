//! Crypto back-ends for QUIP identities and content hashing.
//!
//! Only available with the `crypto` feature. Plugs concrete algorithms
//! behind the trait abstractions defined in [`quip_core`] and
//! [`quip_storage`]:
//!
//! - [`Sha256Hasher`] / [`Blake3Hasher`] — [`quip_storage::ContentHasher`]
//!   implementations used by `QuipStore` to compute and verify CIDs
//!   (spec App. A.3). SHA-256 is mandatory to implement (§8); BLAKE3 is
//!   optional (§8.1) and selected via the `BLAKE3` capability bit.
//! - [`Ed25519Signer`] / [`Ed25519Verifier`] — [`quip_core::messages::Signer`]
//!   and [`quip_core::messages::Verifier`] implementations for
//!   `KeyClaim` (§5.1) and witness/governance signatures (§5.4, §7).

use quip_core::messages::{Signer, Verifier};
use quip_core::cid::HashAlgo;
use quip_storage::ContentHasher;

// -----------------------------------------------------------------------------
// Content hashing (App. A.3)
// -----------------------------------------------------------------------------

/// SHA-256 content hasher.
#[derive(Clone, Debug, Default)]
pub struct Sha256Hasher;

impl ContentHasher for Sha256Hasher {
    fn digest(&self, algo: HashAlgo, payload: &[u8]) -> Option<[u8; 32]> {
        match algo {
            HashAlgo::Sha256 => {
                use sha2::Digest;
                let out = sha2::Sha256::digest(payload);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out);
                Some(arr)
            }
            HashAlgo::Blake3 => None,
        }
    }
}

/// BLAKE3 content hasher.
#[derive(Clone, Debug, Default)]
pub struct Blake3Hasher;

impl ContentHasher for Blake3Hasher {
    fn digest(&self, algo: HashAlgo, payload: &[u8]) -> Option<[u8; 32]> {
        match algo {
            HashAlgo::Blake3 => {
                let mut arr = [0u8; 32];
                let hash = blake3::hash(payload);
                arr.copy_from_slice(hash.as_bytes());
                Some(arr)
            }
            HashAlgo::Sha256 => {
                use sha2::Digest;
                let out = sha2::Sha256::digest(payload);
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&out);
                Some(arr)
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Ed25519 identities (§5)
// -----------------------------------------------------------------------------

/// Ed25519 signer backed by `ed25519-dalek`.
#[derive(Clone)]
pub struct Ed25519Signer {
    keypair: ed25519_dalek::SigningKey,
}

impl Ed25519Signer {
    /// Create from a 32-byte seed (Ed25519 secret key).
    ///
    /// Applications are expected to source this seed from a CSPRNG or a
    /// hardware RNG. This crate deliberately does not bundle an RNG so
    /// that the choice of entropy source stays with the caller, mirroring
    /// the `ContentHasher` / `Verifier` design.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            keypair: ed25519_dalek::SigningKey::from_bytes(seed),
        }
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> [u8; 32] {
        self.keypair.verifying_key().to_bytes()
    }

    fn sign_ed25519(&self, message: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        let sig = self.keypair.sign(message);
        sig.to_bytes()
    }
}

/// Ed25519 verifier backed by `ed25519-dalek`.
#[derive(Clone, Debug, Default)]
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify_ed25519(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool {
        // The `Verifier` trait provides `.verify()`; `ed25519-dalek`
        // re-exports it from the `signature` crate and it is not in
        // scope by default.
        use ed25519_dalek::Verifier as _;
        let Ok(pubkey) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let Ok(sig) = ed25519_dalek::ed25519::Signature::from_slice(signature) else {
            return false;
        };
        pubkey.verify(message, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::cid::Cid;

    #[test]
    fn sha256_and_blake3_produce_distinct_cids() {
        let payload = b"hello quip";
        let sha = Sha256Hasher;
        let blk = Blake3Hasher;
        let a = sha.digest(HashAlgo::Sha256, payload).unwrap();
        let b = blk.digest(HashAlgo::Blake3, payload).unwrap();
        assert_ne!(a, b);
        // SHA-256 path matches exactly.
        let d_sha = sha.digest(HashAlgo::Sha256, payload).unwrap();
        assert_eq!(a, d_sha);
    }

    #[test]
    fn ed25519_sign_and_verify() {
        let seed = [0x42u8; 32];
        let signer = Ed25519Signer::from_seed(&seed);
        let msg = b"message to sign";
        let sig = signer.sign_ed25519(msg);
        // Round-trips through the public key.
        let pk = signer.public_key();
        let ver = Ed25519Verifier;
        assert!(ver.verify_ed25519(&pk, msg, &sig));
        // Wrong message fails.
        assert!(!ver.verify_ed25519(&pk, b"wrong", &sig));
    }

    #[test]
    fn cid_wraps_digest() {
        let sha = Sha256Hasher;
        let d = sha.digest(HashAlgo::Sha256, b"abc").unwrap();
        let _cid = Cid::new(d);
    }
}
