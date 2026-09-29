//! Concrete relay-hop HPKE sealer (spec §12.2).
//!
//! Fills the `RelayHop.encrypted_key` field: HPKE `mode_base`,
//! `DHKEM(X25519, HKDF-SHA256)` / `HKDF-SHA256` /
//! `ChaCha20Poly1305`, `info = "QUIP-relay-hop-v1"`, empty `aad`. The
//! recipient public key is the X25519 key derived from the relay's
//! Ed25519 `NodeId` via the birational map of RFC 8032 §4.1.2.
//!
//! # Why `mode_base`
//!
//! Per §12.2, the relay chain as a whole is signed by its sender, so
//! per-hop sender authentication inside HPKE would be redundant and
//! would enlarge the ciphertext. Recipients verify the chain-level
//! signature, not a per-hop one.

use crate::error::{Error, Result};
use crate::nat::RelayHopSealer;
use alloc::vec::Vec;
use quip_core::dvv::NodeId;

/// The HPKE `info` string fixed by §12.2.
pub const RELAY_HOP_INFO: &[u8] = b"QUIP-relay-hop-v1";

/// Concrete sealer for `RelayHop.encrypted_key` (§12.2).
#[derive(Clone, Debug, Default)]
pub struct HpkeRelayHopSealer;

impl RelayHopSealer for HpkeRelayHopSealer {
    fn seal(&self, recipient: &NodeId, plaintext: &[u8]) -> Result<Vec<u8>> {
        let recipient_x25519 = ed25519_to_x25519(recipient)?;
        seal_base(&recipient_x25519, RELAY_HOP_INFO, &[], plaintext)
    }
}

/// Ed25519 → X25519 birational map (RFC 8032 §4.1.2).
///
/// This is the same map that libsodium exposes as
/// `crypto_sign_ed25519_pk_to_curve25519`. Reimplementing it is a
/// last resort; use [`ed25519_dalek`] or a crypto library when one is
/// available, and verify against the RFC test vectors.
pub fn ed25519_to_x25519(ed_pub: &[u8; 32]) -> Result<[u8; 32]> {
    use curve25519_dalek::edwards::CompressedEdwardsY;
    let compressed = CompressedEdwardsY(*ed_pub);
    let edwards = compressed
        .decompress()
        .ok_or(Error::BadFrame("relay NodeId is not a valid Ed25519 point"))?;
    Ok(edwards.to_montgomery().to_bytes())
}

/// HPKE `mode_base` seal with the §12.2 suite.
fn seal_base(
    recipient_pk: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    use hpke_rs::{Hpke, HpkePublicKey, Mode};
    use hpke_rs_crypto::types::{AeadAlgorithm, KdfAlgorithm, KemAlgorithm};
    use hpke_rs_rust_crypto::HpkeRustCrypto;

    let mut hpke: Hpke<HpkeRustCrypto> = Hpke::new(
        Mode::Base,
        KemAlgorithm::DhKem25519,
        KdfAlgorithm::HkdfSha256,
        AeadAlgorithm::ChaCha20Poly1305,
    );

    // `Hpke::seal` wants an `HpkePublicKey`, which is a byte-vector
    // wrapper. Construct it from the raw X25519 key.
    let pk = HpkePublicKey::new(recipient_pk.to_vec());

    // hpke-rs returns `(enc, ciphertext)`. §12.2 treats `encrypted_key`
    // as a single opaque blob, so we concatenate them: enc || ct.
    // Recipients split at 32 bytes (the X25519 KEM's enc size).
    let (enc, ciphertext) = hpke
        .seal(&pk, info, aad, plaintext, None, None, None)
        .map_err(|_| Error::BadFrame("HPKE seal failed"))?;

    let mut out = Vec::with_capacity(enc.len() + ciphertext.len());
    out.extend_from_slice(&enc);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    /// A deterministic Ed25519 public key for testing.
    fn ed25519_pk(seed: u8) -> [u8; 32] {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        sk.verifying_key().to_bytes()
    }

    #[test]
    fn birational_map_is_deterministic() {
        let pk = ed25519_pk(1);
        let a = ed25519_to_x25519(&pk).unwrap();
        let b = ed25519_to_x25519(&pk).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn birational_map_differs_per_key() {
        let a = ed25519_to_x25519(&ed25519_pk(1)).unwrap();
        let b = ed25519_to_x25519(&ed25519_pk(2)).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn birational_map_is_total_on_valid_keys() {
        // Every Ed25519 public key produced by a real keypair is a
        // compressed Edwards point, so the map must succeed on all of
        // them. Whether arbitrary 32-byte strings decompress is a
        // curve-library detail; the map's contract only concerns real
        // public keys.
        for seed in 0..32u8 {
            let pk = ed25519_pk(seed);
            assert!(ed25519_to_x25519(&pk).is_ok());
        }
    }

    #[test]
    fn seal_produces_enc_plus_ciphertext() {
        let pk = ed25519_pk(1);
        let sealer = HpkeRelayHopSealer;
        let ct = sealer.seal(&pk, b"traffic key material").unwrap();
        // X25519 KEM enc is 32 bytes, AEAD tag is 16, plaintext is 21.
        // Ciphertext body = 21 + 16 = 37. Total = 32 + 37 = 69.
        assert!(ct.len() >= 32 + 16, "at least enc + tag");
        assert!(ct.len() <= 32 + 16 + 1024, "not unreasonable");
    }

    #[test]
    fn seal_differs_per_recipient() {
        let a = HpkeRelayHopSealer.seal(&ed25519_pk(1), b"x").unwrap();
        let b = HpkeRelayHopSealer.seal(&ed25519_pk(2), b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn seal_differs_per_plaintext() {
        let pk = ed25519_pk(1);
        let a = HpkeRelayHopSealer.seal(&pk, b"one").unwrap();
        let b = HpkeRelayHopSealer.seal(&pk, b"two").unwrap();
        assert_ne!(a, b);
    }
}