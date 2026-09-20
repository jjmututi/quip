//! Signature abstraction.

/// A pluggable Ed25519 verifier.
pub trait Verifier {
    /// Verify a 64-byte Ed25519 signature over `message` using `public_key`.
    fn verify_ed25519(
        &self,
        public_key: &[u8; 32],
        message: &[u8],
        signature: &[u8; 64],
    ) -> bool;
}

/// A pluggable Ed25519 signer.
pub trait Signer {
    /// Return the Ed25519 public key.
    fn public_key(&self) -> [u8; 32];

    /// Sign `message`, returning a 64-byte Ed25519 signature.
    fn sign_ed25519(&self, message: &[u8]) -> [u8; 64];
}