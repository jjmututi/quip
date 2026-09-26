//! Shared test helpers.
//!
//! Compiled only under `cfg(test)`. Add helpers here when more than
//! one test module needs the same deterministic stand-in.

use quip_core::dvv::NodeId;
use quip_core::messages::Signer;

/// Deterministic test signer.
///
/// `public_key` is the `node_id` field; `sign_ed25519` returns a
/// constant. This is not cryptography — it exists so signing and
/// verification paths can be exercised without real key material.
pub struct FakeSigner {
    /// The NodeId this signer reports as its public key.
    pub node_id: NodeId,
}

impl FakeSigner {
    /// Build a signer whose public key is `[b; 32]`.
    pub fn new(b: u8) -> Self {
        Self { node_id: [b; 32] }
    }
}

impl Signer for FakeSigner {
    fn public_key(&self) -> [u8; 32] {
        self.node_id
    }
    fn sign_ed25519(&self, _msg: &[u8]) -> [u8; 64] {
        [0xab; 64]
    }
}