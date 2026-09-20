//! BFT consensus wire codecs (spec §5.3.4, §5.3.4.1).
//!
//! # Contents
//!
//! Eight top-level messages:
//!
//! | Verb | Signer | Capability |
//! |---|---|---|
//! | `bft_preprepare` | primary | — |
//! | `bft_prepare` | witness | — |
//! | `bft_precommit` | witness | — |
//! | `bft_commit` | witness | — |
//! | `bft_view_change` | witness | — |
//! | `bft_new_view` | primary | — |
//! | `bft_checkpoint` | witness | `bft_checkpoint` |
//! | `bft_state_transfer` | ring | `bft_checkpoint` |
//!
//! # Wire form
//!
//! Top-level messages use the standard `["quip-v1", verb, ...fields]`
//! envelope. The `operation` field of `bft_preprepare` is a CBOR map
//! with three keys (`kind`, `subject`, `body`), per the CDDL in §5.3.4
//! and the prose in §5.3.4.1.
//!
//! # Pre-prepare digest
//!
//! §5.3.4 defines a digest binding the operation to its ring, view, and
//! sequence:
//!
//! ```text
//! digest = SHA-256(ring_id || view || sequence || QUIP-CBOR-encode(operation))
//! ```
//!
//! where `ring_id` is the raw 32 bytes, `view` and `sequence` are 8-byte
//! big-endian, and `operation` is encoded on its own (the outer envelope
//! is not included). Witnesses MUST recompute this and reject on mismatch
//! with `E_BFT_FAILURE`. The computation lives behind the `crypto`
//! feature because the workspace's `sha2` dependency is gated there.
//!
//! # Signing
//!
//! Per §10.1, each message's signature covers the message array with the
//! signature field removed as a whole and re-encoded with QUIP-CBOR.
//! The messages do not carry the signer's NodeId; callers know whose
//! turn it is from ring context, so [`BftPreprepare::verify`] and its
//! siblings take an explicit `signer: &NodeId`.
//!
//! # Two-layer verification for pre-prepare
//!
//! A witness receiving a `bft_preprepare` MUST perform two independent
//! checks:
//!
//! 1. [`BftPreprepare::verify_digest`] — that `digest` matches the
//!    operation and sequence number.
//! 2. [`BftPreprepare::verify`] — that `primary_sig` is valid under the
//!    primary's key.
//!
//! [`BftPreprepare::verify_full`] performs both and is what a driver
//! SHOULD call.

use crate::codec::{as_array, as_bytes, as_u64, envelope, fields, verb_of};
use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::dvv::NodeId;
use quip_core::messages::{RingSignature, Verifier};

/// A 32-byte ring identifier (matches `witness_ring_id` in Coral).
pub type RingId = [u8; 32];

/// A 32-byte digest of a proposed operation.
pub type Digest = [u8; 32];

/// Maximum recommended operation size, per §5.3.4.1.
///
/// The spec says operations SHOULD be at most 4 KiB. This is a RECOMMENDED
/// bound, not a hard protocol limit; the codec accepts any size and
/// exposes [`Operation::encoded_len`] so a driver can enforce its own
/// policy.
pub const MAX_OPERATION_BYTES: usize = 4 * 1024;

// -------------------------------------------------------------------------
// Operation (§5.3.4, §5.3.4.1)
// -------------------------------------------------------------------------

/// An operation to be ordered by the witness ring.
///
/// CDDL (§5.3.4.1):
///
/// ```text
/// Operation = {
///   kind: tstr,              ; operation kind
///   subject: bytes,          ; opaque subject identifier
///   body: any                ; application-defined payload
/// }
/// ```
///
/// # Kinds defined by this specification
///
/// - `"key_rotation"`
/// - `"revocation"`
/// - `"witness_membership_change"`
/// - `"resource_ownership_transfer"`
///
/// Applications MAY define additional kinds. Witnesses MUST NOT interpret
/// the payload beyond `kind` and `subject`; application-layer conflict
/// detection is performed by the operation's registered handler, not by
/// the ring.
#[derive(Clone, Debug, PartialEq)]
pub struct Operation {
    /// Operation class. See the type-level docs for the defined values.
    pub kind: String,
    /// Opaque subject identifier. Two operations with different subjects
    /// never conflict.
    pub subject: Vec<u8>,
    /// Application-defined payload. Opaque to the ring.
    pub body: CborValue,
}

impl Operation {
    /// Encode to a CBOR map.
    ///
    /// Key order does not matter: the QUIP-CBOR encoder sorts map keys
    /// bytewise, so the output is deterministic regardless of how the
    /// fields are ordered here.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(alloc::vec![
            (
                CborValue::String(String::from("kind")),
                CborValue::String(self.kind.clone()),
            ),
            (
                CborValue::String(String::from("subject")),
                CborValue::Bytes(self.subject.clone()),
            ),
            (CborValue::String(String::from("body")), self.body.clone()),
        ])
    }

    /// Decode from a CBOR map.
    ///
    /// Rejects:
    /// - non-map inputs
    /// - missing `kind`, `subject`, or `body`
    /// - `kind` that is not a text string
    /// - `subject` that is not a byte string
    /// - any key other than the three defined
    pub fn from_cbor(v: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = v else {
            return Err(Error::BadFrame("operation must be a map"));
        };
        let mut kind: Option<String> = None;
        let mut subject: Option<Vec<u8>> = None;
        let mut body: Option<CborValue> = None;
        for (k, val) in pairs {
            let CborValue::String(key) = k else {
                return Err(Error::BadFrame("operation key must be a text string"));
            };
            match key.as_str() {
                "kind" => {
                    let CborValue::String(s) = val else {
                        return Err(Error::BadFrame("operation.kind must be a text string"));
                    };
                    kind = Some(s.clone());
                }
                "subject" => {
                    let CborValue::Bytes(b) = val else {
                        return Err(Error::BadFrame("operation.subject must be a byte string"));
                    };
                    subject = Some(b.clone());
                }
                "body" => body = Some(val.clone()),
                _ => return Err(Error::BadFrame("unknown operation field")),
            }
        }
        Ok(Self {
            kind: kind.ok_or(Error::BadFrame("operation missing `kind`"))?,
            subject: subject.ok_or(Error::BadFrame("operation missing `subject`"))?,
            body: body.ok_or(Error::BadFrame("operation missing `body`"))?,
        })
    }

    /// QUIP-CBOR-encoded length in bytes.
    pub fn encoded_len(&self) -> Result<usize> {
        Ok(encode(&self.to_cbor())?.len())
    }
}

// -------------------------------------------------------------------------
// bft_preprepare
// -------------------------------------------------------------------------

/// `bft_preprepare` — primary proposes an operation (§5.3.4).
#[derive(Clone, Debug, PartialEq)]
pub struct BftPreprepare {
    /// Ring this proposal is for.
    pub ring_id: RingId,
    /// View number.
    pub view: u64,
    /// Sequence number within the view.
    pub sequence: u64,
    /// The proposed operation.
    pub operation: Operation,
    /// `SHA-256(ring_id || view || sequence || QUIP-CBOR(operation))`.
    pub digest: Digest,
    /// Ed25519 signature by the primary, over the message array with
    /// `primary_sig` removed (§10.1).
    pub primary_sig: [u8; 64],
}

impl BftPreprepare {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_preprepare",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.view as i128),
                CborValue::Int(self.sequence as i128),
                self.operation.to_cbor(),
                CborValue::Bytes(self.digest.to_vec()),
                CborValue::Bytes(self.primary_sig.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "bft_preprepare" {
            return Err(Error::BadFrame("not a bft_preprepare"));
        }
        let f = fields(&v, "bft_preprepare")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("bft_preprepare arity"));
        }
        Ok(Self {
            ring_id: as_bytes_n32(&f[0])?,
            view: as_u64(&f[1])?,
            sequence: as_u64(&f[2])?,
            operation: Operation::from_cbor(&f[3])?,
            digest: as_bytes_n32(&f[4])?,
            primary_sig: as_bytes_n64(&f[5])?,
        })
    }

    /// Bytes covered by `primary_sig` (§10.1).
    ///
    /// The `primary_sig` element is removed as a whole. The `digest`
    /// field stays in the payload; the signature covers the digest, and
    /// the digest separately covers the operation.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_preprepare",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.view as i128),
                CborValue::Int(self.sequence as i128),
                self.operation.to_cbor(),
                CborValue::Bytes(self.digest.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the primary's signature over [`Self::signing_payload`].
    pub fn verify(&self, primary: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(primary, &payload, &self.primary_sig))
    }

    /// Compute the pre-prepare digest from the operation and sequence
    /// fields, per §5.3.4:
    ///
    /// ```text
    /// SHA-256(ring_id || view || sequence || QUIP-CBOR(operation))
    /// ```
    ///
    /// `view` and `sequence` are encoded as 8-byte big-endian.
    #[cfg(feature = "crypto")]
    pub fn compute_digest(&self) -> Result<Digest> {
        use sha2::{Digest as _, Sha256};

        let op_cbor = encode(&self.operation.to_cbor())?;
        let mut preimage = Vec::with_capacity(32 + 8 + 8 + op_cbor.len());
        preimage.extend_from_slice(&self.ring_id);
        preimage.extend_from_slice(&self.view.to_be_bytes());
        preimage.extend_from_slice(&self.sequence.to_be_bytes());
        preimage.extend_from_slice(&op_cbor);

        let mut hasher = Sha256::new();
        hasher.update(&preimage);
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        Ok(digest)
    }

    /// Verify that the embedded `digest` matches the recomputed value.
    ///
    /// Returns [`Error::Bft`] with a digest-mismatch message, which
    /// [`Error::code`] maps to `E_BFT_FAILURE` (0x0B), per §5.3.4.
    #[cfg(feature = "crypto")]
    pub fn verify_digest(&self) -> Result<()> {
        let computed = self.compute_digest()?;
        if computed != self.digest {
            return Err(Error::Bft("pre-prepare digest mismatch"));
        }
        Ok(())
    }

    /// Verify both the digest and the primary's signature.
    ///
    /// This is what a driver SHOULD call on receipt. The two checks are
    /// independent: the digest binds the operation to the sequence
    /// number, and the signature binds the message to the primary's key.
    #[cfg(feature = "crypto")]
    pub fn verify_full(&self, primary: &NodeId, v: &impl Verifier) -> Result<()> {
        self.verify_digest()?;
        if !self.verify(primary, v)? {
            return Err(Error::Bft("pre-prepare signature invalid"));
        }
        Ok(())
    }
}

// -------------------------------------------------------------------------
// bft_prepare / bft_precommit / bft_commit
//
// Three messages with identical shapes. Kept as separate types so that
// an accidental type-mix at a call site (passing a Prepare where a
// Commit is expected) is a compile error rather than a runtime one.
// -------------------------------------------------------------------------

/// `bft_prepare` — witness acknowledges a proposal (§5.3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftPrepare {
    /// Ring this vote is for.
    pub ring_id: RingId,
    /// View number.
    pub view: u64,
    /// Sequence number within the view.
    pub sequence: u64,
    /// Digest of the operation being voted on.
    pub digest: Digest,
    /// Ed25519 signature by the voting witness.
    pub witness_sig: [u8; 64],
}

/// `bft_precommit` — witness commits to prepare (§5.3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftPrecommit {
    /// Ring this vote is for.
    pub ring_id: RingId,
    /// View number.
    pub view: u64,
    /// Sequence number within the view.
    pub sequence: u64,
    /// Digest of the operation being voted on.
    pub digest: Digest,
    /// Ed25519 signature by the voting witness.
    pub witness_sig: [u8; 64],
}

/// `bft_commit` — witness finalizes (§5.3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftCommit {
    /// Ring this vote is for.
    pub ring_id: RingId,
    /// View number.
    pub view: u64,
    /// Sequence number within the view.
    pub sequence: u64,
    /// Digest of the operation being voted on.
    pub digest: Digest,
    /// Ed25519 signature by the voting witness.
    pub witness_sig: [u8; 64],
}

macro_rules! impl_vote_message {
    ($name:ident, $verb:literal) => {
        impl $name {
            /// Encode to QUIP-CBOR bytes.
            pub fn to_bytes(&self) -> Result<Vec<u8>> {
                let msg = envelope(
                    $verb,
                    alloc::vec![
                        CborValue::Bytes(self.ring_id.to_vec()),
                        CborValue::Int(self.view as i128),
                        CborValue::Int(self.sequence as i128),
                        CborValue::Bytes(self.digest.to_vec()),
                        CborValue::Bytes(self.witness_sig.to_vec()),
                    ],
                );
                Ok(encode(&msg)?)
            }

            /// Decode from QUIP-CBOR bytes.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
                let v = decode(bytes)?;
                if verb_of(&v)? != $verb {
                    return Err(Error::BadFrame("wrong vote verb"));
                }
                let f = fields(&v, $verb)?;
                if f.len() != 5 {
                    return Err(Error::BadFrame("vote arity"));
                }
                Ok(Self {
                    ring_id: as_bytes_n32(&f[0])?,
                    view: as_u64(&f[1])?,
                    sequence: as_u64(&f[2])?,
                    digest: as_bytes_n32(&f[3])?,
                    witness_sig: as_bytes_n64(&f[4])?,
                })
            }

            /// Bytes covered by `witness_sig` (§10.1).
            pub fn signing_payload(&self) -> Result<Vec<u8>> {
                let msg = envelope(
                    $verb,
                    alloc::vec![
                        CborValue::Bytes(self.ring_id.to_vec()),
                        CborValue::Int(self.view as i128),
                        CborValue::Int(self.sequence as i128),
                        CborValue::Bytes(self.digest.to_vec()),
                    ],
                );
                Ok(encode(&msg)?)
            }

            /// Verify the witness's signature.
            pub fn verify(
                &self,
                witness: &NodeId,
                v: &impl Verifier,
            ) -> Result<bool> {
                let payload = self.signing_payload()?;
                Ok(v.verify_ed25519(witness, &payload, &self.witness_sig))
            }
        }
    };
}

impl_vote_message!(BftPrepare, "bft_prepare");
impl_vote_message!(BftPrecommit, "bft_precommit");
impl_vote_message!(BftCommit, "bft_commit");

// -------------------------------------------------------------------------
// bft_view_change
// -------------------------------------------------------------------------

/// `bft_view_change` — witness signals a view change (§5.3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftViewChange {
    /// Ring this vote is for.
    pub ring_id: RingId,
    /// The view the witness wishes to move to.
    pub new_view: u64,
    /// Last sequence number the witness has seen.
    pub last_sequence: u64,
    /// Digests of operations the witness has prepared.
    pub prepared_digests: Vec<Digest>,
    /// The witness's latest stable checkpoint digest.
    pub checkpoint_digest: Digest,
    /// Ed25519 signature by the voting witness.
    pub witness_sig: [u8; 64],
}

impl BftViewChange {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_view_change",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.new_view as i128),
                CborValue::Int(self.last_sequence as i128),
                CborValue::Array(digest_list(&self.prepared_digests)),
                CborValue::Bytes(self.checkpoint_digest.to_vec()),
                CborValue::Bytes(self.witness_sig.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "bft_view_change" {
            return Err(Error::BadFrame("not a bft_view_change"));
        }
        let f = fields(&v, "bft_view_change")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("bft_view_change arity"));
        }
        let mut prepared_digests = Vec::new();
        for item in as_array(&f[3])? {
            prepared_digests.push(as_bytes_n32(item)?);
        }
        Ok(Self {
            ring_id: as_bytes_n32(&f[0])?,
            new_view: as_u64(&f[1])?,
            last_sequence: as_u64(&f[2])?,
            prepared_digests,
            checkpoint_digest: as_bytes_n32(&f[4])?,
            witness_sig: as_bytes_n64(&f[5])?,
        })
    }

    /// Bytes covered by `witness_sig` (§10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_view_change",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.new_view as i128),
                CborValue::Int(self.last_sequence as i128),
                CborValue::Array(digest_list(&self.prepared_digests)),
                CborValue::Bytes(self.checkpoint_digest.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the witness's signature.
    pub fn verify(&self, witness: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(witness, &payload, &self.witness_sig))
    }
}

// -------------------------------------------------------------------------
// bft_new_view
// -------------------------------------------------------------------------

/// `bft_new_view` — primary announces a completed view change (§5.3.4).
///
/// `view_change_messages`, `prepared_messages`, and `checkpoint_messages`
/// are the encoded wire form of other BFT messages, carried as
/// `[* bytes]`. This codec preserves them verbatim; decoding and
/// verifying their contents is a driver concern (M4b).
///
/// The spec requires that `view_change_messages` contain at least
/// `VIEW_CHANGE_QUORUM` (5) valid entries. The codec does not enforce
/// that — a driver MUST — because doing so would require decoding
/// each entry to count them against a quorum that depends on ring
/// context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftNewView {
    /// Ring this message is for.
    pub ring_id: RingId,
    /// The new view number.
    pub view: u64,
    /// Encoded `bft_view_change` messages, at least `VIEW_CHANGE_QUORUM`.
    pub view_change_messages: Vec<Vec<u8>>,
    /// Full encoded `bft_preprepare` messages for operations prepared
    /// in previous views.
    pub prepared_messages: Vec<Vec<u8>>,
    /// Encoded `bft_checkpoint` messages for the latest stable state.
    pub checkpoint_messages: Vec<Vec<u8>>,
    /// Ed25519 signature by the new primary.
    pub primary_sig: [u8; 64],
}

impl BftNewView {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_new_view",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.view as i128),
                CborValue::Array(bytes_list(&self.view_change_messages)),
                CborValue::Array(bytes_list(&self.prepared_messages)),
                CborValue::Array(bytes_list(&self.checkpoint_messages)),
                CborValue::Bytes(self.primary_sig.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "bft_new_view" {
            return Err(Error::BadFrame("not a bft_new_view"));
        }
        let f = fields(&v, "bft_new_view")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("bft_new_view arity"));
        }
        Ok(Self {
            ring_id: as_bytes_n32(&f[0])?,
            view: as_u64(&f[1])?,
            view_change_messages: bytes_list_from(&f[2])?,
            prepared_messages: bytes_list_from(&f[3])?,
            checkpoint_messages: bytes_list_from(&f[4])?,
            primary_sig: as_bytes_n64(&f[5])?,
        })
    }

    /// Bytes covered by `primary_sig` (§10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_new_view",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.view as i128),
                CborValue::Array(bytes_list(&self.view_change_messages)),
                CborValue::Array(bytes_list(&self.prepared_messages)),
                CborValue::Array(bytes_list(&self.checkpoint_messages)),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the primary's signature.
    pub fn verify(&self, primary: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(primary, &payload, &self.primary_sig))
    }
}

// -------------------------------------------------------------------------
// bft_checkpoint
// -------------------------------------------------------------------------

/// `bft_checkpoint` — witness signs a stable state (§5.3.4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BftCheckpoint {
    /// Ring this checkpoint is for.
    pub ring_id: RingId,
    /// Sequence number of the checkpoint.
    pub sequence: u64,
    /// Digest of the state at the checkpoint.
    pub state_digest: Digest,
    /// Ed25519 signature by the signing witness.
    pub witness_sig: [u8; 64],
}

impl BftCheckpoint {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_checkpoint",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.sequence as i128),
                CborValue::Bytes(self.state_digest.to_vec()),
                CborValue::Bytes(self.witness_sig.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "bft_checkpoint" {
            return Err(Error::BadFrame("not a bft_checkpoint"));
        }
        let f = fields(&v, "bft_checkpoint")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("bft_checkpoint arity"));
        }
        Ok(Self {
            ring_id: as_bytes_n32(&f[0])?,
            sequence: as_u64(&f[1])?,
            state_digest: as_bytes_n32(&f[2])?,
            witness_sig: as_bytes_n64(&f[3])?,
        })
    }

    /// Bytes covered by `witness_sig` (§10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_checkpoint",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.sequence as i128),
                CborValue::Bytes(self.state_digest.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the witness's signature.
    pub fn verify(&self, witness: &NodeId, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(witness, &payload, &self.witness_sig))
    }
}

// -------------------------------------------------------------------------
// bft_state_transfer
// -------------------------------------------------------------------------

/// `bft_state_transfer` — ring-signed state for a lagging witness
/// (§5.3.4.1).
#[derive(Clone, Debug, PartialEq)]
pub struct BftStateTransfer {
    /// Ring this transfer is for.
    pub ring_id: RingId,
    /// Sequence number of the checkpoint being transferred.
    pub checkpoint_sequence: u64,
    /// The state at the checkpoint. Opaque bytes; the ring agrees only
    /// on its digest. The spec does not define the state's internal
    /// structure.
    pub state: Vec<u8>,
    /// Digest of `state`.
    pub checkpoint_digest: Digest,
    /// A ring signature over the transfer.
    ///
    /// MUST be a valid `RingSignature` with at least
    /// `VIEW_CHANGE_QUORUM` (5) signers.
    pub ring_signature: RingSignature,
}

impl BftStateTransfer {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_state_transfer",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.checkpoint_sequence as i128),
                CborValue::Bytes(self.state.clone()),
                CborValue::Bytes(self.checkpoint_digest.to_vec()),
                self.ring_signature.to_cbor(),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "bft_state_transfer" {
            return Err(Error::BadFrame("not a bft_state_transfer"));
        }
        let f = fields(&v, "bft_state_transfer")?;
        if f.len() != 5 {
            return Err(Error::BadFrame("bft_state_transfer arity"));
        }
        Ok(Self {
            ring_id: as_bytes_n32(&f[0])?,
            checkpoint_sequence: as_u64(&f[1])?,
            state: as_bytes(&f[2])?,
            checkpoint_digest: as_bytes_n32(&f[3])?,
            ring_signature: RingSignature::from_cbor(&f[4]).map_err(Error::Core)?,
        })
    }

    /// Bytes covered by the ring signature (§10.1).
    ///
    /// The `ring_signature` element is removed as a whole; the individual
    /// signatures inside it are not separately excluded. This applies to
    /// both `IndividualRingSig` and `FrostRingSig`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "bft_state_transfer",
            alloc::vec![
                CborValue::Bytes(self.ring_id.to_vec()),
                CborValue::Int(self.checkpoint_sequence as i128),
                CborValue::Bytes(self.state.clone()),
                CborValue::Bytes(self.checkpoint_digest.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the ring signature over this transfer.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(self.ring_signature.verify(&payload, v)?)
    }
}

// -------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------

/// Read a 32-byte value or fail.
fn as_bytes_n32(v: &CborValue) -> Result<[u8; 32]> {
    let b = as_bytes(v)?;
    if b.len() != 32 {
        return Err(Error::BadFrame("expected 32-byte value"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

/// Read a 64-byte value or fail.
fn as_bytes_n64(v: &CborValue) -> Result<[u8; 64]> {
    let b = as_bytes(v)?;
    if b.len() != 64 {
        return Err(Error::BadFrame("expected 64-byte value"));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&b);
    Ok(out)
}

/// Encode a list of 32-byte digests as a CBOR array.
fn digest_list(digests: &[Digest]) -> Vec<CborValue> {
    digests
        .iter()
        .map(|d| CborValue::Bytes(d.to_vec()))
        .collect()
}

/// Encode a list of byte strings as a CBOR array.
fn bytes_list(items: &[Vec<u8>]) -> Vec<CborValue> {
    items.iter().map(|b| CborValue::Bytes(b.clone())).collect()
}

/// Decode a CBOR array of byte strings.
fn bytes_list_from(v: &CborValue) -> Result<Vec<Vec<u8>>> {
    as_array(v)?.iter().map(as_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn rid(b: u8) -> RingId {
        [b; 32]
    }

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn op_rotate() -> Operation {
        Operation {
            kind: String::from("key_rotation"),
            subject: vec![0x11; 32],
            body: CborValue::Map(vec![
                (
                    CborValue::String(String::from("new_key")),
                    CborValue::Bytes(vec![0xaa; 32]),
                ),
                (
                    CborValue::String(String::from("effective_at")),
                    CborValue::Int(1_700_000_000_000),
                ),
            ]),
        }
    }

    // ---- Operation ----

    #[test]
    fn operation_roundtrip_simple() {
        let op = Operation {
            kind: String::from("revocation"),
            subject: vec![0xaa, 0xbb],
            body: CborValue::Null,
        };
        let encoded = op.to_cbor();
        let decoded = Operation::from_cbor(&encoded).unwrap();
        assert_eq!(decoded, op);
    }

    #[test]
    fn operation_roundtrip_nested_body() {
        let op = op_rotate();
        let encoded = op.to_cbor();
        let decoded = Operation::from_cbor(&encoded).unwrap();
        assert_eq!(decoded, op);
    }

    #[test]
    fn operation_rejects_missing_kind() {
        let v = CborValue::Map(vec![
            (
                CborValue::String(String::from("subject")),
                CborValue::Bytes(vec![1]),
            ),
            (CborValue::String(String::from("body")), CborValue::Null),
        ]);
        assert!(Operation::from_cbor(&v).is_err());
    }

    #[test]
    fn operation_rejects_missing_subject() {
        let v = CborValue::Map(vec![
            (
                CborValue::String(String::from("kind")),
                CborValue::String(String::from("x")),
            ),
            (CborValue::String(String::from("body")), CborValue::Null),
        ]);
        assert!(Operation::from_cbor(&v).is_err());
    }

    #[test]
    fn operation_rejects_missing_body() {
        let v = CborValue::Map(vec![
            (
                CborValue::String(String::from("kind")),
                CborValue::String(String::from("x")),
            ),
            (
                CborValue::String(String::from("subject")),
                CborValue::Bytes(vec![1]),
            ),
        ]);
        assert!(Operation::from_cbor(&v).is_err());
    }

    #[test]
    fn operation_rejects_non_string_kind() {
        let v = CborValue::Map(vec![
            (
                CborValue::String(String::from("kind")),
                CborValue::Int(1),
            ),
            (
                CborValue::String(String::from("subject")),
                CborValue::Bytes(vec![1]),
            ),
            (CborValue::String(String::from("body")), CborValue::Null),
        ]);
        assert!(Operation::from_cbor(&v).is_err());
    }

    #[test]
    fn operation_rejects_non_bytes_subject() {
        let v = CborValue::Map(vec![
            (
                CborValue::String(String::from("kind")),
                CborValue::String(String::from("x")),
            ),
            (
                CborValue::String(String::from("subject")),
                CborValue::String(String::from("not bytes")),
            ),
            (CborValue::String(String::from("body")), CborValue::Null),
        ]);
        assert!(Operation::from_cbor(&v).is_err());
    }

    #[test]
    fn operation_rejects_unknown_field() {
        let v = CborValue::Map(vec![
            (
                CborValue::String(String::from("kind")),
                CborValue::String(String::from("x")),
            ),
            (
                CborValue::String(String::from("subject")),
                CborValue::Bytes(vec![1]),
            ),
            (CborValue::String(String::from("body")), CborValue::Null),
            (
                CborValue::String(String::from("extra")),
                CborValue::Int(1),
            ),
        ]);
        assert!(Operation::from_cbor(&v).is_err());
    }

    #[test]
    fn operation_rejects_non_map() {
        assert!(Operation::from_cbor(&CborValue::Int(1)).is_err());
        assert!(Operation::from_cbor(&CborValue::Array(vec![])).is_err());
        assert!(Operation::from_cbor(&CborValue::Bytes(vec![])).is_err());
    }

    #[test]
    fn operation_encoded_len_is_positive() {
        let op = op_rotate();
        assert!(op.encoded_len().unwrap() > 0);
    }

    // ---- bft_preprepare ----

    #[test]
    fn preprepare_roundtrip() {
        let m = BftPreprepare {
            ring_id: rid(1),
            view: 3,
            sequence: 100,
            operation: op_rotate(),
            digest: [0xab; 32],
            primary_sig: [0xcd; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftPreprepare::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn preprepare_signing_payload_excludes_primary_sig() {
        let m = BftPreprepare {
            ring_id: rid(1),
            view: 3,
            sequence: 100,
            operation: op_rotate(),
            digest: [0xab; 32],
            primary_sig: [0xff; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "bft_preprepare").unwrap();
        // ring_id, view, sequence, operation, digest — five fields, no sig.
        assert_eq!(f.len(), 5);
    }

    #[test]
    fn preprepare_operation_is_in_signing_payload() {
        let m = BftPreprepare {
            ring_id: rid(1),
            view: 0,
            sequence: 0,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "bft_preprepare").unwrap();
        let op = Operation::from_cbor(&f[3]).unwrap();
        assert_eq!(op.kind, "key_rotation");
        assert_eq!(op.subject, vec![0x11; 32]);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_digest_is_deterministic() {
        let m = BftPreprepare {
            ring_id: rid(1),
            view: 3,
            sequence: 100,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        let d1 = m.compute_digest().unwrap();
        let d2 = m.compute_digest().unwrap();
        assert_eq!(d1, d2);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_digest_is_sensitive_to_ring_id() {
        let mut m = BftPreprepare {
            ring_id: rid(1),
            view: 0,
            sequence: 0,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        let d1 = m.compute_digest().unwrap();
        m.ring_id = rid(2);
        let d2 = m.compute_digest().unwrap();
        assert_ne!(d1, d2);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_digest_is_sensitive_to_view() {
        let mut m = BftPreprepare {
            ring_id: rid(1),
            view: 0,
            sequence: 0,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        let d1 = m.compute_digest().unwrap();
        m.view = 1;
        let d2 = m.compute_digest().unwrap();
        assert_ne!(d1, d2);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_digest_is_sensitive_to_sequence() {
        let mut m = BftPreprepare {
            ring_id: rid(1),
            view: 0,
            sequence: 0,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        let d1 = m.compute_digest().unwrap();
        m.sequence = 1;
        let d2 = m.compute_digest().unwrap();
        assert_ne!(d1, d2);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_digest_is_sensitive_to_operation() {
        let mut m = BftPreprepare {
            ring_id: rid(1),
            view: 0,
            sequence: 0,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        let d1 = m.compute_digest().unwrap();
        m.operation.body = CborValue::Null;
        let d2 = m.compute_digest().unwrap();
        assert_ne!(d1, d2);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_verify_digest_accepts_matching() {
        let mut m = BftPreprepare {
            ring_id: rid(1),
            view: 3,
            sequence: 100,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        m.digest = m.compute_digest().unwrap();
        assert!(m.verify_digest().is_ok());
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_verify_digest_rejects_tampered_operation() {
        let mut m = BftPreprepare {
            ring_id: rid(1),
            view: 3,
            sequence: 100,
            operation: op_rotate(),
            digest: [0; 32],
            primary_sig: [0; 64],
        };
        m.digest = m.compute_digest().unwrap();
        // Tamper with the operation after digest was computed.
        m.operation.subject = vec![0x99; 32];
        let err = m.verify_digest().unwrap_err();
        assert_eq!(err.code(), quip_core::ErrorCode::BftFailure);
    }

    #[cfg(feature = "crypto")]
    #[test]
    fn preprepare_verify_digest_rejects_wrong_digest_field() {
        let m = BftPreprepare {
            ring_id: rid(1),
            view: 3,
            sequence: 100,
            operation: op_rotate(),
            digest: [0x00; 32], // never matches
            primary_sig: [0; 64],
        };
        assert!(m.verify_digest().is_err());
    }

    // ---- vote messages ----

    #[test]
    fn prepare_roundtrip() {
        let m = BftPrepare {
            ring_id: rid(1),
            view: 2,
            sequence: 50,
            digest: [0xcd; 32],
            witness_sig: [0xef; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftPrepare::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn precommit_roundtrip() {
        let m = BftPrecommit {
            ring_id: rid(1),
            view: 2,
            sequence: 50,
            digest: [0xcd; 32],
            witness_sig: [0xef; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftPrecommit::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn commit_roundtrip() {
        let m = BftCommit {
            ring_id: rid(1),
            view: 2,
            sequence: 50,
            digest: [0xcd; 32],
            witness_sig: [0xef; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftCommit::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn prepare_and_commit_are_distinct_verbs() {
        let p = BftPrepare {
            ring_id: rid(1),
            view: 1,
            sequence: 1,
            digest: [0; 32],
            witness_sig: [0; 64],
        };
        let c = BftCommit {
            ring_id: rid(1),
            view: 1,
            sequence: 1,
            digest: [0; 32],
            witness_sig: [0; 64],
        };
        let pb = p.to_bytes().unwrap();
        let cb = c.to_bytes().unwrap();
        assert_ne!(pb, cb);
        assert!(BftPrepare::from_bytes(&cb).is_err());
        assert!(BftCommit::from_bytes(&pb).is_err());
    }

    #[test]
    fn vote_signing_payload_excludes_witness_sig() {
        let m = BftPrepare {
            ring_id: rid(1),
            view: 2,
            sequence: 50,
            digest: [0xcd; 32],
            witness_sig: [0xff; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "bft_prepare").unwrap();
        assert_eq!(f.len(), 4);
    }

    // ---- view change ----

    #[test]
    fn view_change_roundtrip() {
        let m = BftViewChange {
            ring_id: rid(1),
            new_view: 4,
            last_sequence: 100,
            prepared_digests: vec![[0x11; 32], [0x22; 32]],
            checkpoint_digest: [0x33; 32],
            witness_sig: [0x44; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftViewChange::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn view_change_empty_prepared_roundtrips() {
        let m = BftViewChange {
            ring_id: rid(1),
            new_view: 1,
            last_sequence: 0,
            prepared_digests: vec![],
            checkpoint_digest: [0; 32],
            witness_sig: [0; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftViewChange::from_bytes(&bytes).unwrap(), m);
    }

    // ---- new view ----

    #[test]
    fn new_view_roundtrip() {
        let m = BftNewView {
            ring_id: rid(1),
            view: 4,
            view_change_messages: vec![vec![0xaa; 10], vec![0xbb; 20]],
            prepared_messages: vec![vec![0xcc; 5]],
            checkpoint_messages: vec![],
            primary_sig: [0xdd; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftNewView::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn new_view_signing_payload_excludes_primary_sig() {
        let m = BftNewView {
            ring_id: rid(1),
            view: 4,
            view_change_messages: vec![],
            prepared_messages: vec![],
            checkpoint_messages: vec![],
            primary_sig: [0xff; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "bft_new_view").unwrap();
        assert_eq!(f.len(), 5);
    }

    // ---- checkpoint ----

    #[test]
    fn checkpoint_roundtrip() {
        let m = BftCheckpoint {
            ring_id: rid(1),
            sequence: 100,
            state_digest: [0xab; 32],
            witness_sig: [0xcd; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftCheckpoint::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn checkpoint_signing_payload_excludes_witness_sig() {
        let m = BftCheckpoint {
            ring_id: rid(1),
            sequence: 100,
            state_digest: [0xab; 32],
            witness_sig: [0xff; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "bft_checkpoint").unwrap();
        assert_eq!(f.len(), 3);
    }

    // ---- state transfer ----

    #[test]
    fn state_transfer_roundtrip_individual_ring_sig() {
        use quip_core::messages::IndividualRingSig;
        let m = BftStateTransfer {
            ring_id: rid(1),
            checkpoint_sequence: 100,
            state: vec![0x11, 0x22, 0x33],
            checkpoint_digest: [0xab; 32],
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0; 64]; 5],
                signers: vec![nid(1), nid(2), nid(3), nid(4), nid(5)],
            }),
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftStateTransfer::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn state_transfer_roundtrip_frost_ring_sig() {
        use quip_core::messages::FrostRingSig;
        let m = BftStateTransfer {
            ring_id: rid(1),
            checkpoint_sequence: 100,
            state: vec![0x44; 20],
            checkpoint_digest: [0xcd; 32],
            ring_signature: RingSignature::Frost(FrostRingSig {
                aggregate: vec![0xaa; 64],
                participants: vec![nid(1), nid(2), nid(3), nid(4), nid(5)],
                commitment: vec![0xbb; 32],
            }),
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(BftStateTransfer::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn state_transfer_signing_payload_excludes_ring_signature() {
        use quip_core::messages::IndividualRingSig;
        let m = BftStateTransfer {
            ring_id: rid(1),
            checkpoint_sequence: 100,
            state: vec![1, 2, 3],
            checkpoint_digest: [0xab; 32],
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0xff; 64]],
                signers: vec![nid(1)],
            }),
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "bft_state_transfer").unwrap();
        assert_eq!(f.len(), 4);
    }

    // ---- rejects ----

    #[test]
    fn wrong_verb_rejected() {
        let msg = envelope("bft_prepare", vec![]);
        let bytes = encode(&msg).unwrap();
        assert!(BftPreprepare::from_bytes(&bytes).is_err());
    }

    #[test]
    fn wrong_arity_rejected() {
        let msg = envelope(
            "bft_preprepare",
            vec![CborValue::Bytes(vec![0; 32])],
        );
        let bytes = encode(&msg).unwrap();
        assert!(BftPreprepare::from_bytes(&bytes).is_err());
    }

    #[test]
    fn wrong_ring_id_length_rejected() {
        let msg = envelope(
            "bft_checkpoint",
            vec![
                CborValue::Bytes(vec![0; 16]),
                CborValue::Int(0),
                CborValue::Bytes(vec![0; 32]),
                CborValue::Bytes(vec![0; 64]),
            ],
        );
        let bytes = encode(&msg).unwrap();
        assert!(BftCheckpoint::from_bytes(&bytes).is_err());
    }

    #[test]
    fn preprepare_rejects_non_map_operation() {
        let msg = envelope(
            "bft_preprepare",
            vec![
                CborValue::Bytes(vec![0; 32]),
                CborValue::Int(0),
                CborValue::Int(0),
                CborValue::Int(42), // operation must be a map
                CborValue::Bytes(vec![0; 32]),
                CborValue::Bytes(vec![0; 64]),
            ],
        );
        let bytes = encode(&msg).unwrap();
        assert!(BftPreprepare::from_bytes(&bytes).is_err());
    }
}