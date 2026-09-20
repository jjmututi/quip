//! # quip-core
//!
//! Core data structures and algorithms for the QUIC Identity Protocol.
//!
//! Transport-agnostic. Contains:
//!
//! - [`cbor`]     — deterministic CBOR (QUIP-CBOR).
//! - [`cid`]      — Content Identifiers (raw and CIDv1).
//! - [`dvv`]      — Dotted Version Vectors.
//! - [`messages`] — wire-level message types.
//! - [`constants`] — protocol constants.
//! - [`error`]    — unified error type and wire-level error codes.
//! - [`time`]     — Unix-millisecond timestamp newtype.
//!
//! QUIC framing, stream IDs, and NAT traversal live in `quip-net`.
//!
//! ## Feature flags
//!
//! - `std` (default): link against `std`. Disable for `no_std + alloc`.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

extern crate alloc;

pub mod address;
pub mod cbor;
pub mod cid;
pub mod constants;
pub mod dvv;
pub mod error;
pub mod messages;
pub mod time;

pub use address::Address;
pub use cbor::CborValue;
pub use cid::{Cid, CidOrV1, CidV1, HashAlgo};
pub use constants::{ALPN_QUIP, PROTOCOL_VERSION};
pub use dvv::{CausalOrder, Dot, Dvv, NodeId};
pub use error::{Error, ErrorCode, Result};
pub use messages::{
    DelegationCertificate, DerivativeLink, Discontinuity, FrostRingSig, IndividualRingSig,
    KeyClaim, KeyRotation, PinEntry, QuarantineNotice, QuarantineRequest, RevocationNotice,
    RingSignature, SeqReset, Signer, TrustedCidRegistration, UnquarantineRequest, Verifier,
    WitnessStatement,
};
pub use time::{Clock, ManualClock, Timestamp};

#[cfg(feature = "std")]
pub use time::SystemClock;