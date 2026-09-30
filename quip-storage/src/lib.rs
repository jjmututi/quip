//! # quip-storage
//!
//! Persistent state for the QUIC Identity Protocol (QUIP).
//!
//! ## Roadmap
//!
//! Milestone tags in the source (`M4b.1`, `M7`, …) cite entries in
//! the [roadmap].
//!
//! [roadmap]: https://github.com/jjmututi/quip/blob/main/ROADMAP.md
//!
//! Transport-agnostic, like [`quip_core`]: every entry point takes an explicit
//! [`Timestamp`](quip_core::time::Timestamp) so behaviour is deterministic and
//! testable. `quip-net` supplies the clock and the framing; this crate owns the
//! bytes and the bookkeeping.
//!
//! ## Contents
//!
//! - [`blob`]      — content-addressed payload storage ([`BlobStore`] trait,
//!   [`MemoryBlobStore`], and (with `std`) [`FileBlobStore`]).
//! - [`pins`]      — pinning state for the `pin`/`unpin`/`query_pins` verbs and
//!   `pin_announce` gossip (spec §14.2, App. A.5).
//! - [`quarantine`] — quarantine notices and pending requests (spec §7.2).
//! - [`governance`] — Trusted CIDs, derivative links, and delegations (spec §7.1, §7.3).
//! - [`directory`] — resource location hints for `resource_announce`/`query_resource`
//!   (spec §14.5, App. A.6).
//! - [`snapshot`]  — full-store serialisation using canonical QUIP-CBOR (spec §10),
//!   so persistence needs no `serde` and no other dependency.
//! - [`store`]     — [`QuipStore`], which composes the tables and enforces the
//!   cross-cutting rules (CID verification, CIDv1 tagging, quarantine filtering,
//!   staleness).
//! - [`hash`]      — the [`ContentHasher`] trait; hashing algorithms are supplied
//!   by the application, exactly as Ed25519 verification is in `quip-core`.
//!
//! ## Separation of mutable and immutable state
//!
//! Spec §5.2 is explicit: *"Pinning applies only to immutable CIDs. Mutable DVV
//! resources are not pinned; they are synced via DVV merge and RBSR."* This crate
//! therefore stores:
//!
//! - **immutable** content, keyed by CID (bytes are verified against the digest);
//! - **mutable** resource *pointers*, in [`directory`], as an announced
//!   `latest_cid` — never the DVV state itself, which belongs to `quip-net`.
//!
//! ## Feature flags
//!
//! - `std` (default): file-backed blob store ([`mod@file`]) and [`clock`].
//! - Without `std`: `no_std + alloc`, in-memory backends only.
//!
//! ## Example
//!
//! ```
//! use quip_core::cid::HashAlgo;
//! use quip_core::time::Timestamp;
//! use quip_storage::{CidTagging, QuipStore};
//!
//! # struct Fake;
//! # impl quip_storage::ContentHasher for Fake {
//! #     fn digest(&self, algo: HashAlgo, payload: &[u8]) -> Option<[u8; 32]> {
//! #         let mut out = [0u8; 32];
//! #         let seed = match algo { HashAlgo::Sha256 => 0x11, HashAlgo::Blake3 => 0x22 };
//! #         for (i, b) in payload.iter().enumerate() {
//! #             out[i % 32] ^= b ^ seed;
//! #         }
//! #         Some(out)
//! #     }
//! # }
//! let mut store = QuipStore::new();
//! let now = Timestamp::from_millis(1_700_000_000_000);
//!
//! let cid = store
//!     .put_content(b"hello quip".to_vec(), HashAlgo::Sha256, CidTagging::V1, &Fake, now)
//!     .unwrap();
//!
//! // Immutable content can be pinned for 7 days (ttl = 0 selects the default).
//! store.pin(b"docs/readme", &cid, 0, now);
//! assert_eq!(store.pins().len(), 1);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

extern crate alloc;

mod codec;

pub mod blob;
pub mod constants;
pub mod directory;
pub mod error;
pub mod governance;
pub mod hash;
pub mod pins;
pub mod quarantine;
pub mod snapshot;
pub mod store;

#[cfg(feature = "std")]
pub mod clock;
#[cfg(feature = "std")]
pub mod file;

pub use blob::{BlobRecord, BlobStore, MemoryBlobStore};
pub use constants::{
    DEFAULT_PIN_TTL_S, DEFAULT_QUARANTINE_CAPACITY, DEFAULT_RESOURCE_CAPACITY,
    DERIVATIVE_LINK_CAPACITY, INDEFINITE_TTL_S, MAX_ANNOUNCEMENT_AGE_S, PIN_REFRESH_PERCENT,
};
pub use directory::{ResourceAnnouncement, ResourceDirectory};
pub use error::{Error, Result};
pub use governance::GovernanceStore;
pub use hash::{compute_cid, verify_content, ContentHasher};
pub use pins::{PinRecord, PinTable};
pub use quarantine::QuarantineStore;
pub use snapshot::{Snapshot, SNAPSHOT_VERSION};
pub use store::{CidTagging, QuipStore, StoreConfig};

#[cfg(feature = "std")]
pub use clock::unix_now;
#[cfg(feature = "std")]
pub use file::FileBlobStore;