//! QUIP-DVV: Dotted Version Vectors.

pub mod cbor;
mod ops;
mod types;

pub use cbor::{from_bytes, to_bytes};
pub use ops::{happens_after, happens_before, is_concurrent};
pub use types::{CausalOrder, Dot, Dvv, NodeId};