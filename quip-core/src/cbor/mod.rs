//! QUIP-CBOR: deterministic CBOR codec.
//!
//! Constraints on top of RFC 8949:
//!
//! - Integers use shortest-form encoding.
//! - Byte/text/array/map **lengths** use shortest-form encoding.
//! - Map keys sorted by bytewise lexicographic order of their encoded form.
//! - Floats prohibited.
//! - Indefinite-length encoding prohibited.
//! - Only CBOR tags 2 and 3 (bignums) permitted.
//!
//! Any violation is rejected with [`crate::Error::BadEncoding`].

mod decode;
mod encode;
mod types;

pub use decode::decode;
pub use encode::encode;
pub use types::CborValue;