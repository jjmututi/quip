//! CBOR value type.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

/// A CBOR value in QUIP canonical form.
///
/// Floats are intentionally absent. Use `{value, scale}` pairs if you
/// need decimal representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CborValue {
    /// `null`.
    Null,
    /// Boolean.
    Bool(bool),
    /// Integer. Stored as `i128` to cover uint, nint, and bignums.
    Int(i128),
    /// Byte string.
    Bytes(Vec<u8>),
    /// UTF-8 text string.
    String(String),
    /// Definite-length array.
    Array(Vec<CborValue>),
    /// Definite-length map. Keys must be sorted by encoded bytes.
    Map(Vec<(CborValue, CborValue)>),
    /// Tagged value. Only tags 2 and 3 (bignums) are permitted.
    Tag(u64, Box<CborValue>),
}