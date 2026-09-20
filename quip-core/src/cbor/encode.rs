//! Canonical CBOR encoder.

use super::types::CborValue;
use crate::error::{Error, Result};
use alloc::vec::Vec;

/// Encode a [`CborValue`] into canonical QUIP-CBOR bytes.
pub fn encode(value: &CborValue) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_value(value, &mut out)?;
    Ok(out)
}

pub(crate) fn encode_value(value: &CborValue, out: &mut Vec<u8>) -> Result<()> {
    match value {
        CborValue::Null => out.push(0xf6),
        CborValue::Bool(false) => out.push(0xf4),
        CborValue::Bool(true) => out.push(0xf5),
        CborValue::Int(n) => encode_int(*n, out),
        CborValue::Bytes(b) => {
            encode_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        CborValue::String(s) => {
            let b = s.as_bytes();
            encode_head(3, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        CborValue::Array(a) => {
            encode_head(4, a.len() as u64, out);
            for item in a {
                encode_value(item, out)?;
            }
        }
        CborValue::Map(pairs) => encode_map(pairs, out)?,
        CborValue::Tag(tag, inner) => encode_tag(*tag, inner, out)?,
    }
    Ok(())
}

/// Encode an integer. Values outside `[-2^64, 2^64 - 1]` use bignums.
fn encode_int(n: i128, out: &mut Vec<u8>) {
    if n >= 0 {
        if n > u64::MAX as i128 {
            // Positive bignum — encode to temporary buffer, then append.
            let mut tmp = Vec::new();
            encode_bignum(2, n as u128, &mut tmp);
            out.extend_from_slice(&tmp);
        } else {
            encode_head(0, n as u64, out);
        }
    } else if n < -(u64::MAX as i128) - 1 {
        // Negative bignum: magnitude = -1 - n.
        let magnitude = (-1 - n) as u128;
        let mut tmp = Vec::new();
        encode_bignum(3, magnitude, &mut tmp);
        out.extend_from_slice(&tmp);
    } else {
        let v = (-1 - n) as u64;
        encode_head(1, v, out);
    }
}

fn encode_bignum(tag: u64, magnitude: u128, out: &mut Vec<u8>) {
    encode_head(6, tag, out);
    let bytes = magnitude.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let minimal = &bytes[start..];
    let minimal = if minimal.is_empty() { &[0u8][..] } else { minimal };
    encode_head(2, minimal.len() as u64, out);
    out.extend_from_slice(minimal);
}

/// Encode a CBOR "head".
fn encode_head(major: u8, len: u64, out: &mut Vec<u8>) {
    debug_assert!(major <= 7);
    let mt = major << 5;
    if len <= 23 {
        out.push(mt | (len as u8));
    } else if len <= u8::MAX as u64 {
        out.push(mt | 0x18);
        out.push(len as u8);
    } else if len <= u16::MAX as u64 {
        out.push(mt | 0x19);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else if len <= u32::MAX as u64 {
        out.push(mt | 0x1a);
        out.extend_from_slice(&(len as u32).to_be_bytes());
    } else {
        out.push(mt | 0x1b);
        out.extend_from_slice(&len.to_be_bytes());
    }
}

fn encode_map(pairs: &[(CborValue, CborValue)], out: &mut Vec<u8>) -> Result<()> {
    let mut encoded: Vec<(Vec<u8>, usize)> = Vec::with_capacity(pairs.len());
    for (i, (k, _)) in pairs.iter().enumerate() {
        let mut buf = Vec::new();
        encode_value(k, &mut buf)?;
        encoded.push((buf, i));
    }
    encoded.sort_by(|a, b| a.0.cmp(&b.0));

    for w in encoded.windows(2) {
        if w[0].0 == w[1].0 {
            return Err(Error::DuplicateMapKey);
        }
    }

    encode_head(5, encoded.len() as u64, out);
    for (key_bytes, idx) in encoded {
        out.extend_from_slice(&key_bytes);
        encode_value(&pairs[idx].1, out)?;
    }
    Ok(())
}

fn encode_tag(tag: u64, inner: &CborValue, out: &mut Vec<u8>) -> Result<()> {
    match tag {
        2 | 3 => {
            encode_head(6, tag, out);
            encode_value(inner, out)?;
            Ok(())
        }
        _ => Err(Error::UnknownTag(tag)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec;

    #[test]
    fn int_shortest() {
        assert_eq!(encode(&CborValue::Int(0)).unwrap(), &[0x00]);
        assert_eq!(encode(&CborValue::Int(23)).unwrap(), &[0x17]);
        assert_eq!(encode(&CborValue::Int(24)).unwrap(), &[0x18, 0x18]);
        assert_eq!(encode(&CborValue::Int(-1)).unwrap(), &[0x20]);
        assert_eq!(encode(&CborValue::Int(-24)).unwrap(), &[0x37]);
        assert_eq!(encode(&CborValue::Int(-25)).unwrap(), &[0x38, 0x18]);
    }

    #[test]
    fn map_sorts_keys() {
        let m = CborValue::Map(vec![
            (CborValue::Int(2), CborValue::Null),
            (CborValue::Int(1), CborValue::Null),
        ]);
        assert_eq!(encode(&m).unwrap(), &[0xa2, 0x01, 0xf6, 0x02, 0xf6]);
    }

    #[test]
    fn duplicate_key_rejected() {
        let m = CborValue::Map(vec![
            (CborValue::Int(1), CborValue::Null),
            (CborValue::Int(1), CborValue::Null),
        ]);
        assert!(matches!(encode(&m), Err(Error::DuplicateMapKey)));
    }

    #[test]
    fn unknown_tag_rejected() {
        let v = CborValue::Tag(9999, Box::new(CborValue::Null));
        assert!(matches!(encode(&v), Err(Error::UnknownTag(9999))));
    }

    #[test]
    fn bignum_does_not_corrupt_buffer() {
        let v = CborValue::Array(vec![
            CborValue::Int(0x11),
            CborValue::Int(u64::MAX as i128 + 1),
        ]);
        let bytes = encode(&v).unwrap();
        assert_eq!(bytes[0], 0x82);
        assert_eq!(bytes[1], 0x11);
    }
}