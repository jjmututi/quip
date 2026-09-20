//! Strict CBOR decoder for QUIP-CBOR.

use super::types::CborValue;
use crate::error::{Error, Result};
use alloc::string::ToString;
use alloc::vec::Vec;

/// Decode QUIP-CBOR bytes into a [`CborValue`].
pub fn decode(bytes: &[u8]) -> Result<CborValue> {
    if bytes.is_empty() {
        return Err(Error::UnexpectedEnd);
    }
    let mut pos = 0;
    let v = decode_value(bytes, &mut pos)?;
    if pos != bytes.len() {
        return Err(Error::TrailingBytes);
    }
    Ok(v)
}

fn decode_value(bytes: &[u8], pos: &mut usize) -> Result<CborValue> {
    let initial = *bytes.get(*pos).ok_or(Error::UnexpectedEnd)?;
    *pos += 1;
    let major = initial >> 5;
    let info = initial & 0x1f;

    match major {
        0 => Ok(CborValue::Int(decode_int_value(info, bytes, pos)? as i128)),
        1 => {
            let v = decode_int_value(info, bytes, pos)?;
            Ok(CborValue::Int(-1 - (v as i128)))
        }
        2 => {
            let len = decode_length(info, bytes, pos)? as usize;
            let end = pos.checked_add(len).ok_or(Error::UnexpectedEnd)?;
            if end > bytes.len() {
                return Err(Error::UnexpectedEnd);
            }
            let data = bytes[*pos..end].to_vec();
            *pos = end;
            Ok(CborValue::Bytes(data))
        }
        3 => {
            let len = decode_length(info, bytes, pos)? as usize;
            let end = pos.checked_add(len).ok_or(Error::UnexpectedEnd)?;
            if end > bytes.len() {
                return Err(Error::UnexpectedEnd);
            }
            let s = core::str::from_utf8(&bytes[*pos..end])
                .map_err(|_| Error::InvalidUtf8)?
                .to_string();
            *pos = end;
            Ok(CborValue::String(s))
        }
        4 => {
            let len = decode_length(info, bytes, pos)? as usize;
            let mut items = Vec::with_capacity(len.min(64));
            for _ in 0..len {
                items.push(decode_value(bytes, pos)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => decode_map(info, bytes, pos),
        6 => decode_tag(info, bytes, pos),
        7 => decode_simple(info),
        _ => Err(Error::InvalidMajorType(major)),
    }
}

fn decode_int_value(info: u8, bytes: &[u8], pos: &mut usize) -> Result<u64> {
    match info {
        0..=23 => Ok(info as u64),
        24 => {
            let v = read_u8(bytes, pos)?;
            if v <= 23 {
                return Err(Error::NonShortestInteger);
            }
            Ok(v as u64)
        }
        25 => {
            let v = read_u16(bytes, pos)?;
            if v <= u8::MAX as u16 {
                return Err(Error::NonShortestInteger);
            }
            Ok(v as u64)
        }
        26 => {
            let v = read_u32(bytes, pos)?;
            if v <= u16::MAX as u32 {
                return Err(Error::NonShortestInteger);
            }
            Ok(v as u64)
        }
        27 => {
            let v = read_u64(bytes, pos)?;
            if v <= u32::MAX as u64 {
                return Err(Error::NonShortestInteger);
            }
            Ok(v)
        }
        28..=30 => Err(Error::InvalidAdditionalInfo(info)),
        31 => Err(Error::IndefiniteLength),
        _ => unreachable!(),
    }
}

/// Decode a length argument, enforcing shortest-form encoding.
fn decode_length(info: u8, bytes: &[u8], pos: &mut usize) -> Result<u64> {
    match info {
        0..=23 => Ok(info as u64),
        24 => {
            let v = read_u8(bytes, pos)?;
            if v <= 23 {
                return Err(Error::NonShortestLength);
            }
            Ok(v as u64)
        }
        25 => {
            let v = read_u16(bytes, pos)?;
            if v <= u8::MAX as u16 {
                return Err(Error::NonShortestLength);
            }
            Ok(v as u64)
        }
        26 => {
            let v = read_u32(bytes, pos)?;
            if v <= u16::MAX as u32 {
                return Err(Error::NonShortestLength);
            }
            Ok(v as u64)
        }
        27 => {
            let v = read_u64(bytes, pos)?;
            if v <= u32::MAX as u64 {
                return Err(Error::NonShortestLength);
            }
            Ok(v)
        }
        28..=30 => Err(Error::InvalidAdditionalInfo(info)),
        31 => Err(Error::IndefiniteLength),
        _ => unreachable!(),
    }
}

fn decode_map(info: u8, bytes: &[u8], pos: &mut usize) -> Result<CborValue> {
    let len = decode_length(info, bytes, pos)? as usize;
    let mut pairs = Vec::with_capacity(len.min(64));
    let mut last_key: Option<Vec<u8>> = None;

    for _ in 0..len {
        let key = decode_value(bytes, pos)?;
        let mut key_bytes = Vec::new();
        super::encode::encode_value(&key, &mut key_bytes)?;

        if let Some(prev) = &last_key {
            if key_bytes.as_slice() <= prev.as_slice() {
                return Err(Error::InvalidMapOrdering);
            }
        }
        last_key = Some(key_bytes);

        let val = decode_value(bytes, pos)?;
        pairs.push((key, val));
    }
    Ok(CborValue::Map(pairs))
}

fn decode_tag(info: u8, bytes: &[u8], pos: &mut usize) -> Result<CborValue> {
    let tag = decode_length(info, bytes, pos)?;
    match tag {
        2 => {
            let inner = decode_value(bytes, pos)?;
            let b = match inner {
                CborValue::Bytes(b) => b,
                _ => return Err(Error::BadEncoding("bignum tag requires byte string")),
            };
            let mag = bytes_to_u128(&b)?;
            if mag <= u64::MAX as u128 {
                return Err(Error::NonShortestInteger);
            }
            if mag > i128::MAX as u128 {
                return Err(Error::BignumOutOfRange);
            }
            Ok(CborValue::Int(mag as i128))
        }
        3 => {
            let inner = decode_value(bytes, pos)?;
            let b = match inner {
                CborValue::Bytes(b) => b,
                _ => return Err(Error::BadEncoding("bignum tag requires byte string")),
            };
            let mag = bytes_to_u128(&b)?;
            if mag <= u64::MAX as u128 {
                return Err(Error::NonShortestInteger);
            }
            if mag > i128::MAX as u128 {
                return Err(Error::BignumOutOfRange);
            }
            Ok(CborValue::Int(-1 - (mag as i128)))
        }
        _ => Err(Error::UnknownTag(tag)),
    }
}

fn bytes_to_u128(bytes: &[u8]) -> Result<u128> {
    if bytes.is_empty() {
        return Ok(0);
    }
    if bytes.len() > 16 {
        return Err(Error::BignumOutOfRange);
    }
    let mut buf = [0u8; 16];
    buf[16 - bytes.len()..].copy_from_slice(bytes);
    Ok(u128::from_be_bytes(buf))
}

fn decode_simple(info: u8) -> Result<CborValue> {
    match info {
        20 => Ok(CborValue::Bool(false)),
        21 => Ok(CborValue::Bool(true)),
        22 => Ok(CborValue::Null),
        25..=27 => Err(Error::FloatProhibited),
        31 => Err(Error::IndefiniteLength),
        _ => Err(Error::InvalidAdditionalInfo(info)),
    }
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Result<u8> {
    let b = *bytes.get(*pos).ok_or(Error::UnexpectedEnd)?;
    *pos += 1;
    Ok(b)
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > bytes.len() {
        return Err(Error::UnexpectedEnd);
    }
    let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Ok(v)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > bytes.len() {
        return Err(Error::UnexpectedEnd);
    }
    let v = u32::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
    ]);
    *pos += 4;
    Ok(v)
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    if *pos + 8 > bytes.len() {
        return Err(Error::UnexpectedEnd);
    }
    let v = u64::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
        bytes[*pos + 4],
        bytes[*pos + 5],
        bytes[*pos + 6],
        bytes[*pos + 7],
    ]);
    *pos += 8;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;  

    #[test]
    fn null_and_bools() {
        assert_eq!(decode(&[0xf6]).unwrap(), CborValue::Null);
        assert_eq!(decode(&[0xf4]).unwrap(), CborValue::Bool(false));
        assert_eq!(decode(&[0xf5]).unwrap(), CborValue::Bool(true));
    }

    #[test]
    fn undefined_rejected() {
        assert!(matches!(
            decode(&[0xf7]),
            Err(Error::InvalidAdditionalInfo(23))
        ));
    }

    #[test]
    fn simple_value_rejected() {
        assert!(matches!(
            decode(&[0xe0]),
            Err(Error::InvalidAdditionalInfo(0))
        ));
    }

    #[test]
    fn float_rejected() {
        assert!(matches!(
            decode(&[0xf9, 0x00, 0x00]),
            Err(Error::FloatProhibited)
        ));
    }

    #[test]
    fn non_shortest_byte_length_rejected() {
        assert!(matches!(
            decode(&[0x58, 0x01, 0x00]),
            Err(Error::NonShortestLength)
        ));
    }

    #[test]
    fn non_shortest_int_rejected() {
        assert!(matches!(
            decode(&[0x18, 0x00]),
            Err(Error::NonShortestInteger)
        ));
    }

    #[test]
    fn trailing_bytes_rejected() {
        assert!(matches!(decode(&[0x01, 0x02]), Err(Error::TrailingBytes)));
    }

    #[test]
    fn map_key_ordering_enforced() {
        let bad = &[0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02];
        assert!(matches!(decode(bad), Err(Error::InvalidMapOrdering)));
    }

    #[test]
    fn roundtrip_small() {
        let v = CborValue::Array(vec![
            CborValue::Int(1),
            CborValue::String("hello".into()),
            CborValue::Bool(true),
        ]);
        let bytes = super::super::encode::encode(&v).unwrap();
        assert_eq!(decode(&bytes).unwrap(), v);
    }
}