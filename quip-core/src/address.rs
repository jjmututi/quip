//! Transport address (spec §12.1).
//!
//! Wire form:
//!
//! ```text
//! Address = {
//!   family: uint,          ; 4 = IPv4, 6 = IPv6
//!   ip: bytes,             ; 4 bytes for IPv4, 16 bytes for IPv6
//!   port: uint             ; 0-65535
//! }
//! ```
//!
//! Used by `ConnectivityAnnounce`, `Candidate`, `RelayEntry`, and
//! `RelayHop`. Defined once here so that `quip-net` and `quip-storage`
//! share a single representation.

use crate::cbor::CborValue;
use crate::error::{Error, Result};
use alloc::string::ToString;
use alloc::vec;

/// A network transport address.
///
/// The family discriminant matches the spec's `Address.family` field:
/// `4` for IPv4, `6` for IPv6. The wire form is a CBOR map with three
/// keys (`family`, `ip`, `port`), so `Address` round-trips through any
/// QUIP-CBOR codec without further adaptation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Address {
    /// IPv4 address and port.
    V4 {
        /// Four-byte IPv4 address.
        ip: [u8; 4],
        /// Port number.
        port: u16,
    },
    /// IPv6 address and port.
    V6 {
        /// Sixteen-byte IPv6 address.
        ip: [u8; 16],
        /// Port number.
        port: u16,
    },
}

impl Address {
    /// Family discriminant (`4` or `6`) as it appears on the wire.
    pub const fn family(&self) -> u64 {
        match self {
            Address::V4 { .. } => 4,
            Address::V6 { .. } => 6,
        }
    }

    /// Port number.
    pub const fn port(&self) -> u16 {
        match self {
            Address::V4 { port, .. } => *port,
            Address::V6 { port, .. } => *port,
        }
    }

    /// Encode to a CBOR map matching the spec CDDL.
    pub fn to_cbor(&self) -> CborValue {
        let (family, ip, port): (u64, &[u8], u16) = match self {
            Address::V4 { ip, port } => (4, ip.as_slice(), *port),
            Address::V6 { ip, port } => (6, ip.as_slice(), *port),
        };
        CborValue::Map(vec![
            (
                CborValue::String("family".to_string()),
                CborValue::Int(family as i128),
            ),
            (
                CborValue::String("ip".to_string()),
                CborValue::Bytes(ip.to_vec()),
            ),
            (
                CborValue::String("port".to_string()),
                CborValue::Int(port as i128),
            ),
        ])
    }

    /// Decode from a CBOR map.
    ///
    /// Rejects unknown keys, missing keys, wrong types, wrong IP lengths,
    /// and family values other than 4 or 6.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = value else {
            return Err(Error::BadEncoding("Address must be a CBOR map"));
        };
        let mut family: Option<u64> = None;
        let mut ip: Option<alloc::vec::Vec<u8>> = None;
        let mut port: Option<u16> = None;

        for (k, v) in pairs {
            match k {
                CborValue::String(s) if s == "family" => match v {
                    CborValue::Int(n) if *n >= 0 => family = Some(*n as u64),
                    _ => {
                        return Err(Error::BadEncoding(
                            "Address.family must be a non-negative integer",
                        ))
                    }
                },
                CborValue::String(s) if s == "ip" => match v {
                    CborValue::Bytes(b) => ip = Some(b.clone()),
                    _ => return Err(Error::BadEncoding("Address.ip must be a byte string")),
                },
                CborValue::String(s) if s == "port" => match v {
                    CborValue::Int(n) if *n >= 0 && *n <= u16::MAX as i128 => {
                        port = Some(*n as u16);
                    }
                    _ => {
                        return Err(Error::BadEncoding(
                            "Address.port must be in 0..=65535",
                        ))
                    }
                },
                CborValue::String(_) => {
                    return Err(Error::BadEncoding("unknown key in Address"));
                }
                _ => {
                    return Err(Error::BadEncoding("Address keys must be text strings"));
                }
            }
        }

        let family = family.ok_or(Error::BadEncoding("Address.family is required"))?;
        let ip = ip.ok_or(Error::BadEncoding("Address.ip is required"))?;
        let port = port.ok_or(Error::BadEncoding("Address.port is required"))?;

        match family {
            4 => {
                if ip.len() != 4 {
                    return Err(Error::BadEncoding(
                        "IPv4 address must be exactly 4 bytes",
                    ));
                }
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&ip);
                Ok(Address::V4 { ip: arr, port })
            }
            6 => {
                if ip.len() != 16 {
                    return Err(Error::BadEncoding(
                        "IPv6 address must be exactly 16 bytes",
                    ));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&ip);
                Ok(Address::V6 { ip: arr, port })
            }
            _ => Err(Error::BadEncoding(
                "Address.family must be 4 (IPv4) or 6 (IPv6)",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_roundtrip() {
        let a = Address::V4 {
            ip: [192, 168, 1, 1],
            port: 4433,
        };
        let cbor = a.to_cbor();
        let bytes = crate::cbor::encode(&cbor).unwrap();
        let decoded = crate::cbor::decode(&bytes).unwrap();
        assert_eq!(Address::from_cbor(&decoded).unwrap(), a);
    }

    #[test]
    fn v6_roundtrip() {
        let a = Address::V6 {
            ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 4433,
        };
        let cbor = a.to_cbor();
        let bytes = crate::cbor::encode(&cbor).unwrap();
        let decoded = crate::cbor::decode(&bytes).unwrap();
        assert_eq!(Address::from_cbor(&decoded).unwrap(), a);
    }

    #[test]
    fn family_discriminant_matches_spec() {
        let v4 = Address::V4 { ip: [0; 4], port: 0 };
        let v6 = Address::V6 { ip: [0; 16], port: 0 };
        assert_eq!(v4.family(), 4);
        assert_eq!(v6.family(), 6);
    }

    #[test]
    fn wrong_ip_length_rejected() {
        let bad = CborValue::Map(vec![
            (CborValue::String("family".to_string()), CborValue::Int(4)),
            (
                CborValue::String("ip".to_string()),
                CborValue::Bytes(vec![1, 2, 3]),
            ),
            (CborValue::String("port".to_string()), CborValue::Int(80)),
        ]);
        assert!(Address::from_cbor(&bad).is_err());
    }

    #[test]
    fn unknown_family_rejected() {
        let bad = CborValue::Map(vec![
            (CborValue::String("family".to_string()), CborValue::Int(7)),
            (
                CborValue::String("ip".to_string()),
                CborValue::Bytes(vec![0; 4]),
            ),
            (CborValue::String("port".to_string()), CborValue::Int(80)),
        ]);
        assert!(Address::from_cbor(&bad).is_err());
    }

    #[test]
    fn missing_key_rejected() {
        let bad = CborValue::Map(vec![
            (CborValue::String("family".to_string()), CborValue::Int(4)),
            (
                CborValue::String("ip".to_string()),
                CborValue::Bytes(vec![0; 4]),
            ),
        ]);
        assert!(Address::from_cbor(&bad).is_err());
    }

    #[test]
    fn unknown_key_rejected() {
        let bad = CborValue::Map(vec![
            (CborValue::String("family".to_string()), CborValue::Int(4)),
            (
                CborValue::String("ip".to_string()),
                CborValue::Bytes(vec![0; 4]),
            ),
            (CborValue::String("port".to_string()), CborValue::Int(80)),
            (CborValue::String("extra".to_string()), CborValue::Int(0)),
        ]);
        assert!(Address::from_cbor(&bad).is_err());
    }

    #[test]
    fn port_out_of_range_rejected() {
        let bad = CborValue::Map(vec![
            (CborValue::String("family".to_string()), CborValue::Int(4)),
            (
                CborValue::String("ip".to_string()),
                CborValue::Bytes(vec![0; 4]),
            ),
            (
                CborValue::String("port".to_string()),
                CborValue::Int(70_000),
            ),
        ]);
        assert!(Address::from_cbor(&bad).is_err());
    }
}