//! `PinEntry` — spec §14.
//!
//! `PinEntry` is a struct inside `pin_list` messages, not a top-level
//! message on its own.

use super::extract_u64;
use crate::cbor::CborValue;
use crate::cid::CidOrV1;
use crate::error::{Error, Result};
use crate::time::Timestamp;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

/// A single pin record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinEntry {
    /// Resource identifier (application-defined).
    pub resource_id: Vec<u8>,
    /// Pinned CID.
    pub cid: CidOrV1,
    /// Unix milliseconds.
    pub pinned_at: Timestamp,
    /// Remaining TTL in **seconds**. 0 = never expires.
    pub ttl_seconds: u64,
    /// Number of peers that have referenced this pin.
    pub ref_count: u64,
    /// True if the pin is held locally, false if observed remotely.
    pub local: bool,
}

impl PinEntry {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(vec![
            (
                CborValue::String("resource_id".to_string()),
                CborValue::Bytes(self.resource_id.clone()),
            ),
            (CborValue::String("cid".to_string()), self.cid.to_cbor()),
            (
                CborValue::String("pinned_at".to_string()),
                CborValue::Int(self.pinned_at.as_millis() as i128),
            ),
            (
                CborValue::String("ttl".to_string()),
                CborValue::Int(self.ttl_seconds as i128),
            ),
            (
                CborValue::String("ref_count".to_string()),
                CborValue::Int(self.ref_count as i128),
            ),
            (CborValue::String("local".to_string()), CborValue::Bool(self.local)),
        ])
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = value else {
            return Err(Error::BadEncoding("PinEntry must be a CBOR map"));
        };
        let mut resource_id = None;
        let mut cid = None;
        let mut pinned_at = None;
        let mut ttl = None;
        let mut ref_count = None;
        let mut local = None;
        for (k, v) in pairs {
            match k {
                CborValue::String(s) if s == "resource_id" => match v {
                    CborValue::Bytes(b) => resource_id = Some(b.clone()),
                    _ => return Err(Error::BadEncoding("resource_id must be bytes")),
                },
                CborValue::String(s) if s == "cid" => cid = Some(CidOrV1::from_cbor(v)?),
                CborValue::String(s) if s == "pinned_at" => {
                    pinned_at = Some(Timestamp(extract_u64(v)?))
                }
                CborValue::String(s) if s == "ttl" => ttl = Some(extract_u64(v)?),
                CborValue::String(s) if s == "ref_count" => ref_count = Some(extract_u64(v)?),
                CborValue::String(s) if s == "local" => match v {
                    CborValue::Bool(b) => local = Some(*b),
                    _ => return Err(Error::BadEncoding("local must be a bool")),
                },
                _ => return Err(Error::BadEncoding("unknown key in PinEntry")),
            }
        }
        Ok(PinEntry {
            resource_id: resource_id.ok_or(Error::BadEncoding("missing resource_id"))?,
            cid: cid.ok_or(Error::BadEncoding("missing cid"))?,
            pinned_at: pinned_at.ok_or(Error::BadEncoding("missing pinned_at"))?,
            ttl_seconds: ttl.ok_or(Error::BadEncoding("missing ttl"))?,
            ref_count: ref_count.ok_or(Error::BadEncoding("missing ref_count"))?,
            local: local.ok_or(Error::BadEncoding("missing local"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cid::Cid;

    #[test]
    fn roundtrip() {
        let p = PinEntry {
            resource_id: vec![0xab, 0xcd],
            cid: CidOrV1::Raw(Cid([0x42; 32])),
            pinned_at: Timestamp::from_millis(1_700_000_000_000),
            ttl_seconds: 604_800,
            ref_count: 3,
            local: true,
        };
        let back = PinEntry::from_cbor(&p.to_cbor()).unwrap();
        assert_eq!(back, p);
    }
}