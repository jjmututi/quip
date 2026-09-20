//! EVENT-plane datagrams (T3, spec section 14.4).
use crate::codec::{as_bytes, envelope, fields, verb_of};
use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::cid::CidOrV1;

/// `emit = ["emit", event_type: tstr, payload: any]`.
#[derive(Clone, Debug, PartialEq)]
pub struct EmitEvent {
    /// Application event type.
    pub event_type: String,
    /// Opaque CBOR payload.
    pub payload: CborValue,
}

impl EmitEvent {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope("emit", alloc::vec![
            CborValue::String(self.event_type.clone()),
            self.payload.clone(),
        ]);
        Ok(encode(&msg)?)
    }
    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = decode(bytes)?;
        if verb_of(&value)? != "emit" {
            return Err(Error::BadFrame("not an emit"));
        }
        let f = fields(&value, "emit")?;
        if f.len() != 2 {
            return Err(Error::BadFrame("emit arity"));
        }
        let CborValue::String(event_type) = &f[0] else {
            return Err(Error::BadFrame("event_type must be text"));
        };
        Ok(Self { event_type: event_type.clone(), payload: f[1].clone() })
    }
}

/// `pin_announce` gossip (T3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinAnnounce {
    /// Application resource name.
    pub resource_id: Vec<u8>,
    /// Announced CID.
    pub cid: CidOrV1,
    /// TTL in seconds.
    pub ttl_seconds: u64,
    /// Single witness signature (not a ring signature).
    pub witness_sig: [u8; 64],
}

impl PinAnnounce {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope("pin_announce", alloc::vec![
            CborValue::Bytes(self.resource_id.clone()),
            self.cid.to_cbor(),
            CborValue::Int(self.ttl_seconds as i128),
            CborValue::Bytes(self.witness_sig.to_vec()),
        ]);
        Ok(encode(&msg)?)
    }
    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = decode(bytes)?;
        if verb_of(&value)? != "pin_announce" {
            return Err(Error::BadFrame("not a pin_announce"));
        }
        let f = fields(&value, "pin_announce")?;
        if f.len() != 4 {
            return Err(Error::BadFrame("pin_announce arity"));
        }
        let resource_id = as_bytes(&f[0])?;
        let cid = CidOrV1::from_cbor(&f[1])?;
        let ttl_seconds = crate::codec::as_u64(&f[2])?;
        let sig = as_bytes(&f[3])?;
        if sig.len() != 64 {
            return Err(Error::BadFrame("witness_sig must be 64 bytes"));
        }
        let mut witness_sig = [0u8; 64];
        witness_sig.copy_from_slice(&sig);
        Ok(Self { resource_id, cid, ttl_seconds, witness_sig })
    }
}
