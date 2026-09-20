//! QUIP wire-level message types.

use crate::cbor::CborValue;
use crate::constants::MSG_PREFIX;
use crate::dvv::NodeId;
use crate::error::{Error, Result};
use crate::time::Timestamp;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub mod delegation;
pub mod derivative;
pub mod key_claim;
pub mod pin;
pub mod quarantine;
pub mod revocation;
pub mod ring_signature;
pub mod rotation;
pub mod trusted_cid;
pub mod verifier;
pub mod witness;
pub mod discontinuity;
pub mod quarantine_request;
pub mod seq_reset;

pub use delegation::DelegationCertificate;
pub use derivative::DerivativeLink;
pub use key_claim::KeyClaim;
pub use pin::PinEntry;
pub use quarantine::QuarantineNotice;
pub use revocation::RevocationNotice;
pub use ring_signature::{FrostRingSig, IndividualRingSig, RingSignature};
pub use rotation::KeyRotation;
pub use trusted_cid::TrustedCidRegistration;
pub use verifier::{Signer, Verifier};
pub use witness::WitnessStatement;
pub use discontinuity::Discontinuity;
pub use quarantine_request::{QuarantineRequest, UnquarantineRequest};
pub use seq_reset::SeqReset;

// -------------------------------------------------------------------------
// Internal helpers shared by all message types.
// -------------------------------------------------------------------------

/// Build `["quip-v1", verb, ...fields]`.
pub(crate) fn wrap(verb: &str, fields: Vec<CborValue>) -> CborValue {
    let mut arr: Vec<CborValue> = Vec::with_capacity(fields.len() + 2);
    arr.push(CborValue::String(MSG_PREFIX.to_string()));
    arr.push(CborValue::String(verb.to_string()));
    arr.extend(fields);
    CborValue::Array(arr)
}

/// Validate the `["quip-v1", verb]` prefix and return the trailing fields.
pub(crate) fn unwrap<'a>(
    value: &'a CborValue,
    expected_verb: &str,
) -> Result<&'a [CborValue]> {
    let CborValue::Array(arr) = value else {
        return Err(Error::BadEncoding("message must be an array"));
    };
    if arr.len() < 2 {
        return Err(Error::BadEncoding("message array too short"));
    }
    match (&arr[0], &arr[1]) {
        (CborValue::String(p), CborValue::String(v))
            if p.as_str() == MSG_PREFIX && v.as_str() == expected_verb =>
        {
            Ok(&arr[2..])
        }
        _ => Err(Error::BadEncoding("wrong message prefix or verb")),
    }
}

pub(crate) fn expect_len(fields: &[CborValue], n: usize) -> Result<()> {
    if fields.len() != n {
        return Err(Error::BadEncoding("message has wrong number of fields"));
    }
    Ok(())
}

pub(crate) fn extract_node_id(v: &CborValue) -> Result<NodeId> {
    match v {
        CborValue::Bytes(b) if b.len() == 32 => {
            let mut a = [0u8; 32];
            a.copy_from_slice(b);
            Ok(a)
        }
        CborValue::Bytes(b) => Err(Error::InvalidDigestLength(b.len())),
        _ => Err(Error::BadEncoding("expected 32-byte NodeId")),
    }
}

pub(crate) fn extract_u64(v: &CborValue) -> Result<u64> {
    match v {
        CborValue::Int(n) if *n >= 0 && *n <= u64::MAX as i128 => Ok(*n as u64),
        CborValue::Int(_) => Err(Error::BadEncoding("value out of u64 range")),
        _ => Err(Error::BadEncoding("expected non-negative integer")),
    }
}

pub(crate) fn extract_timestamp(v: &CborValue) -> Result<Timestamp> {
    Ok(Timestamp(extract_u64(v)?))
}

pub(crate) fn extract_sig64(v: &CborValue) -> Result<[u8; 64]> {
    match v {
        CborValue::Bytes(b) if b.len() == 64 => {
            let mut a = [0u8; 64];
            a.copy_from_slice(b);
            Ok(a)
        }
        CborValue::Bytes(b) => Err(Error::BadEncoding(if b.len() < 64 {
            "signature shorter than 64 bytes"
        } else {
            "signature longer than 64 bytes"
        })),
        _ => Err(Error::BadEncoding("expected byte string signature")),
    }
}

pub(crate) fn extract_bytes(v: &CborValue) -> Result<Vec<u8>> {
    match v {
        CborValue::Bytes(b) => Ok(b.clone()),
        _ => Err(Error::BadEncoding("expected byte string")),
    }
}

pub(crate) fn extract_text(v: &CborValue) -> Result<String> {
    match v {
        CborValue::String(s) => Ok(s.clone()),
        _ => Err(Error::BadEncoding("expected text string")),
    }
}

pub(crate) fn extract_metadata(v: &CborValue) -> Result<Vec<(String, CborValue)>> {
    let CborValue::Map(pairs) = v else {
        return Err(Error::BadEncoding("expected metadata map"));
    };
    let mut out = Vec::with_capacity(pairs.len());
    for (k, val) in pairs {
        let k = match k {
            CborValue::String(s) => s.clone(),
            _ => return Err(Error::BadEncoding("metadata keys must be text")),
        };
        out.push((k, val.clone()));
    }
    Ok(out)
}

pub(crate) fn metadata_to_cbor(m: &[(String, CborValue)]) -> CborValue {
    CborValue::Map(
        m.iter()
            .map(|(k, v)| (CborValue::String(k.clone()), v.clone()))
            .collect(),
    )
}

pub(crate) fn extract_ring_id(v: &CborValue) -> Result<[u8; 32]> {
    let b = extract_bytes(v)?;
    if b.len() != 32 {
        return Err(Error::BadEncoding("ring_id must be 32 bytes"));
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&b);
    Ok(a)
}