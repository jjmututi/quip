//! `OperationOutcome` — spec §5.3.4.
//!
//! The protocol-defined result of applying a committed operation. It is
//! not an application-defined result: the discriminants are text, the
//! payload is bounded, and the encoding is a closed map.

use crate::cbor::CborValue;
use crate::error::{Error, Result};
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

/// The `success` discriminant (§5.3.4).
///
/// Both success shapes carry this discriminant; the presence of a
/// `payload` key is what distinguishes them, so a success with no
/// payload and a success with an empty payload encode differently.
pub const OUTCOME_SUCCESS: &str = "success";

/// The `application-failure` discriminant (§5.3.4).
pub const OUTCOME_APPLICATION_FAILURE: &str = "application-failure";

/// The maximum payload length, in bytes (§5.3.4).
pub const OUTCOME_MAX_PAYLOAD: usize = 256;

/// Map key naming the discriminant.
pub const OUTCOME_KEY_DISCRIMINANT: &str = "discriminant";

/// Map key naming the payload.
pub const OUTCOME_KEY_PAYLOAD: &str = "payload";

/// The outcome of applying a committed operation (§5.3.4).
///
/// A protocol type, not an application one: the discriminant is
/// text, and the payload is bounded at 256 bytes. Encoded as a map
/// with text keys "discriminant" and, when present, "payload"; the
/// map is closed and a receiver MUST reject an unknown key with
/// E_BAD_ENCODING (per the draft's §10 closed-map rule). The
/// text-keyed map's canonical sort is determined by quip-core's
/// encoder (§5.3.4's "Digest construction" cites it).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationOutcome {
    /// The operation applied and produced no payload.
    Success,
    /// The operation applied and produced `payload` (at most 256 bytes).
    SuccessWithPayload(Vec<u8>),
    /// The operation did not apply; the application's declared failure.
    /// The optional payload is at most 256 bytes.
    ApplicationFailure(Option<Vec<u8>>),
}

impl OperationOutcome {
    /// The discriminant as the wire form names it.
    pub fn discriminant(&self) -> &'static str {
        match self {
            Self::Success | Self::SuccessWithPayload(_) => OUTCOME_SUCCESS,
            Self::ApplicationFailure(_) => OUTCOME_APPLICATION_FAILURE,
        }
    }

    /// The payload, if any.
    pub fn payload(&self) -> Option<&[u8]> {
        match self {
            Self::Success => None,
            Self::SuccessWithPayload(payload) => Some(payload),
            Self::ApplicationFailure(payload) => payload.as_deref(),
        }
    }

    /// Encode to the §5.3.4 CBOR map.
    ///
    /// The `payload` key is absent when there is no payload, so the
    /// two success shapes stay distinguishable on the wire.
    pub fn to_cbor(&self) -> CborValue {
        let mut pairs = vec![(
            CborValue::String(OUTCOME_KEY_DISCRIMINANT.to_string()),
            CborValue::String(self.discriminant().to_string()),
        )];
        if let Some(payload) = self.payload() {
            pairs.push((
                CborValue::String(OUTCOME_KEY_PAYLOAD.to_string()),
                CborValue::Bytes(payload.to_vec()),
            ));
        }
        CborValue::Map(pairs)
    }

    /// Decode from the §5.3.4 CBOR map.
    ///
    /// Rejects a non-map, a non-text key, an unknown key (the map is
    /// closed per §10), a non-text discriminant, an unknown
    /// discriminant, a missing discriminant, a payload that is not a
    /// byte string, and a payload longer than
    /// [`OUTCOME_MAX_PAYLOAD`] — all with [`Error::BadEncoding`].
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = value else {
            return Err(Error::BadEncoding("OperationOutcome must be a CBOR map"));
        };
        let mut discriminant: Option<&str> = None;
        let mut payload: Option<Vec<u8>> = None;
        for (key, value) in pairs {
            let CborValue::String(key) = key else {
                return Err(Error::BadEncoding("OperationOutcome key must be text"));
            };
            match key.as_str() {
                OUTCOME_KEY_DISCRIMINANT => match value {
                    CborValue::String(text) => discriminant = Some(text.as_str()),
                    _ => {
                        return Err(Error::BadEncoding(
                            "OperationOutcome discriminant must be text",
                        ))
                    }
                },
                OUTCOME_KEY_PAYLOAD => match value {
                    CborValue::Bytes(bytes) if bytes.len() <= OUTCOME_MAX_PAYLOAD => {
                        payload = Some(bytes.clone());
                    }
                    CborValue::Bytes(_) => {
                        return Err(Error::BadEncoding(
                            "OperationOutcome payload exceeds 256 bytes",
                        ))
                    }
                    _ => return Err(Error::BadEncoding("OperationOutcome payload must be bytes")),
                },
                _ => return Err(Error::BadEncoding("unknown key in OperationOutcome")),
            }
        }
        match (discriminant, payload) {
            (Some(OUTCOME_SUCCESS), None) => Ok(Self::Success),
            (Some(OUTCOME_SUCCESS), Some(payload)) => Ok(Self::SuccessWithPayload(payload)),
            (Some(OUTCOME_APPLICATION_FAILURE), payload) => Ok(Self::ApplicationFailure(payload)),
            (Some(_), _) => Err(Error::BadEncoding("unknown OperationOutcome discriminant")),
            (None, _) => Err(Error::BadEncoding("OperationOutcome missing discriminant")),
        }
    }
}
