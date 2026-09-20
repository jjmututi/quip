//! Unified error type for storage operations.

use alloc::string::String;
use core::fmt;
use quip_core::{Error as CoreError, ErrorCode};

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Storage-layer error.
///
/// [`Error::Core`] carries encoding/digest failures raised by `quip-core` so
/// that callers have a single error path.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// An error produced while encoding or decoding QUIP-CBOR, or by the
    /// CID/DVV primitives in `quip-core`.
    Core(CoreError),

    /// The payload does not hash to the requested CID.
    ///
    /// Raised on write (content stored under the wrong digest) and on read
    /// (stored bytes no longer match their digest).
    CidMismatch,

    /// No stored entry matches the request.
    NotFound,

    /// The table is full and the operation does not evict.
    CapacityExceeded {
        /// Table name: `"blob"`, `"pin"`, `"quarantine"`, `"governance"`, or `"resource"`.
        table: &'static str,
        /// Configured limit.
        limit: u64,
    },

    /// The CID is under quarantine and must not be served or discovered.
    Quarantined,

    /// A location hint is older than the configured maximum age.
    Stale {
        /// Age of the record, in seconds.
        age_seconds: u64,
        /// Configured maximum age, in seconds.
        max_age_seconds: u64,
    },

    /// The NodeId is neither the owner nor a valid delegate for the permission.
    NotAuthorized,

    /// A snapshot was written by an incompatible version of this crate.
    VersionMismatch {
        /// Version found in the snapshot.
        found: u64,
        /// Version this crate reads and writes.
        expected: u64,
    },

    /// Backend I/O failure (only produced by backends that touch the filesystem).
    Io(String),
}

impl Error {
    /// Best-effort mapping to the wire error registry of spec §15.
    ///
    /// The registry has no storage-specific code, so a few variants map to the
    /// closest general-purpose code:
    ///
    /// | Variant | Code |
    /// |---|---|
    /// | [`Error::Core`] | the wrapped `quip-core` code |
    /// | [`Error::CidMismatch`] | `E_CID_MISMATCH` (0x0C) |
    /// | [`Error::NotFound`] | `E_RESOURCE_NOT_FOUND` (0x0E) |
    /// | [`Error::CapacityExceeded`] | `E_PIN_LIMIT` (0x0D) for `"pin"`, else `E_RATE_LIMIT` (0x03) |
    /// | [`Error::Quarantined`] | `E_QUARANTINED` (0x10) |
    /// | [`Error::Stale`] | `E_RESOURCE_STALE` (0x0F) |
    /// | [`Error::NotAuthorized`] | `E_NOT_AUTHORIZED` (0x11) |
    /// | [`Error::VersionMismatch`] | `E_BAD_ENCODING` (0x01) |
    /// | [`Error::Io`] | `E_VIOLATION` (0x07), the nearest generic failure |
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Core(e) => e.code(),
            Error::CidMismatch => ErrorCode::CidMismatch,
            Error::NotFound => ErrorCode::ResourceNotFound,
            Error::CapacityExceeded { table, .. } => {
                if *table == "pin" {
                    ErrorCode::PinLimit
                } else {
                    ErrorCode::RateLimit
                }
            }
            Error::Quarantined => ErrorCode::Quarantined,
            Error::Stale { .. } => ErrorCode::ResourceStale,
            Error::NotAuthorized => ErrorCode::NotAuthorized,
            Error::VersionMismatch { .. } => ErrorCode::BadEncoding,
            Error::Io(_) => ErrorCode::Violation,
        }
    }
}

impl From<CoreError> for Error {
    fn from(e: CoreError) -> Self {
        Error::Core(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Core(e) => write!(f, "core error: {e}"),
            Error::CidMismatch => write!(f, "payload does not match its CID"),
            Error::NotFound => write!(f, "no stored entry matches the request"),
            Error::CapacityExceeded { table, limit } => {
                write!(f, "{table} capacity of {limit} exceeded")
            }
            Error::Quarantined => write!(f, "content is quarantined"),
            Error::Stale {
                age_seconds,
                max_age_seconds,
            } => write!(
                f,
                "record is {age_seconds}s old, exceeding the {max_age_seconds}s limit"
            ),
            Error::NotAuthorized => write!(f, "node is not authorized for this operation"),
            Error::VersionMismatch { found, expected } => {
                write!(f, "snapshot version {found} is not {expected}")
            }
            Error::Io(msg) => write!(f, "io error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn pin_capacity_maps_to_pin_limit() {
        let e = Error::CapacityExceeded {
            table: "pin",
            limit: 1_000,
        };
        assert_eq!(e.code(), ErrorCode::PinLimit);
    }

    #[test]
    fn core_errors_keep_their_code() {
        let e = Error::from(CoreError::CidMismatch);
        assert_eq!(e.code(), ErrorCode::CidMismatch);
        assert_eq!(e.to_string(), "core error: CID does not match payload hash");
    }

    #[test]
    fn quarantine_maps_to_quarantined() {
        assert_eq!(Error::Quarantined.code(), ErrorCode::Quarantined);
    }
}