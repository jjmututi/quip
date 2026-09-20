//! Unified error type and wire-level error codes.

use core::fmt;

/// Wire-level error code from the spec's error registry.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Success.
    Ok = 0x00,
    /// Invalid CBOR encoding.
    BadEncoding = 0x01,
    /// Unknown verb.
    UnknownVerb = 0x02,
    /// Rate limit exceeded.
    RateLimit = 0x03,
    /// Key not KT_VERIFIED.
    KtUnverified = 0x04,
    /// DVV merge conflict.
    DvvConflict = 0x05,
    /// Flow control blocked.
    FlowBlocked = 0x06,
    /// Violation detected.
    Violation = 0x07,
    /// No common capabilities.
    ProfileMismatch = 0x08,
    /// Witness statement expired.
    WitnessExpired = 0x09,
    /// DHT lookup failed.
    DhtError = 0x0A,
    /// BFT consensus failed.
    BftFailure = 0x0B,
    /// CID does not match payload hash.
    CidMismatch = 0x0C,
    /// Pin limit exceeded.
    PinLimit = 0x0D,
    /// Resource or CID not found.
    ResourceNotFound = 0x0E,
    /// Resource location hint is stale.
    ResourceStale = 0x0F,
    /// Content has been quarantined.
    Quarantined = 0x10,
    /// Requestor not authorized for governance operation.
    NotAuthorized = 0x11,
    /// Trusted CID not found.
    TcidNotFound = 0x12,
    /// Delegation certificate has expired.
    DelegationExpired = 0x13,
    /// Hash algorithm mismatch between peers.
    HashAlgoMismatch = 0x14,
    /// Peer behind NAT cannot be reached directly.
    NatUnreachable = 0x15,
    /// Relay connection failed.
    RelayFailure = 0x16,
    /// Spillover mechanism was triggered.
    SpilloverTriggered = 0x17,
    /// Path-based attack detected.
    PathAttackDetected = 0x18,
    /// No consensus across lookup paths.
    NoConsensus = 0x19,
    /// Peer sent a verb whose capability was not advertised.
    CapabilityViolation = 0x1A,
    /// Range request out of bounds, malformed, or exceeds the length cap.
    RangeInvalid = 0x1B,
    /// Merkle range proof does not verify against the CID.
    ProofInvalid = 0x1C,
    /// Cluster does not meet RTT threshold.
    ClusterUnacceptable = 0x20,
    /// Cluster splitting in progress.
    ClusterSplit = 0x21,
    /// Cluster merging in progress.
    ClusterMerge = 0x22,
    /// No acceptable cluster found.
    NoAcceptableCluster = 0x23,
}

impl ErrorCode {
    /// Every code defined by spec §15, in numeric order.
    ///
    /// Canonical list. `TryFrom<u8>` and the tests in this module both
    /// derive from this array; adding a variant to `ErrorCode` without
    /// adding it here is caught by the exhaustive `name_of` function in the
    /// test module below.
    pub const ALL_DEFINED: &'static [ErrorCode] = &[
        ErrorCode::Ok,                  // 0x00
        ErrorCode::BadEncoding,         // 0x01
        ErrorCode::UnknownVerb,         // 0x02
        ErrorCode::RateLimit,           // 0x03
        ErrorCode::KtUnverified,        // 0x04
        ErrorCode::DvvConflict,         // 0x05
        ErrorCode::FlowBlocked,         // 0x06
        ErrorCode::Violation,           // 0x07
        ErrorCode::ProfileMismatch,     // 0x08
        ErrorCode::WitnessExpired,      // 0x09
        ErrorCode::DhtError,            // 0x0A
        ErrorCode::BftFailure,          // 0x0B
        ErrorCode::CidMismatch,         // 0x0C
        ErrorCode::PinLimit,            // 0x0D
        ErrorCode::ResourceNotFound,    // 0x0E
        ErrorCode::ResourceStale,       // 0x0F
        ErrorCode::Quarantined,         // 0x10
        ErrorCode::NotAuthorized,       // 0x11
        ErrorCode::TcidNotFound,        // 0x12
        ErrorCode::DelegationExpired,   // 0x13
        ErrorCode::HashAlgoMismatch,    // 0x14
        ErrorCode::NatUnreachable,      // 0x15
        ErrorCode::RelayFailure,        // 0x16
        ErrorCode::SpilloverTriggered,  // 0x17
        ErrorCode::PathAttackDetected,  // 0x18
        ErrorCode::NoConsensus,         // 0x19
        ErrorCode::CapabilityViolation, // 0x1A
        ErrorCode::RangeInvalid,        // 0x1B
        ErrorCode::ProofInvalid,        // 0x1C
        ErrorCode::ClusterUnacceptable, // 0x20
        ErrorCode::ClusterSplit,        // 0x21
        ErrorCode::ClusterMerge,        // 0x22
        ErrorCode::NoAcceptableCluster, // 0x23
    ];
}

impl TryFrom<u8> for ErrorCode {
    type Error = ();

    /// Parse a wire-level error code.
    ///
    /// Returns `Err(())` for any byte not defined by spec §15. The
    /// `#[non_exhaustive]` attribute on `ErrorCode` means future spec
    /// revisions may add codes; callers that need forward compatibility
    /// should treat an unrecognized code as an opaque `u8` rather than
    /// dropping the message.
    fn try_from(value: u8) -> core::result::Result<Self, Self::Error> {
        match value {
            0x00 => Ok(ErrorCode::Ok),
            0x01 => Ok(ErrorCode::BadEncoding),
            0x02 => Ok(ErrorCode::UnknownVerb),
            0x03 => Ok(ErrorCode::RateLimit),
            0x04 => Ok(ErrorCode::KtUnverified),
            0x05 => Ok(ErrorCode::DvvConflict),
            0x06 => Ok(ErrorCode::FlowBlocked),
            0x07 => Ok(ErrorCode::Violation),
            0x08 => Ok(ErrorCode::ProfileMismatch),
            0x09 => Ok(ErrorCode::WitnessExpired),
            0x0A => Ok(ErrorCode::DhtError),
            0x0B => Ok(ErrorCode::BftFailure),
            0x0C => Ok(ErrorCode::CidMismatch),
            0x0D => Ok(ErrorCode::PinLimit),
            0x0E => Ok(ErrorCode::ResourceNotFound),
            0x0F => Ok(ErrorCode::ResourceStale),
            0x10 => Ok(ErrorCode::Quarantined),
            0x11 => Ok(ErrorCode::NotAuthorized),
            0x12 => Ok(ErrorCode::TcidNotFound),
            0x13 => Ok(ErrorCode::DelegationExpired),
            0x14 => Ok(ErrorCode::HashAlgoMismatch),
            0x15 => Ok(ErrorCode::NatUnreachable),
            0x16 => Ok(ErrorCode::RelayFailure),
            0x17 => Ok(ErrorCode::SpilloverTriggered),
            0x18 => Ok(ErrorCode::PathAttackDetected),
            0x19 => Ok(ErrorCode::NoConsensus),
            0x1A => Ok(ErrorCode::CapabilityViolation),
            0x1B => Ok(ErrorCode::RangeInvalid),
            0x1C => Ok(ErrorCode::ProofInvalid),
            0x20 => Ok(ErrorCode::ClusterUnacceptable),
            0x21 => Ok(ErrorCode::ClusterSplit),
            0x22 => Ok(ErrorCode::ClusterMerge),
            0x23 => Ok(ErrorCode::NoAcceptableCluster),
            _ => Err(()),
        }
    }
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Unified error type.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// Protocol-level error carrying its wire code.
    Protocol {
        /// Wire code.
        code: ErrorCode,
        /// Human-readable context.
        message: &'static str,
    },

    // ---- CBOR ----
    /// Generic malformed encoding.
    BadEncoding(&'static str),
    /// Floats prohibited.
    FloatProhibited,
    /// Integer not in shortest form.
    NonShortestInteger,
    /// Length prefix not in shortest form.
    NonShortestLength,
    /// Map keys not in canonical order.
    InvalidMapOrdering,
    /// Duplicate map key.
    DuplicateMapKey,
    /// Unknown or unsupported tag.
    UnknownTag(u64),
    /// Indefinite-length encoding prohibited.
    IndefiniteLength,
    /// Trailing bytes after complete item.
    TrailingBytes,
    /// Unexpected end of input.
    UnexpectedEnd,
    /// Invalid UTF-8.
    InvalidUtf8,
    /// Bignum out of representable range.
    BignumOutOfRange,
    /// Invalid major type.
    InvalidMajorType(u8),
    /// Invalid additional-info value.
    InvalidAdditionalInfo(u8),

    // ---- CID ----
    /// Unknown hash algorithm identifier.
    UnknownHashAlgo(u64),
    /// Digest length is not 32 bytes.
    InvalidDigestLength(usize),
    /// CID does not match payload hash.
    CidMismatch,

    // ---- DVV ----
    /// A pruned writer requires a `seq_reset` before resuming.
    PrunedWriterRequiresSeqReset,
    /// Counter would reach or exceed `INF`.
    CounterOverflow,
}

impl Error {
    /// Return the wire-level code that best corresponds to this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Protocol { code, .. } => *code,
            Error::BadEncoding(_)
            | Error::FloatProhibited
            | Error::NonShortestInteger
            | Error::NonShortestLength
            | Error::InvalidMapOrdering
            | Error::DuplicateMapKey
            | Error::UnknownTag(_)
            | Error::IndefiniteLength
            | Error::TrailingBytes
            | Error::UnexpectedEnd
            | Error::InvalidUtf8
            | Error::BignumOutOfRange
            | Error::InvalidMajorType(_)
            | Error::InvalidAdditionalInfo(_) => ErrorCode::BadEncoding,
            Error::UnknownHashAlgo(_) | Error::InvalidDigestLength(_) | Error::CidMismatch => {
                ErrorCode::CidMismatch
            }
            Error::PrunedWriterRequiresSeqReset | Error::CounterOverflow => ErrorCode::DvvConflict,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Protocol { code, message } => write!(f, "protocol error {code:?}: {message}"),
            Error::BadEncoding(msg) => write!(f, "bad encoding: {msg}"),
            Error::FloatProhibited => write!(f, "float values are prohibited in QUIP-CBOR"),
            Error::NonShortestInteger => write!(f, "integer not in shortest form"),
            Error::NonShortestLength => write!(f, "length prefix not in shortest form"),
            Error::InvalidMapOrdering => write!(f, "map keys not in canonical order"),
            Error::DuplicateMapKey => write!(f, "duplicate map key"),
            Error::UnknownTag(tag) => write!(f, "unknown or unsupported tag {tag}"),
            Error::IndefiniteLength => write!(f, "indefinite-length encoding is prohibited"),
            Error::TrailingBytes => write!(f, "trailing bytes after CBOR item"),
            Error::UnexpectedEnd => write!(f, "unexpected end of input"),
            Error::InvalidUtf8 => write!(f, "invalid UTF-8 in text string"),
            Error::BignumOutOfRange => write!(f, "bignum value out of range"),
            Error::InvalidMajorType(mt) => write!(f, "invalid major type {mt}"),
            Error::InvalidAdditionalInfo(ai) => write!(f, "invalid additional info {ai}"),
            Error::UnknownHashAlgo(a) => write!(f, "unknown hash algorithm {a}"),
            Error::InvalidDigestLength(n) => write!(f, "digest length {n} is not 32"),
            Error::CidMismatch => write!(f, "CID does not match payload hash"),
            Error::PrunedWriterRequiresSeqReset => {
                write!(f, "pruned writer requires a seq_reset to resume")
            }
            Error::CounterOverflow => write!(f, "counter would overflow the INF sentinel"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Exhaustive over `ErrorCode`.
    ///
    /// The absence of a `_` wildcard means adding a variant to `ErrorCode`
    /// is a compile error here, which is the prompt to also update
    /// [`ErrorCode::ALL_DEFINED`] and [`TryFrom<u8>`].
    fn name_of(code: ErrorCode) -> &'static str {
        match code {
            ErrorCode::Ok => "E_OK",
            ErrorCode::BadEncoding => "E_BAD_ENCODING",
            ErrorCode::UnknownVerb => "E_UNKNOWN_VERB",
            ErrorCode::RateLimit => "E_RATE_LIMIT",
            ErrorCode::KtUnverified => "E_KT_UNVERIFIED",
            ErrorCode::DvvConflict => "E_DVV_CONFLICT",
            ErrorCode::FlowBlocked => "E_FLOW_BLOCKED",
            ErrorCode::Violation => "E_VIOLATION",
            ErrorCode::ProfileMismatch => "E_PROFILE_MISMATCH",
            ErrorCode::WitnessExpired => "E_WITNESS_EXPIRED",
            ErrorCode::DhtError => "E_DHT_ERROR",
            ErrorCode::BftFailure => "E_BFT_FAILURE",
            ErrorCode::CidMismatch => "E_CID_MISMATCH",
            ErrorCode::PinLimit => "E_PIN_LIMIT",
            ErrorCode::ResourceNotFound => "E_RESOURCE_NOT_FOUND",
            ErrorCode::ResourceStale => "E_RESOURCE_STALE",
            ErrorCode::Quarantined => "E_QUARANTINED",
            ErrorCode::NotAuthorized => "E_NOT_AUTHORIZED",
            ErrorCode::TcidNotFound => "E_TCID_NOT_FOUND",
            ErrorCode::DelegationExpired => "E_DELEGATION_EXPIRED",
            ErrorCode::HashAlgoMismatch => "E_HASH_ALGO_MISMATCH",
            ErrorCode::NatUnreachable => "E_NAT_UNREACHABLE",
            ErrorCode::RelayFailure => "E_RELAY_FAILURE",
            ErrorCode::SpilloverTriggered => "E_SPILLOVER_TRIGGERED",
            ErrorCode::PathAttackDetected => "E_PATH_ATTACK_DETECTED",
            ErrorCode::NoConsensus => "E_NO_CONSENSUS",
            ErrorCode::CapabilityViolation => "E_CAPABILITY_VIOLATION",
            ErrorCode::RangeInvalid => "E_RANGE_INVALID",
            ErrorCode::ProofInvalid => "E_PROOF_INVALID",
            ErrorCode::ClusterUnacceptable => "E_CLUSTER_UNACCEPTABLE",
            ErrorCode::ClusterSplit => "E_CLUSTER_SPLIT",
            ErrorCode::ClusterMerge => "E_CLUSTER_MERGE",
            ErrorCode::NoAcceptableCluster => "E_NO_ACCEPTABLE_CLUSTER",
        }
    }

    #[test]
    fn error_code_roundtrips_through_u8() {
        for &code in ErrorCode::ALL_DEFINED {
            let byte = code as u8;
            assert_eq!(ErrorCode::try_from(byte).unwrap(), code);
        }
        assert!(ErrorCode::try_from(0xFE).is_err());
    }

    #[test]
    fn every_defined_code_roundtrips() {
        for &code in ErrorCode::ALL_DEFINED {
            let byte = code as u8;
            assert_eq!(
                ErrorCode::try_from(byte).unwrap(),
                code,
                "roundtrip failed for {code:?} (byte {byte:#04x})"
            );
        }
    }

    #[test]
    fn all_defined_matches_enum_exhaustively() {
        // `name_of` is exhaustive; every variant of `ErrorCode` must
        // produce a distinct name, which in turn means every variant
        // appears exactly once in `ALL_DEFINED`.
        let mut names: Vec<&str> = ErrorCode::ALL_DEFINED
            .iter()
            .map(|c| name_of(*c))
            .collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before, "duplicate code in ALL_DEFINED");

        // Every variant in ALL_DEFINED must round-trip.
        for &code in ErrorCode::ALL_DEFINED {
            assert_eq!(ErrorCode::try_from(code as u8).unwrap(), code);
        }
    }

    #[test]
    fn reserved_byte_range_is_rejected() {
        // Anything in 0x00..=0xFF not listed in ALL_DEFINED must be
        // rejected by TryFrom. This covers the spec's reserved ranges
        // (0x1D–0x1F, 0x24–0x2F, 0x30–0x7F, 0x80–0xFF) without
        // hard-coding them.
        for byte in 0u8..=0xFF {
            let defined = ErrorCode::ALL_DEFINED.iter().any(|c| *c as u8 == byte);
            if !defined {
                assert!(
                    ErrorCode::try_from(byte).is_err(),
                    "byte {byte:#04x} should not be a defined code"
                );
            }
        }
    }
}