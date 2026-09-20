//! Transport error type with §15 wire-code mapping.

use alloc::string::String;
use core::fmt;
use quip_core::ErrorCode;

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Transport-layer error.
///
/// Protocol failures that cross the wire map to the §15 registry via
/// [`Error::code`]; local framing/codec failures surface as structured
/// variants so callers can distinguish "peer misbehaved" from "my bug".
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// A `quip-core` codec / CID / DVV failure while (de)serialising.
    Core(quip_core::Error),
    /// A `quip-storage` failure (pin table, quarantine, CID verification …).
    Storage(quip_storage::Error),
    /// Handshake failure: version mismatch, no common capabilities, …
    Handshake(&'static str),
    /// Frame header is malformed or exceeds [`crate::constants::MAX_MESSAGE_SIZE`].
    BadFrame(&'static str),
    /// Stream ID violates the tier allocation (§11).
    BadStream(&'static str),
    /// Peer violated the per-tier backpressure caps (§12).
    FlowBlocked {
        /// Tier whose cap was exceeded.
        tier: u8,
        /// Configured limit.
        limit: usize,
    },
    /// Peer sent a verb on the wrong tier (§14).
    WrongTier {
        /// Verb string, e.g. `"set"`.
        verb: &'static str,
        /// Tier it arrived on.
        tier: u8,
    },
    /// Peer sent (or attempted to send) a verb whose required capability
    /// was not in the negotiated set (spec §4).
    CapabilityViolation {
        /// The offending verb.
        verb: &'static str,
        /// The capability bit required by that verb.
        required: u64,
    },
    /// Peer exceeded its per-NodeId rate limit (§19.4).
    RateLimit,
    /// A Merkle range request is out of bounds, malformed, or exceeds
    /// a cap (§8.2).
    RangeInvalid(&'static str),
    /// A Merkle range proof did not verify against the expected CID
    /// (§8.2).
    ProofInvalid(&'static str),
    /// Unknown verb string.
    UnknownVerb(String),
    /// Remote signalled a protocol error (`["error", code, id, text]`).
    Remote {
        /// Wire code from the peer.
        code: ErrorCode,
        /// Request correlation ID from the peer.
        message_id: u64,
        /// Human-readable text from the peer.
        text: String,
    },
    /// BULK transfer failure (missing `send_start`, gap, CID mismatch, …).
    Transfer(&'static str),
    /// NAT traversal failure (hole-punch timeout, relay unreachable, …).
    NatUnreachable,
    /// DHT lookup failure (no acceptable cluster, no consensus, …).
    Dht(&'static str),
    /// BFT consensus failure (digest mismatch, missing quorum, view error).
    Bft(&'static str),
    /// Payload exceeds the tier MTU.
    TooLarge {
        /// Observed size in bytes.
        size: usize,
        /// Tier limit in bytes.
        max: usize,
    },
    /// Transport-layer failure carrying a runtime-formatted reason.
    ///
    /// Used where a third-party error must be wrapped (rustls, quinn,
    /// rcgen, bao). The static-str [`Error::Handshake`] variant covers
    /// messages that are known at compile time.
    Transport(String),
}

impl Error {
    /// Best-effort mapping to the §15 wire registry.
    pub fn code(&self) -> ErrorCode {
        match self {
            Error::Core(e) => e.code(),
            Error::Storage(e) => e.code(),
            Error::Handshake(_) => ErrorCode::ProfileMismatch,
            Error::BadFrame(_) => ErrorCode::BadEncoding,
            Error::BadStream(_) => ErrorCode::BadEncoding,
            Error::FlowBlocked { .. } => ErrorCode::FlowBlocked,
            Error::WrongTier { .. } => ErrorCode::BadEncoding,
            Error::CapabilityViolation { .. } => ErrorCode::CapabilityViolation,
            Error::RateLimit => ErrorCode::RateLimit,
            Error::RangeInvalid(_) => ErrorCode::RangeInvalid,
            Error::ProofInvalid(_) => ErrorCode::ProofInvalid,
            Error::UnknownVerb(_) => ErrorCode::UnknownVerb,
            Error::Remote { code, .. } => *code,
            Error::Transfer(_) => ErrorCode::Violation,
            Error::NatUnreachable => ErrorCode::NatUnreachable,
            Error::Dht(_) => ErrorCode::DhtError,
            Error::Bft(_) => ErrorCode::BftFailure,
            Error::TooLarge { .. } => ErrorCode::BadEncoding,
            Error::Transport(_) => ErrorCode::Violation,
        }
    }
}

impl From<quip_core::Error> for Error {
    fn from(e: quip_core::Error) -> Self {
        Error::Core(e)
    }
}

impl From<quip_storage::Error> for Error {
    fn from(e: quip_storage::Error) -> Self {
        Error::Storage(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Core(e) => write!(f, "core error: {e}"),
            Error::Storage(e) => write!(f, "storage error: {e}"),
            Error::Handshake(m) => write!(f, "handshake failed: {m}"),
            Error::BadFrame(m) => write!(f, "bad frame: {m}"),
            Error::BadStream(m) => write!(f, "bad stream: {m}"),
            Error::FlowBlocked { tier, limit } => {
                write!(f, "tier {tier} exceeded its cap of {limit} streams")
            }
            Error::WrongTier { verb, tier } => {
                write!(f, "verb `{verb}` is not allowed on tier {tier}")
            }
            Error::CapabilityViolation { verb, required } => write!(
                f,
                "verb `{verb}` requires capability bit 0x{required:x}, \
                 not in negotiated set"
            ),
            Error::RateLimit => write!(f, "rate limit exceeded"),
            Error::RangeInvalid(m) => write!(f, "range request invalid: {m}"),
            Error::ProofInvalid(m) => write!(f, "range proof invalid: {m}"),
            Error::UnknownVerb(v) => write!(f, "unknown verb `{v}`"),
            Error::Remote {
                code,
                message_id,
                text,
            } => write!(f, "remote error {code:?} (id {message_id}): {text}"),
            Error::Transfer(m) => write!(f, "transfer failed: {m}"),
            Error::NatUnreachable => write!(f, "peer behind NAT is unreachable"),
            Error::Dht(m) => write!(f, "dht lookup failed: {m}"),
            Error::Bft(m) => write!(f, "bft failure: {m}"),
            Error::TooLarge { size, max } => {
                write!(f, "payload of {size} bytes exceeds tier limit of {max} bytes")
            }
            Error::Transport(msg) => write!(f, "transport error: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mappings_match_section_15() {
        assert_eq!(
            Error::Bft("digest mismatch").code(),
            ErrorCode::BftFailure
        );
        assert_eq!(Error::NatUnreachable.code(), ErrorCode::NatUnreachable);
        assert_eq!(Error::Dht("x").code(), ErrorCode::DhtError);
        assert_eq!(
            Error::FlowBlocked { tier: 1, limit: 2 }.code(),
            ErrorCode::FlowBlocked
        );
        assert_eq!(
            Error::UnknownVerb("nope".into()).code(),
            ErrorCode::UnknownVerb
        );
        assert_eq!(
            Error::Core(quip_core::Error::CidMismatch).code(),
            ErrorCode::CidMismatch
        );
        assert_eq!(
            Error::Storage(quip_storage::Error::Quarantined).code(),
            ErrorCode::Quarantined
        );
        assert_eq!(
            Error::Transport("quinn: x".into()).code(),
            ErrorCode::Violation
        );
        assert_eq!(
            Error::CapabilityViolation {
                verb: "register_tcid",
                required: 0x40,
            }
            .code(),
            ErrorCode::CapabilityViolation
        );
        assert_eq!(Error::RateLimit.code(), ErrorCode::RateLimit);
        assert_eq!(
            Error::TooLarge { size: 100, max: 10 }.code(),
            ErrorCode::BadEncoding
        );
        assert_eq!(
            Error::RangeInvalid("out of bounds").code(),
            ErrorCode::RangeInvalid
        );
        assert_eq!(
            Error::ProofInvalid("bad proof").code(),
            ErrorCode::ProofInvalid
        );
    }
}