//! Handshake and profile negotiation (spec §4).

use crate::error::{Error, Result};
use alloc::vec::Vec;
use quip_core::cbor::{decode, encode, CborValue};

/// Handshake extension keys (spec §4).
///
/// Only these keys are defined for v1. Unknown keys are not rejected at the
/// framing level (a future revision may add keys), but
/// [`ExtensionId::from_u64`] returns an error so callers can decide whether
/// to ignore or refuse them.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum ExtensionId {
    /// 0x01 — `max_message_size` (uint, default 65536).
    MaxMessageSize = 0x01,
    /// 0x02 — `ephemeral_key` (bytes, X25519 public key, 32 bytes).
    EphemeralKey = 0x02,
    /// 0x03 — `dht_announce` (bytes, signed DHT announcement).
    DhtAnnounce = 0x03,
    /// 0x04 — `max_ranges` (uint, default 1024, for RBSR).
    MaxRanges = 0x04,
    /// 0x05 — `pin_capacity` (uint, default 1000, max pins).
    PinCapacity = 0x05,
    /// 0x06 — `gov_capacity` (uint, default 100, max Trusted CIDs).
    GovCapacity = 0x06,
    /// 0x07 — `hash_algo` (uint, 0 = SHA-256, 1 = BLAKE3, default 0).
    HashAlgo = 0x07,
    /// 0x08 — `rbsr_algo` (uint bitmask: bit 0 = XOR, bit 1 = IBLT,
    /// bit 2 = Merkle; default 0x01).
    RbsrAlgo = 0x08,
    /// 0x09 — `nat_traversal` (map, NAT traversal parameters).
    NatTraversal = 0x09,
    /// 0x0A — `cidv1_algo` (uint, 0 = SHA-256, 1 = BLAKE3, default 0).
    Cidv1Algo = 0x0A,
    /// 0x0B — `checkpoint_interval` (uint, default 100).
    CheckpointInterval = 0x0B,
    /// 0x0C — `max_range_length` (uint, default 1048576, for Merkle
    /// range fetching).
    MaxRangeLength = 0x0C,
}

impl ExtensionId {
    /// Parse a wire extension key.
    pub fn from_u64(v: u64) -> Result<Self> {
        match v {
            0x01 => Ok(Self::MaxMessageSize),
            0x02 => Ok(Self::EphemeralKey),
            0x03 => Ok(Self::DhtAnnounce),
            0x04 => Ok(Self::MaxRanges),
            0x05 => Ok(Self::PinCapacity),
            0x06 => Ok(Self::GovCapacity),
            0x07 => Ok(Self::HashAlgo),
            0x08 => Ok(Self::RbsrAlgo),
            0x09 => Ok(Self::NatTraversal),
            0x0A => Ok(Self::Cidv1Algo),
            0x0B => Ok(Self::CheckpointInterval),
            0x0C => Ok(Self::MaxRangeLength),
            _ => Err(Error::Handshake("unknown handshake extension")),
        }
    }
}

/// Capability bits (spec §4).
///
/// Bit values match the spec exactly: capability *n* occupies bit *n*
/// (so `t3_datagram = 1` means bit 1 = `0x02`). Bit 0 is not defined for
/// v1: `witness_bft` is always enabled and is not negotiated.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Capabilities(pub u64);

impl Capabilities {
    /// T3 unreliable datagram transport (bit 1, value 0x02).
    pub const T3_DATAGRAM: u64 = 1 << 1;
    /// Coral DHT discovery (bit 2, value 0x04).
    pub const DHT_DISCOVERY: u64 = 1 << 2;
    /// RBSR-based sync (bit 3, value 0x08).
    pub const RBSR_SYNC: u64 = 1 << 3;
    /// CID content addressing (bit 4, value 0x10).
    pub const CID_ADDRESSING: u64 = 1 << 4;
    /// Resource pinning (bit 5, value 0x20).
    pub const RESOURCE_PIN: u64 = 1 << 5;
    /// Content governance primitives (bit 6, value 0x40, OPTIONAL).
    pub const GOVERNANCE: u64 = 1 << 6;
    /// BLAKE3 hash algorithm (bit 7, value 0x80, OPTIONAL).
    pub const BLAKE3: u64 = 1 << 7;
    /// NAT traversal (bit 8, value 0x100, OPTIONAL).
    pub const NAT_TRAVERSAL: u64 = 1 << 8;
    /// CIDv1 tagged identifiers (bit 9, value 0x200, OPTIONAL).
    pub const CIDV1: u64 = 1 << 9;
    /// BFT consensus with checkpointing (bit 10, value 0x400, OPTIONAL).
    pub const BFT_CHECKPOINT: u64 = 1 << 10;
    /// BLAKE3 Merkle range fetching (bit 11, value 0x800, OPTIONAL).
    pub const MERKLE_RANGE: u64 = 1 << 11;

    /// Bits 1–5: the baseline every v1 peer implements.
    ///
    /// The spec does not require the intersection to contain these bits — it
    /// only requires it to be non-empty — but callers may use this mask to
    /// enforce a stricter local policy.
    pub const BASELINE: u64 = Self::T3_DATAGRAM
        | Self::DHT_DISCOVERY
        | Self::RBSR_SYNC
        | Self::CID_ADDRESSING
        | Self::RESOURCE_PIN;

    /// All bits currently defined by v1 (1–11).
    pub const DEFINED_MASK: u64 = Self::BASELINE
        | Self::GOVERNANCE
        | Self::BLAKE3
        | Self::NAT_TRAVERSAL
        | Self::CIDV1
        | Self::BFT_CHECKPOINT
        | Self::MERKLE_RANGE;

    /// Empty set.
    pub fn empty() -> Self {
        Self(0)
    }

    /// Baseline v1 set (bits 1–5).
    pub fn baseline() -> Self {
        Self(Self::BASELINE)
    }

    /// Intersection of two advertisements.
    pub fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// True when the set is empty.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// True when every baseline bit is set.
    pub fn has_baseline(self) -> bool {
        self.0 & Self::BASELINE == Self::BASELINE
    }

    /// True when `flag` is set (pass one of the `Capabilities::*` constants).
    pub fn has(self, flag: u64) -> bool {
        self.0 & flag != 0
    }

    /// Validate the capability dependency closure (spec §4).
    ///
    /// A peer MUST NOT advertise a capability whose dependencies are not
    /// also advertised. This is a local check: callers invoke it before
    /// sending a handshake, and [`Handshake::from_bytes`] invokes it on
    /// receipt.
    ///
    /// Returns [`Error::Handshake`] (mapped to `E_PROFILE_MISMATCH` by
    /// `quip-net::Error::code`) when a dependency is missing.
    pub fn validate_closure(self) -> Result<()> {
        let bits = self.0;

        // Each tuple is (dependent, required). A dependent bit set requires
        // every bit in the corresponding required mask to be set.
        const RULES: &[(u64, u64)] = &[
            (Capabilities::BLAKE3, Capabilities::CID_ADDRESSING),
            (Capabilities::CIDV1, Capabilities::CID_ADDRESSING),
            (
                Capabilities::MERKLE_RANGE,
                Capabilities::BLAKE3 | Capabilities::CID_ADDRESSING,
            ),
            (
                Capabilities::GOVERNANCE,
                Capabilities::CID_ADDRESSING | Capabilities::DHT_DISCOVERY,
            ),
            (Capabilities::NAT_TRAVERSAL, Capabilities::DHT_DISCOVERY),
            (Capabilities::BFT_CHECKPOINT, Capabilities::DHT_DISCOVERY),
        ];

        for &(dependent, required) in RULES {
            if bits & dependent != 0 && bits & required != required {
                return Err(Error::Handshake(
                    "capability dependency closure violated",
                ));
            }
        }
        Ok(())
    }
}

impl core::ops::BitOr for Capabilities {
    type Output = Self;
    /// Union of two capability sets.
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Capabilities {
    /// In-place union.
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl core::ops::BitAnd for Capabilities {
    type Output = Self;
    /// Intersection of two capability sets.
    ///
    /// Equivalent to [`Capabilities::intersect`]; provided so that `a & b`
    /// and `a.intersect(b)` are interchangeable.
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl core::ops::BitAndAssign for Capabilities {
    /// In-place intersection.
    fn bitand_assign(&mut self, rhs: Self) {
        self.0 &= rhs.0;
    }
}

/// The section 4 handshake message:
///
/// ```text
/// Handshake = [
///   version: uint,
///   capabilities: uint .bits Capabilities,
///   extensions: { * uint => any }
/// ]
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Handshake {
    /// Protocol version (must equal `PROTOCOL_VERSION` = 1).
    pub version: u8,
    /// Advertised capability bits.
    pub capabilities: Capabilities,
    /// Extension map (uint key → CBOR value). Canonical encoding sorts keys
    /// on the wire regardless of insertion order.
    pub extensions: Vec<(u64, CborValue)>,
}

impl Handshake {
    /// Build a handshake offering `capabilities`.
    ///
    /// This constructor does not validate the capability closure. Use
    /// [`Self::new_checked`] if you want config-time rejection; otherwise
    /// validation happens on [`Self::to_bytes`] and on
    /// [`Self::from_bytes`].
    pub fn new(capabilities: Capabilities) -> Self {
        Self {
            version: crate::constants::PROTOCOL_VERSION,
            capabilities,
            extensions: Vec::new(),
        }
    }

    /// Build a handshake, rejecting a locally-configured capability set
    /// that violates the dependency closure (spec §4).
    pub fn new_checked(capabilities: Capabilities) -> Result<Self> {
        capabilities.validate_closure()?;
        Ok(Self::new(capabilities))
    }

    /// Attach an extension entry.
    pub fn with_extension(mut self, id: ExtensionId, value: CborValue) -> Self {
        self.extensions.push((id as u64, value));
        self
    }

    /// Look up an extension value.
    pub fn extension(&self, id: ExtensionId) -> Option<&CborValue> {
        self.extensions
            .iter()
            .find(|(k, _)| *k == id as u64)
            .map(|(_, v)| v)
    }

    /// Encode to canonical QUIP-CBOR bytes.
    ///
    /// Validates the capability closure before encoding; an invalid local
    /// configuration never reaches the wire.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        self.capabilities.validate_closure()?;

        let mut ext: Vec<(CborValue, CborValue)> = Vec::with_capacity(self.extensions.len());
        for (k, v) in &self.extensions {
            ext.push((CborValue::Int(*k as i128), v.clone()));
        }
        let value = CborValue::Array(alloc::vec![
            CborValue::Int(self.version as i128),
            CborValue::Int(self.capabilities.0 as i128),
            CborValue::Map(ext),
        ]);
        Ok(encode(&value)?)
    }

    /// Decode from QUIP-CBOR bytes.
    ///
    /// Validates the capability closure after parsing; a remote handshake
    /// that advertises a dependency-violating set is rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let value = decode(bytes)?;
        let CborValue::Array(items) = &value else {
            return Err(Error::Handshake("handshake must be an array"));
        };
        if items.len() != 3 {
            return Err(Error::Handshake("handshake must have 3 fields"));
        }
        let version = match &items[0] {
            CborValue::Int(n) if *n >= 0 && *n <= u8::MAX as i128 => *n as u8,
            _ => return Err(Error::Handshake("handshake version must be a small uint")),
        };
        if version != crate::constants::PROTOCOL_VERSION {
            return Err(Error::Handshake("unsupported protocol version"));
        }
        let capabilities = match &items[1] {
            CborValue::Int(n) if *n >= 0 && *n <= u64::MAX as i128 => Capabilities(*n as u64),
            _ => return Err(Error::Handshake("capabilities must be a uint")),
        };
        capabilities.validate_closure()?;

        let CborValue::Map(pairs) = &items[2] else {
            return Err(Error::Handshake("extensions must be a map"));
        };
        let mut extensions = Vec::with_capacity(pairs.len());
        for (k, v) in pairs {
            match k {
                CborValue::Int(n) if *n >= 0 && *n <= u64::MAX as i128 => {
                    extensions.push((*n as u64, v.clone()));
                }
                _ => return Err(Error::Handshake("extension keys must be uints")),
            }
        }
        Ok(Self {
            version,
            capabilities,
            extensions,
        })
    }

    /// Negotiate with a remote handshake.
    ///
    /// Per spec §4: both peers compute the intersection of capabilities; if
    /// the intersection is empty, the connection is closed with
    /// `E_PROFILE_MISMATCH`. Callers may additionally check
    /// [`Capabilities::has_baseline`] for a stricter local policy.
    ///
    /// Closure is preserved under intersection if both sides are
    /// individually valid; the check here is defensive.
    pub fn negotiate(&self, remote: &Self) -> Result<Capabilities> {
        if self.version != remote.version {
            return Err(Error::Handshake("handshake version mismatch"));
        }
        let agreed = self.capabilities.intersect(remote.capabilities);
        if agreed.is_empty() {
            return Err(Error::Handshake(
                "no common capabilities (E_PROFILE_MISMATCH)",
            ));
        }
        agreed.validate_closure()?;
        Ok(agreed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(bits: u64) -> Handshake {
        Handshake::new(Capabilities(bits))
    }

    #[test]
    fn baseline_advertises_bits_one_through_five() {
        let h = caps(Capabilities::baseline().0);
        assert!(h.capabilities.has(Capabilities::T3_DATAGRAM));
        assert!(h.capabilities.has(Capabilities::DHT_DISCOVERY));
        assert!(h.capabilities.has(Capabilities::RBSR_SYNC));
        assert!(h.capabilities.has(Capabilities::CID_ADDRESSING));
        assert!(h.capabilities.has(Capabilities::RESOURCE_PIN));
        assert!(!h.capabilities.has(1 << 0), "bit 0 is undefined in v1");
    }

    #[test]
    fn capabilities_bit_values_match_spec() {
        assert_eq!(Capabilities::T3_DATAGRAM, 0x02);
        assert_eq!(Capabilities::DHT_DISCOVERY, 0x04);
        assert_eq!(Capabilities::RBSR_SYNC, 0x08);
        assert_eq!(Capabilities::CID_ADDRESSING, 0x10);
        assert_eq!(Capabilities::RESOURCE_PIN, 0x20);
        assert_eq!(Capabilities::GOVERNANCE, 0x40);
        assert_eq!(Capabilities::BLAKE3, 0x80);
        assert_eq!(Capabilities::NAT_TRAVERSAL, 0x100);
        assert_eq!(Capabilities::CIDV1, 0x200);
        assert_eq!(Capabilities::BFT_CHECKPOINT, 0x400);
        assert_eq!(Capabilities::MERKLE_RANGE, 0x800);
    }

    #[test]
    fn extension_keys_match_spec() {
        assert_eq!(ExtensionId::MaxMessageSize as u64, 0x01);
        assert_eq!(ExtensionId::EphemeralKey as u64, 0x02);
        assert_eq!(ExtensionId::DhtAnnounce as u64, 0x03);
        assert_eq!(ExtensionId::MaxRanges as u64, 0x04);
        assert_eq!(ExtensionId::PinCapacity as u64, 0x05);
        assert_eq!(ExtensionId::GovCapacity as u64, 0x06);
        assert_eq!(ExtensionId::HashAlgo as u64, 0x07);
        assert_eq!(ExtensionId::RbsrAlgo as u64, 0x08);
        assert_eq!(ExtensionId::NatTraversal as u64, 0x09);
        assert_eq!(ExtensionId::Cidv1Algo as u64, 0x0A);
        assert_eq!(ExtensionId::CheckpointInterval as u64, 0x0B);
        assert_eq!(ExtensionId::MaxRangeLength as u64, 0x0C);
        assert!(ExtensionId::from_u64(0x0D).is_err());
    }

    #[test]
    fn closure_accepts_baseline() {
        assert!(Capabilities::baseline().validate_closure().is_ok());
        assert!(Capabilities::empty().validate_closure().is_ok());
    }

    #[test]
    fn closure_rejects_blake3_without_cid_addressing() {
        let caps = Capabilities(Capabilities::BLAKE3);
        assert!(caps.validate_closure().is_err());
    }

    #[test]
    fn closure_rejects_cidv1_without_cid_addressing() {
        let caps = Capabilities(Capabilities::CIDV1);
        assert!(caps.validate_closure().is_err());
    }

    #[test]
    fn closure_rejects_merkle_range_without_blake3() {
        let caps = Capabilities(
            Capabilities::MERKLE_RANGE | Capabilities::CID_ADDRESSING,
        );
        assert!(caps.validate_closure().is_err());
    }

    #[test]
    fn closure_accepts_merkle_range_with_blake3_and_cid_addressing() {
        let caps = Capabilities(
            Capabilities::MERKLE_RANGE
                | Capabilities::BLAKE3
                | Capabilities::CID_ADDRESSING,
        );
        assert!(caps.validate_closure().is_ok());
    }

    #[test]
    fn closure_rejects_governance_without_dht() {
        let caps = Capabilities(Capabilities::GOVERNANCE | Capabilities::CID_ADDRESSING);
        assert!(caps.validate_closure().is_err());
    }

    #[test]
    fn closure_rejects_nat_without_dht() {
        let caps = Capabilities(Capabilities::NAT_TRAVERSAL);
        assert!(caps.validate_closure().is_err());
    }

    #[test]
    fn closure_rejects_bft_checkpoint_without_dht() {
        let caps = Capabilities(Capabilities::BFT_CHECKPOINT);
        assert!(caps.validate_closure().is_err());
    }

    #[test]
    fn handshake_roundtrip() {
        let h = Handshake::new(Capabilities::baseline() | Capabilities(Capabilities::BLAKE3 | Capabilities::CID_ADDRESSING))
            .with_extension(ExtensionId::HashAlgo, CborValue::Int(1))
            .with_extension(ExtensionId::MaxRanges, CborValue::Int(1024));
        let bytes = h.to_bytes().unwrap();
        let back = Handshake::from_bytes(&bytes).unwrap();
        assert_eq!(back.version, h.version);
        assert_eq!(back.capabilities, h.capabilities);
        assert_eq!(back.extension(ExtensionId::HashAlgo), Some(&CborValue::Int(1)));
        assert_eq!(
            back.extension(ExtensionId::MaxRanges),
            Some(&CborValue::Int(1024))
        );
    }

    #[test]
    fn to_bytes_rejects_local_closure_violation() {
        let h = Handshake::new(Capabilities(Capabilities::MERKLE_RANGE));
        assert!(h.to_bytes().is_err());
    }

    #[test]
    fn from_bytes_rejects_remote_closure_violation() {
        // Forge `[1, merkle_range_only, {}]` directly, bypassing to_bytes.
        let value = CborValue::Array(alloc::vec![
            CborValue::Int(1),
            CborValue::Int(Capabilities::MERKLE_RANGE as i128),
            CborValue::Map(alloc::vec![]),
        ]);
        let bytes = encode(&value).unwrap();
        assert!(Handshake::from_bytes(&bytes).is_err());
    }

    #[test]
    fn negotiate_accepts_nonempty_intersection() {
        let local = caps(Capabilities::baseline().0);
        let remote = caps(Capabilities::RESOURCE_PIN);
        let agreed = local.negotiate(&remote).unwrap();
        assert_eq!(agreed.0, Capabilities::RESOURCE_PIN);
    }

    #[test]
    fn negotiate_rejects_empty_intersection() {
        let local = caps(Capabilities::T3_DATAGRAM);
        let remote = caps(Capabilities::BFT_CHECKPOINT);
        assert!(local.negotiate(&remote).is_err());
    }

    #[test]
    fn negotiate_rejects_version_mismatch() {
        let mut remote = caps(Capabilities::baseline().0);
        remote.version = 2;
        let local = caps(Capabilities::baseline().0);
        assert!(local.negotiate(&remote).is_err());
    }

    #[test]
    fn extension_map_is_canonically_ordered_on_wire() {
        let h = Handshake::new(Capabilities::baseline())
            .with_extension(ExtensionId::CheckpointInterval, CborValue::Int(100))
            .with_extension(ExtensionId::HashAlgo, CborValue::Int(0))
            .with_extension(ExtensionId::MaxRanges, CborValue::Int(1024));
        let bytes = h.to_bytes().unwrap();
        let back = Handshake::from_bytes(&bytes).unwrap();
        assert_eq!(back.to_bytes().unwrap(), bytes);
    }

        #[test]
    fn merkle_range_roundtrips_through_wire_path() {
        // A valid local config: MERKLE_RANGE requires BLAKE3 and
        // CID_ADDRESSING (spec §4 capability closure).
        let local = Handshake::new(
            Capabilities::baseline()
                | Capabilities(Capabilities::MERKLE_RANGE)
                | Capabilities(Capabilities::BLAKE3)
                | Capabilities(Capabilities::CID_ADDRESSING),
        );

        // to_bytes must accept a closure-valid local config.
        let bytes = local.to_bytes().unwrap();

        // The wire bytes must decode to a handshake with all three bits.
        let decoded = Handshake::from_bytes(&bytes).unwrap();
        assert!(decoded.capabilities.has(Capabilities::MERKLE_RANGE));
        assert!(decoded.capabilities.has(Capabilities::BLAKE3));
        assert!(decoded.capabilities.has(Capabilities::CID_ADDRESSING));

        // Negotiation against an identical peer preserves the bits.
        let agreed = local.negotiate(&local).unwrap();
        assert!(agreed.has(Capabilities::MERKLE_RANGE));
        agreed.validate_closure().unwrap();

        // Re-encoding the negotiated set must also be closure-valid and
        // round-trip losslessly — this is the M8 hot path.
        let agreed_bytes = Handshake::new(agreed).to_bytes().unwrap();
        let agreed_back = Handshake::from_bytes(&agreed_bytes).unwrap();
        assert_eq!(agreed_back.capabilities, agreed);
    }

    #[test]
    fn merkle_range_dropped_when_remote_lacks_it() {
        let local = Handshake::new(
            Capabilities::baseline()
                | Capabilities(Capabilities::MERKLE_RANGE)
                | Capabilities(Capabilities::BLAKE3)
                | Capabilities(Capabilities::CID_ADDRESSING),
        );
        let remote = Handshake::new(
            Capabilities::baseline()
                | Capabilities(Capabilities::BLAKE3)
                | Capabilities(Capabilities::CID_ADDRESSING),
        );
        let agreed = local.negotiate(&remote).unwrap();
        assert!(!agreed.has(Capabilities::MERKLE_RANGE));
        assert!(agreed.has(Capabilities::BLAKE3));
        assert!(agreed.has(Capabilities::CID_ADDRESSING));
        // Intersection must still be closure-valid.
        agreed.validate_closure().unwrap();
    }

    #[test]
    fn negotiate_rejects_intersection_that_breaks_closure() {
        // Local has all three; remote advertises MERKLE_RANGE without BLAKE3.
        // In practice `from_bytes` would reject such a remote handshake, so
        // this exercises the defensive check inside `negotiate`.
        let local = Handshake::new(
            Capabilities::baseline()
                | Capabilities(Capabilities::MERKLE_RANGE)
                | Capabilities(Capabilities::BLAKE3)
                | Capabilities(Capabilities::CID_ADDRESSING),
        );
        let mut remote = Handshake::new(Capabilities::empty());
        remote.capabilities = Capabilities::baseline()
            | Capabilities(Capabilities::MERKLE_RANGE)
            | Capabilities(Capabilities::CID_ADDRESSING);
        // Intersection = baseline + MERKLE_RANGE + CID_ADDRESSING, which
        // violates the closure because MERKLE_RANGE requires BLAKE3.
        assert!(local.negotiate(&remote).is_err());
    }
}