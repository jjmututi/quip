//! NAT traversal wire codecs (spec §12).
//!
//! # Contents
//!
//! - Four top-level messages: [`ConnectivityAnnounce`],
//!   [`CandidateAnnounce`], [`RelayDiscovery`], [`RelayResponse`].
//! - Two inner structures: [`Candidate`], [`RelayEntry`].
//!
//! # Wire form
//!
//! Top-level messages use the standard `["quip-v1", verb, ...fields]`
//! envelope. Inner structures are CBOR maps with string keys, per the
//! CDDL in §12.
//!
//! # Signing
//!
//! Every message carries an Ed25519 signature over the message array
//! with the `signature` element removed (§10.1). The inner structures
//! ([`Candidate`], [`RelayEntry`]) are not separately signed; they are
//! covered by the enclosing message's signature.

use crate::codec::{
    as_array, as_bool, as_bytes_n, as_node_id, as_u64, envelope, fields, verb_of,
};
use crate::error::{Error, Result};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use quip_core::address::Address;
use quip_core::cbor::{decode, encode, CborValue};
use quip_core::dvv::NodeId;
use quip_core::messages::Verifier;
use quip_core::time::Timestamp;

// -------------------------------------------------------------------------
// Discriminants
// -------------------------------------------------------------------------

/// `nat_type` value: NAT flavour unknown.
pub const NAT_TYPE_UNKNOWN: u64 = 0;
/// `nat_type` value: no NAT (directly reachable).
pub const NAT_TYPE_OPEN: u64 = 1;
/// `nat_type` value: full-cone or restricted-cone NAT.
pub const NAT_TYPE_CONE: u64 = 2;
/// `nat_type` value: port-restricted NAT.
pub const NAT_TYPE_RESTRICTED: u64 = 3;
/// `nat_type` value: symmetric NAT (relay required).
pub const NAT_TYPE_SYMMETRIC: u64 = 4;

/// `Candidate.type` value: local interface address.
pub const CANDIDATE_HOST: u64 = 0;
/// `Candidate.type` value: server-reflexive address, observed by a DHT
/// peer.
pub const CANDIDATE_SERVER_REFLEXIVE: u64 = 1;
/// `Candidate.type` value: relay address.
pub const CANDIDATE_RELAYED: u64 = 2;
/// `Candidate.type` value: peer-reflexive address, discovered during a
/// connectivity check.
pub const CANDIDATE_PEER_REFLEXIVE: u64 = 3;

// -------------------------------------------------------------------------
// Candidate (inner structure, §12.3)
// -------------------------------------------------------------------------

/// A connectivity candidate.
///
/// See the constants above for the `kind` discriminant. `priority` is
/// application-defined; the ordering recommended by §12.3 is
/// host > server-reflexive > peer-reflexive > relayed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The candidate's address.
    pub addr: Address,
    /// Discriminant (`0` = host, `1` = server-reflexive, `2` = relayed,
    /// `3` = peer-reflexive).
    pub kind: u64,
    /// Priority; higher is preferred.
    pub priority: u64,
    /// Foundation string, grouping candidates with the same base
    /// address.
    pub foundation: String,
    /// Component number (application-defined).
    pub component: u64,
}

impl Candidate {
    /// Encode to a CBOR map.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(alloc::vec![
            (CborValue::String("addr".to_string()), self.addr.to_cbor()),
            (
                CborValue::String("type".to_string()),
                CborValue::Int(self.kind as i128),
            ),
            (
                CborValue::String("priority".to_string()),
                CborValue::Int(self.priority as i128),
            ),
            (
                CborValue::String("foundation".to_string()),
                CborValue::String(self.foundation.clone()),
            ),
            (
                CborValue::String("component".to_string()),
                CborValue::Int(self.component as i128),
            ),
        ])
    }

    /// Decode from a CBOR map.
    pub fn from_cbor(v: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = v else {
            return Err(Error::BadFrame("Candidate must be a map"));
        };
        let mut addr: Option<Address> = None;
        let mut kind: Option<u64> = None;
        let mut priority: Option<u64> = None;
        let mut foundation: Option<String> = None;
        let mut component: Option<u64> = None;

        for (k, val) in pairs {
            match k {
                CborValue::String(s) if s == "addr" => {
                    addr = Some(Address::from_cbor(val).map_err(Error::Core)?)
                }
                CborValue::String(s) if s == "type" => kind = Some(as_u64(val)?),
                CborValue::String(s) if s == "priority" => priority = Some(as_u64(val)?),
                CborValue::String(s) if s == "foundation" => match val {
                    CborValue::String(t) => foundation = Some(t.clone()),
                    _ => return Err(Error::BadFrame("foundation must be a string")),
                },
                CborValue::String(s) if s == "component" => component = Some(as_u64(val)?),
                CborValue::String(_) => {
                    return Err(Error::BadFrame("unknown key in Candidate"))
                }
                _ => return Err(Error::BadFrame("Candidate keys must be text")),
            }
        }

        Ok(Self {
            addr: addr.ok_or(Error::BadFrame("missing addr"))?,
            kind: kind.ok_or(Error::BadFrame("missing type"))?,
            priority: priority.ok_or(Error::BadFrame("missing priority"))?,
            foundation: foundation.ok_or(Error::BadFrame("missing foundation"))?,
            component: component.ok_or(Error::BadFrame("missing component"))?,
        })
    }

    /// Encode a list of candidates.
    pub fn list_to_cbor(candidates: &[Candidate]) -> CborValue {
        CborValue::Array(candidates.iter().map(|c| c.to_cbor()).collect())
    }

    /// Decode a list of candidates.
    pub fn list_from_cbor(v: &CborValue) -> Result<Vec<Candidate>> {
        as_array(v)?.iter().map(Candidate::from_cbor).collect()
    }

    /// Priority key ordering recommended by §12.3: host > server-reflexive
    /// > peer-reflexive > relayed. Lower value = higher preference.
    pub fn priority_class(&self) -> u8 {
        match self.kind {
            CANDIDATE_HOST => 0,
            CANDIDATE_SERVER_REFLEXIVE => 1,
            CANDIDATE_PEER_REFLEXIVE => 2,
            CANDIDATE_RELAYED => 3,
            _ => 4,
        }
    }
}

// -------------------------------------------------------------------------
// RelayEntry (inner structure, §12.2)
// -------------------------------------------------------------------------

/// One relay offered in a [`RelayResponse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayEntry {
    /// The relay's NodeId.
    pub relay_id: NodeId,
    /// The relay's externally-reachable address.
    pub external_addr: Address,
    /// Maximum concurrent relay connections.
    pub capacity: u64,
    /// Currently-used capacity.
    pub load: u64,
    /// Application-defined cost metric.
    pub cost: u64,
}

impl RelayEntry {
    /// Encode to a CBOR map.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(alloc::vec![
            (
                CborValue::String("relay_id".to_string()),
                CborValue::Bytes(self.relay_id.to_vec()),
            ),
            (
                CborValue::String("external_addr".to_string()),
                self.external_addr.to_cbor(),
            ),
            (
                CborValue::String("capacity".to_string()),
                CborValue::Int(self.capacity as i128),
            ),
            (
                CborValue::String("load".to_string()),
                CborValue::Int(self.load as i128),
            ),
            (
                CborValue::String("cost".to_string()),
                CborValue::Int(self.cost as i128),
            ),
        ])
    }

    /// Decode from a CBOR map.
    pub fn from_cbor(v: &CborValue) -> Result<Self> {
        let CborValue::Map(pairs) = v else {
            return Err(Error::BadFrame("RelayEntry must be a map"));
        };
        let mut relay_id: Option<NodeId> = None;
        let mut external_addr: Option<Address> = None;
        let mut capacity: Option<u64> = None;
        let mut load: Option<u64> = None;
        let mut cost: Option<u64> = None;

        for (k, val) in pairs {
            match k {
                CborValue::String(s) if s == "relay_id" => relay_id = Some(as_node_id(val)?),
                CborValue::String(s) if s == "external_addr" => {
                    external_addr = Some(Address::from_cbor(val).map_err(Error::Core)?)
                }
                CborValue::String(s) if s == "capacity" => capacity = Some(as_u64(val)?),
                CborValue::String(s) if s == "load" => load = Some(as_u64(val)?),
                CborValue::String(s) if s == "cost" => cost = Some(as_u64(val)?),
                CborValue::String(_) => {
                    return Err(Error::BadFrame("unknown key in RelayEntry"))
                }
                _ => return Err(Error::BadFrame("RelayEntry keys must be text")),
            }
        }

        Ok(Self {
            relay_id: relay_id.ok_or(Error::BadFrame("missing relay_id"))?,
            external_addr: external_addr.ok_or(Error::BadFrame("missing external_addr"))?,
            capacity: capacity.ok_or(Error::BadFrame("missing capacity"))?,
            load: load.ok_or(Error::BadFrame("missing load"))?,
            cost: cost.ok_or(Error::BadFrame("missing cost"))?,
        })
    }

    /// Encode a list of entries.
    pub fn list_to_cbor(entries: &[RelayEntry]) -> CborValue {
        CborValue::Array(entries.iter().map(|e| e.to_cbor()).collect())
    }

    /// Decode a list of entries.
    pub fn list_from_cbor(v: &CborValue) -> Result<Vec<RelayEntry>> {
        as_array(v)?.iter().map(RelayEntry::from_cbor).collect()
    }

    /// Available capacity, saturating at zero.
    pub fn available(&self) -> u64 {
        self.capacity.saturating_sub(self.load)
    }
}

// -------------------------------------------------------------------------
// connectivity_announce
// -------------------------------------------------------------------------

/// `connectivity_announce` — a peer publishes its connectivity to the
/// DHT (§12.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectivityAnnounce {
    /// The announcing peer.
    pub node_id: NodeId,
    /// DHT-observed external address.
    pub external_addr: Address,
    /// Internal address, if known.
    pub internal_addr: Address,
    /// NAT type discriminant (see `NAT_TYPE_*` constants).
    pub nat_type: u64,
    /// Whether the NAT preserves source ports.
    pub port_preservation: bool,
    /// Whether the peer is willing to relay for others.
    pub relay_capable: bool,
    /// Relay capacity when `relay_capable` is true.
    pub capacity: u64,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `node_id`.
    pub signature: [u8; 64],
}

impl ConnectivityAnnounce {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "connectivity_announce",
            alloc::vec![
                CborValue::Bytes(self.node_id.to_vec()),
                self.external_addr.to_cbor(),
                self.internal_addr.to_cbor(),
                CborValue::Int(self.nat_type as i128),
                CborValue::Bool(self.port_preservation),
                CborValue::Bool(self.relay_capable),
                CborValue::Int(self.capacity as i128),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "connectivity_announce" {
            return Err(Error::BadFrame("not a connectivity_announce"));
        }
        let f = fields(&v, "connectivity_announce")?;
        if f.len() != 9 {
            return Err(Error::BadFrame("connectivity_announce arity"));
        }
        Ok(Self {
            node_id: as_node_id(&f[0])?,
            external_addr: Address::from_cbor(&f[1]).map_err(Error::Core)?,
            internal_addr: Address::from_cbor(&f[2]).map_err(Error::Core)?,
            nat_type: as_u64(&f[3])?,
            port_preservation: as_bool(&f[4])?,
            relay_capable: as_bool(&f[5])?,
            capacity: as_u64(&f[6])?,
            timestamp: Timestamp::from_millis(as_u64(&f[7])?),
            signature: as_bytes_n::<64>(&f[8])?,
        })
    }

    /// Bytes covered by `signature` (§10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "connectivity_announce",
            alloc::vec![
                CborValue::Bytes(self.node_id.to_vec()),
                self.external_addr.to_cbor(),
                self.internal_addr.to_cbor(),
                CborValue::Int(self.nat_type as i128),
                CborValue::Bool(self.port_preservation),
                CborValue::Bool(self.relay_capable),
                CborValue::Int(self.capacity as i128),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `node_id`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.node_id, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// candidate_announce
// -------------------------------------------------------------------------

/// `candidate_announce` — a peer offers ICE-like candidates (§12.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateAnnounce {
    /// The announcing peer.
    pub node_id: NodeId,
    /// The candidates on offer.
    pub candidates: Vec<Candidate>,
    /// Session identifier, binding these candidates to one negotiation.
    pub session_id: [u8; 16],
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `node_id`.
    pub signature: [u8; 64],
}

impl CandidateAnnounce {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "candidate_announce",
            alloc::vec![
                CborValue::Bytes(self.node_id.to_vec()),
                Candidate::list_to_cbor(&self.candidates),
                CborValue::Bytes(self.session_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "candidate_announce" {
            return Err(Error::BadFrame("not a candidate_announce"));
        }
        let f = fields(&v, "candidate_announce")?;
        if f.len() != 5 {
            return Err(Error::BadFrame("candidate_announce arity"));
        }
        Ok(Self {
            node_id: as_node_id(&f[0])?,
            candidates: Candidate::list_from_cbor(&f[1])?,
            session_id: as_bytes_n::<16>(&f[2])?,
            timestamp: Timestamp::from_millis(as_u64(&f[3])?),
            signature: as_bytes_n::<64>(&f[4])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "candidate_announce",
            alloc::vec![
                CborValue::Bytes(self.node_id.to_vec()),
                Candidate::list_to_cbor(&self.candidates),
                CborValue::Bytes(self.session_id.to_vec()),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `node_id`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.node_id, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// relay_discovery
// -------------------------------------------------------------------------

/// `relay_discovery` — a peer asks the DHT for relays to a target
/// (§12.2).
///
/// The `request_id` is a freshly generated 16-byte value, unique among
/// the requester's outstanding discoveries. A `RelayResponse` echoes
/// both `request_id` and `target` so the requester can demultiplex
/// responses without serializing discoveries per target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayDiscovery {
    /// Fresh 16-byte value, unique among the requester's outstanding
    /// discoveries.
    pub request_id: [u8; 16],
    /// The peer making the request.
    pub requester: NodeId,
    /// The peer the requester wants to reach.
    pub target: NodeId,
    /// Maximum relay hops the requester is willing to use.
    pub max_hops: u64,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by `requester`.
    pub signature: [u8; 64],
}

impl RelayDiscovery {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "relay_discovery",
            alloc::vec![
                CborValue::Bytes(self.request_id.to_vec()),
                CborValue::Bytes(self.requester.to_vec()),
                CborValue::Bytes(self.target.to_vec()),
                CborValue::Int(self.max_hops as i128),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "relay_discovery" {
            return Err(Error::BadFrame("not a relay_discovery"));
        }
        let f = fields(&v, "relay_discovery")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("relay_discovery arity"));
        }
        Ok(Self {
            request_id: as_bytes_n::<16>(&f[0])?,
            requester: as_node_id(&f[1])?,
            target: as_node_id(&f[2])?,
            max_hops: as_u64(&f[3])?,
            timestamp: Timestamp::from_millis(as_u64(&f[4])?),
            signature: as_bytes_n::<64>(&f[5])?,
        })
    }

    /// Bytes covered by `signature`.
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "relay_discovery",
            alloc::vec![
                CborValue::Bytes(self.request_id.to_vec()),
                CborValue::Bytes(self.requester.to_vec()),
                CborValue::Bytes(self.target.to_vec()),
                CborValue::Int(self.max_hops as i128),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against `requester`.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.requester, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// relay_response
// -------------------------------------------------------------------------

/// `relay_response` — a DHT node answers a [`RelayDiscovery`] (§12.2).
///
/// The response echoes both `request_id` and `target` from the
/// originating `RelayDiscovery` so that a requester with multiple
/// outstanding discoveries can demultiplex responses unambiguously.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayResponse {
    /// The `request_id` from the originating `RelayDiscovery`.
    pub request_id: [u8; 16],
    /// The `target` from the originating `RelayDiscovery`.
    pub target: NodeId,
    /// The original requester.
    pub requester: NodeId,
    /// Relays that can reach the target.
    pub relays: Vec<RelayEntry>,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 signature by the responder.
    pub signature: [u8; 64],
}

impl RelayResponse {
    /// Encode to QUIP-CBOR bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "relay_response",
            alloc::vec![
                CborValue::Bytes(self.request_id.to_vec()),
                CborValue::Bytes(self.target.to_vec()),
                CborValue::Bytes(self.requester.to_vec()),
                RelayEntry::list_to_cbor(&self.relays),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Decode from QUIP-CBOR bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let v = decode(bytes)?;
        if verb_of(&v)? != "relay_response" {
            return Err(Error::BadFrame("not a relay_response"));
        }
        let f = fields(&v, "relay_response")?;
        if f.len() != 6 {
            return Err(Error::BadFrame("relay_response arity"));
        }
        Ok(Self {
            request_id: as_bytes_n::<16>(&f[0])?,
            target: as_node_id(&f[1])?,
            requester: as_node_id(&f[2])?,
            relays: RelayEntry::list_from_cbor(&f[3])?,
            timestamp: Timestamp::from_millis(as_u64(&f[4])?),
            signature: as_bytes_n::<64>(&f[5])?,
        })
    }

    /// Bytes covered by `signature` (§10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        let msg = envelope(
            "relay_response",
            alloc::vec![
                CborValue::Bytes(self.request_id.to_vec()),
                CborValue::Bytes(self.target.to_vec()),
                CborValue::Bytes(self.requester.to_vec()),
                RelayEntry::list_to_cbor(&self.relays),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        );
        Ok(encode(&msg)?)
    }

    /// Verify the signature against the responder.
    ///
    /// The response is signed by the responder, whose NodeId the caller
    /// learns from the enclosing envelope. This method takes an explicit
    /// `responder` because the wire format carries the requester, not
    /// the responder.
    pub fn verify(
        &self,
        responder: &NodeId,
        v: &impl Verifier,
    ) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(responder, &payload, &self.signature))
    }
}

// -------------------------------------------------------------------------
// Tests
// -------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    fn addr(b: u8) -> Address {
        Address::V4 {
            ip: [127, 0, 0, b],
            port: 4433,
        }
    }

    fn addr6() -> Address {
        Address::V6 {
            ip: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            port: 4433,
        }
    }

    fn now() -> Timestamp {
        Timestamp::from_millis(1_700_000_000_000)
    }

    // ---- Candidate ----

    #[test]
    fn candidate_roundtrip_v4() {
        let c = Candidate {
            addr: addr(1),
            kind: CANDIDATE_HOST,
            priority: 100,
            foundation: "abc".into(),
            component: 0,
        };
        let cbor = c.to_cbor();
        assert_eq!(Candidate::from_cbor(&cbor).unwrap(), c);
    }

    #[test]
    fn candidate_roundtrip_v6() {
        let c = Candidate {
            addr: addr6(),
            kind: CANDIDATE_RELAYED,
            priority: 1,
            foundation: "xyz".into(),
            component: 1,
        };
        let cbor = c.to_cbor();
        assert_eq!(Candidate::from_cbor(&cbor).unwrap(), c);
    }

    #[test]
    fn candidate_rejects_wrong_type() {
        assert!(Candidate::from_cbor(&CborValue::Int(1)).is_err());
    }

    #[test]
    fn candidate_priority_class_matches_spec() {
        let mk = |k| Candidate {
            addr: addr(1),
            kind: k,
            priority: 0,
            foundation: "".into(),
            component: 0,
        };
        assert_eq!(mk(CANDIDATE_HOST).priority_class(), 0);
        assert_eq!(mk(CANDIDATE_SERVER_REFLEXIVE).priority_class(), 1);
        assert_eq!(mk(CANDIDATE_PEER_REFLEXIVE).priority_class(), 2);
        assert_eq!(mk(CANDIDATE_RELAYED).priority_class(), 3);
    }

    // ---- RelayEntry ----

    #[test]
    fn relay_entry_roundtrip() {
        let r = RelayEntry {
            relay_id: nid(1),
            external_addr: addr(2),
            capacity: 1000,
            load: 5,
            cost: 10,
        };
        let cbor = r.to_cbor();
        assert_eq!(RelayEntry::from_cbor(&cbor).unwrap(), r);
    }

    #[test]
    fn relay_entry_available_saturates() {
        let r = RelayEntry {
            relay_id: nid(1),
            external_addr: addr(2),
            capacity: 10,
            load: 15,
            cost: 0,
        };
        assert_eq!(r.available(), 0);
    }

    // ---- ConnectivityAnnounce ----

    #[test]
    fn connectivity_announce_roundtrip() {
        let m = ConnectivityAnnounce {
            node_id: nid(1),
            external_addr: addr(1),
            internal_addr: addr(2),
            nat_type: NAT_TYPE_CONE,
            port_preservation: true,
            relay_capable: true,
            capacity: 100,
            timestamp: now(),
            signature: [0xaa; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(ConnectivityAnnounce::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn connectivity_announce_signing_payload_excludes_signature() {
        let m = ConnectivityAnnounce {
            node_id: nid(1),
            external_addr: addr(1),
            internal_addr: addr(2),
            nat_type: NAT_TYPE_OPEN,
            port_preservation: false,
            relay_capable: false,
            capacity: 0,
            timestamp: now(),
            signature: [0xff; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "connectivity_announce").unwrap();
        assert_eq!(f.len(), 8, "signature field must be omitted");

        let mut other = m.clone();
        other.signature = [0; 64];
        assert_eq!(other.signing_payload().unwrap(), payload);
    }

    // ---- CandidateAnnounce ----

    #[test]
    fn candidate_announce_roundtrip() {
        let m = CandidateAnnounce {
            node_id: nid(1),
            candidates: vec![
                Candidate {
                    addr: addr(1),
                    kind: CANDIDATE_HOST,
                    priority: 100,
                    foundation: "f1".into(),
                    component: 0,
                },
                Candidate {
                    addr: addr6(),
                    kind: CANDIDATE_SERVER_REFLEXIVE,
                    priority: 90,
                    foundation: "f1".into(),
                    component: 0,
                },
            ],
            session_id: [0x42; 16],
            timestamp: now(),
            signature: [0xbb; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(CandidateAnnounce::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn candidate_announce_empty_candidates_roundtrips() {
        let m = CandidateAnnounce {
            node_id: nid(1),
            candidates: vec![],
            session_id: [0; 16],
            timestamp: now(),
            signature: [0; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(CandidateAnnounce::from_bytes(&bytes).unwrap(), m);
    }

    // ---- RelayDiscovery ----

    #[test]
    fn relay_discovery_roundtrip() {
        let m = RelayDiscovery {
            request_id: [0x42; 16],
            requester: nid(1),
            target: nid(2),
            max_hops: 2,
            timestamp: now(),
            signature: [0xcc; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(RelayDiscovery::from_bytes(&bytes).unwrap(), m);
    }
    
    #[test]
    fn relay_discovery_signing_payload_excludes_signature() {
        let m = RelayDiscovery {
            request_id: [0x42; 16],
            requester: nid(1),
            target: nid(2),
            max_hops: 2,
            timestamp: now(),
            signature: [0xff; 64],
        };
        let payload = m.signing_payload().unwrap();
        let decoded = decode(&payload).unwrap();
        let f = crate::codec::fields(&decoded, "relay_discovery").unwrap();
        assert_eq!(f.len(), 5, "request_id + requester + target + max_hops + timestamp");
    }

    // ---- RelayResponse ----

    #[test]
    fn relay_response_roundtrip() {
        let m = RelayResponse {
            
            request_id: [0x42; 16],
            target: nid(2),
            requester: nid(1),
            relays: vec![
                RelayEntry {
                    relay_id: nid(10),
                    external_addr: addr(10),
                    capacity: 1000,
                    load: 5,
                    cost: 0,
                },
                RelayEntry {
                    relay_id: nid(11),
                    external_addr: addr6(),
                    capacity: 500,
                    load: 0,
                    cost: 5,
                },
            ],
            timestamp: now(),
            signature: [0xdd; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(RelayResponse::from_bytes(&bytes).unwrap(), m);
    }

    #[test]
    fn relay_response_empty_relays_roundtrips() {
        let m = RelayResponse {
            request_id: [0u8; 16],
            target: nid(2),
            requester: nid(1),
            relays: vec![],
            timestamp: now(),
            signature: [0; 64],
        };
        let bytes = m.to_bytes().unwrap();
        assert_eq!(RelayResponse::from_bytes(&bytes).unwrap(), m);
    }

    // ---- rejects ----

    #[test]
    fn wrong_verb_rejected() {
        let msg = envelope("connectivity_announce_typo", alloc::vec![]);
        let bytes = encode(&msg).unwrap();
        assert!(ConnectivityAnnounce::from_bytes(&bytes).is_err());
    }

    #[test]
    fn wrong_arity_rejected() {
        let msg = envelope(
            "connectivity_announce",
            alloc::vec![CborValue::Bytes(vec![0; 32])],
        );
        let bytes = encode(&msg).unwrap();
        assert!(ConnectivityAnnounce::from_bytes(&bytes).is_err());
    }
}