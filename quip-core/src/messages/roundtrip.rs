//! Integration tests: round-trip every message type through encode/decode.

use quip_core::cid::{Cid, CidOrV1};
use quip_core::cbor::{decode, encode};
use quip_core::messages::*;
use quip_core::time::Timestamp;
use quip_core::NodeId;

fn nid(b: u8) -> NodeId {
    let mut n = [0u8; 32];
    n[0] = b;
    n
}

fn roundtrip_msg<T, F, G>(value: &T, to_cbor: F, from_cbor: G)
where
    T: PartialEq + core::fmt::Debug,
    F: Fn(&T) -> quip_core::CborValue,
    G: Fn(&quip_core::CborValue) -> quip_core::Result<T>,
{
    let cbor = to_cbor(value);
    let bytes = encode(&cbor).unwrap();
    let decoded = decode(&bytes).unwrap();
    let back = from_cbor(&decoded).unwrap();
    assert_eq!(&back, value);
}

#[test]
fn key_claim_roundtrip() {
    let v = KeyClaim {
        node_id: nid(1),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        dht_id: nid(1),
        signature: [0xcd; 64],
    };
    roundtrip_msg(&v, KeyClaim::to_cbor, KeyClaim::from_cbor);
}

#[test]
fn witness_roundtrip() {
    let v = WitnessStatement {
        subject: nid(1),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        valid_until: Timestamp::from_millis(1_700_086_400_000),
        ring_id: [0x42; 32],
        witness: nid(2),
        signature: [0xab; 64],
    };
    roundtrip_msg(&v, WitnessStatement::to_cbor, WitnessStatement::from_cbor);
}

#[test]
fn rotation_roundtrip() {
    let v = KeyRotation {
        old_node_id: nid(1),
        new_node_id: nid(2),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        signature: [0xef; 64],
    };
    roundtrip_msg(&v, KeyRotation::to_cbor, KeyRotation::from_cbor);
}

#[test]
fn revocation_roundtrip() {
    let v = RevocationNotice {
        violator: nid(1),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        evidence: vec![1, 2, 3],
        reporter: nid(2),
        signature: [0xaa; 64],
    };
    roundtrip_msg(&v, RevocationNotice::to_cbor, RevocationNotice::from_cbor);
}

#[test]
fn pin_entry_roundtrip() {
    let v = PinEntry {
        resource_id: vec![0xab, 0xcd],
        cid: CidOrV1::Raw(Cid([0x42; 32])),
        pinned_at: Timestamp::from_millis(1_700_000_000_000),
        ttl_seconds: 604_800,
        ref_count: 3,
        local: true,
    };
    roundtrip_msg(&v, PinEntry::to_cbor, PinEntry::from_cbor);
}

#[test]
fn trusted_cid_roundtrip() {
    let v = TrustedCidRegistration {
        cid: CidOrV1::Raw(Cid([0x11; 32])),
        app_metadata: vec![("title".to_string(), quip_core::CborValue::String("Ex".into()))],
        owner: nid(1),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        signature: [0xef; 64],
    };
    roundtrip_msg(
        &v,
        TrustedCidRegistration::to_cbor,
        TrustedCidRegistration::from_cbor,
    );
}

#[test]
fn quarantine_roundtrip() {
    let v = QuarantineNotice {
        trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
        affected_cids: vec![CidOrV1::Raw(Cid([0x22; 32]))],
        reason: "RtBF".into(),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        valid_until: Timestamp::from_millis(0),
        ring_signature: RingSignature::Individual(IndividualRingSig {
            signatures: vec![[0xaa; 64]],
            signers: vec![nid(1)],
        }),
    };
    roundtrip_msg(&v, QuarantineNotice::to_cbor, QuarantineNotice::from_cbor);
}

#[test]
fn derivative_roundtrip() {
    let v = DerivativeLink {
        trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
        derivative_cid: CidOrV1::Raw(Cid([0x22; 32])),
        app_data: vec![("phash".to_string(), quip_core::CborValue::Int(42))],
        link_type: "perceptual_hash".to_string(),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        reporter: nid(1),
        signature: [0xcc; 64],
    };
    roundtrip_msg(&v, DerivativeLink::to_cbor, DerivativeLink::from_cbor);
}

#[test]
fn delegation_roundtrip() {
    let v = DelegationCertificate {
        trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
        delegate: nid(2),
        permissions: 0b1011,
        valid_from: Timestamp::from_millis(1_700_000_000_000),
        valid_until: Timestamp::from_millis(1_700_086_400_000),
        owner_signature: [0xdd; 64],
    };
    roundtrip_msg(
        &v,
        DelegationCertificate::to_cbor,
        DelegationCertificate::from_cbor,
    );
}

#[test]
fn seq_reset_roundtrip() {
    let v = SeqReset {
        node_id: nid(1),
        last_known_seq: 42,
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        signature: [0xab; 64],
    };
    roundtrip_msg(&v, SeqReset::to_cbor, SeqReset::from_cbor);
}

#[test]
fn discontinuity_roundtrip() {
    let v = Discontinuity {
        old_node_id: nid(1),
        new_node_id: nid(2),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        export_token: vec![1, 2, 3],
        signature: [0xee; 64],
    };
    roundtrip_msg(&v, Discontinuity::to_cbor, Discontinuity::from_cbor);
}

#[test]
fn quarantine_request_roundtrip() {
    let v = QuarantineRequest {
        trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
        affected_cids: vec![CidOrV1::Raw(Cid([0x22; 32]))],
        reason: "DMCA".into(),
        app_data: vec![("notice_id".to_string(), quip_core::CborValue::String("N-1".into()))],
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        requestor: nid(1),
        signature: [0xaa; 64],
    };
    roundtrip_msg(
        &v,
        QuarantineRequest::to_cbor,
        QuarantineRequest::from_cbor,
    );
}

#[test]
fn unquarantine_request_roundtrip() {
    let v = UnquarantineRequest {
        trusted_cid: CidOrV1::Raw(Cid([0x11; 32])),
        affected_cids: vec![CidOrV1::Raw(Cid([0x22; 32]))],
        reason: "error".into(),
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        requestor: nid(1),
        signature: [0xbb; 64],
    };
    roundtrip_msg(
        &v,
        UnquarantineRequest::to_cbor,
        UnquarantineRequest::from_cbor,
    );
}