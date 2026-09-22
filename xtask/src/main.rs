//! Test-vector generator for the signing convention (§10.1).
//!
//! Usage:
//!     cargo xtask generate-vectors
//!
//! Writes four JSON files into `test-vectors/`. Output is
//! deterministic: every key and nonce is derived from a fixed seed.

use std::fs;
use std::path::PathBuf;

use ed25519_dalek::{Signer, SigningKey};
use quip_core::dvv::NodeId;
use quip_core::messages::{KeyClaim, WitnessStatement};
use quip_core::messages::ring_signature::{
    FrostRingSig, IndividualRingSig, RingSignature,
};
use quip_core::time::Timestamp;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::Serialize;

// ---------------------------------------------------------------------
// Deterministic seeds
// ---------------------------------------------------------------------

/// The seed every generated key derives from, parameterised by index.
/// Different indices produce independent keys.
fn seed_for(index: u8) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0xA5; // <- substitute a real byte, see below
    s[1] = index;
    s
}

/// Deterministic signing key for a given index.
fn key_for(index: u8) -> SigningKey {
    SigningKey::from_bytes(&seed_for(index))
}

/// Deterministic NodeId for a given index.
fn node_for(index: u8) -> NodeId {
    key_for(index).verifying_key().to_bytes()
}

// ---------------------------------------------------------------------
// JSON shape
// ---------------------------------------------------------------------

#[derive(Serialize)]
struct Vector {
    description: String,
    message: BytesField,
    signing_payload: BytesField,
    signature: SignatureField,
}

#[derive(Serialize)]
struct BytesField {
    cbor_bytes_hex: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum SignatureField {
    Single {
        hex: String,
        signer_public_key_hex: String,
    },
    Ring {
        hex: String,
        group_public_key_hex: String,
        participants: Vec<String>,
        commitment_hex: String,
    },
    IndividualRing {
        signatures_hex: Vec<String>,
        signers_hex: Vec<String>,
    },
}

fn hex32(b: &[u8; 32]) -> String {
    hex::encode(b)
}

fn hex64(b: &[u8; 64]) -> String {
    hex::encode(b)
}

// ---------------------------------------------------------------------
// KeyClaim vector
// ---------------------------------------------------------------------

fn generate_key_claim() -> Vector {
    let signer = key_for(1);
    let node_id = node_for(1);

    let claim = KeyClaim {
        node_id,
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        dht_id: node_id,
        signature: [0u8; 64], // placeholder; filled below
    };

    let payload = claim.signing_payload().expect("signing_payload");
    let sig = signer.sign(&payload);

    let mut signed = claim.clone();
    signed.signature = sig.to_bytes();

    let message_cbor = quip_core::cbor::encode(&signed.to_cbor()).expect("encode");

    Vector {
        description: "KeyClaim, self-signed (spec §5.1, §10.1)".into(),
        message: BytesField {
            cbor_bytes_hex: hex::encode(&message_cbor),
        },
        signing_payload: BytesField {
            cbor_bytes_hex: hex::encode(&payload),
        },
        signature: SignatureField::Single {
            hex: hex64(&sig.to_bytes()),
            signer_public_key_hex: hex32(&node_id),
        },
    }
}

// ---------------------------------------------------------------------
// WitnessStatement vector
// ---------------------------------------------------------------------

fn generate_witness_statement() -> Vector {
    let witness_key = key_for(2);
    let witness = node_for(2);
    let subject = node_for(1);

    let stmt = WitnessStatement {
        subject,
        timestamp: Timestamp::from_millis(1_700_000_000_000),
        valid_until: Timestamp::from_millis(1_700_086_400_000),
        ring_id: [0x42; 32],
        witness,
        signature: [0u8; 64],
    };

    let payload = stmt.signing_payload().expect("signing_payload");
    let sig = witness_key.sign(&payload);

    let mut signed = stmt.clone();
    signed.signature = sig.to_bytes();

    let message_cbor = quip_core::cbor::encode(&signed.to_cbor()).expect("encode");

    Vector {
        description: "WitnessStatement, witness-signed (spec §5.3.3, §10.1)".into(),
        message: BytesField {
            cbor_bytes_hex: hex::encode(&message_cbor),
        },
        signing_payload: BytesField {
            cbor_bytes_hex: hex::encode(&payload),
        },
        signature: SignatureField::Single {
            hex: hex64(&sig.to_bytes()),
            signer_public_key_hex: hex32(&witness),
        },
    }
}

// ---------------------------------------------------------------------
// IndividualRingSig vector
// ---------------------------------------------------------------------

/// The fixed payload every ring vector signs over. This is not a
/// QUIP message — it is a test fixture. Real ring signatures cover
/// the enclosing message's signing payload; using a fixed payload
/// keeps the vector focused on the signature primitive.
const RING_PAYLOAD: &[u8] = b"QUIP test vector: ring signature payload v1";

fn generate_individual_ring_sig() -> Vector {
    // Five signers, indices 10..14. QUORUM is 5.
    let signers: Vec<SigningKey> = (10..15).map(key_for).collect();
    let signer_ids: Vec<NodeId> = signers
        .iter()
        .map(|k| k.verifying_key().to_bytes())
        .collect();

    let signatures: Vec<[u8; 64]> = signers
        .iter()
        .map(|k| k.sign(RING_PAYLOAD).to_bytes())
        .collect();

    let ring = IndividualRingSig {
        signatures: signatures.clone(),
        signers: signer_ids.clone(),
    };

    let cbor = RingSignature::Individual(ring.clone()).to_cbor();
    let message_cbor = quip_core::cbor::encode(&cbor).expect("encode");

    Vector {
        description:
            "IndividualRingSig, 5-of-5 individual signatures (spec §5.3.4, §10.1)".into(),
        message: BytesField {
            cbor_bytes_hex: hex::encode(&message_cbor),
        },
        signing_payload: BytesField {
            cbor_bytes_hex: hex::encode(RING_PAYLOAD),
        },
        signature: SignatureField::IndividualRing {
            signatures_hex: signatures.iter().map(hex64).collect(),
            signers_hex: signer_ids.iter().map(hex32).collect(),
        },
    }
}

// ---------------------------------------------------------------------
// FROST ring signature vector
// ---------------------------------------------------------------------

fn generate_frost_ring_sig() -> Vector {
    use frost_ed25519 as frost;
    use frost::keys::IdentifierList;
    use std::collections::BTreeMap;

    // 5-of-7 FROST group. Deterministic nonces.
    let max_signers = 7u16;
    let min_signers = 5u16;

    // Trusted dealer. The docs example uses OsRng; for reproducible
    // vectors we use a fixed ChaCha20Rng seed.
    let mut dealer_rng = ChaCha20Rng::from_seed([0x5A; 32]);
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        max_signers,
        min_signers,
        IdentifierList::Default,
        &mut dealer_rng,
    )
    .expect("FROST key generation");

    // Convert SecretShares into KeyPackages. The docs example does
    // this per-participant; we do it once and reuse.
    let mut key_packages: BTreeMap<_, _> = BTreeMap::new();
    for (identifier, secret_share) in shares {
        let key_package = frost::keys::KeyPackage::try_from(secret_share)
            .expect("KeyPackage conversion");
        key_packages.insert(identifier, key_package);
    }

    // Round 1: each participant generates a nonce and a commitment.
    // Deterministic per-participant nonces so the vector is
    // reproducible.
    let mut nonces_map = BTreeMap::new();
    let mut commitments_map = BTreeMap::new();

    for participant_index in 1..=min_signers {
        let participant_identifier: frost::Identifier = participant_index
            .try_into()
            .expect("nonzero participant index");
        let key_package = &key_packages[&participant_identifier];

        // Seed the nonce RNG from the participant identifier.
        let id_bytes = participant_identifier
            .serialize();
        let mut seed = [0u8; 32];
        let n = id_bytes.len().min(32);
        seed[..n].copy_from_slice(&id_bytes[..n]);
        let mut nonce_rng = ChaCha20Rng::from_seed(seed);

        let (nonces, commitments) =
            frost::round1::commit(key_package.signing_share(), &mut nonce_rng);

        nonces_map.insert(participant_identifier, nonces);
        commitments_map.insert(participant_identifier, commitments);
    }

    // Round 2: build the signing package and sign.
    let signing_package =
        frost::SigningPackage::new(commitments_map.clone(), RING_PAYLOAD);

    let mut signature_shares = BTreeMap::new();
    for participant_identifier in nonces_map.keys() {
        let key_package = &key_packages[participant_identifier];
        let nonces = &nonces_map[participant_identifier];
        let signature_share =
            frost::round2::sign(&signing_package, nonces, key_package)
                .expect("round2 sign");
        signature_shares.insert(*participant_identifier, signature_share);
    }

    // Aggregate.
    let group_signature =
        frost::aggregate(&signing_package, &signature_shares, &pubkey_package)
            .expect("aggregate");

    // Serialize.
    let sig_bytes = group_signature
        .serialize()
        .expect("signature serialize");
    let group_pk_bytes = pubkey_package
        .verifying_key()
        .serialize()
        .expect("verifying key serialize");

    // Map the FROST identifiers into 32-byte NodeId slots. The
    // spec's FrostRingSig.participants is Vec<NodeId>, but FROST
    // identifiers are small integers. We left-pad into 32 bytes as a
    // wire-format convention; real deployments will map explicitly.
    let mut participants_sorted: Vec<frost::Identifier> =
        nonces_map.keys().copied().collect();
    participants_sorted.sort_by_key(|id| {
        id.serialize()
    });

    let participants_wire: Vec<NodeId> = participants_sorted
        .iter()
        .map(|id| {
            let bytes = id.serialize();
            let mut n = [0u8; 32];
            let n_copy = bytes.len().min(32);
            n[..n_copy].copy_from_slice(&bytes[..n_copy]);
            n
        })
        .collect();

    // The commitment is the aggregate of all participant
    // commitments for the signing package.
    let commitment_wire: Vec<u8> = participants_sorted
        .iter()
        .flat_map(|id| {
            commitments_map
                .get(id)
                .and_then(|c| c.serialize().ok())
                .unwrap_or_default()
        })
        .collect();

    let frost_wire = FrostRingSig {
        aggregate: sig_bytes.clone(),
        participants: participants_wire,
        commitment: commitment_wire,
    };

    let cbor = RingSignature::Frost(frost_wire).to_cbor();
    let message_cbor = quip_core::cbor::encode(&cbor).expect("encode");

    Vector {
        description:
            "FrostRingSig, 5-of-7 FROST aggregate (spec §5.3.4, §10.1, §9)".into(),
        message: BytesField {
            cbor_bytes_hex: hex::encode(&message_cbor),
        },
        signing_payload: BytesField {
            cbor_bytes_hex: hex::encode(RING_PAYLOAD),
        },
        signature: SignatureField::Ring {
            hex: hex::encode(&sig_bytes),
            group_public_key_hex: hex::encode(&group_pk_bytes),
            participants: participants_sorted
                .iter()
                .map(|id| hex::encode(id.serialize()))
                .collect(),
            commitment_hex: hex::encode(
                commitments_map
                    .values()
                    .next()
                    .and_then(|c| c.serialize().ok())
                    .unwrap_or_default(),
            ),
        },
    }
}

// ---------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------

fn write_vector(name: &str, vector: &Vector) {
    let mut out = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    out.pop(); // leave xtask/
    out.push("test-vectors");
    fs::create_dir_all(&out).expect("mkdir test-vectors");

    out.push(format!("{name}.json"));
    let json = serde_json::to_string_pretty(vector).expect("serialize");
    fs::write(&out, format!("{json}\n")).expect("write");
    println!("wrote {}", out.display());
}

fn generate_vectors() {
    write_vector("key_claim", &generate_key_claim());
    write_vector("witness_statement", &generate_witness_statement());
    write_vector("individual_ring_sig", &generate_individual_ring_sig());
    write_vector("frost_ring_sig", &generate_frost_ring_sig());
}

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("generate-vectors") => generate_vectors(),
        _ => {
            eprintln!("usage: cargo xtask generate-vectors");
            std::process::exit(2);
        }
    }
}