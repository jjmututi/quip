//! `SeqReset` — spec §5.3.6.
//!
//! ```text
//! ["quip-v1", "seq_reset", NodeId, last_known_seq, timestamp, signature]
//! ```
//!
//! A node that has lost its sequence-number state publishes a `SeqReset`
//! to restart its counter. Without this, the `INF` sentinel of a pruned
//! writer permanently shadows the node's updates
//! (see [`crate::dvv::Dvv::apply_seq_reset`]).

use super::verifier::Verifier;
use super::{
    expect_len, extract_node_id, extract_sig64, extract_timestamp, extract_u64, unwrap, wrap,
};
use crate::cbor::{encode, CborValue};
use crate::constants::{MAX_REPLAY_WINDOW_MS, VERB_SEQ_RESET};
use crate::dvv::NodeId;
use crate::error::{Error, Result};
use crate::time::Timestamp;
use alloc::vec;
use alloc::vec::Vec;

/// Attestation that a node has reset its sequence counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeqReset {
    /// The NodeId whose counter is being reset.
    pub node_id: NodeId,
    /// The node's last known sequence number before loss of state.
    pub last_known_seq: u64,
    /// Unix milliseconds.
    pub timestamp: Timestamp,
    /// Ed25519 self-signature over [`Self::signing_payload`].
    pub signature: [u8; 64],
}

impl SeqReset {
    /// Encode to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        wrap(
            VERB_SEQ_RESET,
            vec![
                CborValue::Bytes(self.node_id.to_vec()),
                CborValue::Int(self.last_known_seq as i128),
                CborValue::Int(self.timestamp.as_millis() as i128),
                CborValue::Bytes(self.signature.to_vec()),
            ],
        )
    }

    /// Decode from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let fields = unwrap(value, VERB_SEQ_RESET)?;
        expect_len(fields, 4)?;
        Ok(Self {
            node_id: extract_node_id(&fields[0])?,
            last_known_seq: extract_u64(&fields[1])?,
            timestamp: extract_timestamp(&fields[2])?,
            signature: extract_sig64(&fields[3])?,
        })
    }

    /// Bytes covered by `signature`, per the QUIP signing convention
    /// (draft-mututi-quip-03 §10.1).
    pub fn signing_payload(&self) -> Result<Vec<u8>> {
        encode(&wrap(
            VERB_SEQ_RESET,
            vec![
                CborValue::Bytes(self.node_id.to_vec()),
                CborValue::Int(self.last_known_seq as i128),
                CborValue::Int(self.timestamp.as_millis() as i128),
            ],
        ))
    }

    /// Verify the self-signature.
    pub fn verify(&self, v: &impl Verifier) -> Result<bool> {
        let payload = self.signing_payload()?;
        Ok(v.verify_ed25519(&self.node_id, &payload, &self.signature))
    }

    /// Two-sided replay-window check per spec §5.3.6.
    ///
    /// `last_seen_time` is the most recent timestamp observed from this
    /// NodeId (Unix milliseconds). `now` is the current local time.
    ///
    /// Returns `Ok(())` if the timestamp falls inside the acceptable
    /// window `[last_seen_time - MAX_REPLAY_WINDOW_MS,
    ///          now + MAX_REPLAY_WINDOW_MS]`, and `Err` otherwise.
    pub fn check_replay_window(
        &self,
        last_seen_time: Timestamp,
        now: Timestamp,
    ) -> Result<()> {
        let ts = self.timestamp.as_millis();
        let earliest = last_seen_time.as_millis().saturating_sub(MAX_REPLAY_WINDOW_MS);
        let latest = now.as_millis().saturating_add(MAX_REPLAY_WINDOW_MS);
        if ts < earliest {
            return Err(Error::BadEncoding("seq_reset timestamp too far in the past"));
        }
        if ts > latest {
            return Err(Error::BadEncoding("seq_reset timestamp too far in the future"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn roundtrip() {
        let s = SeqReset {
            node_id: nid(1),
            last_known_seq: 42,
            timestamp: Timestamp::from_millis(1_700_000_000_000),
            signature: [0xab; 64],
        };
        let back = SeqReset::from_cbor(&s.to_cbor()).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn replay_window_accepts_inside() {
        let s = SeqReset {
            node_id: nid(1),
            last_known_seq: 0,
            timestamp: Timestamp::from_millis(1_000_000),
            signature: [0; 64],
        };
        assert!(s
            .check_replay_window(
                Timestamp::from_millis(1_000_000),
                Timestamp::from_millis(1_000_000),
            )
            .is_ok());
    }

    #[test]
    fn replay_window_rejects_too_old() {
        let s = SeqReset {
            node_id: nid(1),
            last_known_seq: 0,
            timestamp: Timestamp::from_millis(0),
            signature: [0; 64],
        };
        assert!(s
            .check_replay_window(
                Timestamp::from_millis(MAX_REPLAY_WINDOW_MS + 1_000),
                Timestamp::from_millis(MAX_REPLAY_WINDOW_MS + 2_000),
            )
            .is_err());
    }

    #[test]
    fn replay_window_rejects_too_future() {
        let s = SeqReset {
            node_id: nid(1),
            last_known_seq: 0,
            timestamp: Timestamp::from_millis(u64::MAX - 1),
            signature: [0; 64],
        };
        assert!(s
            .check_replay_window(
                Timestamp::from_millis(1_000_000),
                Timestamp::from_millis(1_000_000),
            )
            .is_err());
    }
}