//! Content quarantine store.
//!
//! Implements the state behind the `quarantine`, `unquarantine`, and
//! `quarantine_notice` primitives (spec §7.2).
//!
//! Quarantined CIDs:
//! - MUST NOT be returned in `query_resource` responses;
//! - MUST NOT be discoverable via DHT searches;
//! - MAY still be fetched by exact CID lookup (preserving immutability);
//! - Are filtered by [`crate::store::QuipStore`].
//!
//! Expiration:
//! - A notice with `valid_until = 0` is permanent.
//! - A notice with `valid_until > 0` expires when `now >= valid_until`.

use crate::constants::DEFAULT_QUARANTINE_CAPACITY;
use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::cid::CidOrV1;
use quip_core::messages::QuarantineNotice;
use quip_core::time::Timestamp;

/// Storage for active quarantine declarations.
#[derive(Clone, Debug)]
pub struct QuarantineStore {
    /// Notices keyed by the Trusted CID's digest.
    notices: BTreeMap<[u8; 32], QuarantineNotice>,
    capacity: usize,
}

impl QuarantineStore {
    /// Create a new store with default capacity ([`DEFAULT_QUARANTINE_CAPACITY`]).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_QUARANTINE_CAPACITY)
    }

    /// Create a new store with specified maximum capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            notices: BTreeMap::new(),
            capacity: capacity.max(1),
        }
    }

    /// Configured capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of active quarantine notices.
    pub fn len(&self) -> usize {
        self.notices.len()
    }

    /// True when no quarantine notices are stored.
    pub fn is_empty(&self) -> bool {
        self.notices.is_empty()
    }

    /// Clear all quarantine notices.
    pub fn clear(&mut self) {
        self.notices.clear();
    }

    /// All stored notices, in deterministic digest order.
    pub fn notices(&self) -> impl Iterator<Item = &QuarantineNotice> {
        self.notices.values()
    }

    /// Record a quarantine notice validated by the witness ring.
    ///
    /// If capacity is reached, expired notices are swept first. If still full,
    /// [`Error::CapacityExceeded`] is returned.
    pub fn add_notice(&mut self, notice: QuarantineNotice, now: Timestamp) -> Result<()> {
        let key = *notice.trusted_cid.digest();
        if !self.notices.contains_key(&key) && self.notices.len() >= self.capacity {
            self.sweep_expired(now);
            if self.notices.len() >= self.capacity {
                return Err(Error::CapacityExceeded {
                    table: "quarantine",
                    limit: self.capacity as u64,
                });
            }
        }
        self.notices.insert(key, notice);
        Ok(())
    }

    /// Find an active quarantine notice affecting `cid` at `now`.
    ///
    /// Matches if `cid` is the notice's `trusted_cid` or is listed in its
    /// `affected_cids`.
    pub fn notice_for(&self, cid: &CidOrV1, now: Timestamp) -> Option<&QuarantineNotice> {
        let target_digest = cid.digest();
        for notice in self.notices.values() {
            if !notice.is_valid_at(now) {
                continue;
            }
            if notice.trusted_cid.digest() == target_digest {
                return Some(notice);
            }
            if notice
                .affected_cids
                .iter()
                .any(|c| c.digest() == target_digest)
            {
                return Some(notice);
            }
        }
        None
    }

    /// True if `cid` is under an active quarantine notice at `now`.
    pub fn is_quarantined(&self, cid: &CidOrV1, now: Timestamp) -> bool {
        self.notice_for(cid, now).is_some()
    }

    /// Lift quarantine for `trusted_cid`.
    ///
    /// If `affected` is empty, the entire notice for `trusted_cid` is removed.
    /// If `affected` is non-empty, matching CIDs are removed from the notice's
    /// `affected_cids`; if no affected CIDs remain, the notice itself is removed.
    /// Returns the number of CIDs or notices modified/removed.
    pub fn lift(&mut self, trusted_cid: &CidOrV1, affected: &[CidOrV1]) -> usize {
        let key = *trusted_cid.digest();
        if affected.is_empty() {
            if self.notices.remove(&key).is_some() {
                1
            } else {
                0
            }
        } else {
            let Some(notice) = self.notices.get_mut(&key) else {
                return 0;
            };
            let before = notice.affected_cids.len();
            notice.affected_cids.retain(|c| {
                let d = c.digest();
                !affected.iter().any(|a| a.digest() == d)
            });
            let removed = before - notice.affected_cids.len();
            if notice.affected_cids.is_empty() {
                self.notices.remove(&key);
            }
            removed
        }
    }

    /// Sweep expired quarantine notices, returning how many were removed.
    pub fn sweep_expired(&mut self, now: Timestamp) -> usize {
        let before = self.notices.len();
        self.notices.retain(|_, n| n.is_valid_at(now));
        before - self.notices.len()
    }

    /// Restore notices from an iterator, respecting capacity.
    pub fn restore<I: IntoIterator<Item = QuarantineNotice>>(&mut self, notices: I) {
        for notice in notices {
            let key = *notice.trusted_cid.digest();
            if self.notices.len() < self.capacity || self.notices.contains_key(&key) {
                self.notices.insert(key, notice);
            }
        }
    }

    /// Insert notices verbatim **without** enforcing capacity.
    ///
    /// Crate-internal: used only by the snapshot-restore path.
    pub(crate) fn restore_exact<I: IntoIterator<Item = QuarantineNotice>>(&mut self, notices: I) {
        for notice in notices {
            let key = *notice.trusted_cid.digest();
            self.notices.insert(key, notice);
        }
    }

    /// Serialize to CBOR.
    pub fn to_cbor(&self) -> CborValue {
        let items: Vec<CborValue> = self.notices.values().map(|n| n.to_cbor()).collect();
        CborValue::Array(items)
    }

    /// Deserialize from CBOR.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let CborValue::Array(items) = value else {
            return Err(Error::Core(quip_core::Error::BadEncoding(
                "quarantine store must be an array",
            )));
        };
        let mut store = Self::new();
        for item in items {
            let notice = QuarantineNotice::from_cbor(item)?;
            let key = *notice.trusted_cid.digest();
            store.notices.insert(key, notice);
        }
        Ok(store)
    }
}

impl Default for QuarantineStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quip_core::cid::Cid;
    use quip_core::messages::{IndividualRingSig, RingSignature};

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    fn dummy_notice(tcid: u8, affected: &[u8], valid_until_ms: u64) -> QuarantineNotice {
        QuarantineNotice {
            trusted_cid: cid(tcid),
            affected_cids: affected.iter().map(|&b| cid(b)).collect(),
            reason: "dmca".into(),
            timestamp: Timestamp::from_millis(1_000),
            valid_until: Timestamp::from_millis(valid_until_ms),
            ring_signature: RingSignature::Individual(IndividualRingSig {
                signatures: vec![[0xaa; 64]],
                signers: vec![[0x01; 32]],
            }),
        }
    }

    #[test]
    fn permanent_and_temporary_quarantine() {
        let mut store = QuarantineStore::new();
        let notice = dummy_notice(1, &[2, 3], 0); // permanent
        store
            .add_notice(notice, Timestamp::from_millis(1_000))
            .unwrap();

        let t = Timestamp::from_millis(50_000);
        assert!(store.is_quarantined(&cid(1), t));
        assert!(store.is_quarantined(&cid(2), t));
        assert!(store.is_quarantined(&cid(3), t));
        assert!(!store.is_quarantined(&cid(4), t));

        // Temporary notice expiring at 10_000ms
        let temp = dummy_notice(5, &[6], 10_000);
        store.add_notice(temp, Timestamp::from_millis(1_000)).unwrap();
        assert!(store.is_quarantined(&cid(6), Timestamp::from_millis(9_999)));
        assert!(!store.is_quarantined(&cid(6), Timestamp::from_millis(10_000)));

        assert_eq!(store.sweep_expired(Timestamp::from_millis(10_000)), 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn lift_quarantine_partial_and_full() {
        let mut store = QuarantineStore::new();
        let notice = dummy_notice(1, &[2, 3], 0);
        store
            .add_notice(notice, Timestamp::from_millis(1_000))
            .unwrap();

        // Lift one affected CID
        assert_eq!(store.lift(&cid(1), &[cid(2)]), 1);
        assert!(!store.is_quarantined(&cid(2), Timestamp::from_millis(1_000)));
        assert!(store.is_quarantined(&cid(3), Timestamp::from_millis(1_000)));

        // Lift entire notice
        assert_eq!(store.lift(&cid(1), &[]), 1);
        assert!(!store.is_quarantined(&cid(1), Timestamp::from_millis(1_000)));
        assert!(!store.is_quarantined(&cid(3), Timestamp::from_millis(1_000)));
        assert!(store.is_empty());
    }

    #[test]
    fn capacity_exceeded_error() {
        let mut store = QuarantineStore::with_capacity(1);
        store
            .add_notice(dummy_notice(1, &[], 0), Timestamp::from_millis(100))
            .unwrap();
        let err = store
            .add_notice(dummy_notice(2, &[], 0), Timestamp::from_millis(100))
            .unwrap_err();
        assert!(matches!(
            err,
            Error::CapacityExceeded {
                table: "quarantine",
                limit: 1
            }
        ));
    }

    #[test]
    fn restore_exact_ignores_capacity() {
        let mut store = QuarantineStore::with_capacity(1);
        store.restore_exact(alloc::vec![
            dummy_notice(1, &[], 0),
            dummy_notice(2, &[], 0),
        ]);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn cbor_roundtrip() {
        let mut store = QuarantineStore::new();
        store
            .add_notice(dummy_notice(1, &[2], 0), Timestamp::from_millis(100))
            .unwrap();
        let cbor = store.to_cbor();
        let bytes = quip_core::cbor::encode(&cbor).unwrap();
        let decoded = quip_core::cbor::decode(&bytes).unwrap();
        let back = QuarantineStore::from_cbor(&decoded).unwrap();
        assert_eq!(back.len(), 1);
        assert!(back.is_quarantined(&cid(2), Timestamp::from_millis(100)));
    }
}