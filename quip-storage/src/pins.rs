//! Pin table.
//!
//! Implements the state behind the `pin`, `unpin`, `query_pins`, and `pin_list`
//! verbs (spec §14.2) and the T3 `pin_announce` gossip (spec §14.3), following the
//! guidance in App. A.5:
//!
//! - `ttl = 0` selects [`DEFAULT_PIN_TTL_S`] (7 days); `ttl = 0xFFFFFFFF`
//!   ([`INDEFINITE_TTL_S`]) means "store indefinitely, subject to capacity".
//! - Pins **SHOULD** be refreshed before expiry, at 80% of the TTL —
//!   [`PinTable::refresh_due`] reports those records.
//! - When capacity is reached, pins **SHOULD** be evicted by lowest `ref_count`
//!   and then oldest `pinned_at` — internal capacity trimming does exactly
//!   that, so inserting never fails.
//!
//! Pinning applies to immutable CIDs only (spec §5.2): a [`PinRecord`] points at a
//! `CIDOrV1`, never at a DVV.

use crate::codec::{as_bool, as_bytes, as_u64, expect_key, parse_map};
use crate::constants::{DEFAULT_PIN_TTL_S, INDEFINITE_TTL_S, PIN_REFRESH_PERCENT};
use crate::error::Result;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cbor::CborValue;
use quip_core::cid::CidOrV1;
use quip_core::constants::PIN_CAPACITY;
use quip_core::messages::PinEntry;
use quip_core::time::Timestamp;

/// Keys accepted by [`PinRecord::from_cbor`].
const PIN_RECORD_KEYS: &[&str] = &["resource_id", "cid", "pinned_at", "ttl", "ref_count", "local"];

/// A pin held locally or observed from a remote peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinRecord {
    /// Application-defined resource name.
    pub resource_id: Vec<u8>,
    /// The pinned (immutable) CID.
    pub cid: CidOrV1,
    /// When the pin was first accepted.
    pub pinned_at: Timestamp,
    /// Full TTL in **seconds**, never the remaining TTL; [`INDEFINITE_TTL_S`]
    /// means indefinite.
    pub ttl_seconds: u64,
    /// Number of peers known to reference this pin; drives eviction ordering.
    pub ref_count: u64,
    /// True when this peer holds the bytes, false when only observed.
    pub local: bool,
}

impl PinRecord {
    /// Absolute expiry, or `None` for an indefinite pin.
    pub fn expires_at(&self) -> Option<Timestamp> {
        if self.is_indefinite() {
            return None;
        }
        Some(Timestamp(
            self.pinned_at
                .as_millis()
                .saturating_add(self.ttl_seconds.saturating_mul(1_000)),
        ))
    }

    /// True when the TTL sentinel requests indefinite storage.
    pub fn is_indefinite(&self) -> bool {
        self.ttl_seconds >= INDEFINITE_TTL_S
    }

    /// True once `now` has reached the expiry.
    pub fn is_expired(&self, now: Timestamp) -> bool {
        match self.expires_at() {
            Some(expiry) => now >= expiry,
            None => false,
        }
    }

    /// Seconds left before expiry, or [`INDEFINITE_TTL_S`] for an indefinite pin.
    /// Saturates at 0.
    pub fn remaining_seconds(&self, now: Timestamp) -> u64 {
        match self.expires_at() {
            None => INDEFINITE_TTL_S,
            Some(expiry) => expiry
                .as_millis()
                .saturating_sub(now.as_millis())
                .checked_div(1_000)
                .unwrap_or(0),
        }
    }

    /// True when at least [`PIN_REFRESH_PERCENT`] of the TTL has elapsed.
    pub fn needs_refresh(&self, now: Timestamp) -> bool {
        if self.is_indefinite() {
            return false;
        }
        let elapsed_ms = now.as_millis().saturating_sub(self.pinned_at.as_millis()) as u128;
        let threshold_ms = (self.ttl_seconds as u128) * 1_000 * (PIN_REFRESH_PERCENT as u128);
        elapsed_ms * 100 >= threshold_ms
    }

    /// Convert to the wire-level [`PinEntry`] used by `pin_list` responses.
    ///
    /// Note the semantic shift required by the CDDL: `PinEntry.ttl` is the
    /// **remaining** TTL in seconds, while [`PinRecord::ttl_seconds`] is the full
    /// TTL.
    pub fn to_entry(&self, now: Timestamp) -> PinEntry {
        PinEntry {
            resource_id: self.resource_id.clone(),
            cid: self.cid,
            pinned_at: self.pinned_at,
            ttl_seconds: self.remaining_seconds(now),
            ref_count: self.ref_count,
            local: self.local,
        }
    }

    /// Snapshot encoding: the same CBOR shape as [`PinEntry`], but `ttl` carries
    /// the full TTL so that a restored table keeps the original expiry.
    pub fn to_cbor(&self) -> CborValue {
        CborValue::Map(alloc::vec![
            (
                CborValue::String("resource_id".into()),
                CborValue::Bytes(self.resource_id.clone()),
            ),
            (CborValue::String("cid".into()), self.cid.to_cbor()),
            (
                CborValue::String("pinned_at".into()),
                CborValue::Int(self.pinned_at.as_millis() as i128),
            ),
            (
                CborValue::String("ttl".into()),
                CborValue::Int(self.ttl_seconds as i128),
            ),
            (
                CborValue::String("ref_count".into()),
                CborValue::Int(self.ref_count as i128),
            ),
            (CborValue::String("local".into()), CborValue::Bool(self.local)),
        ])
    }

    /// Decode a [`PinRecord::to_cbor`] map.
    pub fn from_cbor(value: &CborValue) -> Result<Self> {
        let map = parse_map(value, PIN_RECORD_KEYS)?;
        Ok(PinRecord {
            resource_id: as_bytes(expect_key(&map, "resource_id", "missing resource_id")?)?,
            cid: CidOrV1::from_cbor(expect_key(&map, "cid", "missing cid")?)?,
            pinned_at: Timestamp::from_millis(as_u64(expect_key(
                &map,
                "pinned_at",
                "missing pinned_at",
            )?)?),
            ttl_seconds: as_u64(expect_key(&map, "ttl", "missing ttl")?)?,
            ref_count: as_u64(expect_key(&map, "ref_count", "missing ref_count")?)?,
            local: as_bool(expect_key(&map, "local", "missing local")?)?,
        })
    }
}

/// Identity of a pin: the resource name plus the content digest.
///
/// The digest (not the raw/tagged form) identifies the content, matching
/// [`crate::blob::BlobStore`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PinKey {
    resource_id: Vec<u8>,
    digest: [u8; 32],
}

impl PinKey {
    fn new(resource_id: &[u8], cid: &CidOrV1) -> Self {
        Self {
            resource_id: resource_id.to_vec(),
            digest: *cid.digest(),
        }
    }
}

/// The pin table.
#[derive(Clone, Debug)]
pub struct PinTable {
    pins: BTreeMap<PinKey, PinRecord>,
    capacity: usize,
    default_ttl_seconds: u64,
    evictions: u64,
}

impl PinTable {
    /// Table with the protocol's pin capacity
    /// ([`PIN_CAPACITY`], configurable by the
    /// `pin_capacity` handshake extension) and the default 7-day TTL.
    pub fn new() -> Self {
        Self::with_capacity(PIN_CAPACITY)
    }

    /// Table with an explicit capacity. Values below 1 are clamped to 1 so that a
    /// freshly inserted pin is always retained.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            pins: BTreeMap::new(),
            capacity: capacity.max(1),
            default_ttl_seconds: DEFAULT_PIN_TTL_S,
            evictions: 0,
        }
    }

    /// Current capacity.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Set the capacity, evicting the lowest-priority pins until it fits.
    /// Returns the number of evictions.
    pub fn set_capacity(&mut self, capacity: usize) -> usize {
        self.capacity = capacity.max(1);
        self.trim_to_capacity()
    }

    /// TTL in seconds selected when a `pin` carries `ttl = 0`.
    pub fn default_ttl_seconds(&self) -> u64 {
        self.default_ttl_seconds
    }

    /// Override the default TTL (spec recommends 7 days).
    pub fn set_default_ttl_seconds(&mut self, ttl_seconds: u64) {
        self.default_ttl_seconds = ttl_seconds;
    }

    /// Total number of evictions performed by this table.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Number of pins held.
    pub fn len(&self) -> usize {
        self.pins.len()
    }

    /// True when no pins are held.
    pub fn is_empty(&self) -> bool {
        self.pins.is_empty()
    }

    /// All records, in deterministic (resource name, digest) order.
    pub fn records(&self) -> impl Iterator<Item = &PinRecord> {
        self.pins.values()
    }

    /// Normalize a wire TTL: `0` → default, values at or above the sentinel →
    /// [`INDEFINITE_TTL_S`], everything else unchanged.
    pub fn normalize_ttl(&self, ttl_seconds: u64) -> u64 {
        if ttl_seconds == 0 {
            self.default_ttl_seconds
        } else if ttl_seconds >= INDEFINITE_TTL_S {
            INDEFINITE_TTL_S
        } else {
            ttl_seconds
        }
    }

    /// Accept (or refresh) a local pin.
    ///
    /// The record's `pinned_at` is reset to `now` and its `ttl_seconds` to the
    /// normalized wire TTL. Capacity is enforced by eviction, but the pin
    /// being inserted is exempt from eviction: the method returns a reference
    /// to it, so it must remain in the table.
    pub fn pin(
        &mut self,
        resource_id: &[u8],
        cid: &CidOrV1,
        ttl_seconds: u64,
        now: Timestamp,
    ) -> &PinRecord {
        let key = PinKey::new(resource_id, cid);
        let ttl = self.normalize_ttl(ttl_seconds);
        match self.pins.get_mut(&key) {
            Some(existing) => {
                existing.cid = *cid;
                existing.pinned_at = now;
                existing.ttl_seconds = ttl;
                existing.local = true;
            }
            None => {
                self.pins.insert(
                    key.clone(),
                    PinRecord {
                        resource_id: resource_id.to_vec(),
                        cid: *cid,
                        pinned_at: now,
                        ttl_seconds: ttl,
                        ref_count: 0,
                        local: true,
                    },
                );
                self.trim_to_capacity_exempt(&key);
            }
        }
        self.pins
            .get(&key)
            .expect("new pin is exempt from trim; existing pin is retained")
    }

    /// Record a pin announced by another peer (T3 `pin_announce`, or a `pin_list`
    /// response). The `ref_count` for the CID is incremented; a locally held pin
    /// stays `local`. Same eviction-exemption rule as [`Self::pin`].
    pub fn observe_remote(
        &mut self,
        resource_id: &[u8],
        cid: &CidOrV1,
        ttl_seconds: u64,
        now: Timestamp,
    ) -> &PinRecord {
        let key = PinKey::new(resource_id, cid);
        let ttl = self.normalize_ttl(ttl_seconds);
        match self.pins.get_mut(&key) {
            Some(existing) => {
                existing.ref_count = existing.ref_count.saturating_add(1);
                if existing.is_expired(now) {
                    existing.pinned_at = now;
                    existing.ttl_seconds = ttl;
                }
            }
            None => {
                self.pins.insert(
                    key.clone(),
                    PinRecord {
                        resource_id: resource_id.to_vec(),
                        cid: *cid,
                        pinned_at: now,
                        ttl_seconds: ttl,
                        ref_count: 1,
                        local: false,
                    },
                );
                self.trim_to_capacity_exempt(&key);
            }
        }
        self.pins
            .get(&key)
            .expect("new pin is exempt from trim; existing pin is retained")
    }

    /// Look up a single pin.
    pub fn get(&self, resource_id: &[u8], cid: &CidOrV1) -> Option<&PinRecord> {
        self.pins.get(&PinKey::new(resource_id, cid))
    }

    /// Drop `cid` for `resource_id`; `None` drops every version of the resource
    /// (`unpin` without a `cid`). Returns the number of records removed.
    pub fn unpin(&mut self, resource_id: &[u8], cid: Option<&CidOrV1>) -> usize {
        match cid {
            Some(cid) => {
                if self.pins.remove(&PinKey::new(resource_id, cid)).is_some() {
                    1
                } else {
                    0
                }
            }
            None => {
                let before = self.pins.len();
                self.pins.retain(|key, _| key.resource_id != resource_id);
                before - self.pins.len()
            }
        }
    }

    /// Reset the TTL of a held pin (the "refresh before expiry" path). Returns the
    /// updated record, or `None` if the pin is not held.
    pub fn refresh(
        &mut self,
        resource_id: &[u8],
        cid: &CidOrV1,
        ttl_seconds: u64,
        now: Timestamp,
    ) -> Option<&PinRecord> {
        let key = PinKey::new(resource_id, cid);
        let ttl = self.normalize_ttl(ttl_seconds);
        {
            let existing = self.pins.get_mut(&key)?;
            existing.pinned_at = now;
            existing.ttl_seconds = ttl;
        }
        self.pins.get(&key)
    }

    /// Answer a `query_pins` request.
    ///
    /// `resource_id` and `cid` are optional filters; both absent returns every
    /// pin. Expired pins are omitted because they are no longer held.
    pub fn query(
        &self,
        resource_id: Option<&[u8]>,
        cid: Option<&CidOrV1>,
        now: Timestamp,
    ) -> Vec<PinEntry> {
        let digest = cid.map(|c| *c.digest());
        self.pins
            .iter()
            .filter(|(key, _)| {
                resource_id
                    .map(|r| r == key.resource_id.as_slice())
                    .unwrap_or(true)
                    && digest.map(|d| d == key.digest).unwrap_or(true)
            })
            .map(|(_, record)| record)
            .filter(|record| !record.is_expired(now))
            .map(|record| record.to_entry(now))
            .collect()
    }

    /// Pins whose expiry has passed.
    pub fn expired(&self, now: Timestamp) -> Vec<&PinRecord> {
        self.pins
            .values()
            .filter(|record| record.is_expired(now))
            .collect()
    }

    /// Pins at or past the 80% refresh threshold (spec App. A.5).
    pub fn refresh_due(&self, now: Timestamp) -> Vec<&PinRecord> {
        self.pins
            .values()
            .filter(|record| record.needs_refresh(now))
            .collect()
    }

    /// Drop expired pins, returning how many were removed.
    pub fn sweep_expired(&mut self, now: Timestamp) -> usize {
        let before = self.pins.len();
        self.pins.retain(|_, record| !record.is_expired(now));
        before - self.pins.len()
    }

    /// Evict up to `count` pins: lowest `ref_count` first, then oldest
    /// `pinned_at`, then key order for determinism. Returns the number evicted.
    pub fn evict(&mut self, count: usize) -> usize {
        let mut evicted = 0;
        while evicted < count && self.evict_one_except(None) {
            evicted += 1;
        }
        evicted
    }

    /// Insert records verbatim (public restore path), enforcing capacity by
    /// eviction.
    pub fn restore<I: IntoIterator<Item = PinRecord>>(&mut self, records: I) {
        for record in records {
            let key = PinKey::new(&record.resource_id, &record.cid);
            self.pins.insert(key, record);
        }
        self.trim_to_capacity();
    }

    /// Insert records verbatim **without** enforcing capacity.
    ///
    /// Crate-internal: used only by
    /// [`crate::store::QuipStore::restore_snapshot`],
    /// where the input is trusted and silently dropping records would be
    /// a data-loss bug.
    pub(crate) fn restore_exact<I: IntoIterator<Item = PinRecord>>(&mut self, records: I) {
        for record in records {
            let key = PinKey::new(&record.resource_id, &record.cid);
            self.pins.insert(key, record);
        }
    }

    /// Evict until `len <= capacity`, never touching `exempt`.
    fn trim_to_capacity_exempt(&mut self, exempt: &PinKey) -> usize {
        let mut evicted = 0;
        while self.pins.len() > self.capacity && self.evict_one_except(Some(exempt)) {
            evicted += 1;
        }
        evicted
    }

    /// Evict until `len <= capacity`.
    fn trim_to_capacity(&mut self) -> usize {
        let mut evicted = 0;
        while self.pins.len() > self.capacity && self.evict_one_except(None) {
            evicted += 1;
        }
        evicted
    }

    /// Remove the single lowest-priority pin, optionally exempting one key.
    /// Returns false when no evictable pin remains.
    fn evict_one_except(&mut self, exempt: Option<&PinKey>) -> bool {
        let victim = self
            .pins
            .iter()
            .filter(|(k, _)| exempt.map(|e| *k != e).unwrap_or(true))
            .min_by_key(|(key, record)| (record.ref_count, record.pinned_at, (*key).clone()))
            .map(|(key, _)| key.clone());
        match victim {
            Some(key) => {
                self.pins.remove(&key);
                self.evictions += 1;
                true
            }
            None => false,
        }
    }
}

impl Default for PinTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::cid::Cid;

    fn cid(b: u8) -> CidOrV1 {
        CidOrV1::Raw(Cid([b; 32]))
    }

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn ttl_zero_selects_default_and_sentinel_is_indefinite() {
        let mut table = PinTable::new();
        let r = table.pin(b"res", &cid(1), 0, t(0));
        assert_eq!(r.ttl_seconds, DEFAULT_PIN_TTL_S);
        assert_eq!(
            r.expires_at(),
            Some(t(DEFAULT_PIN_TTL_S * 1_000)),
            "expiry is pinned_at + default ttl"
        );

        let r = table.pin(b"res", &cid(2), INDEFINITE_TTL_S, t(0));
        assert!(r.is_indefinite());
        assert_eq!(r.expires_at(), None);
        assert_eq!(r.remaining_seconds(t(0)), INDEFINITE_TTL_S);
        assert!(!r.is_expired(t(u64::MAX / 2)));
        assert!(!r.needs_refresh(t(u64::MAX / 2)));

        // Values above the sentinel clamp to it.
        assert_eq!(table.normalize_ttl(u64::MAX), INDEFINITE_TTL_S);
        assert_eq!(table.normalize_ttl(60), 60);
    }

    #[test]
    fn remaining_and_expiry_track_the_clock() {
        let mut table = PinTable::new();
        table.pin(b"res", &cid(1), 100, t(0));
        let r = table.get(b"res", &cid(1)).unwrap();
        assert_eq!(r.remaining_seconds(t(40_000)), 60);
        assert!(!r.is_expired(t(99_000)));
        assert!(r.is_expired(t(100_000)));
        assert_eq!(r.remaining_seconds(t(500_000)), 0);
    }

    #[test]
    fn refresh_is_due_at_eighty_percent() {
        let mut table = PinTable::new();
        table.pin(b"res", &cid(1), 100, t(0));
        let r = table.get(b"res", &cid(1)).unwrap();
        assert!(!r.needs_refresh(t(79_000)));
        assert!(r.needs_refresh(t(80_000)));
        assert_eq!(table.refresh_due(t(80_000)).len(), 1);
        assert!(table.refresh_due(t(10_000)).is_empty());
    }

    #[test]
    fn refresh_resets_pinned_at() {
        let mut table = PinTable::new();
        table.pin(b"res", &cid(1), 100, t(0));
        let r = table.refresh(b"res", &cid(1), 0, t(90_000)).unwrap();
        assert_eq!(r.pinned_at, t(90_000));
        assert_eq!(r.ttl_seconds, DEFAULT_PIN_TTL_S);
        assert!(!r.is_expired(t(90_000)));
        assert!(table.refresh(b"res", &cid(9), 0, t(0)).is_none());
    }

    #[test]
    fn query_filters_and_converts_to_pin_entry() {
        let mut table = PinTable::new();
        table.pin(b"a", &cid(1), 100, t(0));
        table.pin(b"b", &cid(2), 100, t(0));
        assert_eq!(table.query(None, None, t(0)).len(), 2);
        let one = table.query(Some(b"a"), None, t(0));
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].resource_id, b"a".to_vec());
        assert_eq!(one[0].ttl_seconds, 100, "wire ttl is the remaining ttl");
        assert!(one[0].local);
        assert_eq!(table.query(None, Some(&cid(2)), t(0)).len(), 1);
        assert!(table.query(Some(b"zzz"), None, t(0)).is_empty());
        // Expired pins are not reported.
        assert!(table.query(Some(b"a"), None, t(200_000)).is_empty());
    }

    #[test]
    fn unpin_one_or_all_versions() {
        let mut table = PinTable::new();
        table.pin(b"a", &cid(1), 0, t(0));
        table.pin(b"a", &cid(2), 0, t(0));
        table.pin(b"b", &cid(3), 0, t(0));
        assert_eq!(table.unpin(b"a", Some(&cid(1))), 1);
        assert!(table.get(b"a", &cid(1)).is_none());
        assert_eq!(table.unpin(b"a", Some(&cid(1))), 0);
        assert_eq!(table.unpin(b"a", None), 1, "removes every remaining version");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn sweep_expired_only_drops_dead_pins() {
        let mut table = PinTable::new();
        table.pin(b"a", &cid(1), 100, t(0));
        table.pin(b"b", &cid(2), INDEFINITE_TTL_S, t(0));
        assert_eq!(table.expired(t(200_000)).len(), 1);
        assert_eq!(table.sweep_expired(t(200_000)), 1);
        assert_eq!(table.len(), 1);
        assert_eq!(table.sweep_expired(t(200_000)), 0);
    }

    #[test]
    fn eviction_prefers_low_ref_count_then_age() {
        let mut table = PinTable::with_capacity(10);
        table.pin(b"keep", &cid(1), 0, t(0));
        table.observe_remote(b"keep", &cid(1), 0, t(0)); // ref_count = 2
        table.pin(b"cold", &cid(2), 0, t(5_000));
        table.pin(b"colder", &cid(3), 0, t(1_000));
        assert_eq!(table.len(), 3);

        let dropped = table.set_capacity(1);
        assert_eq!(dropped, 2);
        // "keep" survives on ref_count even though it is the oldest.
        assert!(table.get(b"keep", &cid(1)).is_some());
        assert!(table.get(b"cold", &cid(2)).is_none());
        assert!(table.get(b"colder", &cid(3)).is_none());
        assert_eq!(table.evictions(), 2);
    }

    #[test]
    fn inserting_into_a_full_table_evicts_and_keeps_the_new_pin() {
        let mut table = PinTable::with_capacity(2);
        table.pin(b"a", &cid(1), 0, t(0));
        table.pin(b"b", &cid(2), 0, t(0));
        table.pin(b"c", &cid(3), 0, t(10_000));
        assert_eq!(table.len(), 2, "capacity is respected");
        assert!(table.get(b"c", &cid(3)).is_some(), "newest pin is retained");
        assert!(table.get(b"a", &cid(1)).is_none(), "oldest pin was evicted");
    }

    #[test]
    fn pin_does_not_panic_when_the_new_pin_is_lowest_priority() {
        // Regression test: inserting a pin into a full table used to trim
        // without exempting the new pin, which could evict it before the
        // method returned a reference — causing the `.expect(...)` to panic.
        let mut table = PinTable::with_capacity(1);
        table.pin(b"z", &cid(1), 0, t(0));
        // Lexicographically smaller key, same age and ref_count: would have
        // been the eviction victim under the old tie-break.
        let second = table.pin(b"a", &cid(2), 0, t(0));
        assert_eq!(second.resource_id, b"a");
        assert!(table.get(b"a", &cid(2)).is_some());
    }

    #[test]
    fn remote_observation_increments_ref_count_and_keeps_local_flag() {
        let mut table = PinTable::new();
        table.observe_remote(b"a", &cid(1), 0, t(0));
        let r = table.observe_remote(b"a", &cid(1), 0, t(1_000));
        assert_eq!(r.ref_count, 2);
        assert!(!r.local);
        table.pin(b"a", &cid(1), 0, t(2_000));
        let r = table.get(b"a", &cid(1)).unwrap();
        assert!(r.local);
        assert_eq!(r.ref_count, 2, "a local pin keeps the observed ref_count");
    }

    #[test]
    fn restore_reapplies_capacity() {
        let mut table = PinTable::with_capacity(10);
        table.pin(b"a", &cid(1), 0, t(0));
        table.pin(b"b", &cid(2), 0, t(0));
        let records: Vec<PinRecord> = table.records().cloned().collect();

        let mut restored = PinTable::with_capacity(1);
        restored.restore(records);
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn restore_exact_ignores_capacity() {
        let mut table = PinTable::with_capacity(1);
        let records = alloc::vec![
            PinRecord {
                resource_id: b"a".to_vec(),
                cid: cid(1),
                pinned_at: t(0),
                ttl_seconds: 60,
                ref_count: 0,
                local: true,
            },
            PinRecord {
                resource_id: b"b".to_vec(),
                cid: cid(2),
                pinned_at: t(0),
                ttl_seconds: 60,
                ref_count: 0,
                local: true,
            },
        ];
        table.restore_exact(records);
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn pin_record_round_trips_through_cbor() {
        let mut table = PinTable::new();
        table.pin(b"res", &cid(1), 4_000, t(1_700_000_000_000));
        let record = table.get(b"res", &cid(1)).unwrap();
        let bytes = quip_core::cbor::encode(&record.to_cbor()).unwrap();
        let decoded = quip_core::cbor::decode(&bytes).unwrap();
        let back = PinRecord::from_cbor(&decoded).unwrap();
        assert_eq!(&back, record);
        assert_eq!(
            back.ttl_seconds, 4_000,
            "snapshot ttl is the full ttl, not the remainder"
        );
    }

    #[test]
    fn cbor_rejects_unknown_keys() {
        let value = CborValue::Map(alloc::vec![(
            CborValue::String("surprise".into()),
            CborValue::Int(1),
        )]);
        assert!(PinRecord::from_cbor(&value).is_err());
    }
}