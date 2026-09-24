//! Cached bao chunk trees for range responses (M7 hardening; spec §8.2,
//! App. A.4).
//!
//! §8.2 ("Responder Without a Cached Chunk Tree") requires a responder to
//! either recompute a resource's chunk tree on demand or reject the
//! request, and says a responder **SHOULD** cache the tree so that later
//! requests are `O(log(resource_size))` instead of `O(resource_size)`.
//! §A.4 lists the same point as a performance factor and names
//! recomputation a CPU amplification vector.
//!
//! [`BaoCache`] holds the *outboard* form of a resource's bao encoding:
//! the parent nodes, and no payload bytes. For a resource of `n` bytes
//! the outboard is `64 * (ceil(n / 1024) - 1) + 8` bytes, about 6.25% of
//! `n`, against roughly 106% for the combined encoding. A 1 MiB resource
//! caches in 65,480 bytes. Both forms yield byte-identical slice proofs,
//! so caching an outboard changes the responder's cost model and nothing
//! on the wire.
//!
//! # Keying
//!
//! Entries are keyed by the BLAKE3 digest of the payload.
//! [`BaoCache::insert`] obtains the digest as a side effect of building
//! the outboard — `bao::encode::outboard` returns the root hash along
//! with the tree — so an entry that does not match its key is rejected
//! rather than stored, at no extra hashing cost.
//!
//! # Trust boundary
//!
//! [`BaoCache::get`] takes the payload length and refuses to match an
//! entry of a different length, but it does **not** re-hash the payload.
//! Re-hashing would cost `O(n)` and defeat the cache. Callers must pass
//! the payload that matches the CID, exactly as
//! [`crate::range::bao_support::extract_proof`] already requires. A
//! mismatched payload yields a proof the *client* rejects; it cannot be
//! caught server-side without paying the cost the cache exists to avoid.
//!
//! # No expiry
//!
//! Outboards are content-addressed and immutable, so unlike
//! [`SpilloverResponseCache`](crate::discovery::SpilloverResponseCache)
//! and [`WitnessRingCache`](crate::dht::WitnessRingCache) this cache has
//! no TTL and no `sweep`. Eviction is driven by size alone, least
//! recently used first.
//!
//! # Limits
//!
//! [`DEFAULT_BAO_CACHE_ENTRIES`], [`DEFAULT_BAO_CACHE_BYTES`] and
//! [`DEFAULT_BAO_CACHE_ENTRY_BYTES`] are implementation choices, not spec
//! values; §8.2 leaves the caching policy local. Use
//! [`BaoCache::with_limits`] to change them.

use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use quip_core::cid::CidOrV1;
use quip_core::time::Timestamp;

/// Default entry capacity of [`BaoCache`].
///
/// Implementation choice, not spec-mandated. Bounds the map itself;
/// [`DEFAULT_BAO_CACHE_BYTES`] bounds the memory behind it.
pub const DEFAULT_BAO_CACHE_ENTRIES: usize = 64;

/// Default byte budget of [`BaoCache`], counting outboard bytes only.
///
/// Implementation choice. 64 MiB bounds the worst-case heap the cache
/// holds; see [`BaoCache`] for the eviction rule.
pub const DEFAULT_BAO_CACHE_BYTES: usize = 64 * 1024 * 1024;

/// Default per-entry cap on a single outboard.
///
/// Implementation choice. An outboard is about 6.25% of its payload, so
/// this admits resources up to roughly 64 MiB and declines to cache
/// anything larger, which would otherwise evict the entire cache on
/// insert.
pub const DEFAULT_BAO_CACHE_ENTRY_BYTES: usize = 4 * 1024 * 1024;

// -------------------------------------------------------------------------
// CachedTree
// -------------------------------------------------------------------------

/// One cached chunk tree: the outboard encoding of a single resource.
///
/// Holds no payload bytes, so it is reusable only alongside the blob it
/// was built from. [`BaoCache::get`] enforces the payload length; the
/// digest is enforced at insert time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CachedTree {
    digest: [u8; 32],
    outboard: Vec<u8>,
    payload_len: u64,
    last_used: Timestamp,
}

impl CachedTree {
    /// The BLAKE3 digest this tree was built for, and is keyed by.
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    /// The outboard encoding: bao parent nodes, in pre-order.
    ///
    /// Feed this to `bao::encode::SliceExtractor::new_outboard` alongside
    /// the original payload to produce a slice proof.
    pub fn outboard(&self) -> &[u8] {
        &self.outboard
    }

    /// Length in bytes of the payload this tree was built from.
    pub fn payload_len(&self) -> u64 {
        self.payload_len
    }

    /// When this entry was last matched by [`BaoCache::get`], or inserted.
    pub fn last_used(&self) -> Timestamp {
        self.last_used
    }

    /// Heap cost of this entry, which is what the cache accounts for.
    pub fn size_bytes(&self) -> usize {
        self.outboard.len()
    }
}

// -------------------------------------------------------------------------
// CacheStats
// -------------------------------------------------------------------------

/// Counters for a [`BaoCache`].
///
/// `hits` and `misses` count [`BaoCache::get`] calls only;
/// [`BaoCache::peek`] and [`BaoCache::contains`] observe without counting.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Lookups that matched a fresh-enough entry of the right length.
    pub hits: u64,
    /// Lookups that did not match.
    pub misses: u64,
    /// Entries currently held.
    pub entries: usize,
    /// Outboard bytes currently held.
    pub used_bytes: usize,
}

impl CacheStats {
    /// Total lookups counted.
    pub fn lookups(&self) -> u64 {
        self.hits + self.misses
    }
}

// -------------------------------------------------------------------------
// BaoCache
// -------------------------------------------------------------------------

/// A size-bounded, least-recently-used cache of bao chunk trees.
///
/// Keyed by BLAKE3 digest. See the module docs for the trust boundary and
/// for why there is no TTL.
#[derive(Clone, Debug)]
pub struct BaoCache {
    entries: BTreeMap<[u8; 32], CachedTree>,
    max_entries: usize,
    max_bytes: usize,
    max_entry_bytes: usize,
    used_bytes: usize,
    hits: u64,
    misses: u64,
}

impl BaoCache {
    /// A cache with the default limits.
    pub fn new() -> Self {
        Self::with_limits(
            DEFAULT_BAO_CACHE_ENTRIES,
            DEFAULT_BAO_CACHE_BYTES,
            DEFAULT_BAO_CACHE_ENTRY_BYTES,
        )
    }

    /// A cache with explicit limits, in outboard bytes.
    ///
    /// `max_entries` and `max_bytes` are clamped to at least 1 so that an
    /// insert always has somewhere to go. `max_entry_bytes` bounds a
    /// single resource's tree; a tree larger than that is declined by
    /// [`BaoCache::insert_outboard`] rather than cached and immediately
    /// evicted.
    pub fn with_limits(max_entries: usize, max_bytes: usize, max_entry_bytes: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            max_entry_bytes,
            used_bytes: 0,
            hits: 0,
            misses: 0,
        }
    }

    /// Configured entry-count ceiling.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Configured byte budget.
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }

    /// Configured per-entry byte ceiling.
    pub fn max_entry_bytes(&self) -> usize {
        self.max_entry_bytes
    }

    /// Outboard bytes currently held.
    pub fn used_bytes(&self) -> usize {
        self.used_bytes
    }

    /// Number of entries held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if no entries are held.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True if `cid` is held, at any payload length.
    pub fn contains(&self, cid: &CidOrV1) -> bool {
        self.entries.contains_key(cid.digest())
    }

    /// Current counters.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            hits: self.hits,
            misses: self.misses,
            entries: self.entries.len(),
            used_bytes: self.used_bytes,
        }
    }
}

impl Default for BaoCache {
    fn default() -> Self {
        Self::new()
    }
}

// -------------------------------------------------------------------------
// Operations
// -------------------------------------------------------------------------

impl BaoCache {
    /// Build and cache the chunk tree for `payload`, keyed by `cid`.
    ///
    /// Costs `O(payload.len())` — one bao encoding pass — so this is the
    /// write-time hook §8.2 describes ("cache the chunk tree alongside the
    /// blob when the resource is written with `merkle_range` enabled").
    ///
    /// The payload is checked against `cid` as a side effect of the
    /// encoding, so a mismatch is an error rather than a poisoned entry.
    ///
    /// Returns `Ok(true)` if the tree was stored, `Ok(false)` if it was
    /// declined because it exceeds the per-entry cap.
    pub fn insert(&mut self, cid: &CidOrV1, payload: &[u8], now: Timestamp) -> Result<bool> {
        let (outboard, root) = ::bao::encode::outboard(payload);
        if *root.as_bytes() != *cid.digest() {
            return Err(Error::ProofInvalid(
                "payload does not hash to the CID it would be cached under",
            ));
        }
        self.insert_outboard(*cid.digest(), payload.len() as u64, outboard, now)
    }

    /// Cache a chunk tree the caller already holds.
    ///
    /// The outboard's length is checked against the length bao computes for
    /// `payload_len`, which catches a truncated or corrupt tree in `O(1)`
    /// without re-hashing the payload. That makes this the right entry
    /// point for a tree loaded from disk next to its blob.
    ///
    /// Returns `Ok(true)` if stored, `Ok(false)` if declined because it
    /// exceeds the per-entry cap.
    pub fn insert_outboard(
        &mut self,
        digest: [u8; 32],
        payload_len: u64,
        outboard: Vec<u8>,
        now: Timestamp,
    ) -> Result<bool> {
        let expected = ::bao::encode::outboard_size(payload_len);
        if outboard.len() as u128 != expected {
            return Err(Error::ProofInvalid(
                "outboard length does not match the payload length",
            ));
        }

        let size = outboard.len();
        if size > self.max_entry_bytes {
            return Ok(false);
        }

        // Drop any previous tree for this digest before accounting for the
        // new one, so a refresh neither double-counts nor evicts itself.
        if let Some(old) = self.entries.remove(&digest) {
            self.used_bytes -= old.outboard.len();
        }

        while self.used_bytes + size > self.max_bytes || self.entries.len() >= self.max_entries {
            if !self.evict_lru() {
                break;
            }
        }

        if size > self.max_bytes {
            return Ok(false);
        }

        self.entries.insert(
            digest,
            CachedTree {
                digest,
                outboard,
                payload_len,
                last_used: now,
            },
        );
        self.used_bytes += size;
        Ok(true)
    }

    /// Look up the tree for `cid`, requiring a payload of `payload_len`.
    ///
    /// Counts a hit or a miss, and on a hit records `now` as the entry's
    /// last use. A length mismatch is a miss: the cached tree cannot
    /// describe a payload of a different size, and serving it would
    /// produce a proof that cannot verify.
    pub fn get(&mut self, cid: &CidOrV1, payload_len: u64, now: Timestamp) -> Option<&CachedTree> {
        let digest = *cid.digest();
        match self.entries.get_mut(&digest) {
            Some(entry) if entry.payload_len == payload_len => {
                entry.last_used = now;
                self.hits += 1;
                Some(&*entry)
            }
            _ => {
                self.misses += 1;
                None
            }
        }
    }

    /// Look up the tree for `cid` without touching the LRU order or the
    /// hit/miss counters.
    pub fn peek(&self, cid: &CidOrV1) -> Option<&CachedTree> {
        self.entries.get(cid.digest())
    }

    /// Drop the tree for `cid`, if present.
    pub fn remove(&mut self, cid: &CidOrV1) -> Option<CachedTree> {
        let removed = self.entries.remove(cid.digest());
        if let Some(entry) = &removed {
            self.used_bytes -= entry.outboard.len();
        }
        removed
    }

    /// Drop every tree. Counters are left alone.
    pub fn clear(&mut self) {
        self.entries.clear();
        self.used_bytes = 0;
    }

    /// Evict the least recently used entry. Returns false if the cache is
    /// already empty.
    ///
    /// Scans the map for the smallest `last_used`. `BTreeMap` is ordered by
    /// digest, which carries no recency information, so there is no
    /// cheaper key to evict on; the scan is bounded by
    /// [`BaoCache::max_entries`].
    fn evict_lru(&mut self) -> bool {
        let victim = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(digest, _)| *digest);

        match victim {
            Some(digest) => {
                if let Some(entry) = self.entries.remove(&digest) {
                    self.used_bytes -= entry.outboard.len();
                }
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use quip_core::cid::{CidV1, HashAlgo};

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    fn cid_of(payload: &[u8]) -> CidOrV1 {
        CidOrV1::V1(CidV1 {
            hash_algo: HashAlgo::Blake3,
            digest: *::blake3::hash(payload).as_bytes(),
        })
    }

    /// A payload whose outboard is a known size: 4 KiB is four chunks, so
    /// three parent nodes of 64 bytes plus the 8-byte header.
    fn four_kib(seed: u8) -> Vec<u8> {
        vec![seed; 4096]
    }

    /// Generous per-entry cap, so a test only exercises the knob it names.
    const HUGE: usize = 64 * 1024 * 1024;

    // ---- insert + get ----

    #[test]
    fn insert_then_get_is_a_hit() {
        let payload = four_kib(1);
        let cid = cid_of(&payload);
        let mut cache = BaoCache::new();

        assert!(cache.insert(&cid, &payload, t(0)).unwrap());
        assert_eq!(cache.len(), 1);

        let hit = cache.get(&cid, payload.len() as u64, t(10)).unwrap();
        assert_eq!(hit.digest(), cid.digest());
        assert_eq!(hit.payload_len(), payload.len() as u64);
        assert_eq!(hit.last_used(), t(10));

        let stats = cache.stats();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
        assert_eq!(stats.lookups(), 1);
    }

    #[test]
    fn get_on_absent_key_misses() {
        let payload = four_kib(1);
        let mut cache = BaoCache::new();
        assert!(cache
            .get(&cid_of(&payload), payload.len() as u64, t(0))
            .is_none());
        assert_eq!(cache.stats().misses, 1);
        assert_eq!(cache.stats().hits, 0);
    }

    #[test]
    fn get_rejects_a_different_payload_len() {
        let payload = four_kib(1);
        let cid = cid_of(&payload);
        let mut cache = BaoCache::new();
        cache.insert(&cid, &payload, t(0)).unwrap();

        // Same digest, wrong length: must not match.
        assert!(cache.get(&cid, payload.len() as u64 + 1, t(1)).is_none());
        assert_eq!(cache.stats().misses, 1);
        // The entry itself is untouched.
        assert!(cache.peek(&cid).is_some());
        assert_eq!(cache.stats().entries, 1);
    }

    #[test]
    fn insert_rejects_payload_cid_mismatch() {
        let payload = four_kib(1);
        let other = four_kib(2);
        let mut cache = BaoCache::new();

        let err = cache.insert(&cid_of(&other), &payload, t(0)).unwrap_err();
        assert!(matches!(err, Error::ProofInvalid(_)), "got {err:?}");
        assert!(cache.is_empty(), "a mismatched insert must cache nothing");
        assert_eq!(cache.used_bytes(), 0);
    }

    #[test]
    fn insert_outboard_rejects_a_wrong_length() {
        let payload = four_kib(1);
        let (outboard, _) = ::bao::encode::outboard(&payload);
        let digest = *cid_of(&payload).digest();
        let mut cache = BaoCache::new();

        // One byte short of the length bao computes for this payload.
        let err = cache
            .insert_outboard(digest, payload.len() as u64, outboard[1..].to_vec(), t(0))
            .unwrap_err();
        assert!(matches!(err, Error::ProofInvalid(_)), "got {err:?}");

        // A one-byte payload is a single chunk, so it has no parent nodes
        // and its outboard is just the header. Nine bytes cannot be right.
        assert_eq!(::bao::encode::outboard_size(1), 8);
        let err = cache.insert_outboard(digest, 1, vec![0; 9], t(0)).unwrap_err();
        assert!(matches!(err, Error::ProofInvalid(_)), "got {err:?}");
        assert!(cache.is_empty());
    }

    #[test]
    fn insert_outboard_accepts_a_correct_length() {
        let payload = four_kib(1);
        let (outboard, _) = ::bao::encode::outboard(&payload);
        let mut cache = BaoCache::new();

        assert!(cache
            .insert_outboard(*cid_of(&payload).digest(), payload.len() as u64, outboard, t(0))
            .unwrap());
        assert_eq!(cache.len(), 1);
    }

    // ---- sizing ----

    #[test]
    fn outboard_is_about_one_sixteenth_of_the_payload() {
        // The claim the whole cache rests on. 1 MiB is 1024 chunks, so 1023
        // parent nodes of 64 bytes, plus the 8-byte header.
        let payload = vec![7u8; 1024 * 1024];
        let cid = cid_of(&payload);
        let mut cache = BaoCache::new();
        cache.insert(&cid, &payload, t(0)).unwrap();

        let outboard_len = cache.peek(&cid).unwrap().outboard().len();
        assert_eq!(outboard_len, 64 * (1024 - 1) + 8);
        assert_eq!(outboard_len, 65_480);
        assert!(outboard_len < payload.len() / 16 + 16);
    }

    #[test]
    fn size_bytes_matches_used_bytes() {
        let payload = four_kib(1);
        let cid = cid_of(&payload);
        let mut cache = BaoCache::new();
        cache.insert(&cid, &payload, t(0)).unwrap();

        let entry_size = cache.peek(&cid).unwrap().size_bytes();
        assert_eq!(entry_size, 3 * 64 + 8);
        assert_eq!(cache.used_bytes(), entry_size);
    }

    // ---- limits and eviction ----

    #[test]
    fn entry_cap_declines_a_tree_that_is_too_large() {
        let payload = four_kib(1);
        let cid = cid_of(&payload);
        let mut cache = BaoCache::with_limits(100, HUGE, 8);

        assert!(!cache.insert(&cid, &payload, t(0)).unwrap());
        assert!(cache.is_empty());
        assert_eq!(cache.used_bytes(), 0);
    }

    #[test]
    fn byte_budget_evicts_and_keeps_accounting_honest() {
        // Three same-sized trees; a budget that holds exactly two.
        const TREE: usize = 3 * 64 + 8;
        let a = four_kib(1);
        let b = four_kib(2);
        let c = four_kib(3);
        let mut cache = BaoCache::with_limits(100, 2 * TREE, HUGE);

        assert!(cache.insert(&cid_of(&a), &a, t(0)).unwrap());
        assert!(cache.insert(&cid_of(&b), &b, t(1)).unwrap());
        assert_eq!(cache.used_bytes(), 2 * TREE);

        assert!(cache.insert(&cid_of(&c), &c, t(2)).unwrap());
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.used_bytes(), 2 * TREE, "accounting must not drift");

        assert!(!cache.contains(&cid_of(&a)), "oldest should be evicted");
        assert!(cache.contains(&cid_of(&b)));
        assert!(cache.contains(&cid_of(&c)));
    }

    #[test]
    fn eviction_is_lru_not_fifo() {
        let a = four_kib(1);
        let b = four_kib(2);
        let c = four_kib(3);
        let mut cache = BaoCache::with_limits(2, HUGE, HUGE);

        cache.insert(&cid_of(&a), &a, t(0)).unwrap();
        cache.insert(&cid_of(&b), &b, t(1)).unwrap();

        // Touch `a`, so `b` becomes the least recently used.
        assert!(cache.get(&cid_of(&a), a.len() as u64, t(2)).is_some());

        cache.insert(&cid_of(&c), &c, t(3)).unwrap();

        assert!(
            cache.contains(&cid_of(&a)),
            "a was used most recently and must survive"
        );
        assert!(!cache.contains(&cid_of(&b)), "b was least recently used");
        assert!(cache.contains(&cid_of(&c)));
    }

    #[test]
    fn max_entries_is_enforced() {
        let mut cache = BaoCache::with_limits(2, HUGE, HUGE);
        for seed in 1..=5u8 {
            let payload = four_kib(seed);
            cache
                .insert(&cid_of(&payload), &payload, t(u64::from(seed)))
                .unwrap();
        }
        assert_eq!(cache.len(), 2, "entry ceiling must hold");
    }

    #[test]
    fn declined_when_the_tree_exceeds_the_whole_budget() {
        let payload = four_kib(1);
        let mut cache = BaoCache::with_limits(100, 8, HUGE);
        assert!(!cache.insert(&cid_of(&payload), &payload, t(0)).unwrap());
        assert!(cache.is_empty());
    }

    #[test]
    fn refreshing_an_entry_does_not_double_count() {
        let payload = four_kib(1);
        let cid = cid_of(&payload);
        let mut cache = BaoCache::new();

        cache.insert(&cid, &payload, t(0)).unwrap();
        let after_first = cache.used_bytes();
        cache.insert(&cid, &payload, t(1)).unwrap();

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.used_bytes(), after_first);
        assert_eq!(cache.stats().entries, 1);
    }

    // ---- housekeeping ----

    #[test]
    fn remove_and_clear_release_bytes() {
        let payload = four_kib(1);
        let cid = cid_of(&payload);
        let mut cache = BaoCache::new();
        cache.insert(&cid, &payload, t(0)).unwrap();

        // A key that was never inserted does not match.
        let other = CidOrV1::V1(CidV1 {
            hash_algo: HashAlgo::Sha256,
            digest: [9u8; 32],
        });
        assert!(cache.remove(&other).is_none());

        let removed = cache.remove(&cid).expect("entry should be present");
        assert_eq!(removed.digest(), cid.digest());
        assert_eq!(cache.used_bytes(), 0);
        assert!(cache.is_empty());

        cache.insert(&cid, &payload, t(2)).unwrap();
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.used_bytes(), 0);
    }

    #[test]
    fn peek_does_not_count_or_touch() {
        let payload = four_kib(1);
        let cid = cid_of(&payload);
        let mut cache = BaoCache::new();
        cache.insert(&cid, &payload, t(0)).unwrap();

        assert!(cache.peek(&cid).is_some());
        assert_eq!(cache.peek(&cid).unwrap().last_used(), t(0));
        assert_eq!(cache.stats().lookups(), 0, "peek must not count");
    }

    #[test]
    fn limits_are_clamped_to_at_least_one() {
        let cache = BaoCache::with_limits(0, 0, 0);
        assert_eq!(cache.max_entries(), 1);
        assert_eq!(cache.max_bytes(), 1);
        assert_eq!(cache.max_entry_bytes(), 0);
    }

    #[test]
    fn default_matches_new() {
        let cache = BaoCache::default();
        assert_eq!(cache.max_entries(), DEFAULT_BAO_CACHE_ENTRIES);
        assert_eq!(cache.max_bytes(), DEFAULT_BAO_CACHE_BYTES);
        assert_eq!(cache.max_entry_bytes(), DEFAULT_BAO_CACHE_ENTRY_BYTES);
    }

    #[test]
    fn empty_cache_reports_empty_stats() {
        let cache = BaoCache::new();
        let stats = cache.stats();
        assert_eq!(stats, CacheStats::default());
        assert_eq!(stats.lookups(), 0);
        assert!(cache.is_empty());
    }
}
