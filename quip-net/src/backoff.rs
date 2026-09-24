//! Per-key exponential backoff (§19.4).
//!
//! §19.4 lists "exponential backoff after repeated protocol errors from
//! the same NodeId, capped at 60 seconds between retries" as a RECOMMENDED
//! DoS mitigation. This module is that policy.
//!
//! The tracker is a plain state container: no clock, no I/O. Callers pass
//! `now: Timestamp` on every call, matching the rest of `quip-net`.
//!
//! # Semantics
//!
//! After `n` consecutive failures against a key, the next permitted
//! attempt is at `last_failure + min(base * 2^(n - 1), cap)`. A success
//! clears the key's failure count and permits the next attempt
//! immediately. A key that has never failed is always permitted.
//!
//! Keys are generic and `Ord + Clone`. The transport driver keys on the
//! peer `NodeId`; the NAT driver keys on the peer being probed; a DHT
//! layer might key on the target.
//!
//! # Bounds
//!
//! The tracker holds at most `max_keys` entries. When the map is full, a
//! new key evicts the entry with the smallest `next_retry_at`.

use alloc::collections::BTreeMap;
use quip_core::time::Timestamp;

/// Default base delay: one second.
pub const DEFAULT_BASE_MS: u64 = 1_000;

/// Default cap on the delay: 60 seconds, per §19.4.
pub const DEFAULT_MAX_MS: u64 = 60_000;

/// Default ceiling on tracked keys.
pub const DEFAULT_MAX_KEYS: usize = 10_000;

#[derive(Clone, Debug)]
struct Entry {
    consecutive_failures: u32,
    next_retry_at: Timestamp,
}

/// A per-key exponential backoff tracker.
#[derive(Clone, Debug)]
pub struct BackoffTracker<K: Ord + Clone> {
    entries: BTreeMap<K, Entry>,
    base_ms: u64,
    max_ms: u64,
    max_keys: usize,
}

impl<K: Ord + Clone> BackoffTracker<K> {
    /// A tracker with the §19.4 defaults: 1 s base, 60 s cap, 10 000 keys.
    pub fn new() -> Self {
        Self::with_config(DEFAULT_BASE_MS, DEFAULT_MAX_MS, DEFAULT_MAX_KEYS)
    }

    /// A tracker with explicit base, cap, and key ceiling.
    pub fn with_config(base_ms: u64, max_ms: u64, max_keys: usize) -> Self {
        let base_ms = base_ms.max(1);
        let max_ms = max_ms.max(base_ms);
        Self {
            entries: BTreeMap::new(),
            base_ms,
            max_ms,
            max_keys: max_keys.max(1),
        }
    }

    /// The configured base delay in milliseconds.
    pub fn base_ms(&self) -> u64 {
        self.base_ms
    }

    /// The configured cap in milliseconds.
    pub fn max_ms(&self) -> u64 {
        self.max_ms
    }

    /// The configured key ceiling.
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }

    /// Number of keys currently tracked.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when no keys are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The consecutive failure count for `key`, or 0.
    pub fn failures(&self, key: &K) -> u32 {
        self.entries.get(key).map_or(0, |e| e.consecutive_failures)
    }

    /// True if `key` may attempt an operation at `now`.
    pub fn can_attempt(&self, key: &K, now: Timestamp) -> bool {
        self.entries
            .get(key)
            .map_or(true, |entry| now >= entry.next_retry_at)
    }

    /// The next permitted attempt time for `key`, if it is currently
    /// backed off. `None` if the key has no backoff state or its backoff
    /// has expired.
    pub fn next_retry_at(&self, key: &K, now: Timestamp) -> Option<Timestamp> {
        self.entries
            .get(key)
            .filter(|entry| entry.next_retry_at > now)
            .map(|entry| entry.next_retry_at)
    }

    /// The remaining backoff duration in milliseconds, or `None`.
    pub fn remaining_ms(&self, key: &K, now: Timestamp) -> Option<u64> {
        let next = self.next_retry_at(key, now)?;
        Some(next.as_millis().saturating_sub(now.as_millis()))
    }

    /// Record a failure for `key` at `now`, updating its backoff.
    ///
    /// Returns the time at which the next attempt is permitted.
    pub fn record_failure(&mut self, key: K, now: Timestamp) -> Timestamp {
        if !self.entries.contains_key(&key) {
            self.ensure_capacity();
        }

        // Read the config fields before taking a mutable borrow on
        // `self.entries`. `delay_for` needs them but does not need
        // `self`; passing them as arguments avoids a borrow conflict
        // with the `entry()` mutable borrow below.
        let base_ms = self.base_ms;
        let max_ms = self.max_ms;

        let entry = self.entries.entry(key).or_insert(Entry {
            consecutive_failures: 0,
            next_retry_at: now,
        });
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        let delay = delay_for(base_ms, max_ms, entry.consecutive_failures);
        entry.next_retry_at =
            Timestamp::from_millis(now.as_millis().saturating_add(delay));
        entry.next_retry_at
    }

    /// Record a success for `key`: clear its backoff state.
    ///
    /// Returns the number of consecutive failures the key had accumulated.
    pub fn record_success(&mut self, key: &K) -> u32 {
        self.entries.remove(key).map_or(0, |e| e.consecutive_failures)
    }

    /// Forget `key` without recording a success.
    pub fn forget(&mut self, key: &K) -> bool {
        self.entries.remove(key).is_some()
    }

    /// Drop entries whose backoff has expired at `now`.
    ///
    /// Returns the number removed. Callers SHOULD invoke this
    /// periodically to bound the map.
    pub fn sweep(&mut self, now: Timestamp) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| entry.next_retry_at > now);
        before - self.entries.len()
    }

    fn ensure_capacity(&mut self) {
        if self.entries.len() < self.max_keys {
            return;
        }
        if let Some(victim) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.next_retry_at)
            .map(|(k, _)| k.clone())
        {
            self.entries.remove(&victim);
        }
    }
}

impl<K: Ord + Clone> Default for BackoffTracker<K> {
    fn default() -> Self {
        Self::new()
    }
}

/// Compute the backoff delay for `failures` consecutive failures, given
/// `base_ms` and `max_ms`.
///
/// A free function rather than a method: `record_failure` calls it while
/// holding a mutable borrow on `self.entries`, and a method call would
/// require `&self`, which overlaps.
fn delay_for(base_ms: u64, max_ms: u64, failures: u32) -> u64 {
    let shift = failures.saturating_sub(1).min(31);
    let base = base_ms.saturating_mul(1u64 << shift);
    base.min(max_ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(ms: u64) -> Timestamp {
        Timestamp::from_millis(ms)
    }

    #[test]
    fn new_key_can_attempt_immediately() {
        let b: BackoffTracker<u8> = BackoffTracker::new();
        assert!(b.can_attempt(&1, t(0)));
        assert_eq!(b.failures(&1), 0);
        assert_eq!(b.next_retry_at(&1, t(0)), None);
    }

    #[test]
    fn first_failure_backs_off_by_base() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 10);
        assert_eq!(b.record_failure(1, t(0)), t(1000));
        assert!(!b.can_attempt(&1, t(500)));
        assert!(b.can_attempt(&1, t(1000)));
        assert_eq!(b.failures(&1), 1);
    }

    #[test]
    fn backoff_doubles_each_failure_up_to_the_cap() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 10);
        assert_eq!(b.record_failure(1, t(0)), t(1000));
        assert_eq!(b.record_failure(1, t(1000)), t(3000));
        assert_eq!(b.record_failure(1, t(3000)), t(7000));
        assert_eq!(b.record_failure(1, t(7000)), t(15000));
        assert_eq!(b.record_failure(1, t(15000)), t(31000));
        assert_eq!(b.record_failure(1, t(31000)), t(63000));
        // 63 s delay would exceed the 60 s cap, so the retry lands at
        // last_failure + 60 s.
        assert_eq!(b.record_failure(1, t(63000)), t(123000));
    }

    #[test]
    fn success_clears_state() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 10);
        b.record_failure(1, t(0));
        b.record_failure(1, t(1000));
        assert_eq!(b.record_success(&1), 2);
        assert_eq!(b.failures(&1), 0);
        assert!(b.can_attempt(&1, t(2000)));
    }

    #[test]
    fn success_on_unknown_key_is_a_noop() {
        let mut b: BackoffTracker<u8> = BackoffTracker::new();
        assert_eq!(b.record_success(&1), 0);
        assert!(b.is_empty());
    }

    #[test]
    fn keys_are_independent() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 10);
        b.record_failure(1, t(0));
        assert!(!b.can_attempt(&1, t(100)));
        assert!(b.can_attempt(&2, t(100)));
    }

    #[test]
    fn sweep_drops_expired_entries() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 10);
        b.record_failure(1, t(0));
        b.record_failure(2, t(0));
        assert_eq!(b.sweep(t(500)), 0);
        assert_eq!(b.sweep(t(1000)), 2);
        assert!(b.is_empty());
    }

    #[test]
    fn forget_removes_an_entry() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 10);
        b.record_failure(1, t(0));
        assert!(b.forget(&1));
        assert!(!b.forget(&1));
        assert!(b.is_empty());
    }

    #[test]
    fn max_keys_is_enforced() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 3);
        for k in 0..5u8 {
            b.record_failure(k, t(u64::from(k) * 1000));
        }
        assert!(b.len() <= 3);
    }

    #[test]
    fn remaining_ms_tracks_the_backoff() {
        let mut b = BackoffTracker::with_config(1000, 60_000, 10);
        b.record_failure(1, t(0));
        assert_eq!(b.remaining_ms(&1, t(0)), Some(1000));
        assert_eq!(b.remaining_ms(&1, t(500)), Some(500));
        assert_eq!(b.remaining_ms(&1, t(1000)), None);
    }

    #[test]
    fn config_is_clamped() {
        let b: BackoffTracker<u8> = BackoffTracker::with_config(0, 0, 0);
        assert_eq!(b.base_ms(), 1);
        assert_eq!(b.max_ms(), 1);
        assert_eq!(b.max_keys(), 1);
    }

    #[test]
    fn default_matches_new() {
        let a: BackoffTracker<u8> = BackoffTracker::default();
        assert_eq!(a.base_ms(), DEFAULT_BASE_MS);
        assert_eq!(a.max_ms(), DEFAULT_MAX_MS);
        assert_eq!(a.max_keys(), DEFAULT_MAX_KEYS);
    }
}