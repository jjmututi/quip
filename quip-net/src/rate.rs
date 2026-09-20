//! Per-NodeId rate limiting (spec §19.4).
//!
//! QUIP bounds operations per peer to prevent resource-exhaustion attacks.
//! The spec gives numeric limits in §19.4 and specific per-operation
//! limits in §13.8 (spillover), §12.2 (relay connections), and §7
//! (governance).
//!
//! The limiter is a token bucket per `(NodeId, OperationKind)` pair. A
//! bucket has a capacity and a refill rate; each operation consumes one
//! or more tokens. An operation with no tokens available is rejected
//! with [`Error::RateLimit`], which maps to `E_RATE_LIMIT` (0x03) on
//! the wire.
//!
//! Buckets are lazily refilled on each check: the elapsed time since the
//! last check is converted to tokens at the refill rate and added, capped
//! at the bucket's capacity. This gives smooth smoothing without a
//! background task, and works identically in `no_std`.
//!
//! # Burst allowance
//!
//! §19.4 grants a "short burst allowance" of 100 operations for the
//! general per-NodeId limit. The bucket's capacity is `limit + burst`,
//! so an idle peer can send `limit + burst` requests before being
//! throttled. Burst is configurable per operation kind.
//!
//! # Stateful, and deliberately so
//!
//! Rate limiting is inherently stateful. This module holds no clock and
//! no I/O: callers pass `now: Timestamp` on every call, in line with the
//! rest of `quip-net`. That makes the limiter trivially testable with
//! [`quip_core::time::ManualClock`].

use crate::error::{Error, Result};
use alloc::collections::BTreeMap;
use quip_core::dvv::NodeId;
use quip_core::time::Timestamp;

/// Micro-token scale. One token = `SCALE` micro-tokens. Using scaled
/// integers keeps the refill path integer-only.
const SCALE: u64 = 1_000_000;

/// Default cap on tracked `(NodeId, OperationKind)` buckets.
///
/// Implementation choice, not spec-mandated. Callers with more concurrent
/// peers than this can raise it via [`RateLimiterConfig::max_entries`].
pub const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Operation categories with distinct rate limits.
///
/// The spec assigns different limits to different verbs. Verbs that are
/// not listed here fall under [`OperationKind::General`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationKind {
    /// T0 and T1 traffic not covered by a more specific kind. Spec §19.4
    /// default: 1000 ops/min per NodeId.
    General,
    /// `pin_announce` gossip. Spec §19.4: 100/min per NodeId.
    PinAnnounce,
    /// `spillover` requests. Spec §13.8 and §19.4: 10/min per NodeId.
    Spillover,
    /// Relay connection attempts. Spec §19.4: 100/min per NodeId.
    Relay,
    /// Governance operations (`register_tcid`, `delegation`,
    /// `quarantine`, `unquarantine`, `derivative_link`). Spec §19.4:
    /// 100/min per NodeId.
    Governance,
}

impl OperationKind {
    /// All kinds, in a stable order.
    pub const ALL: [OperationKind; 5] = [
        OperationKind::General,
        OperationKind::PinAnnounce,
        OperationKind::Spillover,
        OperationKind::Relay,
        OperationKind::Governance,
    ];
}

/// Per-kind bucket configuration.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BucketConfig {
    /// Sustained rate, in operations per minute.
    pub limit_per_minute: u64,
    /// Extra tokens a peer may consume in a burst.
    pub burst: u64,
}

impl BucketConfig {
    /// Total tokens available from an idle bucket.
    pub const fn capacity(&self) -> u64 {
        self.limit_per_minute.saturating_add(self.burst)
    }
}

/// All configuration for [`RateLimiter`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RateLimiterConfig {
    /// General T0/T1 operations. Default: 1000/min, burst 100.
    pub general: BucketConfig,
    /// Pin gossip. Default: 100/min, burst 10.
    pub pin_announce: BucketConfig,
    /// Spillover requests. Default: 10/min, burst 2.
    pub spillover: BucketConfig,
    /// Relay connection attempts. Default: 100/min, burst 10.
    pub relay: BucketConfig,
    /// Governance operations. Default: 100/min, burst 10.
    pub governance: BucketConfig,
    /// Maximum number of `(NodeId, OperationKind)` buckets tracked at
    /// once. When the map is full, [`RateLimiter::check`] evicts the
    /// oldest bucket to make room.
    pub max_entries: usize,
}

impl Default for RateLimiterConfig {
    fn default() -> Self {
        Self {
            general: BucketConfig {
                limit_per_minute: 1000,
                burst: 100,
            },
            pin_announce: BucketConfig {
                limit_per_minute: 100,
                burst: 10,
            },
            spillover: BucketConfig {
                limit_per_minute: 10,
                burst: 2,
            },
            relay: BucketConfig {
                limit_per_minute: 100,
                burst: 10,
            },
            governance: BucketConfig {
                limit_per_minute: 100,
                burst: 10,
            },
            max_entries: DEFAULT_MAX_ENTRIES,
        }
    }
}

// -------------------------------------------------------------------------
// Token bucket
// -------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
struct Bucket {
    /// Available tokens, in micro-tokens (`SCALE` = 1 token).
    tokens_ut: u64,
    /// Refill rate, in micro-tokens per second.
    refill_ut_per_sec: u64,
    /// Maximum tokens, in micro-tokens.
    capacity_ut: u64,
    /// Last time the bucket was refilled.
    last: Timestamp,
}

impl Bucket {
    fn full(config: BucketConfig, now: Timestamp) -> Self {
        let capacity = config.capacity();
        let capacity_ut = capacity.saturating_mul(SCALE);
        // `limit_per_minute * SCALE / 60` per second. Integer division
        // is acceptable: the error is well under one token per minute
        // for any limit we care about, and it never accumulates.
        let refill_ut_per_sec = config.limit_per_minute.saturating_mul(SCALE) / 60;
        Self {
            tokens_ut: capacity_ut,
            refill_ut_per_sec,
            capacity_ut,
            last: now,
        }
    }

    /// Add tokens accrued since `last`, then update `last` to `now`.
    ///
    /// A clock that moves backwards does not add tokens and does not
    /// update `last`, so the next forward-moving check picks up from the
    /// last observed time.
    fn refill(&mut self, now: Timestamp) {
        if now <= self.last {
            return;
        }
        let elapsed_ms = now.as_millis().saturating_sub(self.last.as_millis());
        // For realistic elapsed_ms (< ~1e10 ms) and refill (< ~2e7 µt/s),
        // the product stays well within u64.
        let add = elapsed_ms.saturating_mul(self.refill_ut_per_sec) / 1000;
        self.tokens_ut = self.tokens_ut.saturating_add(add).min(self.capacity_ut);
        self.last = now;
    }

    /// Try to consume `n` tokens, all-or-nothing.
    fn try_consume(&mut self, n: u64, now: Timestamp) -> bool {
        self.refill(now);
        let needed = n.saturating_mul(SCALE);
        if self.tokens_ut >= needed {
            self.tokens_ut -= needed;
            true
        } else {
            false
        }
    }

    /// True when the bucket would be at capacity at `now`.
    fn is_full_at(&self, now: Timestamp) -> bool {
        if self.tokens_ut >= self.capacity_ut {
            return true;
        }
        if now <= self.last {
            return false;
        }
        let elapsed_ms = now.as_millis().saturating_sub(self.last.as_millis());
        let add = elapsed_ms.saturating_mul(self.refill_ut_per_sec) / 1000;
        self.tokens_ut.saturating_add(add) >= self.capacity_ut
    }
}

// -------------------------------------------------------------------------
// RateLimiter
// -------------------------------------------------------------------------

/// Per-NodeId rate limiter.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    buckets: BTreeMap<(NodeId, OperationKind), Bucket>,
    config: RateLimiterConfig,
}

impl RateLimiter {
    /// Create with spec defaults.
    pub fn new() -> Self {
        Self::with_config(RateLimiterConfig::default())
    }

    /// Create with an explicit configuration.
    pub fn with_config(config: RateLimiterConfig) -> Self {
        Self {
            buckets: BTreeMap::new(),
            config,
        }
    }

    /// Active configuration.
    pub fn config(&self) -> &RateLimiterConfig {
        &self.config
    }

    /// Number of tracked buckets.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// True when no buckets are tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }

    /// Check and consume one token for `(node, kind)`.
    ///
    /// Returns `Ok(())` if the operation is allowed; `Err(Error::RateLimit)`
    /// if the bucket is exhausted.
    pub fn check(&mut self, node: NodeId, kind: OperationKind, now: Timestamp) -> Result<()> {
        self.check_at_most(node, kind, 1, now)
    }

    /// Check and consume `n` tokens for `(node, kind)`.
    ///
    /// All-or-nothing: if `n` tokens are not available, none are consumed.
    /// Callers implementing a weighted scheme (e.g. charging more for a
    /// larger `fetch_range`) can use this.
    pub fn check_at_most(
        &mut self,
        node: NodeId,
        kind: OperationKind,
        n: u64,
        now: Timestamp,
    ) -> Result<()> {
        let cfg = self.config_for(kind);
        let key = (node, kind);

        if !self.buckets.contains_key(&key) {
            self.ensure_capacity(now);
            self.buckets.insert(key, Bucket::full(cfg, now));
        }

        let bucket = self
            .buckets
            .get_mut(&key)
            .expect("bucket was just inserted or was already present");
        if bucket.try_consume(n, now) {
            Ok(())
        } else {
            Err(Error::RateLimit)
        }
    }

    /// Remove buckets that are at capacity at `now`, returning how many
    /// were removed.
    ///
    /// Callers SHOULD invoke this periodically (e.g. once a minute) to
    /// bound memory. The limiter also sweeps internally when the bucket
    /// map reaches `max_entries`.
    pub fn sweep(&mut self, now: Timestamp) -> usize {
        let before = self.buckets.len();
        self.buckets.retain(|_, b| !b.is_full_at(now));
        before - self.buckets.len()
    }

    fn config_for(&self, kind: OperationKind) -> BucketConfig {
        match kind {
            OperationKind::General => self.config.general,
            OperationKind::PinAnnounce => self.config.pin_announce,
            OperationKind::Spillover => self.config.spillover,
            OperationKind::Relay => self.config.relay,
            OperationKind::Governance => self.config.governance,
        }
    }

    /// Ensure the bucket map has room for a new entry. Sweeps idle
    /// buckets; if still full, evicts the bucket with the smallest
    /// `last` timestamp (the least recently touched).
    fn ensure_capacity(&mut self, now: Timestamp) {
        if self.buckets.len() < self.config.max_entries {
            return;
        }
        self.sweep(now);
        if self.buckets.len() < self.config.max_entries {
            return;
        }
        if let Some(oldest) = self
            .buckets
            .iter()
            .min_by_key(|(_, b)| b.last)
            .map(|(k, _)| *k)
        {
            self.buckets.remove(&oldest);
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quip_core::time::{Clock, ManualClock};

    fn nid(b: u8) -> NodeId {
        [b; 32]
    }

    #[test]
    fn within_limit_is_allowed() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        for _ in 0..1000 {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap();
        }
    }

    #[test]
    fn exceeding_limit_is_denied() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cap = RateLimiterConfig::default().general.capacity();
        for _ in 0..cap {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap();
        }
        assert!(matches!(
            rl.check(nid(1), OperationKind::General, clock.now()),
            Err(Error::RateLimit)
        ));
    }

    #[test]
    fn refill_restores_tokens_over_time() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cap = RateLimiterConfig::default().general.capacity();
        for _ in 0..cap {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap();
        }
        assert!(rl.check(nid(1), OperationKind::General, clock.now()).is_err());

        // Advance 1 second. General refills at 1000/min ≈ 16.67/sec.
        clock.advance(1000);
        let mut allowed = 0u64;
        while rl.check(nid(1), OperationKind::General, clock.now()).is_ok() {
            allowed += 1;
            if allowed > 100 {
                panic!("refill produced too many tokens");
            }
        }
        assert!(
            (15..=17).contains(&allowed),
            "expected ~16 tokens after 1s, got {allowed}"
        );
    }

    #[test]
    fn operations_have_independent_buckets() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cap = RateLimiterConfig::default().general.capacity();
        for _ in 0..cap {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap();
        }
        assert!(rl.check(nid(1), OperationKind::General, clock.now()).is_err());
        // Governance is a separate bucket.
        rl.check(nid(1), OperationKind::Governance, clock.now())
            .unwrap();
    }

    #[test]
    fn nodes_have_independent_buckets() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cap = RateLimiterConfig::default().general.capacity();
        for _ in 0..cap {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap();
        }
        assert!(rl.check(nid(1), OperationKind::General, clock.now()).is_err());
        rl.check(nid(2), OperationKind::General, clock.now())
            .unwrap();
    }

    #[test]
    fn burst_allowance_permits_extra_ops() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cfg = RateLimiterConfig::default();
        assert!(cfg.general.burst > 0, "burst must be configured");
        // An idle bucket carries limit + burst tokens.
        for i in 0..cfg.general.capacity() {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap_or_else(|_| panic!("op {i} should be allowed"));
        }
    }

    #[test]
    fn spillover_limit_is_ten_per_minute() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cfg = RateLimiterConfig::default();
        assert_eq!(cfg.spillover.limit_per_minute, 10);
        for _ in 0..cfg.spillover.capacity() {
            rl.check(nid(1), OperationKind::Spillover, clock.now())
                .unwrap();
        }
        assert!(matches!(
            rl.check(nid(1), OperationKind::Spillover, clock.now()),
            Err(Error::RateLimit)
        ));
    }

    #[test]
    fn sweep_removes_idle_buckets() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        rl.check(nid(1), OperationKind::General, clock.now())
            .unwrap();
        assert_eq!(rl.len(), 1);

        // Advance far enough that the bucket refills to full.
        clock.advance(60_000);
        let swept = rl.sweep(clock.now());
        assert_eq!(swept, 1);
        assert!(rl.is_empty());
    }

    #[test]
    fn sweep_keeps_non_full_buckets() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        for _ in 0..100 {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap();
        }
        let swept = rl.sweep(clock.now());
        assert_eq!(swept, 0);
        assert_eq!(rl.len(), 1);
    }

    #[test]
    fn max_entries_is_enforced() {
        let mut rl = RateLimiter::with_config(RateLimiterConfig {
            max_entries: 3,
            ..RateLimiterConfig::default()
        });
        let clock = ManualClock::new(Timestamp::from_millis(0));
        for i in 0..5u8 {
            rl.check(nid(i), OperationKind::General, clock.now())
                .unwrap();
        }
        assert!(
            rl.len() <= 3,
            "map size exceeded max_entries: {}",
            rl.len()
        );
    }

    #[test]
    fn check_at_most_with_n_above_limit_denies() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cap = RateLimiterConfig::default().general.capacity();
        assert!(matches!(
            rl.check_at_most(nid(1), OperationKind::General, cap + 1, clock.now()),
            Err(Error::RateLimit)
        ));
    }

    #[test]
    fn check_at_most_consumes_all_or_nothing() {
        let clock = ManualClock::new(Timestamp::from_millis(0));
        let mut rl = RateLimiter::new();
        let cfg = RateLimiterConfig::default();
        for _ in 0..5 {
            rl.check(nid(1), OperationKind::General, clock.now())
                .unwrap();
        }
        let key = (nid(1), OperationKind::General);
        let before = rl.buckets.get(&key).unwrap().tokens_ut;
        assert!(rl
            .check_at_most(
                nid(1),
                OperationKind::General,
                cfg.general.capacity() + 1,
                clock.now()
            )
            .is_err());
        let after = rl.buckets.get(&key).unwrap().tokens_ut;
        assert_eq!(before, after, "no tokens should have been consumed");
    }

    #[test]
    fn clock_moving_backwards_does_not_panic() {
        let clock = ManualClock::new(Timestamp::from_millis(1_000_000));
        let mut rl = RateLimiter::new();
        rl.check(nid(1), OperationKind::General, clock.now())
            .unwrap();
        // Move the clock backwards. The limiter must not underflow.
        clock.set(Timestamp::from_millis(500_000));
        rl.check(nid(1), OperationKind::General, clock.now())
            .unwrap();
    }
}