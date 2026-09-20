//! DVV types.

use crate::cid::CidOrV1;
use crate::constants::{INF, MAX_DEPENDENCIES};
use crate::error::{Error, Result};
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

/// 32-byte Ed25519 public key identifying a writer.
pub type NodeId = [u8; 32];

/// A single write event.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dot {
    /// Writer that produced this event.
    pub writer: NodeId,
    /// Monotonic counter for that writer.
    pub counter: u64,
}

impl Dot {
    /// Construct a new dot.
    pub fn new(writer: NodeId, counter: u64) -> Self {
        Self { writer, counter }
    }
}

/// Result of comparing two DVVs.
///
/// This is a **derived** value, not a wire type. The spec is explicit
/// (draft-mututi-quip-03 §5.2): sync messages carry DVV values, and the
/// receiver re-derives causal order by comparing them locally.
/// Implementations **MUST NOT** serialize `CausalOrder`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CausalOrder {
    /// `a` strictly happens-before `b`. Named `Less` to match spec
    /// terminology; read as "`a` is causally less than `b`".
    Less,
    /// `a` strictly happens-after `b`.
    Greater,
    /// `a` and `b` are causally identical.
    ///
    /// **Deviation from spec:** the spec's three-valued enum has no
    /// `Equal` variant because it assumes the caller filters equal DVVs
    /// before classification. Returning `Less` for equal DVVs would make
    /// `happens_before(a, b)` and `happens_before(b, a)` both true, which
    /// violates the partial-order axioms. Since `CausalOrder` is never
    /// serialized (per §5.2), adding this variant is a local correctness
    /// improvement with no wire-format consequence.
    Equal,
    /// `a` and `b` are concurrent.
    Concurrent,
}

/// Dotted Version Vector.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Dvv {
    /// Current dot, if this DVV has been written to.
    pub dot: Option<Dot>,
    /// Active writer counters.
    pub deps: BTreeMap<NodeId, u64>,
    /// Writers whose counter has been replaced by the [`INF`] sentinel.
    pub pruned: BTreeSet<NodeId>,
    /// Optional CID of the current state snapshot.
    pub cid: Option<CidOrV1>,
}

impl Dvv {
    /// Empty DVV.
    pub fn new() -> Self {
        Self::default()
    }

    /// DVV representing a single write.
    pub fn from_write(writer: NodeId, counter: u64) -> Self {
        let mut d = Self::new();
        d.deps.insert(writer, counter);
        d.dot = Some(Dot::new(writer, counter));
        d
    }

    /// Effective counter for a writer. Pruned writers report [`INF`].
    pub fn get_counter(&self, writer: &NodeId) -> u64 {
        if self.pruned.contains(writer) {
            return INF;
        }
        self.deps.get(writer).copied().unwrap_or(0)
    }

    /// Observe a write. No-op if the writer is pruned.
    pub fn observe(&mut self, writer: NodeId, counter: u64) {
        if self.pruned.contains(&writer) {
            return;
        }
        let current = self.deps.get(&writer).copied().unwrap_or(0);
        if counter > current {
            self.deps.insert(writer, counter);
        }
    }

    /// Increment the DVV for `writer`, producing a new dot.
    ///
    /// Returns [`Error::PrunedWriterRequiresSeqReset`] if the writer has
    /// been pruned. Call [`Self::apply_seq_reset`] first.
    pub fn increment(&mut self, writer: NodeId) -> Result<Dot> {
        if self.pruned.contains(&writer) {
            return Err(Error::PrunedWriterRequiresSeqReset);
        }
        let current = self.deps.get(&writer).copied().unwrap_or(0);
        let next = current.checked_add(1).ok_or(Error::CounterOverflow)?;
        if next >= INF {
            return Err(Error::CounterOverflow);
        }
        self.deps.insert(writer, next);
        let dot = Dot::new(writer, next);
        self.dot = Some(dot.clone());
        Ok(dot)
    }

    /// Apply a `seq_reset` for `writer`: remove from `pruned` and reset
    /// the counter. The next `increment` will produce counter 1.
    pub fn apply_seq_reset(&mut self, writer: NodeId) {
        self.pruned.remove(&writer);
        self.deps.remove(&writer);
    }

    /// True if `deps` exceeds [`MAX_DEPENDENCIES`].
    pub fn needs_prune(&self) -> bool {
        self.deps.len() > MAX_DEPENDENCIES
    }

    /// Move the lowest-counter writers to `pruned` until `deps` fits.
    pub fn prune(&mut self) {
        if !self.needs_prune() {
            return;
        }
        let excess = self.deps.len() - MAX_DEPENDENCIES;
        let mut entries: Vec<(NodeId, u64)> =
            self.deps.iter().map(|(&k, &v)| (k, v)).collect();
        entries.sort_by_key(|&(_, c)| c);
        for (w, _) in entries.into_iter().take(excess) {
            self.deps.remove(&w);
            self.pruned.insert(w);
        }
    }

    /// Causal comparison. Returns the derived [`CausalOrder`] of `self`
    /// relative to `other`.
    pub fn compare(&self, other: &Self) -> CausalOrder {
        let self_dom = self.dominates(other);
        let other_dom = other.dominates(self);
        match (self_dom, other_dom) {
            (true, true) => CausalOrder::Equal,
            (true, false) => CausalOrder::Greater,
            (false, true) => CausalOrder::Less,
            (false, false) => CausalOrder::Concurrent,
        }
    }

    fn dominates(&self, other: &Self) -> bool {
        for w in other.deps.keys() {
            if self.get_counter(w) < other.get_counter(w) {
                return false;
            }
        }
        for w in &other.pruned {
            if self.get_counter(w) != INF {
                return false;
            }
        }
        if let Some(dot) = &other.dot {
            if self.get_counter(&dot.writer) < dot.counter {
                return false;
            }
        }
        true
    }

    /// Deterministic merge per spec §5.2.
    pub fn merge(&self, other: &Self) -> Self {
        let mut out = Self::new();

        let mut all: BTreeSet<NodeId> = BTreeSet::new();
        all.extend(self.deps.keys().copied());
        all.extend(self.pruned.iter().copied());
        all.extend(other.deps.keys().copied());
        all.extend(other.pruned.iter().copied());

        for w in all {
            let a = self.get_counter(&w);
            let b = other.get_counter(&w);
            let max = a.max(b);
            if max == INF {
                out.pruned.insert(w);
            } else {
                out.deps.insert(w, max);
            }
        }

        out.dot = match (&self.dot, &other.dot) {
            (Some(a), Some(b)) => {
                if a.counter != b.counter {
                    Some(if a.counter > b.counter { a.clone() } else { b.clone() })
                } else {
                    Some(if a.writer <= b.writer { a.clone() } else { b.clone() })
                }
            }
            (Some(a), None) => Some(a.clone()),
            (None, Some(b)) => Some(b.clone()),
            (None, None) => None,
        };

        out.cid = match (self.cid, other.cid) {
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (Some(a), Some(b)) => {
                if a == b {
                    Some(a)
                } else {
                    let winner_is_self = match (&self.dot, &other.dot) {
                        (Some(sd), Some(od)) => {
                            let higher = sd.counter > od.counter;
                            let tie_and_lower_writer =
                                sd.counter == od.counter && sd.writer <= od.writer;
                            higher || tie_and_lower_writer
                        }
                        _ => true,
                    };
                    Some(if winner_is_self { a } else { b })
                }
            }
            (None, None) => None,
        };

        out.prune();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> NodeId {
        let mut n = [0u8; 32];
        n[0] = b;
        n
    }

    #[test]
    fn increment_and_observe() {
        let mut d = Dvv::new();
        assert_eq!(d.increment(id(1)).unwrap().counter, 1);
        assert_eq!(d.increment(id(1)).unwrap().counter, 2);
        d.observe(id(2), 7);
        assert_eq!(d.get_counter(&id(2)), 7);
    }

    #[test]
    fn pruned_writer_reports_inf() {
        let mut d = Dvv::new();
        d.pruned.insert(id(1));
        d.deps.insert(id(1), 5);
        assert_eq!(d.get_counter(&id(1)), INF);
    }

    #[test]
    fn increment_on_pruned_writer_errors() {
        let mut d = Dvv::new();
        d.pruned.insert(id(1));
        assert!(matches!(
            d.increment(id(1)),
            Err(Error::PrunedWriterRequiresSeqReset)
        ));
    }

    #[test]
    fn apply_seq_reset_clears_pruned() {
        let mut d = Dvv::new();
        d.pruned.insert(id(1));
        d.apply_seq_reset(id(1));
        assert!(!d.pruned.contains(&id(1)));
        assert_eq!(d.increment(id(1)).unwrap().counter, 1);
    }

    #[test]
    fn merge_inf_beats_finite() {
        let mut a = Dvv::new();
        a.pruned.insert(id(1));
        let mut b = Dvv::new();
        b.deps.insert(id(1), 5);
        let m = a.merge(&b);
        assert!(m.pruned.contains(&id(1)));
        assert!(!m.deps.contains_key(&id(1)));
    }

    #[test]
    fn merge_preserves_pruned_from_both_sides() {
        let mut a = Dvv::new();
        a.pruned.insert(id(1));
        let mut b = Dvv::new();
        b.pruned.insert(id(2));
        let m = a.merge(&b);
        assert!(m.pruned.contains(&id(1)));
        assert!(m.pruned.contains(&id(2)));
    }

    #[test]
    fn test_compare_equal_dvvs() {
        let a = Dvv::from_write(id(1), 5);
        let b = Dvv::from_write(id(1), 5);
        assert_eq!(a.compare(&b), CausalOrder::Equal);
    }

    #[test]
    fn test_compare_less_greater() {
        let a = Dvv::from_write(id(1), 3);
        let b = Dvv::from_write(id(1), 5);
        assert_eq!(a.compare(&b), CausalOrder::Less);
        assert_eq!(b.compare(&a), CausalOrder::Greater);
    }

    #[test]
    fn test_compare_concurrent() {
        let a = Dvv::from_write(id(1), 5);
        let b = Dvv::from_write(id(2), 7);
        assert_eq!(a.compare(&b), CausalOrder::Concurrent);
    }

    #[test]
    fn test_compare_with_pruned() {
        let mut a = Dvv::new();
        a.deps.insert(id(1), 5);
        let mut b = Dvv::new();
        b.pruned.insert(id(1));
        assert_eq!(a.compare(&b), CausalOrder::Less);
        assert_eq!(b.compare(&a), CausalOrder::Greater);
    }

    #[test]
    fn prune_moves_lowest_counters() {
        let mut d = Dvv::new();
        for i in 0..(MAX_DEPENDENCIES + 5) {
            let mut w = [0u8; 32];
            w[0..8].copy_from_slice(&(i as u64).to_be_bytes());
            d.deps.insert(w, (i as u64) + 1);
        }
        d.prune();
        assert_eq!(d.deps.len(), MAX_DEPENDENCIES);
        assert_eq!(d.pruned.len(), 5);
    }
}