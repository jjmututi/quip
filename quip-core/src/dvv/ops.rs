//! Free-function wrappers for DVV operations.

use super::types::{CausalOrder, Dvv};

/// `a` strictly happens-before `b`.
pub fn happens_before(a: &Dvv, b: &Dvv) -> bool {
    matches!(a.compare(b), CausalOrder::Less)
}

/// `a` strictly happens-after `b`.
pub fn happens_after(a: &Dvv, b: &Dvv) -> bool {
    matches!(a.compare(b), CausalOrder::Greater)
}

/// `a` and `b` are concurrent.
pub fn is_concurrent(a: &Dvv, b: &Dvv) -> bool {
    matches!(a.compare(b), CausalOrder::Concurrent)
}