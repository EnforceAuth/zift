//! Merge semantic findings into the structural-pass finding set.
//!
//! Real merge logic lands in commit 6:
//!
//! - Semantic finding overlapping a structural finding's range (>= 50%
//!   overlap, same file) replaces the structural one **iff** semantic
//!   confidence ≥ structural confidence.
//! - `is_false_positive: true` from a `SemanticFinding` drops the seed
//!   structural finding entirely.
//! - Non-overlapping semantic findings are appended.
//!
//! In commit 2 this is a trivial concat — semantic findings are appended
//! verbatim. Sufficient because [`crate::deep::run`] is itself a no-op stub
//! that returns an empty vec.

use crate::types::Finding;

pub fn merge(structural: Vec<Finding>, semantic: Vec<Finding>) -> Vec<Finding> {
    // TODO(commit 6): overlap detection + confidence-based replacement +
    // false-positive drops.
    let mut all = structural;
    all.extend(semantic);
    all
}
