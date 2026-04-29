//! Token-based USD cost ceiling for deep-scan calls.
//!
//! See plans/todo/01-pr1-deep-http-transport.md §10. Implementation lands
//! in commit 5.

#![allow(dead_code)]

use crate::deep::client::TokenUsage;
use crate::deep::config::DeepRuntime;
use crate::deep::error::DeepError;

/// Tracks cumulative USD spend across deep-scan requests; errors via
/// [`DeepError::CostExceeded`] when the cap is reached.
///
/// If both rates are `None`, tracking is a no-op (spent stays 0).
pub struct CostTracker {
    // Fields land in commit 5 (atomic spend counter, cap, rates).
}

impl CostTracker {
    pub fn new(_runtime: &DeepRuntime) -> Self {
        unimplemented!("CostTracker::new: commit 5")
    }

    /// Record token usage from one response; return Err if cap exceeded.
    pub fn record(&self, _usage: &TokenUsage) -> Result<(), DeepError> {
        unimplemented!("CostTracker::record: commit 5")
    }

    /// Cumulative USD spent so far.
    pub fn spent_usd(&self) -> f64 {
        unimplemented!("CostTracker::spent_usd: commit 5")
    }
}
