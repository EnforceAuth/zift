//! Token-based USD cost ceiling for deep-scan calls.
//!
//! Spend is tracked in micro-USD (millionths of a dollar) using
//! [`AtomicU64`] so the tracker is safe to share across threads when
//! running concurrent requests. If both per-1k rates are unset (or zero),
//! tracking is a no-op and `record` always returns `Ok`.

#![allow(dead_code)] // wired into the binary in commit 6

use crate::deep::client::TokenUsage;
use crate::deep::config::DeepRuntime;
use crate::deep::error::DeepError;
use std::sync::atomic::{AtomicU64, Ordering};

const MICRO_PER_USD: u64 = 1_000_000;

/// Tracks cumulative USD spend across deep-scan requests; errors via
/// [`DeepError::CostExceeded`] when the cap is reached.
pub struct CostTracker {
    spent_micro_usd: AtomicU64,
    cap_micro_usd: Option<u64>,
    in_rate_per_1k: f64,
    out_rate_per_1k: f64,
}

impl CostTracker {
    pub fn new(runtime: &DeepRuntime) -> Self {
        Self {
            spent_micro_usd: AtomicU64::new(0),
            cap_micro_usd: runtime
                .max_cost_usd
                .filter(|c| c.is_finite() && *c >= 0.0)
                .map(|c| (c * MICRO_PER_USD as f64) as u64),
            in_rate_per_1k: runtime.cost_per_1k_input.unwrap_or(0.0),
            out_rate_per_1k: runtime.cost_per_1k_output.unwrap_or(0.0),
        }
    }

    /// Add this request's token usage to the running total. Returns
    /// [`DeepError::CostExceeded`] if the new total exceeds the cap.
    ///
    /// If both per-1k rates are zero (default for local models), this is
    /// a no-op — there's no concept of cost without rates.
    pub fn record(&self, usage: &TokenUsage) -> Result<(), DeepError> {
        if self.in_rate_per_1k == 0.0 && self.out_rate_per_1k == 0.0 {
            return Ok(());
        }

        let delta_usd = (usage.input_tokens as f64 / 1000.0) * self.in_rate_per_1k
            + (usage.output_tokens as f64 / 1000.0) * self.out_rate_per_1k;
        let delta_micro = (delta_usd * MICRO_PER_USD as f64).round() as u64;

        let prior = self
            .spent_micro_usd
            .fetch_add(delta_micro, Ordering::Relaxed);
        let new_total = prior + delta_micro;

        if let Some(cap) = self.cap_micro_usd
            && new_total > cap
        {
            let spent = new_total as f64 / MICRO_PER_USD as f64;
            return Err(DeepError::CostExceeded { spent });
        }
        Ok(())
    }

    /// Cumulative USD spent so far. Useful for end-of-run logging.
    pub fn spent_usd(&self) -> f64 {
        self.spent_micro_usd.load(Ordering::Relaxed) as f64 / MICRO_PER_USD as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(cap: Option<f64>, in_rate: Option<f64>, out_rate: Option<f64>) -> DeepRuntime {
        DeepRuntime {
            base_url: "http://x/v1".into(),
            model: "m".into(),
            api_key: None,
            max_cost_usd: cap,
            cost_per_1k_input: in_rate,
            cost_per_1k_output: out_rate,
            request_timeout_secs: 60,
            max_candidates: 50,
            max_concurrent: 1,
            temperature: 0.0,
            max_prompt_chars: 16_000,
        }
    }

    fn usage(in_tokens: u32, out_tokens: u32) -> TokenUsage {
        TokenUsage {
            input_tokens: in_tokens,
            output_tokens: out_tokens,
        }
    }

    #[test]
    fn no_rates_means_no_tracking() {
        let tracker = CostTracker::new(&rt(Some(0.01), None, None));
        // Massive usage, but no rates → no spend recorded → no cap trigger.
        for _ in 0..1000 {
            tracker.record(&usage(10_000, 10_000)).unwrap();
        }
        assert_eq!(tracker.spent_usd(), 0.0);
    }

    #[test]
    fn under_cap_records_without_error() {
        // 1k input @ $0.001/k = $0.001 spent
        let tracker = CostTracker::new(&rt(Some(1.0), Some(0.001), Some(0.001)));
        tracker.record(&usage(1_000, 0)).unwrap();
        let spent = tracker.spent_usd();
        assert!(
            (spent - 0.001).abs() < 1e-6,
            "expected ~$0.001, got {spent}"
        );
    }

    #[test]
    fn cap_exceeded_triggers_error() {
        // Cap $0.01; one request @ $0.10 → trips cap.
        let tracker = CostTracker::new(&rt(Some(0.01), Some(0.10), None));
        let err = tracker.record(&usage(1_000, 0)).unwrap_err();
        assert!(matches!(err, DeepError::CostExceeded { .. }));
    }

    #[test]
    fn cap_exceeded_after_multiple_records() {
        // Cap $1.00; 10 requests @ $0.20 each → trips on the 6th.
        let tracker = CostTracker::new(&rt(Some(1.00), Some(0.20), None));
        for i in 0..10 {
            let result = tracker.record(&usage(1_000, 0));
            if i < 5 {
                assert!(result.is_ok(), "request {i} should be under cap");
            } else if i == 5 {
                assert!(matches!(
                    result.unwrap_err(),
                    DeepError::CostExceeded { .. }
                ));
                break;
            }
        }
    }

    #[test]
    fn no_cap_never_errors() {
        // Rates set but cap not — no error regardless of spend.
        let tracker = CostTracker::new(&rt(None, Some(100.0), Some(100.0)));
        for _ in 0..100 {
            tracker.record(&usage(10_000, 10_000)).unwrap();
        }
        assert!(tracker.spent_usd() > 0.0);
    }

    #[test]
    fn input_and_output_rates_both_apply() {
        // 1k input @ $0.01/k + 2k output @ $0.05/k = $0.01 + $0.10 = $0.11
        let tracker = CostTracker::new(&rt(None, Some(0.01), Some(0.05)));
        tracker.record(&usage(1_000, 2_000)).unwrap();
        let spent = tracker.spent_usd();
        assert!((spent - 0.11).abs() < 1e-6, "expected ~$0.11, got {spent}");
    }

    #[test]
    fn thread_safe_concurrent_records() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(CostTracker::new(&rt(None, Some(0.001), None)));
        let mut handles = Vec::new();
        for _ in 0..10 {
            let t = Arc::clone(&tracker);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    t.record(&usage(1_000, 0)).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // 10 threads × 100 records × $0.001 = $1.00
        let spent = tracker.spent_usd();
        assert!((spent - 1.0).abs() < 1e-3, "expected ~$1.00, got {spent}");
    }
}
