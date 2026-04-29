//! Transport-agnostic analyzer interface.
//!
//! `Analyzer` is the seam between [`crate::deep::run`] and the concrete
//! transports — HTTP today, subprocess (PR 3) tomorrow. Adding a new
//! transport means writing one `impl Analyzer` and dispatching on
//! [`crate::deep::config::DeepMode`]; the orchestrator, candidate
//! selection, prompt rendering, schema, merge, and cost tracker all stay
//! unchanged.
//!
//! The shared types ([`AnalyzeResponse`], [`TokenUsage`]) live here so
//! transports can depend on the trait module without taking a transitive
//! dep on each other (the HTTP client must not know the subprocess
//! client exists, and vice versa).

use crate::deep::error::DeepError;
use crate::deep::finding::SemanticFinding;
use crate::deep::prompt::RenderedPrompt;

/// One round-trip's worth of model output: the parsed semantic findings
/// plus token-usage stats for cost tracking.
///
/// Transports that don't have a notion of token usage (subprocess hooks
/// shelling out to opaque CLIs) populate [`TokenUsage::default`], which
/// the cost tracker treats as a no-op.
#[derive(Debug)]
pub struct AnalyzeResponse {
    pub findings: Vec<SemanticFinding>,
    pub usage: TokenUsage,
}

/// Token counts reported by the upstream model. `0` for both fields means
/// "no usage reported" — the cost tracker short-circuits to a no-op when
/// either rate is zero, so an empty `TokenUsage` from a transport that
/// can't measure tokens (e.g. subprocess) costs nothing.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Send one prompt to a transport and parse the response.
///
/// Implementations are expected to be cheap to construct (one per
/// `deep::run`) and safe to call serially from the orchestrator. The
/// orchestrator currently dispatches sequentially; a future fan-out
/// would require `Sync`, which we'll add when (if) we wire that up.
pub trait Analyzer {
    /// Errors must map to the categories [`crate::deep::run`] handles:
    ///
    /// - [`DeepError::Config`] / [`DeepError::Io`]: hard fail the whole
    ///   deep pass — these are operator-actionable misconfiguration or
    ///   system-level failures, not per-call hiccups.
    /// - [`DeepError::Http`], [`DeepError::BadResponse`],
    ///   [`DeepError::Transient`], [`DeepError::Timeout`]: skip the
    ///   candidate, continue dispatching others. Best-effort enrichment.
    fn analyze(&self, prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError>;
}
