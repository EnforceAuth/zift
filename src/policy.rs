//! Engine-agnostic policy generation. The [`PolicyGenerator`] trait
//! collapses the parallel Rego/Cedar pipelines that grew out of Phase A
//! (#27) into a single dispatch surface keyed off [`PolicyEngine`].
//!
//! Generators are stateless and cheap to construct, so callers obtain one
//! per engine via [`generator_for`] and pass it through as `&dyn
//! PolicyGenerator`. The trait carries the operations every engine needs
//! along the extract and MCP paths: validate a finished policy, render a
//! captured template, generate a category-default stub, wrap a stub for
//! its confidence level, and group findings into per-source-file output
//! units.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::types::{AuthCategory, Confidence, Finding, PolicyEngine};

/// One generated output file produced by a [`PolicyGenerator`]. The
/// `label` is the engine's human-readable identifier — Rego packages use
/// dotted names (`app.api.orders`); Cedar files reuse the same dotted
/// shape purely for log-line consistency since Cedar has no package
/// keyword. The body of the file is `content`; `finding_count` is the
/// number of findings folded into it.
pub struct PolicyFile {
    pub label: String,
    pub output_path: PathBuf,
    pub content: String,
    pub finding_count: usize,
}

/// Result of validating a generated policy string. Engines parse the
/// content with their respective parsers (`regorus` for Rego, `cedar-policy`
/// for Cedar) and report the first parse error, if any.
#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
}

pub trait PolicyGenerator {
    /// Which engine this generator produces output for.
    fn engine(&self) -> PolicyEngine;

    /// Validate a complete policy string. The engine-specific parser is
    /// the source of truth — callers don't need to know which one ran.
    fn validate(&self, policy: &str) -> ValidationResult;

    /// Render a `{{var}}`-templated policy body against captures. The
    /// caller is responsible for adding any engine-specific derived
    /// variables (e.g. role-set expansions) before calling.
    fn render_template(&self, template: &str, vars: &HashMap<String, String>) -> String;

    /// Generate the category's default stub when a finding has no rule
    /// template available.
    fn default_stub(&self, category: AuthCategory, snippet: &str) -> String;

    /// Wrap a generated stub in confidence-appropriate guidance — fully
    /// commented for `Low`, TODO-prefixed for `Medium`, raw for `High`.
    /// The exact comment syntax is engine-specific.
    fn wrap_by_confidence(&self, body: &str, confidence: Confidence) -> String;

    /// Group findings into per-source-file output units. The exact
    /// per-engine layout (Rego packages vs flat Cedar files) lives in
    /// the engine modules.
    fn group_and_generate(
        &self,
        findings: &[Finding],
        policy_prefix: &str,
        output_dir: &Path,
    ) -> Vec<PolicyFile>;
}

/// Obtain the generator for a policy engine. Generators are zero-sized
/// and constructed on demand so dispatch sites can stay generic over
/// `&dyn PolicyGenerator` without thinking about ownership.
pub fn generator_for(engine: PolicyEngine) -> Box<dyn PolicyGenerator> {
    match engine {
        PolicyEngine::Rego => Box::new(crate::rego::RegoGenerator),
        PolicyEngine::Cedar => Box::new(crate::cedar::CedarGenerator),
    }
}
