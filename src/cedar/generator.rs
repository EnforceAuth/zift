//! [`PolicyGenerator`] implementation for Cedar. Thin adapter over the
//! engine-specific `templates`, `validator`, and `grouping` modules.

use std::collections::HashMap;
use std::path::Path;

use crate::policy::{PolicyFile, PolicyGenerator, ValidationResult};
use crate::types::{AuthCategory, Confidence, Finding, PolicyEngine};

pub struct CedarGenerator;

impl PolicyGenerator for CedarGenerator {
    fn engine(&self) -> PolicyEngine {
        PolicyEngine::Cedar
    }

    fn validate(&self, policy: &str) -> ValidationResult {
        let r = super::validator::validate_cedar(policy);
        ValidationResult {
            valid: r.valid,
            error: r.error,
        }
    }

    fn render_template(&self, template: &str, vars: &HashMap<String, String>) -> String {
        super::templates::render_template(template, vars)
    }

    fn default_stub(&self, category: AuthCategory, snippet: &str) -> String {
        super::templates::generate_default_stub(category, snippet)
    }

    fn wrap_by_confidence(&self, body: &str, confidence: Confidence) -> String {
        super::templates::apply_confidence_wrapping(body, confidence)
    }

    fn group_and_generate(
        &self,
        findings: &[Finding],
        policy_prefix: &str,
        output_dir: &Path,
    ) -> Vec<PolicyFile> {
        super::grouping::group_findings(findings, policy_prefix, output_dir)
            .into_iter()
            .map(|f| PolicyFile {
                label: f.label,
                output_path: f.output_path,
                content: f.content,
                finding_count: f.finding_count,
            })
            .collect()
    }
}
