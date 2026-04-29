use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub file: PathBuf,
    pub line_start: usize,
    pub line_end: usize,
    pub code_snippet: String,
    pub language: Language,
    pub category: AuthCategory,
    pub confidence: Confidence,
    pub description: String,
    pub pattern_rule: Option<String>,
    pub rego_stub: Option<String>,
    pub pass: ScanPass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum AuthCategory {
    Rbac,
    Abac,
    Middleware,
    #[value(name = "business-rule")]
    BusinessRule,
    Ownership,
    #[value(name = "feature-gate")]
    FeatureGate,
    Custom,
}

impl AuthCategory {
    /// Snake_case wire form, matching the serde `rename_all = "snake_case"`
    /// applied to this enum. Use this anywhere the canonical wire spelling
    /// is needed (JSON map keys, prompt schema enum, MCP tool args).
    /// Distinct from [`std::fmt::Display`], which produces a human-friendly
    /// form (`"Business Rule"`) — mixing the two in one JSON document
    /// produces inconsistent keys (e.g. summary `"business rule"` vs.
    /// finding `"business_rule"`), which breaks consumers grouping by
    /// category.
    pub fn slug(&self) -> &'static str {
        match self {
            AuthCategory::Rbac => "rbac",
            AuthCategory::Abac => "abac",
            AuthCategory::Middleware => "middleware",
            AuthCategory::BusinessRule => "business_rule",
            AuthCategory::Ownership => "ownership",
            AuthCategory::FeatureGate => "feature_gate",
            AuthCategory::Custom => "custom",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl std::str::FromStr for Confidence {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "low" => Ok(Confidence::Low),
            "medium" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            _ => Err(format!("unknown confidence level: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanPass {
    Structural,
    Semantic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Java,
    #[serde(rename = "typescript")]
    #[value(name = "typescript")]
    TypeScript,
    #[serde(rename = "javascript")]
    #[value(name = "javascript")]
    JavaScript,
    Python,
    Go,
    #[serde(rename = "csharp")]
    #[value(name = "csharp")]
    CSharp,
    Kotlin,
    Ruby,
    Php,
}

impl std::fmt::Display for Language {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Language::Java => write!(f, "java"),
            Language::TypeScript => write!(f, "typescript"),
            Language::JavaScript => write!(f, "javascript"),
            Language::Python => write!(f, "python"),
            Language::Go => write!(f, "go"),
            Language::CSharp => write!(f, "csharp"),
            Language::Kotlin => write!(f, "kotlin"),
            Language::Ruby => write!(f, "ruby"),
            Language::Php => write!(f, "php"),
        }
    }
}

impl std::fmt::Display for AuthCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthCategory::Rbac => write!(f, "RBAC"),
            AuthCategory::Abac => write!(f, "ABAC"),
            AuthCategory::Middleware => write!(f, "Middleware"),
            AuthCategory::BusinessRule => write!(f, "Business Rule"),
            AuthCategory::Ownership => write!(f, "Ownership"),
            AuthCategory::FeatureGate => write!(f, "Feature Gate"),
            AuthCategory::Custom => write!(f, "Custom"),
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Confidence::Low => write!(f, "low"),
            Confidence::Medium => write!(f, "medium"),
            Confidence::High => write!(f, "high"),
        }
    }
}
