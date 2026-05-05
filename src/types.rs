use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
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
    /// Where in a typical app this finding lives — frontend (UI/client) or
    /// backend (server/API). Inferred from the file path via simple
    /// directory-name heuristics in [`Surface::classify`]. Surfaced so
    /// downstream consumers can filter out frontend `ownership`-style noise
    /// (e.g. Zulip's `web/src/...` `user.user_id === current_user.user_id`
    /// matches, which are UI state checks rather than security gates) without
    /// us having to bake that filter into rule predicates. Defaults to
    /// `Backend` when the path doesn't match any frontend-shaped directory,
    /// which is the right default for the scanner's primary target (backend
    /// authz code).
    #[serde(default)]
    pub surface: Surface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Surface {
    #[default]
    Backend,
    Frontend,
}

impl Surface {
    /// Classify a finding's surface from its file path. Heuristic-only —
    /// looks for a small set of well-known *strong* frontend directory names
    /// anywhere in the path (`web`, `webapp`, `client`, `frontend`, `ui`).
    /// Generic tokens like `public/` and `static/` are intentionally **not**
    /// in the strong list — they show up in plenty of backend trees
    /// (`lib/public/api.go`, `services/static/registry.rs`) and treating
    /// them as Frontend on their own would silently downgrade real findings.
    /// They only count when a strong marker is also present in the path
    /// (e.g. `apps/web/public/main.js`), which already classifies as Frontend
    /// via the strong marker — so dropping them from the regex is equivalent
    /// to "weak markers require a nearby strong marker."
    ///
    /// Conservative on purpose: false negatives (frontend code classified as
    /// backend) leave the existing behavior unchanged, while false positives
    /// (backend code classified as frontend) would silently downgrade real
    /// findings — so when in doubt, return `Backend`.
    ///
    /// The match is case-insensitive and segment-bounded (we want
    /// `app/web/foo.ts` but not `apps/network/foo.ts` or `webhooks/foo.ts`).
    pub fn classify(path: &Path) -> Self {
        static FRONTEND_RE: OnceLock<Regex> = OnceLock::new();
        let re = FRONTEND_RE.get_or_init(|| {
            // Anchored at a path separator (or string start) and followed by
            // a separator so we don't accidentally match `webhooks/`,
            // `clientservice/`, etc. `(?i)` makes it case-insensitive.
            Regex::new(r"(?i)(^|[\\/])(web|webapp|client|frontend|ui)[\\/]")
                .expect("static regex compiles")
        });
        if re.is_match(&path.to_string_lossy()) {
            Surface::Frontend
        } else {
            Surface::Backend
        }
    }
}

impl std::fmt::Display for Surface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Surface::Backend => write!(f, "backend"),
            Surface::Frontend => write!(f, "frontend"),
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_classifies_frontend_directories() {
        assert_eq!(
            Surface::classify(Path::new("web/src/foo.ts")),
            Surface::Frontend
        );
        assert_eq!(
            Surface::classify(Path::new("apps/web/src/page.tsx")),
            Surface::Frontend
        );
        assert_eq!(
            Surface::classify(Path::new("packages/client/index.ts")),
            Surface::Frontend
        );
        assert_eq!(
            Surface::classify(Path::new("frontend/components/Foo.tsx")),
            Surface::Frontend
        );
        assert_eq!(
            Surface::classify(Path::new("apps/ui/Settings.tsx")),
            Surface::Frontend
        );
        // `public/` co-occurring with a strong marker (`web`) is still
        // Frontend — the strong marker carries the classification.
        assert_eq!(
            Surface::classify(Path::new("apps/web/public/main.js")),
            Surface::Frontend
        );
        // Case-insensitive — matches `Web/` as well as `web/`.
        assert_eq!(
            Surface::classify(Path::new("Apps/Web/Foo.tsx")),
            Surface::Frontend
        );
    }

    #[test]
    fn surface_does_not_misclassify_backend_paths() {
        // Adjacent-name traps: `webhooks/` is not `web/`, `clientservice/`
        // is not `client/` — segment boundaries matter.
        assert_eq!(
            Surface::classify(Path::new("internal/webhooks/handler.go")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("services/clientservice/main.go")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("server/api/users.py")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("zerver/views/auth.py")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("models/perm/access/role.go")),
            Surface::Backend
        );
        // Generic tokens without a strong marker stay Backend, by design —
        // false-positive avoidance for trees like `lib/public/api.go` or
        // `services/static/registry.rs`. Accepts a false negative on
        // bare `public/assets/main.js`-style trees in exchange.
        assert_eq!(
            Surface::classify(Path::new("lib/public/api.go")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("services/static/registry.rs")),
            Surface::Backend
        );
    }

    #[test]
    fn surface_default_round_trips_through_serde() {
        // Old JSON output predates the `surface` field — deserialization
        // must default to Backend rather than failing.
        let no_surface = r#"{
            "id": "x",
            "file": "a.ts",
            "line_start": 1,
            "line_end": 1,
            "code_snippet": "",
            "language": "typescript",
            "category": "rbac",
            "confidence": "low",
            "description": "",
            "pattern_rule": null,
            "rego_stub": null,
            "pass": "structural"
        }"#;
        let f: Finding = serde_json::from_str(no_surface).unwrap();
        assert_eq!(f.surface, Surface::Backend);
    }
}
