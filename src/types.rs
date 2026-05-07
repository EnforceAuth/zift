use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEngine {
    Rego,
    Cedar,
}

impl PolicyEngine {
    /// Lowercase canonical identifier used in JSON keys, CLI flags, and
    /// log lines. Stable across the public surface — matches the serde
    /// representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            PolicyEngine::Rego => "rego",
            PolicyEngine::Cedar => "cedar",
        }
    }

    /// Human-readable name for prose-style output (e.g. "Generated 3
    /// Rego files"). Distinct from [`Self::as_str`] so user-facing
    /// messages stay capitalized.
    pub fn human_name(&self) -> &'static str {
        match self {
            PolicyEngine::Rego => "Rego",
            PolicyEngine::Cedar => "Cedar",
        }
    }
}

impl std::fmt::Display for PolicyEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOutput {
    pub engine: PolicyEngine,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(from = "FindingShim")]
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
    /// Generated policy stubs, one per engine. Replaces the parallel
    /// `rego_stub`/`cedar_stub` fields that existed pre-Phase-B (#71).
    /// Deserialization is tolerant of legacy findings: a `FindingShim`
    /// reads `rego_stub` / `cedar_stub` if present and folds them into
    /// `policy_outputs` so persisted findings files keep loading.
    /// Serialization writes only `policy_outputs`.
    #[serde(default)]
    pub policy_outputs: Vec<PolicyOutput>,
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

impl Finding {
    /// Look up the generated policy content for an engine, if any.
    pub fn policy_output(&self, engine: PolicyEngine) -> Option<&str> {
        self.policy_outputs
            .iter()
            .find(|p| p.engine == engine)
            .map(|p| p.content.as_str())
    }

    /// Insert or replace the policy output for an engine. Removes any
    /// existing entries for the engine first so the vector holds at most
    /// one [`PolicyOutput`] per [`PolicyEngine`], even if a Finding was
    /// constructed in-memory with duplicates.
    pub fn set_policy_output(&mut self, engine: PolicyEngine, content: String) {
        self.policy_outputs.retain(|p| p.engine != engine);
        self.policy_outputs.push(PolicyOutput { engine, content });
    }
}

/// Deserialization shim for [`Finding`]. Accepts both the current
/// `policy_outputs` array and the legacy parallel `rego_stub` / `cedar_stub`
/// fields so existing persisted findings JSON keeps loading after the Phase B
/// refactor (#71). On the read side legacy fields are folded into
/// `policy_outputs`; the serialize side never emits them.
#[derive(Deserialize)]
struct FindingShim {
    id: String,
    file: PathBuf,
    line_start: usize,
    line_end: usize,
    code_snippet: String,
    language: Language,
    category: AuthCategory,
    confidence: Confidence,
    description: String,
    pattern_rule: Option<String>,
    #[serde(default)]
    rego_stub: Option<String>,
    #[serde(default)]
    cedar_stub: Option<String>,
    #[serde(default)]
    policy_outputs: Vec<PolicyOutput>,
    pass: ScanPass,
    #[serde(default)]
    surface: Surface,
}

impl From<FindingShim> for Finding {
    fn from(s: FindingShim) -> Self {
        // Dedupe explicit entries by engine, keeping the first occurrence.
        // Hand-written or mid-migration JSON could carry duplicates; the
        // lookup helpers (`policy_output`) silently return the first match,
        // so dropping the rest at parse time keeps the in-memory shape
        // honest.
        let mut policy_outputs: Vec<PolicyOutput> = Vec::with_capacity(s.policy_outputs.len());
        for po in s.policy_outputs {
            if !policy_outputs.iter().any(|p| p.engine == po.engine) {
                policy_outputs.push(po);
            }
        }
        // Fold legacy fields into policy_outputs only when the new field
        // doesn't already carry an entry for that engine — explicit
        // `policy_outputs` wins on conflict.
        if let Some(content) = s.rego_stub
            && !policy_outputs
                .iter()
                .any(|p| p.engine == PolicyEngine::Rego)
        {
            policy_outputs.push(PolicyOutput {
                engine: PolicyEngine::Rego,
                content,
            });
        }
        if let Some(content) = s.cedar_stub
            && !policy_outputs
                .iter()
                .any(|p| p.engine == PolicyEngine::Cedar)
        {
            policy_outputs.push(PolicyOutput {
                engine: PolicyEngine::Cedar,
                content,
            });
        }
        Finding {
            id: s.id,
            file: s.file,
            line_start: s.line_start,
            line_end: s.line_end,
            code_snippet: s.code_snippet,
            language: s.language,
            category: s.category,
            confidence: s.confidence,
            description: s.description,
            pattern_rule: s.pattern_rule,
            policy_outputs,
            pass: s.pass,
            surface: s.surface,
        }
    }
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
    /// requires **both** a well-known *strong* frontend directory name
    /// (`web`, `webapp`, `client`, `frontend`, `ui`) AND a frontend file
    /// extension on the leaf. Generic tokens like `public/` and `static/`
    /// are intentionally **not** in the strong list — they show up in
    /// plenty of backend trees (`lib/public/api.go`,
    /// `services/static/registry.rs`) and treating them as Frontend on
    /// their own would silently downgrade real findings. They only count
    /// when a strong marker is also present in the path (e.g.
    /// `apps/web/public/main.js`), which already classifies as Frontend
    /// via the strong marker — so dropping them from the regex is
    /// equivalent to "weak markers require a nearby strong marker."
    ///
    /// The extension gate covers the inverse trap: a Java/Rust/Go backend
    /// project may legitimately use a `web/`, `client/`, or `ui/`
    /// subdirectory for its server-side HTTP/UI-glue layer
    /// (`src/main/java/com/x/web/UserService.java`,
    /// `crates/server/src/web/handler.rs`). Without an extension check the
    /// directory marker alone would misclassify those as Frontend and
    /// silently suppress real backend findings for consumers that filter
    /// frontend results.
    ///
    /// Conservative on purpose: false negatives (frontend code classified
    /// as backend) leave the existing behavior unchanged, while false
    /// positives (backend code classified as frontend) would silently
    /// downgrade real findings — so when in doubt, return `Backend`.
    ///
    /// The directory match is case-insensitive and segment-bounded (we
    /// want `app/web/foo.ts` but not `apps/network/foo.ts` or
    /// `webhooks/foo.ts`). The extension match is also case-insensitive.
    pub fn classify(path: &Path) -> Self {
        static FRONTEND_RE: OnceLock<Regex> = OnceLock::new();
        let re = FRONTEND_RE.get_or_init(|| {
            // Anchored at a path separator (or string start) and followed by
            // a separator so we don't accidentally match `webhooks/`,
            // `clientservice/`, etc. `(?i)` makes it case-insensitive.
            Regex::new(r"(?i)(^|[\\/])(web|webapp|client|frontend|ui)[\\/]")
                .expect("static regex compiles")
        });
        if !re.is_match(&path.to_string_lossy()) {
            return Surface::Backend;
        }
        if !has_frontend_extension(path) {
            return Surface::Backend;
        }
        Surface::Frontend
    }
}

/// Frontend-asset file extensions we recognize when gating
/// [`Surface::classify`]. Lowercase, no leading dot. Kept narrow on
/// purpose: a backend `web/` package full of `.java`/`.go`/`.py` files
/// must not slip through. Extensionless files (no extension at all)
/// stay Backend by design — the directory marker on its own isn't a
/// strong enough signal to override the safe default.
fn has_frontend_extension(path: &Path) -> bool {
    const FRONTEND_EXTS: &[&str] = &[
        "js", "jsx", "ts", "tsx", "mjs", "cjs", "html", "htm", "css", "scss", "sass", "less",
        "vue", "svelte", "astro",
    ];
    let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
        return false;
    };
    let lower = ext.to_ascii_lowercase();
    FRONTEND_EXTS.iter().any(|e| *e == lower)
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
    fn surface_requires_frontend_extension_even_with_strong_marker() {
        // Strong directory marker present, but the leaf file is a backend
        // language — must classify as Backend. Java/Rust/Go projects
        // legitimately use `web/`, `client/`, `ui/` packages for their
        // server-side HTTP/UI-glue layer, and treating those as Frontend
        // would silently downgrade real findings for consumers that filter
        // frontend results.
        assert_eq!(
            Surface::classify(Path::new("src/main/java/com/x/web/UserService.java")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("crates/server/src/web/handler.rs")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("internal/client/auth.go")),
            Surface::Backend
        );
        assert_eq!(
            Surface::classify(Path::new("services/ui/templating.py")),
            Surface::Backend
        );
        // Extensionless files stay Backend — directory marker alone isn't
        // strong enough signal to override the safe default.
        assert_eq!(
            Surface::classify(Path::new("apps/web/Makefile")),
            Surface::Backend
        );
    }

    #[test]
    fn surface_extension_gate_is_case_insensitive() {
        // Same as `Apps/Web/Foo.tsx` upstream, but capitalised extension —
        // the `.TSX` should still trip the frontend gate.
        assert_eq!(
            Surface::classify(Path::new("apps/web/Component.TSX")),
            Surface::Frontend
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

    #[test]
    fn legacy_stub_fields_fold_into_policy_outputs() {
        // Pre-#71 findings JSON used parallel `rego_stub` and `cedar_stub`
        // fields. The Phase B shim must accept both shapes and surface them
        // through `policy_outputs` so consumers loading old findings files
        // see the generated policies in the new place.
        let legacy = r#"{
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
            "rego_stub": "package x\nallow := true",
            "cedar_stub": "permit(principal, action, resource);",
            "pass": "structural"
        }"#;
        let f: Finding = serde_json::from_str(legacy).unwrap();
        assert_eq!(
            f.policy_output(PolicyEngine::Rego),
            Some("package x\nallow := true")
        );
        assert_eq!(
            f.policy_output(PolicyEngine::Cedar),
            Some("permit(principal, action, resource);")
        );
    }

    #[test]
    fn explicit_policy_outputs_wins_over_legacy_fields() {
        // If a producer wrote both shapes (e.g. mid-migration), the explicit
        // `policy_outputs` entry takes precedence — matches the From impl
        // contract that the new field is authoritative.
        let mixed = r#"{
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
            "rego_stub": "legacy",
            "policy_outputs": [{"engine": "rego", "content": "current"}],
            "pass": "structural"
        }"#;
        let f: Finding = serde_json::from_str(mixed).unwrap();
        assert_eq!(f.policy_output(PolicyEngine::Rego), Some("current"));
    }

    #[test]
    fn finding_serializes_only_policy_outputs() {
        // After the refactor we never write `rego_stub` / `cedar_stub` on
        // serialize — only the `policy_outputs` array. Existing downstream
        // consumers reading the legacy keys are documented to need an
        // update (see the changelog for #71).
        let f: Finding = serde_json::from_str(
            r#"{
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
            "rego_stub": "package x",
            "pass": "structural"
        }"#,
        )
        .unwrap();
        let json = serde_json::to_string(&f).unwrap();
        assert!(!json.contains("rego_stub"));
        assert!(!json.contains("cedar_stub"));
        assert!(json.contains("policy_outputs"));
    }
}
