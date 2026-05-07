mod embedded;

use std::path::Path;

use crate::config::ZiftConfig;
use crate::error::{Result, ZiftError};
use crate::types::{AuthCategory, Confidence, Language, PolicyEngine};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct PatternRule {
    pub id: String,
    pub languages: Vec<Language>,
    pub category: AuthCategory,
    pub confidence: Confidence,
    pub description: String,
    pub externalized: bool,
    pub query_source: String,
    pub predicates: Vec<(String, Predicate)>,
    pub cross_predicates: Vec<CrossPredicate>,
    /// Generated policy templates, one entry per engine. Replaces the
    /// parallel `rego_template` / `cedar_template` fields that existed
    /// pre-Phase-B (#71). The TOML parser accepts both the new
    /// `[[rule.policy_templates]]` array form and the legacy
    /// `[rule.rego_template]` / `[rule.cedar_template]` blocks.
    pub policy_templates: Vec<PolicyTemplate>,
    pub tests: Vec<RuleTest>,
    /// Optional capture name whose matched text should be copied onto each
    /// finding's `provenance` field. Set on rules where the AST exposes a
    /// package-prefix capture (e.g. `@anno_scope` on the scoped-identifier
    /// branch of an annotation alternation) so consumers can distinguish
    /// `javax.*` vs `jakarta.*` migrations without grepping snippets. The
    /// referenced capture must exist in the rule's query — validated by
    /// `compile_rule`. Left `None` when the rule has no notion of provenance
    /// (most rules) or when the capture didn't fire on a particular match
    /// (bare-identifier annotation form).
    pub provenance_capture: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyTemplate {
    pub engine: PolicyEngine,
    pub template: String,
}

impl PatternRule {
    /// Look up the rendered template for a policy engine, if any.
    pub fn template_for(&self, engine: PolicyEngine) -> Option<&str> {
        self.policy_templates
            .iter()
            .find(|t| t.engine == engine)
            .map(|t| t.template.as_str())
    }
}

#[derive(Debug, Clone)]
pub enum Predicate {
    Match(regex::Regex),
    Eq(String),
    NotMatch(regex::Regex),
    NotEq(String),
}

/// A predicate that operates over multiple captures at once. Per-capture
/// predicates (`Predicate`) check a single capture against a value; cross
/// predicates check a *relationship* across two or more captures — e.g.
/// "at least one of these captures must look like a principal getter".
#[derive(Debug, Clone)]
pub enum CrossPredicate {
    /// At least one of the listed captures must match the regex.
    AnyMatch {
        captures: Vec<String>,
        regex: regex::Regex,
    },
    /// All of the listed captures must match the regex.
    AllMatch {
        captures: Vec<String>,
        regex: regex::Regex,
    },
}

impl CrossPredicate {
    /// The captures this predicate references. Centralized so traversal
    /// sites (matcher capture validation, MCP serialization, future tools)
    /// don't each need a `match` arm per variant.
    pub fn referenced_captures(&self) -> &[String] {
        match self {
            CrossPredicate::AnyMatch { captures, .. }
            | CrossPredicate::AllMatch { captures, .. } => captures,
        }
    }

    /// The compiled regex this predicate evaluates captures against.
    pub fn regex(&self) -> &regex::Regex {
        match self {
            CrossPredicate::AnyMatch { regex, .. } | CrossPredicate::AllMatch { regex, .. } => {
                regex
            }
        }
    }

    /// Snake-case variant label, matching the TOML `kind` discriminator.
    /// Used in error messages and JSON serialization.
    pub fn kind_label(&self) -> &'static str {
        match self {
            CrossPredicate::AnyMatch { .. } => "any_match",
            CrossPredicate::AllMatch { .. } => "all_match",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleTest {
    pub input: String,
    pub language: Option<Language>,
    pub expect_match: bool,
}

// -- TOML deserialization types (separate from domain types for flexibility) --

#[derive(Debug, Deserialize)]
struct RuleFile {
    rule: RuleToml,
}

#[derive(Debug, Deserialize)]
struct RuleToml {
    id: String,
    languages: Vec<Language>,
    category: AuthCategory,
    confidence: Confidence,
    description: String,
    #[serde(default)]
    externalized: bool,
    query: String,
    #[serde(default)]
    predicates: std::collections::HashMap<String, PredicateToml>,
    #[serde(default)]
    cross_predicates: Vec<CrossPredicateToml>,
    /// Legacy single-engine template blocks. Read-tolerant: parsing folds
    /// these into `policy_templates` at the [`PatternRule`] level. New rules
    /// should use `[[rule.policy_templates]]` instead.
    rego_template: Option<RegoTemplateToml>,
    cedar_template: Option<CedarTemplateToml>,
    #[serde(default)]
    policy_templates: Vec<PolicyTemplateToml>,
    #[serde(default)]
    tests: Vec<RuleTestToml>,
    #[serde(default)]
    provenance_capture: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyTemplateToml {
    engine: PolicyEngine,
    template: String,
}

#[derive(Debug, Deserialize)]
struct PredicateToml {
    #[serde(rename = "match")]
    match_re: Option<String>,
    eq: Option<String>,
    not_match: Option<String>,
    not_eq: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CrossPredicateToml {
    AnyMatch {
        captures: Vec<String>,
        #[serde(rename = "match")]
        match_re: String,
    },
    AllMatch {
        captures: Vec<String>,
        #[serde(rename = "match")]
        match_re: String,
    },
}

#[derive(Debug, Deserialize)]
struct RegoTemplateToml {
    template: String,
}

#[derive(Debug, Deserialize)]
struct CedarTemplateToml {
    template: String,
}

#[derive(Debug, Deserialize)]
struct RuleTestToml {
    input: String,
    language: Option<Language>,
    expect_match: bool,
}

/// Validate the shared shape of a cross-predicate's TOML fields and compile
/// the regex. Captures must be non-empty and free of duplicates; the regex
/// must parse. Errors include `cross_predicate[i] (kind_label): ...` so a
/// failing rule load points at the exact entry.
fn parse_cross_predicate_fields(
    rule_id: &str,
    index: usize,
    kind_label: &str,
    captures: Vec<String>,
    match_re: &str,
) -> Result<(Vec<String>, regex::Regex)> {
    if captures.is_empty() {
        return Err(ZiftError::RuleParse {
            rule_id: rule_id.to_string(),
            message: format!("cross_predicate[{index}] ({kind_label}): captures must not be empty"),
        });
    }
    let mut seen = std::collections::HashSet::new();
    for capture in &captures {
        if !seen.insert(capture.as_str()) {
            return Err(ZiftError::RuleParse {
                rule_id: rule_id.to_string(),
                message: format!(
                    "cross_predicate[{index}] ({kind_label}): duplicate capture \
                     '{capture}' in captures list"
                ),
            });
        }
    }
    let regex = regex::Regex::new(match_re).map_err(|e| ZiftError::RuleParse {
        rule_id: rule_id.to_string(),
        message: format!("cross_predicate[{index}] ({kind_label}): invalid regex: {e}"),
    })?;
    Ok((captures, regex))
}

fn parse_rule(toml_str: &str, source: &str) -> Result<PatternRule> {
    let file: RuleFile = toml::from_str(toml_str).map_err(|e| ZiftError::RuleParse {
        rule_id: source.to_string(),
        message: e.to_string(),
    })?;

    let r = file.rule;

    let mut predicates = Vec::new();
    for (capture_name, pred) in r.predicates {
        let set_count = [
            pred.match_re.is_some(),
            pred.eq.is_some(),
            pred.not_match.is_some(),
            pred.not_eq.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();

        if set_count > 1 {
            return Err(ZiftError::RuleParse {
                rule_id: r.id.clone(),
                message: format!(
                    "predicate '{capture_name}' must set exactly one of: match, eq, not_match, not_eq"
                ),
            });
        }

        let p = if let Some(re) = pred.match_re {
            Predicate::Match(regex::Regex::new(&re).map_err(|e| ZiftError::RuleParse {
                rule_id: r.id.clone(),
                message: format!("invalid regex in predicate '{capture_name}': {e}"),
            })?)
        } else if let Some(val) = pred.eq {
            Predicate::Eq(val)
        } else if let Some(re) = pred.not_match {
            Predicate::NotMatch(regex::Regex::new(&re).map_err(|e| ZiftError::RuleParse {
                rule_id: r.id.clone(),
                message: format!("invalid regex in predicate '{capture_name}': {e}"),
            })?)
        } else if let Some(val) = pred.not_eq {
            Predicate::NotEq(val)
        } else {
            return Err(ZiftError::RuleParse {
                rule_id: r.id.clone(),
                message: format!("predicate '{capture_name}' has no condition"),
            });
        };
        predicates.push((capture_name, p));
    }

    let mut cross_predicates = Vec::new();
    for (i, cp) in r.cross_predicates.into_iter().enumerate() {
        let parsed = match cp {
            CrossPredicateToml::AnyMatch { captures, match_re } => {
                let (captures, regex) =
                    parse_cross_predicate_fields(&r.id, i, "any_match", captures, &match_re)?;
                CrossPredicate::AnyMatch { captures, regex }
            }
            CrossPredicateToml::AllMatch { captures, match_re } => {
                let (captures, regex) =
                    parse_cross_predicate_fields(&r.id, i, "all_match", captures, &match_re)?;
                CrossPredicate::AllMatch { captures, regex }
            }
        };
        cross_predicates.push(parsed);
    }

    // Dedupe by engine, keeping the first occurrence. `template_for`
    // returns the first match, so hand-written TOML with two
    // `[[rule.policy_templates]]` blocks for the same engine would
    // silently use one of them — drop the rest at parse time so the
    // in-memory shape can't surprise later code.
    let mut policy_templates: Vec<PolicyTemplate> = Vec::with_capacity(r.policy_templates.len());
    for t in r.policy_templates {
        if !policy_templates.iter().any(|p| p.engine == t.engine) {
            policy_templates.push(PolicyTemplate {
                engine: t.engine,
                template: t.template,
            });
        }
    }
    // Fold legacy single-engine template blocks into the new collection.
    // Explicit `[[rule.policy_templates]]` entries win on conflict — same
    // contract as the Finding shim.
    if let Some(t) = r.rego_template
        && !policy_templates
            .iter()
            .any(|p| p.engine == PolicyEngine::Rego)
    {
        policy_templates.push(PolicyTemplate {
            engine: PolicyEngine::Rego,
            template: t.template,
        });
    }
    if let Some(t) = r.cedar_template
        && !policy_templates
            .iter()
            .any(|p| p.engine == PolicyEngine::Cedar)
    {
        policy_templates.push(PolicyTemplate {
            engine: PolicyEngine::Cedar,
            template: t.template,
        });
    }

    Ok(PatternRule {
        id: r.id,
        languages: r.languages,
        category: r.category,
        confidence: r.confidence,
        description: r.description,
        externalized: r.externalized,
        query_source: r.query,
        predicates,
        cross_predicates,
        policy_templates,
        tests: r
            .tests
            .into_iter()
            .map(|t| RuleTest {
                input: t.input,
                language: t.language,
                expect_match: t.expect_match,
            })
            .collect(),
        provenance_capture: r.provenance_capture,
    })
}

#[cfg(test)]
pub fn parse_rule_for_test(toml_str: &str) -> PatternRule {
    parse_rule(toml_str, "test").unwrap()
}

const MAX_RULES_DIR_DEPTH: usize = 10;

fn load_external_rules(dir: &Path) -> Result<Vec<PatternRule>> {
    load_external_rules_inner(dir, 0)
}

fn load_external_rules_inner(dir: &Path, depth: usize) -> Result<Vec<PatternRule>> {
    if depth > MAX_RULES_DIR_DEPTH {
        return Err(ZiftError::General(format!(
            "rules directory exceeds max depth ({MAX_RULES_DIR_DEPTH}): {}",
            dir.display()
        )));
    }
    let mut rules = Vec::new();
    if !dir.exists() {
        return Ok(rules);
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type().is_ok_and(|ft| ft.is_symlink()) {
            tracing::debug!("skipping symlink: {}", path.display());
            continue;
        }
        if path.extension().is_some_and(|e| e == "toml") {
            let content = std::fs::read_to_string(&path)?;
            let rule = parse_rule(&content, &path.display().to_string())?;
            rules.push(rule);
        } else if path.is_dir() {
            rules.extend(load_external_rules_inner(&path, depth + 1)?);
        }
    }
    Ok(rules)
}

pub fn load_rules(extra_rules_dir: Option<&Path>, config: &ZiftConfig) -> Result<Vec<PatternRule>> {
    let mut rules = embedded::load_embedded_rules()?;

    // Load from config additional dirs
    for dir in &config.rules.additional {
        let external = load_external_rules(Path::new(dir))?;
        merge_rules(&mut rules, external);
    }

    // Load from CLI --rules-dir
    if let Some(dir) = extra_rules_dir {
        let external = load_external_rules(dir)?;
        merge_rules(&mut rules, external);
    }

    Ok(rules)
}

fn merge_rules(base: &mut Vec<PatternRule>, overrides: Vec<PatternRule>) {
    for rule in overrides {
        if let Some(pos) = base.iter().position(|r| r.id == rule.id) {
            base[pos] = rule;
        } else {
            base.push(rule);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE: &str = r#"
[rule]
id = "test-role-check"
languages = ["typescript", "javascript"]
category = "rbac"
confidence = "high"
description = "Test role check"
query = """
(if_statement
  condition: (binary_expression
    left: (member_expression
      property: (property_identifier) @prop)
    operator: ["==" "==="]
    right: (string) @role_value)
) @match
"""

[rule.predicates.prop]
match = "role|roles"

[[rule.tests]]
input = """
if (user.role === "admin") { }
"""
expect_match = true
"#;

    #[test]
    fn parse_rule_from_toml() {
        let rule = parse_rule(SAMPLE_RULE, "test").unwrap();
        assert_eq!(rule.id, "test-role-check");
        assert_eq!(rule.languages.len(), 2);
        assert_eq!(rule.category, AuthCategory::Rbac);
        assert_eq!(rule.confidence, Confidence::High);
        assert_eq!(rule.predicates.len(), 1);
        assert_eq!(rule.tests.len(), 1);
        assert!(rule.tests[0].expect_match);
    }

    #[test]
    fn cross_predicate_duplicate_captures_is_parse_error() {
        // A duplicated capture is harmless for any_match/all_match (just
        // redundant work) but indicates user confusion or copy-paste —
        // future variants like `none_match` may treat duplicates
        // differently, so fail loud now.
        let bad_rule = r#"
[rule]
id = "test-cross-dup-captures"
languages = ["java"]
category = "ownership"
confidence = "medium"
description = "Cross-predicate has a duplicated capture"
query = """
(method_invocation
  name: (identifier) @getter
) @match
"""

[[rule.cross_predicates]]
kind = "any_match"
captures = ["getter", "getter"]
match = ".*"
"#;
        let err = parse_rule(bad_rule, "test").expect_err("duplicate captures must error");
        let msg = err.to_string();
        assert!(
            msg.contains("duplicate capture"),
            "error should mention duplicate capture; got: {msg}"
        );
        assert!(
            msg.contains("'getter'"),
            "error should name the duplicated capture; got: {msg}"
        );
        assert!(
            msg.contains("any_match"),
            "error should name the predicate kind; got: {msg}"
        );
    }

    #[test]
    fn cross_predicate_empty_captures_is_parse_error() {
        // Empty captures list is meaningless; same diagnostic family as
        // the duplicate case so users get a consistent error vocabulary.
        let bad_rule = r#"
[rule]
id = "test-cross-empty-captures"
languages = ["java"]
category = "ownership"
confidence = "medium"
description = "Cross-predicate has an empty captures list"
query = """
(method_invocation
  name: (identifier) @getter
) @match
"""

[[rule.cross_predicates]]
kind = "all_match"
captures = []
match = ".*"
"#;
        let err = parse_rule(bad_rule, "test").expect_err("empty captures must error");
        let msg = err.to_string();
        assert!(
            msg.contains("captures must not be empty"),
            "error should mention empty captures; got: {msg}"
        );
        assert!(
            msg.contains("all_match"),
            "error should name the predicate kind; got: {msg}"
        );
    }

    #[test]
    fn legacy_template_blocks_fold_into_policy_templates() {
        // Pre-#71 rules used `[rule.rego_template]` / `[rule.cedar_template]`
        // single-engine blocks. The Phase B parser must accept these and
        // surface them through `policy_templates` so external rule trees
        // keep loading without forced migration.
        let legacy = r#"
[rule]
id = "test-legacy-templates"
languages = ["typescript"]
category = "rbac"
confidence = "high"
description = "uses legacy template blocks"
query = """
(if_statement) @match
"""

[rule.rego_template]
template = "package x\nallow := true"

[rule.cedar_template]
template = "permit(principal, action, resource);"
"#;
        let rule = parse_rule(legacy, "test").unwrap();
        assert_eq!(
            rule.template_for(PolicyEngine::Rego),
            Some("package x\nallow := true")
        );
        assert_eq!(
            rule.template_for(PolicyEngine::Cedar),
            Some("permit(principal, action, resource);")
        );
    }

    #[test]
    fn policy_templates_array_form_parses() {
        let new_form = r#"
[rule]
id = "test-new-templates"
languages = ["typescript"]
category = "rbac"
confidence = "high"
description = "uses new policy_templates array"
query = """
(if_statement) @match
"""

[[rule.policy_templates]]
engine = "rego"
template = "package x"

[[rule.policy_templates]]
engine = "cedar"
template = "permit(principal, action, resource);"
"#;
        let rule = parse_rule(new_form, "test").unwrap();
        assert_eq!(rule.policy_templates.len(), 2);
        assert_eq!(rule.template_for(PolicyEngine::Rego), Some("package x"));
        assert_eq!(
            rule.template_for(PolicyEngine::Cedar),
            Some("permit(principal, action, resource);")
        );
    }

    #[test]
    fn merge_overrides_by_id() {
        let r1 = PatternRule {
            id: "rule-a".into(),
            languages: vec![Language::TypeScript],
            category: AuthCategory::Rbac,
            confidence: Confidence::High,
            description: "original".into(),
            externalized: false,
            query_source: "".into(),
            predicates: vec![],
            cross_predicates: vec![],
            policy_templates: vec![],
            tests: vec![],
            provenance_capture: None,
        };
        let r2 = PatternRule {
            id: "rule-a".into(),
            languages: vec![Language::TypeScript],
            category: AuthCategory::Rbac,
            confidence: Confidence::Medium,
            description: "override".into(),
            externalized: false,
            query_source: "".into(),
            predicates: vec![],
            cross_predicates: vec![],
            policy_templates: vec![],
            tests: vec![],
            provenance_capture: None,
        };

        let mut base = vec![r1];
        merge_rules(&mut base, vec![r2]);
        assert_eq!(base.len(), 1);
        assert_eq!(base[0].description, "override");
    }
}
