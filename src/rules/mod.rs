mod embedded;

use std::path::Path;

use crate::config::ZiftConfig;
use crate::error::{Result, ZiftError};
use crate::types::{AuthCategory, Confidence, Language};

use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct PatternRule {
    pub id: String,
    pub languages: Vec<Language>,
    pub category: AuthCategory,
    pub confidence: Confidence,
    pub description: String,
    pub query_source: String,
    pub predicates: Vec<(String, Predicate)>,
    pub rego_template: Option<String>,
    pub tests: Vec<RuleTest>,
}

#[derive(Debug, Clone)]
pub enum Predicate {
    Match(regex::Regex),
    Eq(String),
    NotMatch(regex::Regex),
    NotEq(String),
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
    query: String,
    #[serde(default)]
    predicates: std::collections::HashMap<String, PredicateToml>,
    rego_template: Option<RegoTemplateToml>,
    #[serde(default)]
    tests: Vec<RuleTestToml>,
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
struct RegoTemplateToml {
    template: String,
}

#[derive(Debug, Deserialize)]
struct RuleTestToml {
    input: String,
    language: Option<Language>,
    expect_match: bool,
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

    Ok(PatternRule {
        id: r.id,
        languages: r.languages,
        category: r.category,
        confidence: r.confidence,
        description: r.description,
        query_source: r.query,
        predicates,
        rego_template: r.rego_template.map(|t| t.template),
        tests: r
            .tests
            .into_iter()
            .map(|t| RuleTest {
                input: t.input,
                language: t.language,
                expect_match: t.expect_match,
            })
            .collect(),
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

pub fn load_rules(
    extra_rules_dir: Option<&Path>,
    config: &ZiftConfig,
) -> Result<Vec<PatternRule>> {
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
    fn merge_overrides_by_id() {
        let r1 = PatternRule {
            id: "rule-a".into(),
            languages: vec![Language::TypeScript],
            category: AuthCategory::Rbac,
            confidence: Confidence::High,
            description: "original".into(),
            query_source: "".into(),
            predicates: vec![],
            rego_template: None,
            tests: vec![],
        };
        let r2 = PatternRule {
            id: "rule-a".into(),
            languages: vec![Language::TypeScript],
            category: AuthCategory::Rbac,
            confidence: Confidence::Medium,
            description: "override".into(),
            query_source: "".into(),
            predicates: vec![],
            rego_template: None,
            tests: vec![],
        };

        let mut base = vec![r1];
        merge_rules(&mut base, vec![r2]);
        assert_eq!(base.len(), 1);
        assert_eq!(base[0].description, "override");
    }
}
