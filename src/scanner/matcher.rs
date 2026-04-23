use std::collections::HashMap;
use std::path::Path;

use sha2::{Digest, Sha256};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Query, QueryCursor, Tree};

use crate::error::{Result, ZiftError};
use crate::rules::{PatternRule, Predicate};
use crate::types::{Confidence, Finding, Language, ScanPass};

pub struct CompiledRule<'a> {
    pub rule: &'a PatternRule,
    pub query: Query,
    pub match_index: u32,
    pub capture_names: Vec<String>,
}

pub fn compile_rule<'a>(
    rule: &'a PatternRule,
    ts_lang: &tree_sitter::Language,
) -> Result<CompiledRule<'a>> {
    let query = Query::new(ts_lang, &rule.query_source).map_err(|e| ZiftError::QueryError {
        rule_id: rule.id.clone(),
        message: e.to_string(),
    })?;

    let capture_names: Vec<String> = query
        .capture_names()
        .iter()
        .map(|s| s.to_string())
        .collect();

    let match_index = capture_names
        .iter()
        .position(|n| n == "match")
        .ok_or_else(|| ZiftError::QueryError {
            rule_id: rule.id.clone(),
            message: "query must have a @match capture".into(),
        })? as u32;

    Ok(CompiledRule {
        rule,
        query,
        match_index,
        capture_names,
    })
}

pub fn execute_query(
    compiled: &CompiledRule<'_>,
    tree: &Tree,
    source: &[u8],
    file_path: &Path,
    language: Language,
) -> Result<Vec<Finding>> {
    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&compiled.query, tree.root_node(), source);
    let mut findings = Vec::new();

    while let Some(query_match) = matches.next() {
        // Extract capture texts
        let mut captures: HashMap<&str, String> = HashMap::new();
        let mut match_node = None;

        for capture in query_match.captures {
            let name = compiled
                .capture_names
                .get(capture.index as usize)
                .ok_or_else(|| {
                    ZiftError::General(format!(
                        "rule '{}': capture index {} out of range (max {})",
                        compiled.rule.id,
                        capture.index,
                        compiled.capture_names.len() - 1,
                    ))
                })?;
            let text = capture
                .node
                .utf8_text(source)
                .unwrap_or_default()
                .to_string();

            if capture.index == compiled.match_index {
                match_node = Some(capture.node);
            }
            captures.insert(name, text);
        }

        let Some(matched) = match_node else {
            continue;
        };

        // Apply predicates
        if !check_predicates(&compiled.rule.predicates, &captures) {
            continue;
        }

        let line_start = matched.start_position().row + 1;
        let line_end = matched.end_position().row + 1;
        let code_snippet = matched.utf8_text(source).unwrap_or_default().to_string();

        let id = compute_finding_id(
            &compiled.rule.id,
            file_path,
            line_start,
            line_end,
            &code_snippet,
        );

        findings.push(Finding {
            id,
            file: file_path.to_path_buf(),
            line_start,
            line_end,
            code_snippet,
            language,
            category: compiled.rule.category,
            confidence: compiled.rule.confidence,
            description: compiled.rule.description.clone(),
            pattern_rule: Some(compiled.rule.id.clone()),
            rego_stub: compiled.rule.rego_template.as_ref().map(|tmpl| {
                let owned: HashMap<String, String> = captures
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect();
                crate::rego::render_template(tmpl, &owned)
            }),
            pass: ScanPass::Structural,
        });
    }

    Ok(findings)
}

fn check_predicates(predicates: &[(String, Predicate)], captures: &HashMap<&str, String>) -> bool {
    for (capture_name, predicate) in predicates {
        let Some(text) = captures.get(capture_name.as_str()) else {
            return false;
        };
        match predicate {
            Predicate::Match(re) => {
                if !re.is_match(text) {
                    return false;
                }
            }
            Predicate::Eq(expected) => {
                if text != expected {
                    return false;
                }
            }
            Predicate::NotMatch(re) => {
                if re.is_match(text) {
                    return false;
                }
            }
            Predicate::NotEq(expected) => {
                if text == expected {
                    return false;
                }
            }
        }
    }
    true
}

fn compute_finding_id(
    rule_id: &str,
    file_path: &Path,
    line_start: usize,
    line_end: usize,
    snippet: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(rule_id.as_bytes());
    hasher.update(file_path.to_string_lossy().as_bytes());
    hasher.update(line_start.to_le_bytes());
    hasher.update(line_end.to_le_bytes());
    hasher.update(snippet.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn filter_findings(
    findings: Vec<Finding>,
    min_confidence: Option<Confidence>,
    categories: &[crate::types::AuthCategory],
) -> Vec<Finding> {
    findings
        .into_iter()
        .filter(|f| {
            if let Some(min) = min_confidence
                && f.confidence < min
            {
                return false;
            }
            if !categories.is_empty() && !categories.contains(&f.category) {
                return false;
            }
            true
        })
        .collect()
}

pub fn dedup_findings(findings: Vec<Finding>) -> Vec<Finding> {
    let mut seen = std::collections::HashSet::new();
    findings
        .into_iter()
        .filter(|f| seen.insert(f.id.clone()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules;
    use crate::scanner::parser;

    fn parse_and_match(source: &str, rule_toml: &str) -> Vec<Finding> {
        let rule = rules::parse_rule_for_test(rule_toml);
        let mut ts_parser = tree_sitter::Parser::new();
        let lang = rule.languages[0];
        let ts_lang = parser::get_language(lang, false).unwrap();
        let tree = parser::parse_source(&mut ts_parser, source.as_bytes(), lang, false).unwrap();
        let compiled = compile_rule(&rule, &ts_lang).unwrap();
        execute_query(
            &compiled,
            &tree,
            source.as_bytes(),
            Path::new("test.ts"),
            lang,
        )
        .unwrap()
    }

    #[test]
    fn role_check_conditional_matches() {
        let findings = parse_and_match(
            r#"if (user.role === "admin") { deleteUser(id); }"#,
            include_str!("../../rules/typescript/role-check-conditional.toml"),
        );
        assert!(!findings.is_empty(), "expected a finding for role check");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn role_check_conditional_no_false_positive() {
        let findings = parse_and_match(
            r#"if (user.name === "admin") { greet(); }"#,
            include_str!("../../rules/typescript/role-check-conditional.toml"),
        );
        assert!(findings.is_empty(), "should not match non-role property");
    }

    #[test]
    fn has_role_call_matches() {
        let findings = parse_and_match(
            r#"if (hasRole("manager")) { approveRequest(); }"#,
            include_str!("../../rules/typescript/has-role-call.toml"),
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn express_auth_middleware_matches() {
        let findings = parse_and_match(
            r#"app.use(requireAuth);"#,
            include_str!("../../rules/typescript/express-auth-middleware.toml"),
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn express_auth_middleware_no_false_positive() {
        let findings = parse_and_match(
            r#"app.use(cors);"#,
            include_str!("../../rules/typescript/express-auth-middleware.toml"),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn permission_check_matches() {
        let findings = parse_and_match(
            r#"if (user.can("delete")) { doIt(); }"#,
            include_str!("../../rules/typescript/permission-check-call.toml"),
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn dedup_removes_duplicates() {
        let f = Finding {
            id: "abc123".into(),
            file: "test.ts".into(),
            line_start: 1,
            line_end: 1,
            code_snippet: "test".into(),
            language: Language::TypeScript,
            category: crate::types::AuthCategory::Rbac,
            confidence: Confidence::High,
            description: "test".into(),
            pattern_rule: None,
            rego_stub: None,
            pass: ScanPass::Structural,
        };
        let findings = vec![f.clone(), f];
        let deduped = dedup_findings(findings);
        assert_eq!(deduped.len(), 1);
    }
}
