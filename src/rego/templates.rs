use std::collections::HashMap;

use regex::Regex;

use crate::types::{AuthCategory, Confidence};

/// Render a template string by replacing `{{key}}` placeholders with values.
/// String values captured from tree-sitter are stripped of surrounding quotes.
pub fn render_template(template: &str, vars: &HashMap<String, String>) -> String {
    let re = Regex::new(r"\{\{(\w+)\}\}").unwrap();
    re.replace_all(template, |caps: &regex::Captures| {
        let key = &caps[1];
        match vars.get(key) {
            Some(val) if key == "roles_set" => val.to_string(),
            Some(val) => strip_quotes(val).to_string(),
            None => caps[0].to_string(), // leave placeholder
        }
    })
    .to_string()
}

/// Strip surrounding single or double quotes from a string value.
fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    if s.len() >= 2
        && ((s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')))
    {
        &s[1..s.len() - 1]
    } else {
        s
    }
}

/// Extract quoted string literals from a code snippet.
pub fn extract_string_literals(code: &str) -> Vec<String> {
    let re = Regex::new(r#"["']([^"']+)["']"#).unwrap();
    re.captures_iter(code).map(|c| c[1].to_string()).collect()
}

/// Return a default Rego template for the given auth category.
pub fn default_template(category: AuthCategory) -> &'static str {
    match category {
        AuthCategory::Rbac => {
            r#"default allow := false

allow if {
    input.user.role in {{roles}}
}"#
        }
        AuthCategory::Abac => {
            r#"default allow := false

allow if {
    # TODO: verify attribute check
    input.user.{{attribute}} == "{{value}}"
}"#
        }
        AuthCategory::Middleware => {
            r#"default allow := false

allow if {
    input.request.authenticated == true
}"#
        }
        AuthCategory::Ownership => {
            r#"default allow := false

allow if {
    input.resource.owner == input.user.id
}"#
        }
        AuthCategory::BusinessRule => {
            r#"# TODO: business rule — review and implement manually
# default allow := false
# allow if {
#     ...
# }"#
        }
        AuthCategory::FeatureGate => {
            r#"default allow := false

allow if {
    input.user.plan in {{plans}}
}"#
        }
        AuthCategory::Custom => {
            r#"# TODO: custom authorization pattern — review and implement manually
# default allow := false
# allow if {
#     ...
# }"#
        }
    }
}

/// Build a Rego stub for a finding using category defaults + extracted values.
pub fn generate_default_stub(category: AuthCategory, code_snippet: &str) -> String {
    let template = default_template(category);
    let literals = extract_string_literals(code_snippet);

    let mut vars = HashMap::new();

    match category {
        AuthCategory::Rbac => {
            // If any string contains ':', it likely represents a permission (e.g., "orders:read")
            // rather than a role name — use a permission-based template instead
            if literals.iter().any(|s| s.contains(':')) {
                let checks = literals
                    .iter()
                    .filter(|s| s.contains(':'))
                    .map(|p| format!("    \"{p}\" in input.user.permissions"))
                    .collect::<Vec<_>>()
                    .join("\n");
                return format!("default allow := false\n\nallow if {{\n{checks}\n}}");
            }
            let roles = if literals.is_empty() {
                "{\"TODO\"}".to_string()
            } else {
                format!(
                    "{{{}}}",
                    literals
                        .iter()
                        .map(|r| format!("\"{r}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            vars.insert("roles".to_string(), roles);
        }
        AuthCategory::FeatureGate => {
            let plans = if literals.is_empty() {
                "{\"TODO\"}".to_string()
            } else {
                format!(
                    "{{{}}}",
                    literals
                        .iter()
                        .map(|p| format!("\"{p}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            vars.insert("plans".to_string(), plans);
        }
        AuthCategory::Abac => {
            vars.insert(
                "attribute".to_string(),
                literals.first().cloned().unwrap_or("TODO".into()),
            );
            vars.insert(
                "value".to_string(),
                literals.get(1).cloned().unwrap_or("TODO".into()),
            );
        }
        _ => {}
    }

    // For default templates, we do a simple replacement (no {{ }} delimiters
    // since defaults embed them literally for sets like {{"admin"}})
    // We need a different approach: replace the {{key}} placeholders
    render_template(template, &vars)
}

/// Wrap a Rego stub based on confidence level.
pub fn apply_confidence_wrapping(rego_body: &str, confidence: Confidence) -> String {
    match confidence {
        Confidence::High => rego_body.to_string(),
        Confidence::Medium => {
            format!("# TODO: verify this policy\n{rego_body}")
        }
        Confidence::Low => {
            let commented: String = rego_body
                .lines()
                .map(|line| {
                    if line.is_empty() || line.starts_with('#') {
                        line.to_string()
                    } else {
                        format!("# {line}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("# SUGGESTION: review and uncomment if correct\n{commented}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_simple_template() {
        let mut vars = HashMap::new();
        vars.insert("role".to_string(), "\"admin\"".to_string());
        let result = render_template("role == \"{{role}}\"", &vars);
        assert_eq!(result, "role == \"admin\"");
    }

    #[test]
    fn render_set_template_keeps_item_quotes() {
        let mut vars = HashMap::new();
        vars.insert(
            "roles_set".to_string(),
            "\"Admin\", \"Manager\"".to_string(),
        );
        let result = render_template("role in {{{roles_set}}}", &vars);
        assert_eq!(result, "role in {\"Admin\", \"Manager\"}");
    }

    #[test]
    fn render_unknown_set_template_strips_outer_quotes() {
        let mut vars = HashMap::new();
        vars.insert("claims_set".to_string(), "\"Admin\"".to_string());
        let result = render_template("claim == \"{{claims_set}}\"", &vars);
        assert_eq!(result, "claim == \"Admin\"");
    }

    #[test]
    fn render_missing_var_leaves_placeholder() {
        let vars = HashMap::new();
        let result = render_template("{{missing}}", &vars);
        assert_eq!(result, "{{missing}}");
    }

    #[test]
    fn strip_quotes_double() {
        assert_eq!(strip_quotes("\"admin\""), "admin");
    }

    #[test]
    fn strip_quotes_single() {
        assert_eq!(strip_quotes("'admin'"), "admin");
    }

    #[test]
    fn strip_quotes_none() {
        assert_eq!(strip_quotes("admin"), "admin");
    }

    #[test]
    fn extract_literals() {
        let code = r#"if (user.role === "admin" || user.role === "manager")"#;
        let lits = extract_string_literals(code);
        assert_eq!(lits, vec!["admin", "manager"]);
    }

    #[test]
    fn default_stub_rbac_permissions() {
        let stub = generate_default_stub(
            AuthCategory::Rbac,
            r#"authorize(user, "audit:read", { type: "audit" })"#,
        );
        assert!(stub.contains("input.user.permissions"));
        assert!(stub.contains("audit:read"));
        // "audit" (without colon) should not appear as a permission check
        assert!(!stub.contains("\"audit\" in"));
    }

    #[test]
    fn default_stub_rbac_roles() {
        let stub = generate_default_stub(AuthCategory::Rbac, r#"if (user.role === "admin") { }"#);
        assert!(stub.contains("input.user.role in"));
        assert!(stub.contains("admin"));
    }

    #[test]
    fn confidence_wrapping_high() {
        let wrapped = apply_confidence_wrapping("allow if { true }", Confidence::High);
        assert_eq!(wrapped, "allow if { true }");
    }

    #[test]
    fn confidence_wrapping_medium() {
        let wrapped = apply_confidence_wrapping("allow if { true }", Confidence::Medium);
        assert!(wrapped.starts_with("# TODO:"));
        assert!(wrapped.contains("allow if { true }"));
    }

    #[test]
    fn confidence_wrapping_low() {
        let wrapped = apply_confidence_wrapping("allow if { true }", Confidence::Low);
        assert!(wrapped.contains("# SUGGESTION:"));
        assert!(wrapped.contains("# allow if { true }"));
    }
}
