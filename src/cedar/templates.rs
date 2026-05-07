//! Cedar policy template rendering, category-default stubs, and
//! confidence wrapping. Mirror of [`crate::rego::templates`] for the Cedar
//! engine — same primitives, Cedar-flavored output. Cedar uses `//` line
//! comments and the `permit (...) when { ... };` policy form.

use std::collections::HashMap;
use std::sync::OnceLock;

use regex::Regex;

use crate::types::{AuthCategory, Confidence};

fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\{(\w+)\}\}").unwrap())
}

fn string_literal_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#""([^"]+)"|'([^']+)'"#).unwrap())
}

/// Render a Cedar template by replacing `{{key}}` placeholders with values.
/// String values captured from tree-sitter are stripped of surrounding quotes.
pub fn render_template(template: &str, vars: &HashMap<String, String>) -> String {
    placeholder_re()
        .replace_all(template, |caps: &regex::Captures| {
            let key = &caps[1];
            match vars.get(key) {
                Some(val) if key.ends_with("_set") => val.to_string(),
                Some(val) => strip_quotes(val).to_string(),
                None => caps[0].to_string(),
            }
        })
        .to_string()
}

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

/// Extract quoted string literals from a code snippet. Same shape as the
/// Rego helper; kept separate so the two engines can diverge if Cedar grows
/// engine-specific extraction (e.g. principal/action splits) without
/// destabilising the Rego path.
pub fn extract_string_literals(code: &str) -> Vec<String> {
    string_literal_re()
        .captures_iter(code)
        .filter_map(|c| {
            c.get(1)
                .or_else(|| c.get(2))
                .map(|m| m.as_str().to_string())
        })
        .collect()
}

/// Return a default Cedar policy template for a given category.
///
/// These are intentionally minimal `permit`/`forbid` shells — Cedar's type
/// system is strict, so we keep entity references generic
/// (`principal`/`resource`) and let users specialize. The templates compile
/// against the empty/unconstrained schema; callers wanting strict
/// type-checking should provide their own schema during validation.
pub fn default_template(category: AuthCategory) -> &'static str {
    match category {
        AuthCategory::Rbac => {
            r#"permit (
    principal,
    action,
    resource
)
when {
    principal.role == "{{role_value}}"
};"#
        }
        AuthCategory::Abac => {
            r#"permit (
    principal,
    action,
    resource
)
when {
    // TODO: verify attribute check
    principal.{{attribute}} == "{{value}}"
};"#
        }
        AuthCategory::Middleware => {
            r#"permit (
    principal,
    action,
    resource
)
when {
    context.authenticated == true
};"#
        }
        AuthCategory::Ownership => {
            r#"permit (
    principal,
    action,
    resource
)
when {
    resource.owner == principal
};"#
        }
        AuthCategory::BusinessRule => {
            r#"// TODO: business rule — review and implement manually
// permit (
//     principal,
//     action,
//     resource
// )
// when {
//     ...
// };"#
        }
        AuthCategory::FeatureGate => {
            r#"permit (
    principal,
    action,
    resource
)
when {
    principal.plan == "{{plan_value}}"
};"#
        }
        AuthCategory::Route => {
            r#"// TODO: route declaration with no inline auth check — add a policy or confirm intentionally public
// permit (
//     principal,
//     action,
//     resource
// )
// when {
//     ...
// };"#
        }
        AuthCategory::Custom => {
            r#"// TODO: custom authorization pattern — review and implement manually
// permit (
//     principal,
//     action,
//     resource
// )
// when {
//     ...
// };"#
        }
    }
}

/// Build a Cedar stub for a finding using category defaults + extracted
/// string literals. Mirrors [`crate::rego::templates::generate_default_stub`]
/// for parity, with category-specific shaping where Cedar's grammar differs
/// from Rego (sets use `[a, b]`, comparisons use `==`/`in`).
pub fn generate_default_stub(category: AuthCategory, code_snippet: &str) -> String {
    let literals = extract_string_literals(code_snippet);
    let mut vars = HashMap::new();

    match category {
        AuthCategory::Rbac => {
            // Permission-shaped strings (e.g. "orders:read") collapse into a
            // membership check against `principal.permissions`. Pure roles
            // get a single equality or `in` check.
            if literals.iter().any(|s| s.contains(':')) {
                let perms: Vec<&String> = literals.iter().filter(|s| s.contains(':')).collect();
                let body = if perms.len() == 1 {
                    format!("    \"{}\" in principal.permissions", perms[0])
                } else {
                    let items = perms
                        .iter()
                        .map(|p| format!("\"{p}\""))
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!("    [{items}].containsAny(principal.permissions)")
                };
                return format!(
                    "permit (\n    principal,\n    action,\n    resource\n)\nwhen {{\n{body}\n}};"
                );
            }
            let role_value = literals.first().cloned().unwrap_or_else(|| "TODO".into());
            if literals.len() <= 1 {
                vars.insert("role_value".to_string(), role_value);
                return render_template(default_template(category), &vars);
            }
            // Multiple roles → emit a set membership check rather than a
            // single equality. This is the structural-template counterpart
            // to Rego's `input.user.role in {"a","b"}` form.
            let items = literals
                .iter()
                .map(|r| format!("\"{r}\""))
                .collect::<Vec<_>>()
                .join(", ");
            return format!(
                "permit (\n    principal,\n    action,\n    resource\n)\nwhen {{\n    principal.role in [{items}]\n}};"
            );
        }
        AuthCategory::FeatureGate => {
            let plan_value = literals.first().cloned().unwrap_or_else(|| "TODO".into());
            if literals.len() <= 1 {
                vars.insert("plan_value".to_string(), plan_value);
            } else {
                let items = literals
                    .iter()
                    .map(|p| format!("\"{p}\""))
                    .collect::<Vec<_>>()
                    .join(", ");
                return format!(
                    "permit (\n    principal,\n    action,\n    resource\n)\nwhen {{\n    principal.plan in [{items}]\n}};"
                );
            }
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

    render_template(default_template(category), &vars)
}

/// Wrap a Cedar stub based on confidence level. Cedar uses `//` for line
/// comments — different from Rego's `#` — so the wrapping helpers can't be
/// shared with the Rego engine.
pub fn apply_confidence_wrapping(cedar_body: &str, confidence: Confidence) -> String {
    match confidence {
        Confidence::High => cedar_body.to_string(),
        Confidence::Medium => format!("// TODO: verify this policy\n{cedar_body}"),
        Confidence::Low => {
            let commented: String = cedar_body
                .lines()
                .map(|line| {
                    if line.is_empty() || line.starts_with("//") {
                        line.to_string()
                    } else {
                        format!("// {line}")
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            format!("// SUGGESTION: review and uncomment if correct\n{commented}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_simple_template() {
        let mut vars = HashMap::new();
        vars.insert("role_value".to_string(), "\"admin\"".to_string());
        let out = render_template("principal.role == \"{{role_value}}\"", &vars);
        assert_eq!(out, "principal.role == \"admin\"");
    }

    #[test]
    fn render_set_template_keeps_item_quotes() {
        let mut vars = HashMap::new();
        vars.insert(
            "roles_set".to_string(),
            "\"admin\", \"manager\"".to_string(),
        );
        let out = render_template("principal.role in [{{roles_set}}]", &vars);
        assert_eq!(out, "principal.role in [\"admin\", \"manager\"]");
    }

    #[test]
    fn extract_literals() {
        let lits = extract_string_literals(r#"hasRole("admin", "manager")"#);
        assert_eq!(lits, vec!["admin", "manager"]);
    }

    #[test]
    fn extract_literals_mixed_quote_styles() {
        let lits = extract_string_literals(r#"check("admin"); check('manager');"#);
        assert_eq!(lits, vec!["admin", "manager"]);
    }

    #[test]
    fn extract_literals_skips_mismatched_quotes() {
        // The old `["']([^"']+)["']` pattern would pair the opening `"` with
        // the closing `'`; alternation enforces matching delimiters.
        let lits = extract_string_literals(r#"check("foo')"#);
        assert!(lits.is_empty());
    }

    #[test]
    fn default_stub_rbac_role() {
        let stub = generate_default_stub(AuthCategory::Rbac, r#"if (user.role === "admin") {}"#);
        assert!(stub.contains("permit"));
        assert!(stub.contains("principal.role == \"admin\""));
    }

    #[test]
    fn default_stub_rbac_role_set() {
        let stub = generate_default_stub(
            AuthCategory::Rbac,
            r#"hasRole("admin") || hasRole("manager")"#,
        );
        assert!(stub.contains("principal.role in [\"admin\", \"manager\"]"));
    }

    #[test]
    fn default_stub_rbac_permissions() {
        let stub = generate_default_stub(AuthCategory::Rbac, r#"authorize(user, "audit:read")"#);
        assert!(stub.contains("\"audit:read\" in principal.permissions"));
    }

    #[test]
    fn default_stub_feature_gate() {
        let stub = generate_default_stub(
            AuthCategory::FeatureGate,
            r#"if (user.plan === "enterprise") {}"#,
        );
        assert!(stub.contains("principal.plan == \"enterprise\""));
    }

    #[test]
    fn default_stub_route_returns_commented_todo() {
        let stub = generate_default_stub(AuthCategory::Route, "");
        assert!(stub.contains("TODO: route declaration"));
        assert!(!stub.contains("\npermit ("));
    }

    #[test]
    fn confidence_wrapping_low_uses_double_slash() {
        let wrapped =
            apply_confidence_wrapping("permit (principal, action, resource);", Confidence::Low);
        assert!(wrapped.starts_with("// SUGGESTION"));
        assert!(wrapped.contains("// permit (principal, action, resource);"));
    }

    #[test]
    fn confidence_wrapping_medium_prepends_todo() {
        let wrapped =
            apply_confidence_wrapping("permit (principal, action, resource);", Confidence::Medium);
        assert!(wrapped.starts_with("// TODO:"));
    }
}
