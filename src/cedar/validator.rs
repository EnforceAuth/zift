//! Cedar policy validator. Mirror of [`crate::rego::validator`] using the
//! `cedar-policy` crate's `PolicySet` parser. Schema-free: we only verify
//! that the policy parses, matching the Rego validator's "syntactic
//! correctness" contract. Type-checking against an entity schema is a
//! separate concern that callers can layer on with `cedar_policy::Validator`
//! when they have a schema in hand.

use std::str::FromStr;

use cedar_policy::PolicySet;

#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
}

/// Parse a Cedar policy (or policy set) and report whether it's
/// syntactically well-formed. Empty strings parse to an empty PolicySet,
/// which is a degenerate but valid input — same shape as
/// [`crate::rego::validator::validate_rego`] for an empty Rego module.
pub fn validate_cedar(policy: &str) -> ValidationResult {
    match PolicySet::from_str(policy) {
        Ok(_) => ValidationResult {
            valid: true,
            error: None,
        },
        Err(e) => ValidationResult {
            valid: false,
            error: Some(e.to_string()),
        },
    }
}

/// Validate a Cedar template by substituting placeholder values for
/// `{{var}}` markers and parsing the result. Bare placeholders (in
/// identifier position, e.g. `principal.{{attribute}}`) get a dummy
/// identifier; quoted placeholders get a dummy string. Same approach as
/// [`crate::rego::validator::validate_template`].
pub fn validate_template(template: &str) -> ValidationResult {
    let re_quoted = regex::Regex::new(r#"["']\{\{(\w+)\}\}["']"#).unwrap();
    let rendered = re_quoted
        .replace_all(template, "\"placeholder\"")
        .to_string();
    // Set-context placeholder: `[{{var}}]` expands at scan time to a
    // comma-separated list of quoted strings (e.g. `"admin", "manager"`).
    // Substitute the bare placeholder with a single quoted string so the
    // resulting `["placeholder"]` parses as a valid Cedar set literal.
    let re_set = regex::Regex::new(r"\[\s*\{\{(\w+)\}\}\s*\]").unwrap();
    let rendered = re_set
        .replace_all(&rendered, "[\"placeholder\"]")
        .to_string();
    let re_bare = regex::Regex::new(r"\{\{(\w+)\}\}").unwrap();
    let rendered = re_bare
        .replace_all(&rendered, "placeholder_value")
        .to_string();
    validate_cedar(&rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_policy() {
        let policy = r#"permit (
    principal,
    action,
    resource
)
when {
    principal.role == "admin"
};"#;
        let res = validate_cedar(policy);
        assert!(res.valid, "expected valid, got: {:?}", res.error);
    }

    #[test]
    fn invalid_policy() {
        let res = validate_cedar("this is not cedar");
        assert!(!res.valid);
        assert!(res.error.is_some());
    }

    #[test]
    fn valid_template_quoted_placeholder() {
        let tmpl = r#"permit (principal, action, resource)
when {
    principal.role == "{{role_value}}"
};"#;
        let res = validate_template(tmpl);
        assert!(res.valid, "expected valid, got: {:?}", res.error);
    }

    #[test]
    fn valid_template_set_placeholder() {
        // Regression: `[{{cedar_roles_set}}]` expands at scan time to a CSV
        // of quoted strings (e.g. `"admin", "manager"`). Without set-context
        // handling, validate_template would substitute the bare identifier
        // and produce `[placeholder_value]`, which Cedar rejects.
        let tmpl = r#"permit (principal, action, resource)
when {
    principal.role in [{{cedar_roles_set}}]
};"#;
        let res = validate_template(tmpl);
        assert!(res.valid, "expected valid, got: {:?}", res.error);
    }

    #[test]
    fn valid_template_bare_placeholder() {
        let tmpl = r#"permit (principal, action, resource)
when {
    principal.{{attribute}} == "{{value}}"
};"#;
        let res = validate_template(tmpl);
        assert!(res.valid, "expected valid, got: {:?}", res.error);
    }
}
