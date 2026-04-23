use regorus::Engine;

/// Result of validating a Rego policy string.
#[derive(Debug)]
pub struct ValidationResult {
    pub valid: bool,
    pub error: Option<String>,
}

/// Validate that a Rego policy string is syntactically correct.
pub fn validate_rego(policy: &str) -> ValidationResult {
    let mut engine = Engine::new();
    match engine.add_policy("validate.rego".into(), policy.into()) {
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

/// Validate a Rego template by rendering it with placeholder values and checking syntax.
/// Templates may contain `{{var}}` placeholders — we substitute them with dummy values
/// to produce parseable Rego.
pub fn validate_template(template: &str) -> ValidationResult {
    // Replace "{{var}}" (quoted placeholder) with a quoted string, then
    // replace any remaining bare {{var}} with a bare identifier.
    // This matters because bare placeholders may appear in identifier positions
    // (e.g. input.user.{{attribute}}) where a quoted string would be invalid Rego.
    let re_quoted = regex::Regex::new(r#"["']\{\{(\w+)\}\}["']"#).unwrap();
    let rendered = re_quoted
        .replace_all(template, "\"placeholder\"")
        .to_string();
    let re_bare = regex::Regex::new(r"\{\{(\w+)\}\}").unwrap();
    let rendered = re_bare
        .replace_all(&rendered, "placeholder_value")
        .to_string();

    // Wrap in a minimal package to form a complete Rego module
    let full_policy = format!("package validate_template\n\nimport rego.v1\n\n{rendered}");
    validate_rego(&full_policy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_policy() {
        let policy = r#"
package test

import rego.v1

default allow := false

allow if {
    input.user.role == "admin"
}
"#;
        let result = validate_rego(policy);
        assert!(result.valid, "expected valid, got: {:?}", result.error);
    }

    #[test]
    fn invalid_policy() {
        let policy = r#"
package test

import rego.v1

default allow := false

allow if {
    input.user.role ==
}
"#;
        let result = validate_rego(policy);
        assert!(!result.valid);
        assert!(result.error.is_some());
    }

    #[test]
    fn valid_template() {
        let template = r#"default allow := false

allow if {
    input.user.role == "{{role_value}}"
}"#;
        let result = validate_template(template);
        assert!(result.valid, "expected valid, got: {:?}", result.error);
    }

    #[test]
    fn valid_template_with_identifier_placeholder() {
        let template = r#"default allow := false

allow if {
    input.user.{{attribute}} == "{{value}}"
}"#;
        let result = validate_template(template);
        assert!(result.valid, "expected valid, got: {:?}", result.error);
    }

    #[test]
    fn valid_template_with_set() {
        let template = r#"default allow := false

allow if {
    input.user.role in {"{{role_value}}"}
}"#;
        let result = validate_template(template);
        assert!(result.valid, "expected valid, got: {:?}", result.error);
    }
}
