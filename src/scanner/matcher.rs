use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;

use sha2::{Digest, Sha256};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Query, QueryCursor, Tree};

use crate::error::{Result, ZiftError};
use crate::rules::{CrossPredicate, PatternRule, Predicate};
use crate::types::{Confidence, Finding, Language, PolicyEngine, PolicyOutput, ScanPass, Surface};

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

    // Validate that every per-capture predicate references a real capture.
    for (capture_name, _) in &rule.predicates {
        if !capture_names.iter().any(|n| n == capture_name) {
            return Err(ZiftError::QueryError {
                rule_id: rule.id.clone(),
                message: format!(
                    "predicate references unknown capture '{capture_name}' \
                     (query captures: {})",
                    capture_names.join(", "),
                ),
            });
        }
    }

    // Validate that the optional provenance capture exists. A typo'd
    // `provenance_capture` would otherwise silently produce no-provenance
    // findings, which is exactly the bug we're trying to avoid.
    if let Some(capture_name) = &rule.provenance_capture
        && !capture_names.iter().any(|n| n == capture_name)
    {
        return Err(ZiftError::QueryError {
            rule_id: rule.id.clone(),
            message: format!(
                "provenance_capture references unknown capture '{capture_name}' \
                 (query captures: {})",
                capture_names.join(", "),
            ),
        });
    }

    // Validate that every cross-predicate references real captures.
    for (i, cp) in rule.cross_predicates.iter().enumerate() {
        for capture_name in cp.referenced_captures() {
            if !capture_names.iter().any(|n| n == capture_name) {
                return Err(ZiftError::QueryError {
                    rule_id: rule.id.clone(),
                    message: format!(
                        "cross_predicate[{i}] ({}) references unknown capture \
                         '{capture_name}' (query captures: {})",
                        cp.kind_label(),
                        capture_names.join(", "),
                    ),
                });
            }
        }
    }

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
                        compiled.capture_names.len(),
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

        // Apply predicates. Per-capture predicates run first because they're
        // typically more selective and short-circuit more matches.
        if !check_predicates(&compiled.rule.predicates, &captures) {
            continue;
        }
        if !check_cross_predicates(&compiled.rule.cross_predicates, &captures) {
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

        let mut policy_outputs = Vec::new();
        if let Some(tmpl) = compiled.rule.template_for(PolicyEngine::Rego) {
            let mut owned: HashMap<String, String> = captures
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            add_template_derived_values(&mut owned);
            policy_outputs.push(PolicyOutput {
                engine: PolicyEngine::Rego,
                content: crate::rego::render_template(tmpl, &owned),
            });
        }
        if let Some(tmpl) = compiled.rule.template_for(PolicyEngine::Cedar) {
            let mut owned: HashMap<String, String> = captures
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect();
            add_cedar_template_derived_values(&mut owned);
            policy_outputs.push(PolicyOutput {
                engine: PolicyEngine::Cedar,
                content: crate::cedar::render_template(tmpl, &owned),
            });
        }

        let provenance = compiled
            .rule
            .provenance_capture
            .as_deref()
            .and_then(|name| captures.get(name))
            .map(|s| s.to_string())
            .filter(|s| !s.is_empty());

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
            policy_outputs,
            pass: ScanPass::Structural,
            surface: Surface::classify(file_path),
            provenance,
        });
    }

    Ok(findings)
}

fn add_template_derived_values(vars: &mut HashMap<String, String>) {
    if let Some(roles) = vars.get("roles") {
        vars.insert("roles_set".to_string(), comma_separated_quoted_items(roles));
    }
}

/// Cedar-flavored counterpart to [`add_template_derived_values`]. Cedar's set
/// syntax is `[a, b]` (templates wrap the brackets) — the raw item list is
/// engine-neutral, but we keep this helper separate so the Rego and Cedar
/// derivation paths can diverge without dragging each other along (e.g. if
/// Cedar grows entity-type prefixes like `Role::"admin"` for its set items).
fn add_cedar_template_derived_values(vars: &mut HashMap<String, String>) {
    let source = vars.get("roles").or_else(|| vars.get("role_value"));
    if let Some(value) = source {
        vars.insert(
            "cedar_roles_set".to_string(),
            comma_separated_quoted_items(value),
        );
    }
}

fn comma_separated_quoted_items(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .split(',')
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .map(|role| format!("\"{role}\""))
        .collect::<Vec<_>>()
        .join(", ")
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

/// Apply cross-capture predicates. Each cross-predicate is an AND term —
/// all must hold for the match to pass. A capture missing from `captures`
/// (e.g. an optional sub-pattern that didn't fire) is treated as not
/// matching the regex; for `any_match` other listed captures may still
/// satisfy the predicate, while `all_match` fails closed.
fn check_cross_predicates(
    cross_predicates: &[CrossPredicate],
    captures: &HashMap<&str, String>,
) -> bool {
    for cp in cross_predicates {
        match cp {
            CrossPredicate::AnyMatch {
                captures: names,
                regex,
            } => {
                let any = names.iter().any(|name| {
                    captures
                        .get(name.as_str())
                        .is_some_and(|text| regex.is_match(text))
                });
                if !any {
                    return false;
                }
            }
            CrossPredicate::AllMatch {
                captures: names,
                regex,
            } => {
                let all = names.iter().all(|name| {
                    captures
                        .get(name.as_str())
                        .is_some_and(|text| regex.is_match(text))
                });
                if !all {
                    return false;
                }
            }
        }
    }
    true
}

pub(crate) fn compute_finding_id(
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
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(out, "{b:02x}");
    }
    out
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
    fn csharp_authorize_roles_splits_comma_separated_roles_in_cedar() {
        // Regression: the cedar_template path used to drop the captured
        // role list and emit `principal.role == "TODO"`. With the
        // `cedar_roles_set` derived var it should now expand to a Cedar
        // set membership check matching the Rego sibling.
        let findings = parse_and_match(
            r#"[Authorize(Roles = "Admin,Manager")]
public IActionResult Delete(int id) => Ok();"#,
            include_str!("../../rules/csharp/aspnet-authorize-roles.toml"),
        );

        assert_eq!(findings.len(), 1);
        let cedar = findings[0].policy_output(PolicyEngine::Cedar).unwrap();
        assert!(
            cedar.contains(r#"principal.role in ["Admin", "Manager"]"#),
            "cedar should split ASP.NET comma-separated roles into a set; got: {cedar}"
        );
    }

    #[test]
    fn csharp_authorize_roles_splits_comma_separated_roles_in_rego() {
        let findings = parse_and_match(
            r#"[Authorize(Roles = "Admin,Manager")]
public IActionResult Delete(int id) => Ok();"#,
            include_str!("../../rules/csharp/aspnet-authorize-roles.toml"),
        );

        assert_eq!(findings.len(), 1);
        let rego = findings[0].policy_output(PolicyEngine::Rego).unwrap();
        assert!(
            rego.contains(r#"input.user.role in {"Admin", "Manager"}"#),
            "rego should split ASP.NET comma-separated roles; got: {rego}"
        );
    }

    #[test]
    fn csharp_has_claim_rego_includes_claim_value() {
        let findings = parse_and_match(
            r#"if (User.HasClaim("scope", "users.delete")) {
    return Ok();
}"#,
            include_str!("../../rules/csharp/has-claim-call.toml"),
        );

        assert_eq!(findings.len(), 1);
        let rego = findings[0].policy_output(PolicyEngine::Rego).unwrap();
        assert!(
            rego.contains(r#"input.user.claims["scope"] == "users.delete""#),
            "rego should require the claim value; got: {rego}"
        );
    }

    #[test]
    fn csharp_authorize_policy_shorthand_matches() {
        let findings = parse_and_match(
            r#"[Authorize("CanReadReports")]
public IActionResult Reports() => Ok();"#,
            include_str!("../../rules/csharp/aspnet-authorize-policy-shorthand.toml"),
        );

        assert_eq!(findings.len(), 1);
        let rego = findings[0].policy_output(PolicyEngine::Rego).unwrap();
        assert!(
            rego.contains(r#"input.policy == "CanReadReports""#),
            "rego should include the shorthand policy name; got: {rego}"
        );
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
    fn identifier_includes_check_is_role_shaped_only() {
        let findings = parse_and_match(
            r#"if (userGroups.includes("manager")) { allow(); }"#,
            include_str!("../../rules/typescript/identifier-includes-check.toml"),
        );

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
        let rego = findings[0].policy_output(PolicyEngine::Rego).unwrap();
        assert!(
            rego.contains(r#""manager" in input.user.roles"#),
            "rego should use a role membership check; got: {rego}"
        );
        let cedar = findings[0].policy_output(PolicyEngine::Cedar).unwrap();
        assert!(
            cedar.contains(r#"principal.roles.contains("manager")"#),
            "cedar should use a role membership check; got: {cedar}"
        );

        let permission_findings = parse_and_match(
            r#"if (permissions.includes("write")) { allow(); }"#,
            include_str!("../../rules/typescript/identifier-includes-check.toml"),
        );
        assert!(
            permission_findings.is_empty(),
            "bare permission collections need a permission-shaped rule"
        );
    }

    // -- Java rule tests --

    fn parse_and_match_java(source: &str, rule_toml: &str) -> Vec<Finding> {
        let rule = rules::parse_rule_for_test(rule_toml);
        let mut ts_parser = tree_sitter::Parser::new();
        let lang = Language::Java;
        let ts_lang = parser::get_language(lang, false).unwrap();
        // Wrap in a class+method if not already a class declaration
        let wrapped = if source.contains("class ") {
            source.to_string()
        } else {
            format!("public class Test {{ public void test() {{ {source} }} }}")
        };
        let tree = parser::parse_source(&mut ts_parser, wrapped.as_bytes(), lang, false).unwrap();
        let compiled = compile_rule(&rule, &ts_lang).unwrap();
        execute_query(
            &compiled,
            &tree,
            wrapped.as_bytes(),
            Path::new("Test.java"),
            lang,
        )
        .unwrap()
    }

    #[test]
    fn java_preauthorize_matches() {
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @PreAuthorize("hasRole('ADMIN')")
    public void delete() { }
}
"#,
            include_str!("../../rules/java/spring-preauthorize.toml"),
        );
        assert!(!findings.is_empty(), "should match @PreAuthorize");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn java_preauthorize_no_false_positive() {
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @Override
    public void delete() { }
}
"#,
            include_str!("../../rules/java/spring-preauthorize.toml"),
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn java_secured_matches() {
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @Secured("ROLE_ADMIN")
    public void delete() { }
}
"#,
            include_str!("../../rules/java/spring-secured.toml"),
        );
        assert!(!findings.is_empty(), "should match @Secured");
    }

    #[test]
    fn java_roles_allowed_matches() {
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @RolesAllowed("admin")
    public void delete() { }
}
"#,
            include_str!("../../rules/java/spring-roles-allowed.toml"),
        );
        assert!(!findings.is_empty(), "should match @RolesAllowed");
        // Bare-identifier annotation has no scope to capture — provenance
        // must be `None`. The package isn't resolvable from the call site
        // alone (we'd need the file's import statement), so leaving it
        // unset is the honest answer.
        assert!(
            findings[0].provenance.is_none(),
            "bare annotation should not carry provenance; got: {:?}",
            findings[0].provenance
        );
    }

    #[test]
    fn java_roles_allowed_qualified_carries_provenance() {
        // Fully-qualified annotation: `@jakarta.annotation.security.RolesAllowed`
        // — the `scoped_identifier` exposes the package prefix, which the
        // matcher copies into `Finding.provenance`. Consumers split on the
        // head segment (`provenance.split('.').next()`) to bucket findings
        // as `javax` (legacy) vs `jakarta` (modern) for migration reporting.
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @jakarta.annotation.security.RolesAllowed("admin")
    public void delete() { }
}
"#,
            include_str!("../../rules/java/spring-roles-allowed.toml"),
        );
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].provenance.as_deref(),
            Some("jakarta.annotation.security"),
            "qualified annotation should carry full package prefix as provenance",
        );

        let findings_javax = parse_and_match_java(
            r#"
public class Ctrl {
    @javax.annotation.security.RolesAllowed("admin")
    public void delete() { }
}
"#,
            include_str!("../../rules/java/spring-roles-allowed.toml"),
        );
        assert_eq!(findings_javax.len(), 1);
        assert_eq!(
            findings_javax[0].provenance.as_deref(),
            Some("javax.annotation.security"),
            "javax-qualified annotation should carry javax provenance",
        );
    }

    #[test]
    fn java_is_user_in_role_matches() {
        let findings = parse_and_match_java(
            r#"request.isUserInRole("admin");"#,
            include_str!("../../rules/java/is-user-in-role.toml"),
        );
        assert!(!findings.is_empty(), "should match isUserInRole");
    }

    #[test]
    fn java_is_user_in_role_non_literal_arg_matches() {
        let findings = parse_and_match_java(
            r#"request.isUserInRole(Role.ADMIN);"#,
            include_str!("../../rules/java/is-user-in-role.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match isUserInRole with field-access arg"
        );
    }

    #[test]
    fn java_is_user_in_role_identifier_arg_matches() {
        let findings = parse_and_match_java(
            r#"request.isUserInRole(roleVar);"#,
            include_str!("../../rules/java/is-user-in-role.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match isUserInRole with identifier arg (variable role name)"
        );
    }

    #[test]
    fn java_has_role_call_matches() {
        let findings = parse_and_match_java(
            r#"http.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");"#,
            include_str!("../../rules/java/has-role-call.toml"),
        );
        assert!(!findings.is_empty(), "should match hasRole");
    }

    #[test]
    fn java_has_role_call_field_access_arg_matches() {
        let findings = parse_and_match_java(
            r#"if (!acct.hasRole(Role.ADMIN)) { throw new ForbiddenException(); }"#,
            include_str!("../../rules/java/has-role-call.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match hasRole with field-access arg (e.g., Role.ADMIN)"
        );
    }

    #[test]
    fn java_has_role_call_identifier_arg_matches() {
        let findings = parse_and_match_java(
            r#"if (acct.hasRole(roleName)) { allow(); }"#,
            include_str!("../../rules/java/has-role-call.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match hasRole with identifier arg (variable role name)"
        );
    }

    #[test]
    fn java_shiro_requires_permissions_matches() {
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @RequiresPermissions("user:delete")
    public void delete() { }
}
"#,
            include_str!("../../rules/java/shiro-requires-permissions.toml"),
        );
        assert!(!findings.is_empty(), "should match @RequiresPermissions");
    }

    #[test]
    fn java_shiro_is_permitted_matches() {
        let findings = parse_and_match_java(
            r#"subject.isPermitted("user:delete");"#,
            include_str!("../../rules/java/shiro-is-permitted.toml"),
        );
        assert!(!findings.is_empty(), "should match isPermitted");
    }

    #[test]
    fn java_shiro_is_permitted_non_literal_arg_matches() {
        let findings = parse_and_match_java(
            r#"subject.isPermitted(Permissions.USER_DELETE);"#,
            include_str!("../../rules/java/shiro-is-permitted.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match isPermitted with field-access arg"
        );
    }

    #[test]
    fn java_shiro_is_permitted_identifier_arg_matches() {
        let findings = parse_and_match_java(
            r#"subject.isPermitted(permVar);"#,
            include_str!("../../rules/java/shiro-is-permitted.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match isPermitted with identifier arg (variable permission)"
        );
    }

    #[test]
    fn java_marker_annotation_matches() {
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @RequiresAuthentication
    public void secure() { }
}
"#,
            include_str!("../../rules/java/shiro-requires-authentication.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match @RequiresAuthentication marker annotation"
        );
    }

    #[test]
    fn java_marker_annotation_no_false_positive() {
        let findings = parse_and_match_java(
            r#"
public class Ctrl {
    @Override
    public void toString() { }
}
"#,
            include_str!("../../rules/java/shiro-requires-authentication.toml"),
        );
        assert!(findings.is_empty(), "should not match @Override");
    }

    #[test]
    fn java_role_equals_check_matches() {
        let findings = parse_and_match_java(
            r#"user.getRole().equals("admin");"#,
            include_str!("../../rules/java/role-equals-check.toml"),
        );
        assert!(!findings.is_empty(), "should match getRole().equals()");
    }

    #[test]
    fn java_role_equals_check_field_access_arg_matches() {
        let findings = parse_and_match_java(
            r#"user.getRole().equals(Role.ADMIN);"#,
            include_str!("../../rules/java/role-equals-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match getRole().equals(field-access)"
        );
    }

    #[test]
    fn java_role_equals_check_identifier_arg_matches() {
        let findings = parse_and_match_java(
            r#"user.getRole().equals(roleVar);"#,
            include_str!("../../rules/java/role-equals-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match getRole().equals(identifier)"
        );
    }

    #[test]
    fn java_role_equals_check_no_false_positive() {
        let findings = parse_and_match_java(
            r#"user.getName().equals("admin");"#,
            include_str!("../../rules/java/role-equals-check.toml"),
        );
        assert!(findings.is_empty(), "should not match getName().equals()");
    }

    #[test]
    fn java_ownership_check_matches() {
        let findings = parse_and_match_java(
            r#"user.getUserId().equals(resource.getOwnerId());"#,
            include_str!("../../rules/java/ownership-check.toml"),
        );
        assert!(!findings.is_empty(), "should match ownership check");
    }

    #[test]
    fn java_authenticated_check_matches() {
        let findings = parse_and_match_java(
            r#"authentication.isAuthenticated();"#,
            include_str!("../../rules/java/authenticated-check.toml"),
        );
        assert!(!findings.is_empty(), "should match isAuthenticated()");
    }

    #[test]
    fn java_security_interface_impl_cases() {
        // Table-driven: (case_name, source, expect_match)
        let cases: &[(&str, &str, bool)] = &[
            (
                "plain UserDetailsService",
                r#"
public class MyUserService implements UserDetailsService {
    public UserDetails loadUserByUsername(String username) { return null; }
}
"#,
                true,
            ),
            (
                "fully-qualified UserDetailsService",
                r#"
public class MyUserService implements org.springframework.security.core.userdetails.UserDetailsService {
    public UserDetails loadUserByUsername(String username) { return null; }
}
"#,
                true,
            ),
            (
                "generic AuthorizationManager",
                r#"
public class MyAuthManager implements AuthorizationManager<RequestAuthorizationContext> {
    public AuthorizationDecision check() { return null; }
}
"#,
                true,
            ),
            (
                "unrelated Serializable (no false positive)",
                r#"
public class MyService implements Serializable {
    public void doWork() { }
}
"#,
                false,
            ),
        ];

        for (case_name, source, expect_match) in cases {
            let findings = parse_and_match_java(
                source,
                include_str!("../../rules/java/security-interface-impl.toml"),
            );
            if *expect_match {
                assert!(
                    !findings.is_empty(),
                    "case `{case_name}`: expected at least one finding",
                );
            } else {
                assert!(
                    findings.is_empty(),
                    "case `{case_name}`: expected no findings, got {findings:?}",
                );
            }
        }
    }

    #[test]
    fn java_custom_authz_call_matches_role_suffix() {
        let findings = parse_and_match_java(
            r#"if (!privService.isOrgAdmin(account.getId(), org.getId())) { throw new ForbiddenException(); }"#,
            include_str!("../../rules/java/custom-authz-call.toml"),
        );
        assert!(!findings.is_empty(), "should match custom isOrgAdmin call");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Custom);
    }

    #[test]
    fn java_custom_authz_call_matches_keyword_in_middle() {
        let findings = parse_and_match_java(
            r#"if (!privService.isAdminForAccount(actor, org, subject)) { throw new ForbiddenException(); }"#,
            include_str!("../../rules/java/custom-authz-call.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match isAdminForAccount (keyword in middle)"
        );
    }

    #[test]
    fn java_custom_authz_call_matches_has_access() {
        let findings = parse_and_match_java(
            r#"if (privService.hasFullOrganizationAccess(account, orgId)) { allow(); }"#,
            include_str!("../../rules/java/custom-authz-call.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match hasFullOrganizationAccess"
        );
    }

    #[test]
    fn java_custom_authz_call_no_substring_false_positive() {
        // "Admin" appears as a substring of "Admins" — must NOT match.
        let findings = parse_and_match_java(
            r#"if (req.isIncludeAdmins()) { include(); }"#,
            include_str!("../../rules/java/custom-authz-call.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match isIncludeAdmins (Admin is a substring of Admins, not a complete sub-word)"
        );
    }

    #[test]
    fn java_custom_authz_call_no_state_check_false_positive() {
        let findings = parse_and_match_java(
            r#"if (note.isArchived()) { return; }"#,
            include_str!("../../rules/java/custom-authz-call.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match state-check methods like isArchived"
        );
    }

    #[test]
    fn java_custom_authz_call_excludes_known_framework_methods() {
        // hasRole/hasAuthority/isUserInRole are handled by dedicated rules;
        // this rule must NOT report them to avoid duplicate findings.
        for snippet in [
            r#"http.authorizeRequests().antMatchers("/admin/**").hasRole("ADMIN");"#,
            r#"http.authorizeRequests().antMatchers("/api/**").hasAuthority("SCOPE_read");"#,
            r#"if (request.isUserInRole("admin")) { allow(); }"#,
        ] {
            let findings = parse_and_match_java(
                snippet,
                include_str!("../../rules/java/custom-authz-call.toml"),
            );
            assert!(
                findings.is_empty(),
                "custom-authz-call must not duplicate framework rule for: {snippet}"
            );
        }
    }

    #[test]
    fn java_feature_gate_matches() {
        let findings = parse_and_match_java(
            r#"featureFlags.hasFeature("advanced");"#,
            include_str!("../../rules/java/feature-gate-check.toml"),
        );
        assert!(!findings.is_empty(), "should match hasFeature()");
    }

    #[test]
    fn java_feature_gate_non_literal_arg_matches() {
        let findings = parse_and_match_java(
            r#"featureFlags.hasFeature(Features.BETA_DASHBOARD);"#,
            include_str!("../../rules/java/feature-gate-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match hasFeature with field-access arg"
        );
    }

    #[test]
    fn java_feature_gate_identifier_arg_matches() {
        let findings = parse_and_match_java(
            r#"featureFlags.hasFeature(featureKey);"#,
            include_str!("../../rules/java/feature-gate-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match hasFeature with identifier arg (variable feature key)"
        );
    }

    // -- Python rule tests --

    fn parse_and_match_python(source: &str, rule_toml: &str) -> Vec<Finding> {
        let rule = rules::parse_rule_for_test(rule_toml);
        let mut ts_parser = tree_sitter::Parser::new();
        let lang = Language::Python;
        let ts_lang = parser::get_language(lang, false).unwrap();
        let tree = parser::parse_source(&mut ts_parser, source.as_bytes(), lang, false).unwrap();
        let compiled = compile_rule(&rule, &ts_lang).unwrap();
        execute_query(
            &compiled,
            &tree,
            source.as_bytes(),
            Path::new("test.py"),
            lang,
        )
        .unwrap()
    }

    #[test]
    fn py_django_permission_required_matches() {
        let findings = parse_and_match_python(
            "@permission_required('app.delete_user')\ndef delete_user(request, id):\n    pass\n",
            include_str!("../../rules/python/django-permission-required.toml"),
        );
        assert!(!findings.is_empty(), "should match @permission_required");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Middleware);
    }

    #[test]
    fn py_django_permission_required_qualified_matches() {
        let findings = parse_and_match_python(
            "@django.contrib.auth.decorators.permission_required('app.delete_user')\ndef delete_user(request, id):\n    pass\n",
            include_str!("../../rules/python/django-permission-required.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match module-qualified @permission_required"
        );
    }

    #[test]
    fn py_login_required_decorator_matches() {
        let findings = parse_and_match_python(
            "@login_required\ndef my_view(request):\n    pass\n",
            include_str!("../../rules/python/login-required-decorator.toml"),
        );
        assert!(!findings.is_empty(), "should match bare @login_required");
    }

    #[test]
    fn py_login_required_decorator_no_false_positive_on_unrelated_decorator() {
        let findings = parse_and_match_python(
            "@staticmethod\ndef helper():\n    pass\n",
            include_str!("../../rules/python/login-required-decorator.toml"),
        );
        assert!(findings.is_empty(), "should not match @staticmethod");
    }

    #[test]
    fn py_login_required_decorator_call_form_matches() {
        let findings = parse_and_match_python(
            "@login_required(redirect_field_name='login_url')\ndef my_view(request):\n    pass\n",
            include_str!("../../rules/python/login-required-decorator.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match @login_required(...) call form"
        );
    }

    #[test]
    fn py_has_perm_call_matches() {
        let findings = parse_and_match_python(
            "if request.user.has_perm('app.delete_user'):\n    delete_user()\n",
            include_str!("../../rules/python/has-perm-call.toml"),
        );
        assert!(!findings.is_empty(), "should match request.user.has_perm()");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn py_fastapi_depends_typed_default_matches() {
        let findings = parse_and_match_python(
            "def read_items(token: str = Depends(oauth2_scheme)):\n    pass\n",
            include_str!("../../rules/python/fastapi-depends.toml"),
        );
        assert!(!findings.is_empty(), "should match Depends() typed default");
    }

    #[test]
    fn py_fastapi_depends_untyped_default_matches() {
        let findings = parse_and_match_python(
            "def read_items(token = Depends(get_current_user)):\n    pass\n",
            include_str!("../../rules/python/fastapi-depends.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match Depends() untyped default"
        );
    }

    #[test]
    fn py_role_check_conditional_matches() {
        let findings = parse_and_match_python(
            "if user.role == \"admin\":\n    delete_user()\n",
            include_str!("../../rules/python/role-check-conditional.toml"),
        );
        assert!(!findings.is_empty(), "should match user.role == \"admin\"");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn py_role_check_conditional_excludes_chat_message_role() {
        let findings = parse_and_match_python(
            "if msg.role == \"assistant\":\n    process_response()\n",
            include_str!("../../rules/python/role-check-conditional.toml"),
        );
        assert!(
            findings.is_empty(),
            "should not match LLM chat message role"
        );
    }

    #[test]
    fn py_role_check_conditional_is_operator_matches() {
        let findings = parse_and_match_python(
            "if user.role is \"admin\":\n    delete_user()\n",
            include_str!("../../rules/python/role-check-conditional.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match `is` operator (string identity equality)"
        );
    }

    #[test]
    fn py_has_role_call_matches() {
        let findings = parse_and_match_python(
            "if has_role(\"manager\"):\n    approve_request()\n",
            include_str!("../../rules/python/has-role-call.toml"),
        );
        assert!(!findings.is_empty(), "should match has_role()");
    }

    #[test]
    fn py_permission_check_call_matches() {
        let findings = parse_and_match_python(
            "if user.can(\"delete\"):\n    delete_resource()\n",
            include_str!("../../rules/python/permission-check-call.toml"),
        );
        assert!(!findings.is_empty(), "should match user.can()");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Abac);
    }

    #[test]
    fn py_permission_check_call_excludes_django_has_perm() {
        // `has_perm` belongs to py-has-perm-call (rbac); it must not also
        // surface here as abac, otherwise the same call produces two
        // findings with conflicting categories.
        let findings = parse_and_match_python(
            "if user.has_perm(\"blog.add_post\"):\n    create_post()\n",
            include_str!("../../rules/python/permission-check-call.toml"),
        );
        assert!(
            findings.is_empty(),
            "permission-check-call must not duplicate has_perm (covered by py-has-perm-call)"
        );
    }

    #[test]
    fn py_ownership_check_matches() {
        let findings = parse_and_match_python(
            "if resource.owner_id == user.id:\n    allow_edit()\n",
            include_str!("../../rules/python/ownership-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match owner_id == user.id ownership check"
        );
        assert_eq!(findings[0].category, crate::types::AuthCategory::Ownership);
    }

    #[test]
    fn py_feature_gate_matches() {
        let findings = parse_and_match_python(
            "if feature_flags.has_feature(\"advanced\"):\n    enable()\n",
            include_str!("../../rules/python/feature-gate-check.toml"),
        );
        assert!(!findings.is_empty(), "should match has_feature()");
        assert_eq!(
            findings[0].category,
            crate::types::AuthCategory::FeatureGate
        );
    }

    #[test]
    fn py_feature_gate_property_comparison_matches() {
        let findings = parse_and_match_python(
            "if user.plan == \"enterprise\":\n    enable_advanced()\n",
            include_str!("../../rules/python/feature-gate-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match property comparison shape (user.plan == ...)"
        );
        assert_eq!(
            findings[0].category,
            crate::types::AuthCategory::FeatureGate
        );
    }

    #[test]
    fn py_feature_gate_property_comparison_excludes_role() {
        // `role` is not a feature-gate key; this should be picked up by
        // py-role-check-conditional, not py-feature-gate-check.
        let findings = parse_and_match_python(
            "if user.role == \"admin\":\n    delete()\n",
            include_str!("../../rules/python/feature-gate-check.toml"),
        );
        assert!(
            findings.is_empty(),
            "feature-gate must not match role-style property comparisons"
        );
    }

    // -- Kotlin rule tests --

    fn parse_and_match_kotlin(source: &str, rule_toml: &str) -> Vec<Finding> {
        let rule = rules::parse_rule_for_test(rule_toml);
        let mut ts_parser = tree_sitter::Parser::new();
        let lang = Language::Kotlin;
        let ts_lang = parser::get_language(lang, false).unwrap();
        let tree = parser::parse_source(&mut ts_parser, source.as_bytes(), lang, false).unwrap();
        let compiled = compile_rule(&rule, &ts_lang).unwrap();
        execute_query(
            &compiled,
            &tree,
            source.as_bytes(),
            Path::new("Test.kt"),
            lang,
        )
        .unwrap()
    }

    #[test]
    fn kotlin_preauthorize_matches() {
        let findings = parse_and_match_kotlin(
            r#"
class Ctrl {
    @PreAuthorize("hasRole('ADMIN')")
    fun delete() { }
}
"#,
            include_str!("../../rules/kotlin/spring-preauthorize.toml"),
        );
        assert!(!findings.is_empty(), "should match @PreAuthorize in Kotlin");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn kotlin_preauthorize_qualified_matches() {
        // Kotlin's grammar flattens fully-qualified annotation names into a
        // single `user_type` node with one identifier per dotted segment.
        // The rule regex matches the trailing segment, so both bare and
        // qualified forms produce exactly one finding (no per-identifier
        // explosion).
        let findings = parse_and_match_kotlin(
            r#"
class Ctrl {
    @org.springframework.security.access.prepost.PreAuthorize("hasRole('ADMIN')")
    fun delete() { }
}
"#,
            include_str!("../../rules/kotlin/spring-preauthorize.toml"),
        );
        assert_eq!(
            dedup_findings(findings).len(),
            1,
            "qualified annotation should collapse to a single finding after dedup",
        );
    }

    #[test]
    fn kotlin_secured_matches() {
        let findings = parse_and_match_kotlin(
            r#"
class Ctrl {
    @Secured("ROLE_ADMIN")
    fun delete() { }
}
"#,
            include_str!("../../rules/kotlin/spring-secured.toml"),
        );
        assert!(!findings.is_empty(), "should match @Secured in Kotlin");
    }

    #[test]
    fn kotlin_secured_multi_string_dedups() {
        // `@Secured("A", "B")` fires the query twice (once per string arg)
        // but both raw findings share the same (rule_id, file, line range,
        // snippet) — the whole annotation node — so dedup collapses them
        // to a single finding. This guards the dedup claim in
        // rules/kotlin/spring-secured.toml.
        let findings = parse_and_match_kotlin(
            r#"
class Ctrl {
    @Secured("ROLE_ADMIN", "ROLE_USER")
    fun delete() { }
}
"#,
            include_str!("../../rules/kotlin/spring-secured.toml"),
        );
        assert_eq!(
            findings.len(),
            2,
            "raw matcher should fire once per string arg",
        );
        assert_eq!(
            dedup_findings(findings).len(),
            1,
            "multi-string @Secured should collapse to one finding after dedup",
        );
    }

    #[test]
    fn kotlin_roles_allowed_matches() {
        let findings = parse_and_match_kotlin(
            r#"
class Ctrl {
    @RolesAllowed("admin")
    fun delete() { }
}
"#,
            include_str!("../../rules/kotlin/roles-allowed.toml"),
        );
        assert!(!findings.is_empty(), "should match @RolesAllowed in Kotlin");
    }

    #[test]
    fn kotlin_has_role_call_matches() {
        let findings = parse_and_match_kotlin(
            r#"
fun check(acct: Account) {
    if (!acct.hasRole("ADMIN")) { throw Forbidden() }
}
"#,
            include_str!("../../rules/kotlin/has-role-call.toml"),
        );
        assert!(!findings.is_empty(), "should match hasRole(\"...\")");
    }

    #[test]
    fn kotlin_has_role_call_field_arg_matches() {
        let findings = parse_and_match_kotlin(
            r#"
fun check(acct: Account) {
    if (!acct.hasRole(Role.ADMIN)) { throw Forbidden() }
}
"#,
            include_str!("../../rules/kotlin/has-role-call.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match hasRole with field-access arg"
        );
    }

    #[test]
    fn kotlin_role_equals_check_matches() {
        let findings = parse_and_match_kotlin(
            "fun check(user: User) {\n    if (user.role == \"admin\") { allow() }\n}\n",
            include_str!("../../rules/kotlin/role-equals-check.toml"),
        );
        assert!(!findings.is_empty(), "should match user.role == \"admin\"");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn kotlin_role_equals_check_excludes_unrelated_property() {
        let findings = parse_and_match_kotlin(
            "fun check(user: User) {\n    if (user.name == \"admin\") { greet() }\n}\n",
            include_str!("../../rules/kotlin/role-equals-check.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match unrelated property comparisons"
        );
    }

    #[test]
    fn kotlin_role_equals_check_excludes_inequality_operator() {
        let findings = parse_and_match_kotlin(
            "fun check(user: User) {\n    if (user.role != \"admin\") { deny() }\n}\n",
            include_str!("../../rules/kotlin/role-equals-check.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match `!=` — this rule covers equality only"
        );
    }

    #[test]
    fn kotlin_role_collection_contains_matches() {
        let findings = parse_and_match_kotlin(
            "fun check(user: User) {\n    if (user.roles.contains(\"admin\")) { allow() }\n}\n",
            include_str!("../../rules/kotlin/role-collection-contains.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match user.roles.contains(\"...\")"
        );
    }

    #[test]
    fn kotlin_ktor_authenticate_block_matches() {
        let findings = parse_and_match_kotlin(
            r#"
fun Application.module() {
    authenticate("auth-jwt") {
        get("/admin") { call.respondText("hi") }
    }
}
"#,
            include_str!("../../rules/kotlin/ktor-authenticate-block.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match Ktor authenticate(...) {{ ... }}"
        );
        assert_eq!(findings[0].category, crate::types::AuthCategory::Middleware);
    }

    #[test]
    fn kotlin_ktor_authenticate_no_args_matches() {
        let findings = parse_and_match_kotlin(
            r#"
fun Application.module() {
    authenticate {
        get("/admin") { call.respondText("hi") }
    }
}
"#,
            include_str!("../../rules/kotlin/ktor-authenticate-block.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match Ktor authenticate {{ ... }} no-args form"
        );
    }

    #[test]
    fn kotlin_ktor_install_authentication_matches() {
        let findings = parse_and_match_kotlin(
            r#"
fun Application.module() {
    install(Authentication) {
        jwt("auth-jwt") { }
    }
}
"#,
            include_str!("../../rules/kotlin/ktor-install-authentication.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match install(Authentication) with block"
        );
    }

    #[test]
    fn kotlin_ktor_install_authentication_no_block_matches() {
        let findings = parse_and_match_kotlin(
            r#"
fun Application.module() {
    install(Authentication)
}
"#,
            include_str!("../../rules/kotlin/ktor-install-authentication.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match install(Authentication) without a trailing lambda"
        );
    }

    #[test]
    fn kotlin_ktor_install_authentication_rejects_other_plugins() {
        let findings = parse_and_match_kotlin(
            r#"
fun Application.module() {
    install(CallLogging)
}
"#,
            include_str!("../../rules/kotlin/ktor-install-authentication.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match unrelated plugin installs"
        );
    }

    // -- Ruby rule tests --

    fn parse_and_match_ruby(source: &str, rule_toml: &str) -> Vec<Finding> {
        let rule = rules::parse_rule_for_test(rule_toml);
        let mut ts_parser = tree_sitter::Parser::new();
        let lang = Language::Ruby;
        let ts_lang = parser::get_language(lang, false).unwrap();
        let tree = parser::parse_source(&mut ts_parser, source.as_bytes(), lang, false).unwrap();
        let compiled = compile_rule(&rule, &ts_lang).unwrap();
        execute_query(
            &compiled,
            &tree,
            source.as_bytes(),
            Path::new("app.rb"),
            lang,
        )
        .unwrap()
    }

    #[test]
    fn ruby_pundit_authorize_matches() {
        let findings = parse_and_match_ruby(
            r#"
class PostsController < ApplicationController
  def destroy
    authorize @post
    @post.destroy
  end
end
"#,
            include_str!("../../rules/ruby/pundit-authorize.toml"),
        );
        assert!(!findings.is_empty(), "should match Pundit authorize call");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn ruby_pundit_authorize_bang_matches() {
        // CanCanCan's `authorize!` shape — same AST as Pundit's `authorize`
        // (no receiver, method=identifier), so it collapses into the same rule.
        let findings = parse_and_match_ruby(
            r#"
class ArticlesController < ApplicationController
  def update
    authorize! :update, @article
  end
end
"#,
            include_str!("../../rules/ruby/pundit-authorize.toml"),
        );
        assert!(!findings.is_empty(), "should match authorize! bang form");
    }

    #[test]
    fn ruby_pundit_authorize_no_false_positive_on_receiver_chain() {
        // `something.authorize(...)` is NOT a Pundit gate; the rule restricts
        // to bare (receiver-less) calls so chained method calls don't fire.
        let findings = parse_and_match_ruby(
            r#"
def init
  client.authorize(token)
end
"#,
            include_str!("../../rules/ruby/pundit-authorize.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match chained `obj.authorize` calls"
        );
    }

    #[test]
    fn ruby_pundit_policy_method_matches() {
        let findings = parse_and_match_ruby(
            r#"
def edit_link
  link_to 'Edit', edit_post_path(@post) if policy(@post).edit?
end
"#,
            include_str!("../../rules/ruby/pundit-policy-method.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match policy(@post).<action>? chain"
        );
    }

    #[test]
    fn ruby_pundit_policy_class_matches() {
        let findings = parse_and_match_ruby(
            r#"
class PostPolicy < ApplicationPolicy
  def update?
    user.admin? || record.owner == user
  end
end
"#,
            include_str!("../../rules/ruby/pundit-policy-class.toml"),
        );
        assert!(!findings.is_empty(), "should match Pundit policy class");
    }

    #[test]
    fn ruby_pundit_policy_class_no_false_positive_on_unrelated_class() {
        let findings = parse_and_match_ruby(
            r#"
class PostPresenter
  def initialize(post)
    @post = post
  end
end
"#,
            include_str!("../../rules/ruby/pundit-policy-class.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match non-Policy classes without an ApplicationPolicy superclass"
        );
    }

    #[test]
    fn ruby_cancancan_can_declaration_matches() {
        let findings = parse_and_match_ruby(
            r#"
class Ability
  include CanCan::Ability
  def initialize(user)
    can :read, Article
  end
end
"#,
            include_str!("../../rules/ruby/cancancan-can-declaration.toml"),
        );
        assert!(!findings.is_empty(), "should match `can :read, Article`");
    }

    #[test]
    fn ruby_cancancan_can_check_matches() {
        let findings = parse_and_match_ruby(
            r#"
def gate
  return unless current_user.can?(:update, @post)
end
"#,
            include_str!("../../rules/ruby/cancancan-can-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match `user.can?(:action, ...)`"
        );
    }

    #[test]
    fn ruby_cancancan_can_check_excludes_non_principal_receiver() {
        // Domain objects that happen to expose `.can?` aren't authz — the
        // tightened receiver predicate is what keeps the rule honest.
        let findings = parse_and_match_ruby(
            r#"
def render_widget
  return unless widget.can?(:render)
end
"#,
            include_str!("../../rules/ruby/cancancan-can-check.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match `.can?` on non-principal receivers"
        );
    }

    #[test]
    fn ruby_rails_before_action_matches() {
        let findings = parse_and_match_ruby(
            r#"
class AdminController < ApplicationController
  before_action :require_admin
end
"#,
            include_str!("../../rules/ruby/rails-before-action-filter.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match before_action :require_admin"
        );
        assert_eq!(findings[0].category, crate::types::AuthCategory::Middleware);
    }

    #[test]
    fn ruby_rails_before_action_devise_marker_matches() {
        // Devise's `before_action :authenticate_user!` is the most common
        // Rails-auth filter in the wild; bang-suffixed symbol must match.
        let findings = parse_and_match_ruby(
            r#"
class ApplicationController < ActionController::Base
  before_action :authenticate_user!
end
"#,
            include_str!("../../rules/ruby/rails-before-action-filter.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match before_action :authenticate_user! (Devise idiom)"
        );
    }

    #[test]
    fn ruby_rails_before_action_skip_matches() {
        let findings = parse_and_match_ruby(
            r#"
class PublicController < ApplicationController
  skip_before_action :authorize_resource, only: [:show]
end
"#,
            include_str!("../../rules/ruby/rails-before-action-filter.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match skip_before_action :authorize_resource"
        );
    }

    #[test]
    fn ruby_rails_before_action_excludes_non_authz_filter_names() {
        // Plain bookkeeping callbacks (`load_post`, etc.) must NOT fire — the
        // rule's filter-name predicate is exactly what keeps this rule
        // useful at scale on real Rails repos.
        let findings = parse_and_match_ruby(
            r#"
class PostsController < ApplicationController
  before_action :load_post
end
"#,
            include_str!("../../rules/ruby/rails-before-action-filter.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match `before_action :load_post` — not authz-shaped"
        );
    }

    #[test]
    fn ruby_role_equals_check_matches() {
        let findings = parse_and_match_ruby(
            "def gate(user)\n  return unless user.role == \"admin\"\nend\n",
            include_str!("../../rules/ruby/role-equals-check.toml"),
        );
        assert!(!findings.is_empty(), "should match user.role == \"admin\"");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn ruby_role_equals_check_excludes_unrelated_property() {
        let findings = parse_and_match_ruby(
            "def greet(user)\n  puts user.name if user.name == \"admin\"\nend\n",
            include_str!("../../rules/ruby/role-equals-check.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match unrelated property comparisons"
        );
    }

    #[test]
    fn ruby_role_collection_include_matches() {
        let findings = parse_and_match_ruby(
            "def manager?\n  current_user.roles.include?(:manager)\nend\n",
            include_str!("../../rules/ruby/role-collection-include.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match user.roles.include?(:manager)"
        );
    }

    #[test]
    fn ruby_role_collection_include_string_arg_matches() {
        // Both symbol and string args are common — the alternation in the
        // query covers both, so the test must pin both shapes.
        let findings = parse_and_match_ruby(
            "def has_read?\n  user.permissions.include?(\"read\")\nend\n",
            include_str!("../../rules/ruby/role-collection-include.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match user.permissions.include?(\"read\")"
        );
    }

    #[test]
    fn ruby_role_collection_include_excludes_unrelated_collection() {
        let findings = parse_and_match_ruby(
            "def tagged?\n  post.tags.include?(:featured)\nend\n",
            include_str!("../../rules/ruby/role-collection-include.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match unrelated `tags.include?` collections"
        );
    }

    #[test]
    fn ruby_current_user_role_predicate_matches() {
        let findings = parse_and_match_ruby(
            "def admin_only\n  redirect_to root_path unless current_user.admin?\nend\n",
            include_str!("../../rules/ruby/current-user-role-predicate.toml"),
        );
        assert!(!findings.is_empty(), "should match current_user.admin?");
    }

    #[test]
    fn ruby_current_user_role_predicate_excludes_non_role_predicates() {
        // `published?` and `confirmed?` are predicate methods but not
        // role-shaped — the rule's regex is exactly what keeps it from
        // flagging arbitrary `?` predicates on `user`-shaped receivers.
        let findings = parse_and_match_ruby(
            "def show\n  return unless user.confirmed?\nend\n",
            include_str!("../../rules/ruby/current-user-role-predicate.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match non-role predicate methods on user-shaped receivers"
        );
    }

    // -- PHP rule tests --

    fn parse_and_match_php(source: &str, rule_toml: &str) -> Vec<Finding> {
        let rule = rules::parse_rule_for_test(rule_toml);
        let mut ts_parser = tree_sitter::Parser::new();
        let lang = Language::Php;
        let ts_lang = parser::get_language(lang, false).unwrap();
        let tree = parser::parse_source(&mut ts_parser, source.as_bytes(), lang, false).unwrap();
        let compiled = compile_rule(&rule, &ts_lang).unwrap();
        execute_query(
            &compiled,
            &tree,
            source.as_bytes(),
            Path::new("test.php"),
            lang,
        )
        .unwrap()
    }

    #[test]
    fn php_laravel_gate_allows_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class C {
    public function update($post) {
        if (Gate::allows('update-post', $post)) { return true; }
    }
}
"#,
            include_str!("../../rules/php/laravel-gate-allows-denies.toml"),
        );
        assert!(!findings.is_empty(), "should match Gate::allows");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn php_laravel_gate_denies_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class C { public function f($post) { if (Gate::denies('delete', $post)) { abort(403); } } }
"#,
            include_str!("../../rules/php/laravel-gate-allows-denies.toml"),
        );
        assert!(!findings.is_empty(), "should match Gate::denies");
    }

    #[test]
    fn php_laravel_gate_excludes_non_gate_scope() {
        // `Other::allows(...)` shares the verb but not the scope — must not
        // fire. That guard is what keeps the rule from claiming unrelated
        // facade-style calls in third-party libraries.
        let findings = parse_and_match_php(
            r#"<?php
class C { public function f($post) { return Other::allows('x', $post); } }
"#,
            include_str!("../../rules/php/laravel-gate-allows-denies.toml"),
        );
        assert!(findings.is_empty(), "must not match non-Gate scopes");
    }

    #[test]
    fn php_laravel_gate_define_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class AuthServiceProvider {
    public function boot() {
        Gate::define('update-post', function ($user, $post) { return $user->id === $post->user_id; });
    }
}
"#,
            include_str!("../../rules/php/laravel-gate-define.toml"),
        );
        assert!(!findings.is_empty(), "should match Gate::define");
    }

    #[test]
    fn php_laravel_authorize_helper_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class PostController {
    public function update(Request $request, Post $post) {
        $this->authorize('update', $post);
        $post->save();
    }
}
"#,
            include_str!("../../rules/php/laravel-authorize-helper.toml"),
        );
        assert!(!findings.is_empty(), "should match $this->authorize");
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn php_laravel_can_helper_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class PostController { public function show($req, $post) { if ($req->user()->can('view', $post)) { return view('post'); } } }
"#,
            include_str!("../../rules/php/laravel-authorize-helper.toml"),
        );
        assert!(!findings.is_empty(), "should match ->can()");
    }

    #[test]
    fn php_laravel_authorize_helper_excludes_non_principal_receiver() {
        // `can`/`cannot` are common method names well outside authz (network
        // clients, render gates, feature toggles…). The receiver predicate is
        // exactly what keeps this rule's high-confidence promise honest — a
        // bare `$widget->can(...)` or `$client->cannot(...)` must NOT fire.
        let findings = parse_and_match_php(
            r#"<?php
function f($widget, $client) {
    $widget->can('render');
    $client->cannot('disconnect');
}
"#,
            include_str!("../../rules/php/laravel-authorize-helper.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match non-principal receivers; got: {findings:?}",
        );
    }

    #[test]
    fn php_laravel_can_helper_matches_facade_chain() {
        // `Auth::user()->can(...)` and `auth()->user()->can(...)` are the
        // canonical Laravel non-controller idioms. The `.+->user\(\)` /
        // `.+::user\(\)` receiver alternatives are what catch them.
        let findings = parse_and_match_php(
            r#"<?php
function check($post) {
    if (Auth::user()->can('view', $post)) { return true; }
    if (auth()->user()->cannot('delete', $post)) { abort(403); }
}
"#,
            include_str!("../../rules/php/laravel-authorize-helper.toml"),
        );
        assert_eq!(
            findings.len(),
            2,
            "should match both Auth::user()->can and auth()->user()->cannot; got: {findings:?}",
        );
    }

    #[test]
    fn php_laravel_can_helper_matches_nullsafe() {
        // PHP 8 nullsafe call (`$user?->can(...)`) takes a separate grammar
        // node (`nullsafe_member_call_expression`). The query alternation
        // covers it explicitly so the modern idiom matches the same way.
        let findings = parse_and_match_php(
            r#"<?php
function check($user, $post) {
    return $user?->can('view', $post);
}
"#,
            include_str!("../../rules/php/laravel-authorize-helper.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match $user?->can(...) nullsafe call; got: {findings:?}",
        );
    }

    #[test]
    fn php_laravel_policy_class_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class PostPolicy {
    public function update(User $user, Post $post) { return $user->id === $post->user_id; }
    public function delete(User $user, Post $post) { return $user->is_admin; }
}
"#,
            include_str!("../../rules/php/laravel-policy-class.toml"),
        );
        // Two policy-verb methods on a *Policy class — each becomes its own
        // ability finding.
        assert_eq!(
            findings.len(),
            2,
            "policy class with two ability methods should produce two findings"
        );
    }

    #[test]
    fn php_laravel_policy_class_excludes_non_policy_class() {
        let findings = parse_and_match_php(
            r#"<?php
class PostPresenter {
    public function update($post) { return $post; }
}
"#,
            include_str!("../../rules/php/laravel-policy-class.toml"),
        );
        assert!(findings.is_empty(), "must not match non-*Policy classes");
    }

    #[test]
    fn php_laravel_route_middleware_matches_auth_alias() {
        let findings = parse_and_match_php(
            r#"<?php
Route::middleware('auth')->group(function () {
    Route::get('/dashboard', [DashboardController::class, 'index']);
});
"#,
            include_str!("../../rules/php/laravel-route-middleware.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match Route::middleware('auth')"
        );
        assert_eq!(findings[0].category, crate::types::AuthCategory::Middleware);
    }

    #[test]
    fn php_laravel_route_middleware_matches_can_alias() {
        let findings = parse_and_match_php(
            r#"<?php
Route::get('/admin', [AdminController::class, 'index'])->middleware(['auth', 'can:update,post']);
"#,
            include_str!("../../rules/php/laravel-route-middleware.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match chained ->middleware([...]) with auth/can aliases"
        );
    }

    #[test]
    fn php_laravel_route_middleware_excludes_throttle() {
        // Throttle isn't authz — it's rate-limiting. The arg-regex gate is
        // what keeps the rule from claiming every `->middleware(...)` call.
        let findings = parse_and_match_php(
            r#"<?php
Route::middleware(['throttle:60,1'])->group(function () {});
"#,
            include_str!("../../rules/php/laravel-route-middleware.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match throttle/non-authz middleware aliases"
        );
    }

    #[test]
    fn php_symfony_voter_class_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class PostVoter extends Voter {
    protected function supports(string $attribute, mixed $subject): bool {
        return in_array($attribute, ['VIEW', 'EDIT']);
    }
}
"#,
            include_str!("../../rules/php/symfony-voter-class.toml"),
        );
        assert!(!findings.is_empty(), "should match class extending Voter");
    }

    #[test]
    fn php_symfony_voter_class_qualified_base_matches() {
        // Real-world Symfony code often uses the fully-qualified parent —
        // the qualified_name branch of the query alternation handles it.
        let findings = parse_and_match_php(
            r#"<?php
abstract class CommentVoter extends \Symfony\Component\Security\Core\Authorization\Voter\Voter {
}
"#,
            include_str!("../../rules/php/symfony-voter-class.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match fully-qualified \\Symfony\\...\\Voter base"
        );
    }

    #[test]
    fn php_symfony_is_granted_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class PostController {
    public function edit(Post $post) {
        $this->denyAccessUnlessGranted('EDIT', $post);
    }
}
"#,
            include_str!("../../rules/php/symfony-is-granted.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match $this->denyAccessUnlessGranted(...)"
        );
    }

    #[test]
    fn php_symfony_is_granted_attribute_matches() {
        let findings = parse_and_match_php(
            r#"<?php
class AdminController {
    #[IsGranted('ROLE_ADMIN')]
    public function dashboard() {}
}
"#,
            include_str!("../../rules/php/symfony-is-granted-attribute.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match #[IsGranted('ROLE_ADMIN')]"
        );
    }

    #[test]
    fn php_symfony_is_granted_attribute_excludes_other_attributes() {
        let findings = parse_and_match_php(
            r#"<?php
class FooController {
    #[Route('/foo')]
    public function show() {}
}
"#,
            include_str!("../../rules/php/symfony-is-granted-attribute.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match unrelated attributes like #[Route]"
        );
    }

    #[test]
    fn php_role_equals_check_strict_matches() {
        let findings = parse_and_match_php(
            r#"<?php
function f($user) { if ($user->role === 'admin') { return true; } }
"#,
            include_str!("../../rules/php/role-equals-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match `$user->role === 'admin'`"
        );
        assert_eq!(findings[0].category, crate::types::AuthCategory::Rbac);
    }

    #[test]
    fn php_role_equals_check_loose_matches() {
        // Loose `==` is also widely used in real PHP code; the alternation
        // covers both forms.
        let findings = parse_and_match_php(
            r#"<?php
function f($account) { return $account->account_type == "enterprise"; }
"#,
            include_str!("../../rules/php/role-equals-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match loose `==` role comparison"
        );
    }

    #[test]
    fn php_role_equals_check_excludes_non_role_property() {
        let findings = parse_and_match_php(
            r#"<?php
function f($user) { if ($user->name === 'admin') { echo "hi"; } }
"#,
            include_str!("../../rules/php/role-equals-check.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match property comparisons whose name isn't role-shaped"
        );
    }

    #[test]
    fn php_in_array_role_check_matches() {
        let findings = parse_and_match_php(
            r#"<?php
function f($user) { return in_array('manager', $user->roles); }
"#,
            include_str!("../../rules/php/in-array-role-check.toml"),
        );
        assert!(
            !findings.is_empty(),
            "should match `in_array('manager', $user->roles)`"
        );
    }

    #[test]
    fn php_in_array_role_check_excludes_unrelated_collection() {
        let findings = parse_and_match_php(
            r#"<?php
function f($post) { return in_array('featured', $post->tags); }
"#,
            include_str!("../../rules/php/in-array-role-check.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match in_array against unrelated collections"
        );
    }

    #[test]
    fn php_has_role_call_matches() {
        let findings = parse_and_match_php(
            r#"<?php
function f($user) { return $user->hasRole('admin'); }
"#,
            include_str!("../../rules/php/has-role-call.toml"),
        );
        assert!(!findings.is_empty(), "should match `->hasRole('admin')`");
    }

    #[test]
    fn php_has_role_call_excludes_unrelated_predicate() {
        // `hasMany` is an Eloquent relation, not authz; the method-name
        // predicate is exactly what keeps this rule from claiming
        // `->hasMany('Comment')`.
        let findings = parse_and_match_php(
            r#"<?php
function f($post) { return $post->hasMany('App\Comment'); }
"#,
            include_str!("../../rules/php/has-role-call.toml"),
        );
        assert!(
            findings.is_empty(),
            "must not match `->hasMany` or other unrelated predicates"
        );
    }

    // -- cross_predicates tests (synthetic rules) --

    /// A synthetic rule shaped like ownership-check: two getters in an
    /// `equals(...)` invocation. The cross-predicate requires at least one
    /// side to look like a principal getter. Per-capture predicates stay
    /// broad on purpose (`getId|getUserId|...`) so the cross-predicate is
    /// what's actually doing the asymmetry check.
    const CROSS_ANY_MATCH_RULE: &str = r#"
[rule]
id = "test-cross-any-match"
languages = ["java"]
category = "ownership"
confidence = "medium"
description = "Synthetic any_match cross-predicate test"
query = """
(method_invocation
  object: (method_invocation
    name: (identifier) @getter)
  name: (identifier) @method_name
  arguments: (argument_list
    (method_invocation
      name: (identifier) @other_getter))
) @match
"""

[rule.predicates.method_name]
eq = "equals"

[rule.predicates.getter]
match = "(?i)^(getId|getUserId|getOwnerId|getCreatedBy|getAuthorId)$"

[rule.predicates.other_getter]
match = "(?i)^(getId|getUserId|getOwnerId|getCreatedBy|getAuthorId)$"

[[rule.cross_predicates]]
kind = "any_match"
captures = ["getter", "other_getter"]
match = "(?i)^(getUserId|getOwnerId|getCreatedBy|getAuthorId)$"
"#;

    #[test]
    fn cross_any_match_matches_when_left_side_is_principal() {
        let findings = parse_and_match_java(
            r#"user.getUserId().equals(resource.getId());"#,
            CROSS_ANY_MATCH_RULE,
        );
        assert!(
            !findings.is_empty(),
            "any_match should accept principal-flavored left side"
        );
    }

    #[test]
    fn cross_any_match_matches_when_right_side_is_principal() {
        let findings = parse_and_match_java(
            r#"record.getId().equals(other.getOwnerId());"#,
            CROSS_ANY_MATCH_RULE,
        );
        assert!(
            !findings.is_empty(),
            "any_match should accept principal-flavored right side"
        );
    }

    #[test]
    fn cross_any_match_rejects_when_neither_side_is_principal() {
        // Both sides are bare getId() — no principal hint anywhere.
        let findings = parse_and_match_java(
            r#"record.getId().equals(other.getId());"#,
            CROSS_ANY_MATCH_RULE,
        );
        assert!(
            findings.is_empty(),
            "any_match should reject when neither side names a principal-flavored getter"
        );
    }

    const CROSS_ALL_MATCH_RULE: &str = r#"
[rule]
id = "test-cross-all-match"
languages = ["java"]
category = "ownership"
confidence = "medium"
description = "Synthetic all_match cross-predicate test"
query = """
(method_invocation
  object: (method_invocation
    name: (identifier) @getter)
  name: (identifier) @method_name
  arguments: (argument_list
    (method_invocation
      name: (identifier) @other_getter))
) @match
"""

[rule.predicates.method_name]
eq = "equals"

[[rule.cross_predicates]]
kind = "all_match"
captures = ["getter", "other_getter"]
match = "^get[A-Z]"
"#;

    #[test]
    fn cross_all_match_requires_every_capture() {
        let findings =
            parse_and_match_java(r#"a.getFoo().equals(b.getBar());"#, CROSS_ALL_MATCH_RULE);
        assert!(
            !findings.is_empty(),
            "all_match should accept when all captures match"
        );
    }

    #[test]
    fn cross_all_match_rejects_when_one_capture_fails() {
        // `lookupBar` does not start with `get[A-Z]`.
        let findings =
            parse_and_match_java(r#"a.getFoo().equals(b.lookupBar());"#, CROSS_ALL_MATCH_RULE);
        assert!(
            findings.is_empty(),
            "all_match should reject when any capture fails the regex"
        );
    }

    #[test]
    fn cross_predicate_unknown_capture_is_compile_error() {
        let bad_rule = r#"
[rule]
id = "test-cross-bad-capture"
languages = ["java"]
category = "ownership"
confidence = "medium"
description = "Cross-predicate references a capture that doesn't exist in the query"
query = """
(method_invocation
  name: (identifier) @method_name
) @match
"""

[[rule.cross_predicates]]
kind = "any_match"
captures = ["nonexistent_capture"]
match = ".*"
"#;
        let rule = rules::parse_rule_for_test(bad_rule);
        let ts_lang = parser::get_language(Language::Java, false).unwrap();
        match compile_rule(&rule, &ts_lang) {
            Ok(_) => {
                panic!("compile_rule should reject cross_predicate referencing an unknown capture")
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("nonexistent_capture"),
                    "error should name the missing capture; got: {msg}"
                );
                // The error should also identify the kind of the failing
                // cross-predicate so multi-cross_predicate rules are
                // diagnosable.
                assert!(
                    msg.contains("any_match"),
                    "error should name the predicate kind; got: {msg}"
                );
            }
        }
    }

    #[test]
    fn predicate_unknown_capture_is_compile_error() {
        // Mirror of the cross-predicate test, but for per-capture
        // predicates. A typo'd capture name in `[rule.predicates.X]` used
        // to silently make the rule never match (the predicate would look
        // up a non-existent capture and fail at runtime); compile_rule now
        // surfaces it eagerly.
        let bad_rule = r#"
[rule]
id = "test-predicate-bad-capture"
languages = ["java"]
category = "ownership"
confidence = "medium"
description = "Per-capture predicate references a capture that doesn't exist in the query"
query = """
(method_invocation
  name: (identifier) @method_name
) @match
"""

[rule.predicates.nonexistent_capture]
match = ".*"
"#;
        let rule = rules::parse_rule_for_test(bad_rule);
        let ts_lang = parser::get_language(Language::Java, false).unwrap();
        match compile_rule(&rule, &ts_lang) {
            Ok(_) => {
                panic!("compile_rule should reject predicate referencing an unknown capture")
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("nonexistent_capture"),
                    "error should name the missing capture; got: {msg}"
                );
            }
        }
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
            policy_outputs: vec![],
            pass: ScanPass::Structural,
            surface: Surface::Backend,
            provenance: None,
        };
        let findings = vec![f.clone(), f];
        let deduped = dedup_findings(findings);
        assert_eq!(deduped.len(), 1);
    }
}
