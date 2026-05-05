use std::collections::HashMap;
use std::fmt::Write;
use std::path::Path;

use sha2::{Digest, Sha256};
use streaming_iterator::StreamingIterator;
use tree_sitter::{Query, QueryCursor, Tree};

use crate::error::{Result, ZiftError};
use crate::rules::{CrossPredicate, PatternRule, Predicate};
use crate::types::{Confidence, Finding, Language, ScanPass, Surface};

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
                let mut owned: HashMap<String, String> = captures
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.clone()))
                    .collect();
                add_template_derived_values(&mut owned);
                crate::rego::render_template(tmpl, &owned)
            }),
            pass: ScanPass::Structural,
            surface: Surface::classify(file_path),
        });
    }

    Ok(findings)
}

fn add_template_derived_values(vars: &mut HashMap<String, String>) {
    if let Some(roles) = vars.get("roles") {
        vars.insert(
            "roles_set".to_string(),
            comma_separated_rego_set_items(roles),
        );
    }
}

fn comma_separated_rego_set_items(value: &str) -> String {
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
    fn csharp_authorize_roles_splits_comma_separated_roles_in_rego() {
        let findings = parse_and_match(
            r#"[Authorize(Roles = "Admin,Manager")]
public IActionResult Delete(int id) => Ok();"#,
            include_str!("../../rules/csharp/aspnet-authorize-roles.toml"),
        );

        assert_eq!(findings.len(), 1);
        let rego = findings[0].rego_stub.as_deref().unwrap();
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
        let rego = findings[0].rego_stub.as_deref().unwrap();
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
        let rego = findings[0].rego_stub.as_deref().unwrap();
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
            rego_stub: None,
            pass: ScanPass::Structural,
            surface: Surface::Backend,
        };
        let findings = vec![f.clone(), f];
        let deduped = dedup_findings(findings);
        assert_eq!(deduped.len(), 1);
    }
}
