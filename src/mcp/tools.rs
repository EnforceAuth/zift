//! MCP tool implementations.
//!
//! Each tool is a function that takes the [`ServerContext`] plus a JSON
//! arguments value and returns a [`ToolsCallResult`]. Tools never panic on
//! bad input — they return `is_error: true` content blocks describing the
//! problem, so the agent host can recover.
//!
//! Architectural rule: tools are transport adapters. They reuse the same
//! primitives the deep-scan HTTP client uses ([`crate::scanner::scan`],
//! [`crate::deep::context::expand_finding`], [`crate::deep::prompt::render`],
//! [`crate::rego::validator::validate_rego`]) — no parallel implementations.

use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::cli::ScanArgs;
use crate::deep::candidate::{Candidate, CandidateKind};
use crate::deep::context::expand_region;
use crate::deep::prompt::{PromptInputs, render};
use crate::mcp::protocol::{ToolDescriptor, ToolsCallResult, ToolsListResult};
use crate::mcp::server::ServerContext;
use crate::rego::templates::{apply_confidence_wrapping, generate_default_stub, render_template};
use crate::rego::validator::validate_rego;
use crate::rules::PatternRule;
use crate::scanner;
use crate::types::{AuthCategory, Confidence, Finding, Language, ScanPass, Surface};

const DEFAULT_MAX_PROMPT_CHARS: usize = 16_000;

/// The tool catalog. Order is the order the agent host displays them in.
pub fn list_tools() -> ToolsListResult {
    ToolsListResult {
        tools: vec![
            scan_authz_descriptor(),
            get_finding_context_descriptor(),
            list_rules_descriptor(),
            get_rule_descriptor(),
            suggest_rego_descriptor(),
            validate_rego_descriptor(),
            analyze_snippet_descriptor(),
        ],
    }
}

/// Dispatch a `tools/call` to the named tool. Returns a `ToolsCallResult`
/// (never panics, never returns Err — tool-level failures live inside the
/// result with `is_error: true`).
pub fn dispatch(ctx: &ServerContext, name: &str, args: &Value) -> ToolsCallResult {
    match name {
        "scan_authz" => run_or_error(scan_authz(ctx, args)),
        "get_finding_context" => run_or_error(get_finding_context(ctx, args)),
        "list_rules" => run_or_error(list_rules(ctx, args)),
        "get_rule" => run_or_error(get_rule(ctx, args)),
        "suggest_rego" => run_or_error(suggest_rego(ctx, args)),
        "validate_rego" => run_or_error(validate_rego_tool(args)),
        "analyze_snippet" => run_or_error(analyze_snippet(ctx, args)),
        other => ToolsCallResult::error(format!("unknown tool: {other}")),
    }
}

fn run_or_error(r: Result<Value, String>) -> ToolsCallResult {
    match r {
        Ok(v) => ToolsCallResult::ok(v),
        Err(msg) => ToolsCallResult::error(msg),
    }
}

// -- scan_authz -----------------------------------------------------------

fn scan_authz_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "scan_authz",
        description: "Run Zift's structural scan over a path inside scan_root. \
                      Returns the finding set plus the count of policy-engine \
                      enforcement points (calls into Casbin/OPA/etc. that mean \
                      the inline check is already deferred to a real engine).",
        input_schema: json!({
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path inside scan_root (default: '.')."
                },
                "languages": {
                    "type": "array",
                    "items": {"type": "string", "enum": [
                        "java", "typescript", "javascript", "python", "go",
                        "csharp", "kotlin", "ruby", "php"
                    ]},
                    "description": "Optional language filter."
                },
                "categories": {
                    "type": "array",
                    "items": {"type": "string", "enum": [
                        "rbac", "abac", "middleware", "business_rule",
                        "ownership", "feature_gate", "custom"
                    ]},
                    "description": "Optional category filter."
                },
                "min_confidence": {
                    "type": "string",
                    "enum": ["low", "medium", "high"],
                    "description": "Drop findings below this confidence."
                }
            },
            "additionalProperties": false
        }),
    }
}

#[derive(Debug, Default, Deserialize)]
struct ScanAuthzArgs {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    languages: Vec<Language>,
    #[serde(default)]
    categories: Vec<AuthCategory>,
    #[serde(default)]
    min_confidence: Option<Confidence>,
}

fn scan_authz(ctx: &ServerContext, args: &Value) -> Result<Value, String> {
    let parsed: ScanAuthzArgs = parse_args(args, "scan_authz")?;
    let path = resolve_inside_scan_root(&ctx.scan_root, parsed.path.as_deref())?;

    let scan_args = ScanArgs {
        path: path.clone(),
        language: parsed.languages,
        category: parsed.categories,
        confidence: parsed.min_confidence,
        ..ScanArgs::default()
    };

    let result = scanner::scan(&path, &ctx.rules, &scan_args, &ctx.config)
        .map_err(|e| format!("scan failed: {e}"))?;

    Ok(json!({
        "findings": result.findings,
        "enforcement_points": result.enforcement_points,
    }))
}

// -- get_finding_context --------------------------------------------------

fn get_finding_context_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "get_finding_context",
        description: "Expand a finding's surrounding code window: 5 lines before, \
                      15 lines after, plus the file's first 20 lines as imports. \
                      Same expansion the deep-scan candidate selector uses. The \
                      file path is resolved inside scan_root.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "description": "Path relative to scan_root."
                },
                "language": {
                    "type": "string",
                    "enum": ["java", "typescript", "javascript", "python", "go",
                             "csharp", "kotlin", "ruby", "php"]
                },
                "line_start": {"type": "integer", "minimum": 1},
                "line_end": {"type": "integer", "minimum": 1},
                "max_chars": {
                    "type": "integer",
                    "description": "Optional payload-budget cap. Defaults to 16_000.",
                    "minimum": 200
                }
            },
            "required": ["file", "language", "line_start", "line_end"],
            "additionalProperties": false
        }),
    }
}

#[derive(Debug, Deserialize)]
struct GetFindingContextArgs {
    file: String,
    language: Language,
    line_start: usize,
    line_end: usize,
    #[serde(default)]
    max_chars: Option<usize>,
}

fn get_finding_context(ctx: &ServerContext, args: &Value) -> Result<Value, String> {
    let parsed: GetFindingContextArgs = parse_args(args, "get_finding_context")?;
    let max = parsed.max_chars.unwrap_or(DEFAULT_MAX_PROMPT_CHARS);
    let relative = PathBuf::from(&parsed.file);
    let absolute = ensure_inside_scan_root(&ctx.scan_root, &relative)?;
    let ctx_out = expand_region(
        &absolute,
        relative,
        parsed.language,
        parsed.line_start,
        parsed.line_end,
        max,
    )
    .map_err(|e| format!("expand_region failed: {e}"))?;
    Ok(json!({
        "file": ctx_out.file_relative,
        "language": ctx_out.language,
        "line_start": ctx_out.line_start,
        "line_end": ctx_out.line_end,
        "snippet": ctx_out.snippet,
        "imports": ctx_out.imports,
    }))
}

// -- list_rules ----------------------------------------------------------

fn list_rules_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "list_rules",
        description: "Enumerate Zift's pattern rule library. Returns id, languages, \
                      category, confidence, and description for each rule.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "language": {
                    "type": "string",
                    "enum": ["java", "typescript", "javascript", "python", "go",
                             "csharp", "kotlin", "ruby", "php"],
                    "description": "Optional language filter."
                },
                "category": {
                    "type": "string",
                    "enum": ["rbac", "abac", "middleware", "business_rule",
                             "ownership", "feature_gate", "custom"],
                    "description": "Optional category filter."
                }
            },
            "additionalProperties": false
        }),
    }
}

#[derive(Debug, Default, Deserialize)]
struct ListRulesArgs {
    #[serde(default)]
    language: Option<Language>,
    #[serde(default)]
    category: Option<AuthCategory>,
}

fn list_rules(ctx: &ServerContext, args: &Value) -> Result<Value, String> {
    let parsed: ListRulesArgs = parse_args(args, "list_rules")?;
    let summaries: Vec<Value> = ctx
        .rules
        .iter()
        .filter(|r| match parsed.language {
            Some(l) => r.languages.contains(&l),
            None => true,
        })
        .filter(|r| match parsed.category {
            Some(c) => r.category == c,
            None => true,
        })
        .map(rule_summary)
        .collect();
    Ok(json!({"rules": summaries}))
}

fn rule_summary(r: &PatternRule) -> Value {
    json!({
        "id": r.id,
        "languages": r.languages,
        "category": r.category,
        "confidence": r.confidence,
        "description": r.description,
        "has_rego_template": r.rego_template.is_some(),
    })
}

// -- get_rule ------------------------------------------------------------

fn get_rule_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "get_rule",
        description: "Fetch one rule's full definition: tree-sitter query, \
                      predicates, Rego template (if any), and test fixtures.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Rule id, e.g. 'ts-role-check-conditional'."}
            },
            "required": ["id"],
            "additionalProperties": false
        }),
    }
}

#[derive(Debug, Deserialize)]
struct GetRuleArgs {
    id: String,
}

fn get_rule(ctx: &ServerContext, args: &Value) -> Result<Value, String> {
    let parsed: GetRuleArgs = parse_args(args, "get_rule")?;
    let rule = ctx
        .rules
        .iter()
        .find(|r| r.id == parsed.id)
        .ok_or_else(|| format!("no rule with id: {}", parsed.id))?;

    let predicates: Vec<Value> = rule
        .predicates
        .iter()
        .map(|(name, p)| {
            let (kind, value) = match p {
                crate::rules::Predicate::Match(re) => ("match", re.as_str().to_string()),
                crate::rules::Predicate::Eq(s) => ("eq", s.clone()),
                crate::rules::Predicate::NotMatch(re) => ("not_match", re.as_str().to_string()),
                crate::rules::Predicate::NotEq(s) => ("not_eq", s.clone()),
            };
            json!({"capture": name, "kind": kind, "value": value})
        })
        .collect();

    let cross_predicates: Vec<Value> = rule
        .cross_predicates
        .iter()
        .map(|cp| {
            json!({
                "kind": cp.kind_label(),
                "captures": cp.referenced_captures(),
                "match": cp.regex().as_str(),
            })
        })
        .collect();

    let tests: Vec<Value> = rule
        .tests
        .iter()
        .map(|t| {
            json!({
                "input": t.input,
                "language": t.language,
                "expect_match": t.expect_match,
            })
        })
        .collect();

    Ok(json!({
        "id": rule.id,
        "languages": rule.languages,
        "category": rule.category,
        "confidence": rule.confidence,
        "description": rule.description,
        "query": rule.query_source,
        "predicates": predicates,
        "cross_predicates": cross_predicates,
        "rego_template": rule.rego_template,
        "tests": tests,
    }))
}

// -- suggest_rego --------------------------------------------------------

fn suggest_rego_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "suggest_rego",
        description: "Suggest a Rego policy stub for a finding. If a rule_id with \
                      a rego_template is supplied, the template is rendered against \
                      string literals extracted from the snippet. Otherwise a \
                      category-default stub is generated. The stub is wrapped in \
                      confidence-appropriate guidance (commented for low, TODO \
                      header for medium, raw for high).",
        input_schema: json!({
            "type": "object",
            "properties": {
                "category": {
                    "type": "string",
                    "enum": ["rbac", "abac", "middleware", "business_rule",
                             "ownership", "feature_gate", "custom"]
                },
                "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                "code_snippet": {"type": "string"},
                "rule_id": {
                    "type": "string",
                    "description": "Optional. If supplied and the rule has a \
                                    rego_template, that template wins over the default."
                }
            },
            "required": ["category", "confidence", "code_snippet"],
            "additionalProperties": false
        }),
    }
}

#[derive(Debug, Deserialize)]
struct SuggestRegoArgs {
    category: AuthCategory,
    confidence: Confidence,
    code_snippet: String,
    #[serde(default)]
    rule_id: Option<String>,
}

fn suggest_rego(ctx: &ServerContext, args: &Value) -> Result<Value, String> {
    let parsed: SuggestRegoArgs = parse_args(args, "suggest_rego")?;

    let rendered = if let Some(rid) = parsed.rule_id.as_deref() {
        let rule = ctx.rules.iter().find(|r| r.id == rid);
        match rule.and_then(|r| r.rego_template.as_deref()) {
            Some(tmpl) => {
                // Render the rule's template with literals extracted from the
                // snippet. We use an empty vars map keyed by capture name —
                // the model fills these in during deep mode; here we mirror
                // the structural-pass behavior for ad-hoc agent calls.
                let vars = build_template_vars(&parsed.code_snippet);
                render_template(tmpl, &vars)
            }
            None => generate_default_stub(parsed.category, &parsed.code_snippet),
        }
    } else {
        generate_default_stub(parsed.category, &parsed.code_snippet)
    };

    let wrapped = apply_confidence_wrapping(&rendered, parsed.confidence);
    Ok(json!({"rego": wrapped}))
}

fn build_template_vars(snippet: &str) -> std::collections::HashMap<String, String> {
    use crate::rego::templates::extract_string_literals;
    let mut vars = std::collections::HashMap::new();
    let literals = extract_string_literals(snippet);
    // Single-value placeholders. Tree-sitter captures used by rule templates
    // are listed exhaustively so a rule using e.g. {{plan_value}} or
    // {{perm_value}} doesn't render with the literal placeholder still in
    // place. `expr` (SpEL passthrough in spring-preauthorize.toml) has no
    // sensible literal-derived value and is intentionally omitted —
    // unsubstituted is the right behavior there.
    if let Some(first) = literals.first() {
        for key in [
            "role_value",
            "plan_value",
            "perm_value",
            "permission",
            "attribute",
            "value",
        ] {
            vars.insert(key.to_string(), first.clone());
        }
    }
    // Set-form placeholders used by category-default templates.
    if !literals.is_empty() {
        let set = format!(
            "{{{}}}",
            literals
                .iter()
                .map(|s| format!("\"{s}\""))
                .collect::<Vec<_>>()
                .join(", ")
        );
        vars.insert("roles".to_string(), set.clone());
        vars.insert("plans".to_string(), set);
    }
    vars
}

// -- validate_rego -------------------------------------------------------

fn validate_rego_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "validate_rego",
        description: "Validate a Rego policy string by parsing it with the \
                      embedded `regorus` engine. Returns valid=true on success \
                      or valid=false plus the parse error.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "policy": {"type": "string", "description": "Full Rego policy to validate."}
            },
            "required": ["policy"],
            "additionalProperties": false
        }),
    }
}

#[derive(Debug, Deserialize)]
struct ValidateRegoArgs {
    policy: String,
}

fn validate_rego_tool(args: &Value) -> Result<Value, String> {
    let parsed: ValidateRegoArgs = parse_args(args, "validate_rego")?;
    let result = validate_rego(&parsed.policy);
    Ok(json!({
        "valid": result.valid,
        "error": result.error,
    }))
}

// -- analyze_snippet -----------------------------------------------------

fn analyze_snippet_descriptor() -> ToolDescriptor {
    ToolDescriptor {
        name: "analyze_snippet",
        description: "Render the deep-scan prompt for a snippet WITHOUT calling \
                      any model. Returns the system prompt, user prompt, and the \
                      JSON Schema the response should validate against. The agent \
                      host's model produces the analysis; Zift never sees it. \
                      This is the headline transport pattern: Zift owns the \
                      authz expertise, the agent host owns the model.",
        input_schema: json!({
            "type": "object",
            "properties": {
                "file": {"type": "string"},
                "language": {
                    "type": "string",
                    "enum": ["java", "typescript", "javascript", "python", "go",
                             "csharp", "kotlin", "ruby", "php"]
                },
                "line_start": {"type": "integer", "minimum": 1},
                "line_end": {"type": "integer", "minimum": 1},
                "snippet": {"type": "string"},
                "imports": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Optional. Used for framework detection."
                },
                "seed_finding": {
                    "type": "object",
                    "description": "Optional. If provided, the prompt frames the \
                                    request as 'confirm or reject' against this \
                                    structural finding.",
                    "properties": {
                        "id": {"type": "string"},
                        "category": {
                            "type": "string",
                            "enum": ["rbac", "abac", "middleware", "business_rule",
                                     "ownership", "feature_gate", "custom"]
                        },
                        "confidence": {"type": "string", "enum": ["low", "medium", "high"]},
                        "description": {"type": "string"},
                        "pattern_rule": {"type": ["string", "null"]}
                    },
                    "required": ["id", "category", "confidence", "description"]
                }
            },
            "required": ["file", "language", "line_start", "line_end", "snippet"],
            "additionalProperties": false
        }),
    }
}

#[derive(Debug, Deserialize)]
struct AnalyzeSnippetArgs {
    file: String,
    language: Language,
    line_start: usize,
    line_end: usize,
    snippet: String,
    #[serde(default)]
    imports: Vec<String>,
    #[serde(default)]
    seed_finding: Option<SeedFindingArg>,
}

#[derive(Debug, Deserialize)]
struct SeedFindingArg {
    id: String,
    category: AuthCategory,
    confidence: Confidence,
    description: String,
    #[serde(default)]
    pattern_rule: Option<String>,
}

fn analyze_snippet(_ctx: &ServerContext, args: &Value) -> Result<Value, String> {
    let parsed: AnalyzeSnippetArgs = parse_args(args, "analyze_snippet")?;

    let candidate = Candidate {
        kind: if parsed.seed_finding.is_some() {
            CandidateKind::Escalation
        } else {
            CandidateKind::ColdRegion
        },
        file: PathBuf::from(&parsed.file),
        language: parsed.language,
        line_start: parsed.line_start,
        line_end: parsed.line_end,
        source_snippet: parsed.snippet,
        imports: parsed.imports,
        original_finding_id: parsed.seed_finding.as_ref().map(|s| s.id.clone()),
        seed_category: parsed.seed_finding.as_ref().map(|s| s.category),
    };

    // Synthesize a Finding from the seed (if any) so the prompt renderer
    // gets the same shape it does in the deep-scan path.
    let seed_finding: Option<Finding> = parsed.seed_finding.as_ref().map(|s| Finding {
        id: s.id.clone(),
        file: PathBuf::from(&parsed.file),
        line_start: parsed.line_start,
        line_end: parsed.line_end,
        code_snippet: candidate.source_snippet.clone(),
        language: parsed.language,
        category: s.category,
        confidence: s.confidence,
        description: s.description.clone(),
        pattern_rule: s.pattern_rule.clone(),
        rego_stub: None,
        pass: ScanPass::Structural,
        surface: Surface::classify(&PathBuf::from(&parsed.file)),
    });

    let rendered = render(&PromptInputs {
        candidate: &candidate,
        structural_finding: seed_finding.as_ref(),
    });

    Ok(json!({
        "system": rendered.system,
        "user": rendered.user,
        "schema": rendered.schema,
    }))
}

// -- helpers --------------------------------------------------------------

fn parse_args<T: for<'de> Deserialize<'de>>(args: &Value, tool: &str) -> Result<T, String> {
    serde_json::from_value(args.clone()).map_err(|e| format!("invalid arguments for {tool}: {e}"))
}

/// Resolve `path` (defaulting to ".") against `scan_root` and verify the
/// canonical result is inside `scan_root`. Returns the canonical absolute
/// path on success.
///
/// `scan_root` is already canonicalized at startup
/// (`commands::mcp::execute`), so we don't re-canonicalize it here — both
/// to save the syscall and to keep a single canonical-root invariant.
fn resolve_inside_scan_root(scan_root: &Path, path: Option<&str>) -> Result<PathBuf, String> {
    let candidate = match path {
        Some(p) if !p.is_empty() => scan_root.join(p),
        _ => scan_root.to_path_buf(),
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|e| format!("cannot resolve path {}: {e}", candidate.display()))?;
    if !canonical.starts_with(scan_root) {
        return Err(format!(
            "path {} is outside scan_root {}",
            canonical.display(),
            scan_root.display(),
        ));
    }
    Ok(canonical)
}

/// Same containment check, but for an explicit relative path argument.
/// `scan_root` is assumed canonical (see [`resolve_inside_scan_root`]).
fn ensure_inside_scan_root(scan_root: &Path, relative: &Path) -> Result<PathBuf, String> {
    let absolute = scan_root.join(relative);
    let canonical = absolute
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", absolute.display()))?;
    if !canonical.starts_with(scan_root) {
        return Err(format!(
            "path {} is outside scan_root {}",
            canonical.display(),
            scan_root.display(),
        ));
    }
    Ok(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZiftConfig;
    use crate::rules::load_rules;
    use std::fs;
    use tempfile::tempdir;

    fn ctx_with_root(root: PathBuf) -> ServerContext {
        let config = ZiftConfig::default();
        let rules = load_rules(None, &config).unwrap();
        ServerContext {
            scan_root: root,
            rules,
            config,
        }
    }

    #[test]
    fn list_tools_returns_seven_tools_with_schemas() {
        let result = list_tools();
        assert_eq!(result.tools.len(), 7);
        for t in &result.tools {
            // Every tool must have an object input schema.
            assert_eq!(t.input_schema["type"], "object");
        }
    }

    #[test]
    fn dispatch_unknown_tool_is_error_not_panic() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().to_path_buf());
        let res = dispatch(&ctx, "no_such_tool", &json!({}));
        assert!(res.is_error);
    }

    #[test]
    fn scan_authz_runs_against_a_real_repo_and_returns_findings() {
        let dir = tempdir().unwrap();
        // Drop a TS file with an obvious role check the embedded rule should hit.
        fs::write(
            dir.path().join("auth.ts"),
            r#"
function check(user: { role: string }) {
  if (user.role === "admin") {
    return true;
  }
  return false;
}
"#,
        )
        .unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(&ctx, "scan_authz", &json!({}));
        assert!(!res.is_error, "scan_authz returned error: {res:?}");
        // Pull the embedded JSON payload out of the text content block.
        let text = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => text.clone(),
        };
        let payload: Value = serde_json::from_str(&text).unwrap();
        assert!(!payload["findings"].as_array().unwrap().is_empty());
    }

    #[test]
    fn scan_authz_rejects_path_outside_scan_root() {
        let dir = tempdir().unwrap();
        let inner = dir.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        // `outer.ts` exists in the parent — must not be reachable from inner.
        fs::write(dir.path().join("outer.ts"), "x").unwrap();
        let ctx = ctx_with_root(inner.canonicalize().unwrap());
        let res = dispatch(&ctx, "scan_authz", &json!({"path": "../outer.ts"}));
        assert!(res.is_error);
    }

    #[test]
    fn list_rules_filters_by_language() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(&ctx, "list_rules", &json!({"language": "java"}));
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        let rules = payload["rules"].as_array().unwrap();
        assert!(!rules.is_empty(), "expected at least one Java rule");
        for r in rules {
            let langs = r["languages"].as_array().unwrap();
            assert!(langs.iter().any(|l| l == "java"));
        }
    }

    #[test]
    fn get_rule_returns_full_definition() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "get_rule",
            &json!({"id": "ts-role-check-conditional"}),
        );
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        assert_eq!(payload["id"], "ts-role-check-conditional");
        assert!(payload["query"].as_str().unwrap().contains("if_statement"));
        assert!(payload["rego_template"].is_string());
        // cross_predicates is always present (empty array if the rule has none).
        assert!(payload["cross_predicates"].is_array());
    }

    #[test]
    fn get_rule_serializes_cross_predicates() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        // java-ownership-check carries an any_match cross-predicate.
        let res = dispatch(&ctx, "get_rule", &json!({"id": "java-ownership-check"}));
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        let cps = payload["cross_predicates"].as_array().unwrap();
        assert!(
            !cps.is_empty(),
            "java-ownership-check must expose its cross_predicates"
        );
        assert_eq!(cps[0]["kind"], "any_match");
        let captures = cps[0]["captures"].as_array().unwrap();
        assert!(captures.iter().any(|c| c == "getter"));
        assert!(captures.iter().any(|c| c == "other_getter"));
        assert!(cps[0]["match"].is_string());
    }

    #[test]
    fn get_rule_unknown_id_returns_error() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(&ctx, "get_rule", &json!({"id": "no-such-rule"}));
        assert!(res.is_error);
    }

    #[test]
    fn validate_rego_accepts_valid_policy() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "validate_rego",
            &json!({
                "policy": "package x\nimport rego.v1\ndefault allow := false\n"
            }),
        );
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        assert_eq!(payload["valid"], true);
    }

    #[test]
    fn validate_rego_reports_invalid_policy() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "validate_rego",
            &json!({"policy": "this is not rego"}),
        );
        assert!(!res.is_error); // tool itself succeeded; payload reports invalid
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        assert_eq!(payload["valid"], false);
        assert!(payload["error"].is_string());
    }

    #[test]
    fn suggest_rego_returns_default_stub_for_rbac() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "suggest_rego",
            &json!({
                "category": "rbac",
                "confidence": "high",
                "code_snippet": "if (user.role === \"admin\") {}"
            }),
        );
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        let rego = payload["rego"].as_str().unwrap();
        assert!(rego.contains("input.user.role"));
        assert!(rego.contains("admin"));
    }

    #[test]
    fn suggest_rego_with_rule_id_substitutes_all_placeholder_names() {
        // Regression: build_template_vars used to only fill role_value /
        // attribute / value / roles / plans, leaving rules with
        // {{plan_value}} or {{perm_value}} or {{permission}} placeholders
        // unrendered. Verify suggest_rego with a feature-gate rule
        // ({{plan_value}}) and a permission rule ({{perm_value}}) come back
        // fully substituted.
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());

        let res = dispatch(
            &ctx,
            "suggest_rego",
            &json!({
                "category": "feature_gate",
                "confidence": "high",
                "code_snippet": "if (user.plan === \"enterprise\") { ... }",
                "rule_id": "ts-feature-gate-check",
            }),
        );
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        let rego = payload["rego"].as_str().unwrap();
        assert!(
            !rego.contains("{{"),
            "unrendered placeholder in suggest_rego output: {rego}"
        );
        assert!(rego.contains("enterprise"));
    }

    #[test]
    fn suggest_rego_low_confidence_comments_the_stub() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "suggest_rego",
            &json!({
                "category": "rbac",
                "confidence": "low",
                "code_snippet": "if (user.role === \"admin\") {}"
            }),
        );
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        let rego = payload["rego"].as_str().unwrap();
        assert!(rego.starts_with("# SUGGESTION"));
    }

    #[test]
    fn analyze_snippet_returns_system_user_and_schema() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "analyze_snippet",
            &json!({
                "file": "src/auth.ts",
                "language": "typescript",
                "line_start": 1,
                "line_end": 3,
                "snippet": "function isAdmin() { return user.role === 'admin'; }",
                "imports": []
            }),
        );
        assert!(!res.is_error, "analyze_snippet returned error: {res:?}");
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        // System prompt is the canonical SYSTEM_PROMPT — must contain category list.
        assert!(payload["system"].as_str().unwrap().contains("CATEGORIES"));
        // User prompt mentions the file + line numbers we passed.
        let user = payload["user"].as_str().unwrap();
        assert!(user.contains("src/auth.ts"));
        assert!(user.contains("Lines: 1-3"));
        // Schema is the canonical output schema — verify the shape.
        assert_eq!(payload["schema"]["type"], "object");
        assert_eq!(payload["schema"]["required"][0], "findings");
    }

    #[test]
    fn analyze_snippet_with_seed_finding_renders_escalation_prompt() {
        let dir = tempdir().unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "analyze_snippet",
            &json!({
                "file": "src/auth.ts",
                "language": "typescript",
                "line_start": 10,
                "line_end": 15,
                "snippet": "function isAdmin() { return user.role === 'admin'; }",
                "seed_finding": {
                    "id": "structural-1",
                    "category": "custom",
                    "confidence": "low",
                    "description": "matched custom rule"
                }
            }),
        );
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        let user = payload["user"].as_str().unwrap();
        assert!(user.contains("structural rule flagged"));
        assert!(user.contains("Custom"));
        assert!(user.contains("low"));
    }

    #[test]
    fn get_finding_context_expands_window() {
        let dir = tempdir().unwrap();
        let body: String = (1..=50)
            .map(|i| format!("line {i}"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(dir.path().join("a.ts"), &body).unwrap();
        let ctx = ctx_with_root(dir.path().canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "get_finding_context",
            &json!({
                "file": "a.ts",
                "language": "typescript",
                "line_start": 20,
                "line_end": 22
            }),
        );
        assert!(!res.is_error);
        let payload: Value = match &res.content[0] {
            crate::mcp::protocol::ContentBlock::Text { text } => {
                serde_json::from_str(text).unwrap()
            }
        };
        // 5 before, 15 after the requested window.
        assert_eq!(payload["line_start"], 15);
        assert_eq!(payload["line_end"], 37);
        let snippet = payload["snippet"].as_str().unwrap();
        assert!(snippet.contains("line 20"));
        assert!(!snippet.contains("line 14"));
    }

    #[test]
    fn get_finding_context_rejects_path_traversal() {
        let dir = tempdir().unwrap();
        let inner = dir.path().join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(dir.path().join("secret.txt"), "leaked").unwrap();
        // need a real file inside the inner root for canonicalize to succeed
        fs::write(inner.join("ok.ts"), "x").unwrap();
        let ctx = ctx_with_root(inner.canonicalize().unwrap());
        let res = dispatch(
            &ctx,
            "get_finding_context",
            &json!({
                "file": "../secret.txt",
                "language": "typescript",
                "line_start": 1,
                "line_end": 1
            }),
        );
        assert!(res.is_error);
    }
}
