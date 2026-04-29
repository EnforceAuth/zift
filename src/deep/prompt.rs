//! Prompt rendering and JSON output schema for the deep scan.
//!
//! [`SYSTEM_PROMPT`] and [`output_schema`] are exported for reuse by PR 2
//! (MCP server) and PR 3 (subprocess hook). Every transport binds to this
//! contract.
//!
//! Tone: terse. Local 7B-14B models do better with structured prompts than
//! prose. Token economy matters when the user pays per million.
//!
//! Framework guidance is injected per-call only when a known framework is
//! detected in the candidate's imports — keeps the base prompt small for
//! the common case, adds targeted hints when relevant.

use crate::deep::candidate::Candidate;
use crate::types::{Finding, Language};

/// System prompt sent on every deep-scan request. The seven `category` and
/// three `confidence` enums match the `output_schema()` and the canonical
/// [`crate::types::AuthCategory`] / [`crate::types::Confidence`] enums.
pub const SYSTEM_PROMPT: &str = r#"You identify authorization logic in source code.

AUTHZ:
- Role checks (hasRole, isAdmin, requires X)
- Attribute checks (user.tenant, user.plan)
- Ownership (user X owns resource Y)
- Route guards / middleware / decorators
- Feature gates (plan-based, tenant-based, flag-based)
- Business rules that gate access by user

NOT AUTHZ:
- Input validation, null checks
- Rate limits not user-conditioned
- Retry / idempotency / caching
- Factory / service-locator / DI patterns
- Logging or audit trails (the action, not the gate)

CATEGORIES:
- rbac: role-based
- abac: attribute-based
- middleware: route/handler-level guards
- business_rule: domain-specific access rules
- ownership: resource-owner checks
- feature_gate: plan/tenant/flag-based
- custom: doesn't fit the above

CONFIDENCE:
- high: unambiguous authz check
- medium: likely authz, reasonable alternative interpretation exists
- low: could be authz, depends on context not shown

OUTPUT: JSON matching the supplied schema. No prose, no markdown fences.
Empty findings array if no authz logic is present.
For escalations: set is_false_positive=true ONLY when you reject the seed flag.
Use line numbers from the supplied snippet."#;

#[derive(Debug, Clone)]
pub struct PromptInputs<'a> {
    pub candidate: &'a Candidate,
    pub structural_finding: Option<&'a Finding>,
}

#[derive(Debug, Clone)]
pub struct RenderedPrompt {
    pub system: String,
    pub user: String,
    pub schema: serde_json::Value,
}

/// Build the per-candidate prompt + schema bundle.
pub fn render(inputs: &PromptInputs) -> RenderedPrompt {
    let frameworks = detect_frameworks(&inputs.candidate.imports, inputs.candidate.language);

    let mut user = String::with_capacity(inputs.candidate.source_snippet.len() + 512);
    user.push_str("File: ");
    user.push_str(&inputs.candidate.file.display().to_string());
    user.push_str("\nLanguage: ");
    user.push_str(&inputs.candidate.language.to_string());
    user.push_str(&format!(
        "\nLines: {}-{}\n",
        inputs.candidate.line_start, inputs.candidate.line_end
    ));

    if let Some(seed) = inputs.structural_finding {
        user.push_str(&format!(
            "\nA structural rule flagged this region as {} ({}). Confirm or reject.\n",
            seed.category, seed.confidence,
        ));
    }

    if !frameworks.is_empty() {
        user.push_str("\nFramework hints:\n");
        for fw in &frameworks {
            user.push_str("- ");
            user.push_str(fw.name);
            user.push_str(": ");
            user.push_str(fw.guidance);
            user.push('\n');
        }
    }

    user.push_str("\n```");
    user.push_str(language_fence(inputs.candidate.language));
    user.push('\n');
    user.push_str(&inputs.candidate.source_snippet);
    if !inputs.candidate.source_snippet.ends_with('\n') {
        user.push('\n');
    }
    user.push_str(
        "```\n\nIdentify all authorization decisions in the snippet. Use line numbers from the snippet.",
    );

    RenderedPrompt {
        system: SYSTEM_PROMPT.to_string(),
        user,
        schema: output_schema(),
    }
}

/// JSON Schema the model must emit. Matches [`SemanticFinding`] field-for-field.
///
/// [`SemanticFinding`]: crate::deep::finding::SemanticFinding
pub fn output_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "line_start":        { "type": "integer", "minimum": 1 },
                        "line_end":          { "type": "integer", "minimum": 1 },
                        "category":          {
                            "type": "string",
                            "enum": ["rbac", "abac", "middleware", "business_rule",
                                     "ownership", "feature_gate", "custom"]
                        },
                        "confidence":        {
                            "type": "string",
                            "enum": ["low", "medium", "high"]
                        },
                        "description":       { "type": "string", "maxLength": 280 },
                        "reasoning":         { "type": "string", "maxLength": 800 },
                        "is_false_positive": { "type": "boolean" }
                    },
                    "required": ["line_start", "line_end", "category", "confidence",
                                 "description", "reasoning", "is_false_positive"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["findings"],
        "additionalProperties": false
    })
}

// -- Framework detection ---------------------------------------------------

struct Framework {
    name: &'static str,
    languages: &'static [Language],
    /// Substrings to look for in the candidate's `imports` slice.
    signatures: &'static [&'static str],
    /// 1-2 sentence guidance injected into the user prompt when detected.
    guidance: &'static str,
}

const FRAMEWORKS: &[Framework] = &[
    Framework {
        name: "Express",
        languages: &[Language::TypeScript, Language::JavaScript],
        signatures: &[
            "from 'express'",
            "from \"express\"",
            "require('express')",
            "require(\"express\")",
        ],
        guidance: "Express middleware in app.use(...) or app.METHOD(..., handler, ...) chains often gates access; flag as middleware. Common: requireAuth, passport.authenticate, role-checking middleware.",
    },
    Framework {
        name: "NestJS",
        languages: &[Language::TypeScript, Language::JavaScript],
        signatures: &["@nestjs/", "from '@nestjs", "from \"@nestjs"],
        guidance: "NestJS @UseGuards(...) decorators are middleware-category. @Roles(...) and @Permissions(...) are typically rbac.",
    },
    Framework {
        name: "Next.js",
        languages: &[Language::TypeScript, Language::JavaScript],
        signatures: &["from 'next/", "from \"next/", "next-auth"],
        guidance: "Next.js middleware.ts or route handlers calling getServerSession are often middleware. NextAuth session checks are middleware/rbac.",
    },
    Framework {
        name: "Django",
        languages: &[Language::Python],
        signatures: &["from django.", "import django"],
        guidance: "Django @login_required, @permission_required, @user_passes_test are middleware. request.user.has_perm(...) and request.user.groups are rbac. django-guardian object-level perms are abac/ownership.",
    },
    Framework {
        name: "Flask",
        languages: &[Language::Python],
        signatures: &["from flask", "import flask"],
        guidance: "Flask custom decorators using functools.wraps + flask.g.user are middleware. flask-login's @login_required is middleware.",
    },
    Framework {
        name: "FastAPI",
        languages: &[Language::Python],
        signatures: &["from fastapi", "import fastapi"],
        guidance: "FastAPI Depends(...) on auth-y functions is middleware. OAuth2PasswordBearer + Depends is rbac/middleware.",
    },
    Framework {
        name: "Spring Security",
        languages: &[Language::Java, Language::Kotlin],
        signatures: &[
            "org.springframework.security",
            "import org.springframework.security",
        ],
        guidance: "Spring Security @PreAuthorize / @PostAuthorize / @Secured / @RolesAllowed are rbac. SecurityContextHolder.getContext().getAuthentication() reads current user. SecurityFilterChain / WebSecurityConfigurerAdapter are middleware.",
    },
    Framework {
        name: "Rails",
        languages: &[Language::Ruby],
        signatures: &[
            "ApplicationController",
            "ActionController",
            "Rails.application",
            "before_action",
        ],
        guidance: "Rails before_action :auth_method is middleware. Pundit's authorize @resource and CanCanCan's can?/cannot? are rbac/abac. current_user is the universal user accessor.",
    },
    Framework {
        name: "Gin",
        languages: &[Language::Go],
        signatures: &["github.com/gin-gonic/gin"],
        guidance: "Gin gin.HandlerFunc returned from auth-y constructors are middleware. c.Set(\"user\", ...) followed by c.MustGet is the user-flow.",
    },
    Framework {
        name: "Echo",
        languages: &[Language::Go],
        signatures: &["github.com/labstack/echo", "labstack/echo"],
        guidance: "Echo middleware.JWT and middleware.BasicAuth are middleware. Custom MiddlewareFunc with role checks is rbac middleware.",
    },
    Framework {
        name: "ASP.NET Core",
        languages: &[Language::CSharp],
        signatures: &["Microsoft.AspNetCore", "using Microsoft.AspNetCore"],
        guidance: "[Authorize] / [Authorize(Roles=\"...\")] / [Authorize(Policy=\"...\")] attributes are rbac. User.IsInRole(...) and ClaimsPrincipal checks are rbac/abac. AuthorizationHandler<T> is custom.",
    },
    Framework {
        name: "Laravel",
        languages: &[Language::Php],
        signatures: &["Illuminate\\", "use Illuminate"],
        guidance: "Laravel middleware in routes (auth, can:, role:) is middleware. Gate::define and Gate::allows are abac. $user->can(...) is rbac/abac.",
    },
];

fn detect_frameworks(imports: &[String], language: Language) -> Vec<&'static Framework> {
    let combined = imports.join("\n");
    FRAMEWORKS
        .iter()
        .filter(|fw| fw.languages.contains(&language))
        .filter(|fw| fw.signatures.iter().any(|s| combined.contains(s)))
        .collect()
}

fn language_fence(lang: Language) -> &'static str {
    match lang {
        Language::TypeScript => "typescript",
        Language::JavaScript => "javascript",
        Language::Java => "java",
        Language::Python => "python",
        Language::Go => "go",
        Language::CSharp => "csharp",
        Language::Kotlin => "kotlin",
        Language::Ruby => "ruby",
        Language::Php => "php",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deep::candidate::{Candidate, CandidateKind};
    use crate::types::{AuthCategory, Confidence, ScanPass};
    use std::path::PathBuf;

    fn candidate_with_imports(language: Language, imports: Vec<String>) -> Candidate {
        Candidate {
            kind: CandidateKind::ColdRegion,
            file: PathBuf::from("src/auth.ts"),
            language,
            line_start: 10,
            line_end: 25,
            source_snippet: "function isAdmin() { return user.role === 'admin'; }".into(),
            imports,
            original_finding_id: None,
            seed_category: None,
        }
    }

    fn finding_seed() -> Finding {
        Finding {
            id: "structural-1".into(),
            file: PathBuf::from("src/auth.ts"),
            line_start: 10,
            line_end: 25,
            code_snippet: String::new(),
            language: Language::TypeScript,
            category: AuthCategory::Custom,
            confidence: Confidence::Low,
            description: "matched custom rule".into(),
            pattern_rule: Some("ts-custom-1".into()),
            rego_stub: None,
            pass: ScanPass::Structural,
        }
    }

    #[test]
    fn system_prompt_is_non_empty_and_concise() {
        assert!(!SYSTEM_PROMPT.is_empty());
        // Token-budget sanity: keep system prompt under ~2k chars (~500 tokens).
        // Local 7B-14B models need room for the user prompt + framework hints.
        assert!(SYSTEM_PROMPT.len() < 2_000, "SYSTEM_PROMPT is too verbose");
    }

    #[test]
    fn system_prompt_lists_all_seven_categories() {
        for cat in [
            "rbac",
            "abac",
            "middleware",
            "business_rule",
            "ownership",
            "feature_gate",
            "custom",
        ] {
            assert!(
                SYSTEM_PROMPT.contains(cat),
                "SYSTEM_PROMPT missing category: {cat}"
            );
        }
    }

    #[test]
    fn output_schema_has_required_shape() {
        let schema = output_schema();
        assert_eq!(schema["type"], "object");
        assert_eq!(schema["required"][0], "findings");
        let item_required = &schema["properties"]["findings"]["items"]["required"];
        assert!(
            item_required
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("line_start".into()))
        );
        assert!(
            item_required
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("is_false_positive".into()))
        );
    }

    #[test]
    fn output_schema_categories_match_authcategory_enum() {
        let schema = output_schema();
        let categories =
            schema["properties"]["findings"]["items"]["properties"]["category"]["enum"]
                .as_array()
                .unwrap();
        let names: Vec<&str> = categories.iter().filter_map(|v| v.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "rbac",
                "abac",
                "middleware",
                "business_rule",
                "ownership",
                "feature_gate",
                "custom"
            ]
        );
    }

    #[test]
    fn render_includes_file_language_and_lines() {
        let cand = candidate_with_imports(Language::TypeScript, vec![]);
        let inputs = PromptInputs {
            candidate: &cand,
            structural_finding: None,
        };
        let rendered = render(&inputs);
        assert!(rendered.user.contains("File: src/auth.ts"));
        assert!(rendered.user.contains("Language: typescript"));
        assert!(rendered.user.contains("Lines: 10-25"));
        assert!(rendered.user.contains("```typescript"));
    }

    #[test]
    fn render_includes_seed_when_escalation() {
        let cand = candidate_with_imports(Language::TypeScript, vec![]);
        let seed = finding_seed();
        let inputs = PromptInputs {
            candidate: &cand,
            structural_finding: Some(&seed),
        };
        let rendered = render(&inputs);
        assert!(rendered.user.contains("structural rule flagged"));
        assert!(rendered.user.contains("Custom"));
        assert!(rendered.user.contains("low"));
    }

    #[test]
    fn render_omits_framework_section_when_none_detected() {
        let cand =
            candidate_with_imports(Language::TypeScript, vec!["// no framework here".into()]);
        let inputs = PromptInputs {
            candidate: &cand,
            structural_finding: None,
        };
        let rendered = render(&inputs);
        assert!(!rendered.user.contains("Framework hints:"));
    }

    #[test]
    fn render_includes_framework_hints_when_detected() {
        let cand = candidate_with_imports(
            Language::TypeScript,
            vec!["import express from 'express';".into()],
        );
        let inputs = PromptInputs {
            candidate: &cand,
            structural_finding: None,
        };
        let rendered = render(&inputs);
        assert!(rendered.user.contains("Framework hints:"));
        assert!(rendered.user.contains("Express"));
    }

    #[test]
    fn detect_frameworks_respects_language() {
        // "from django" is a substring of arbitrary TS code; should NOT match in TS.
        let imports = vec!["// from django.contrib.auth import login".into()];
        let py = detect_frameworks(&imports, Language::Python);
        let ts = detect_frameworks(&imports, Language::TypeScript);
        assert!(py.iter().any(|fw| fw.name == "Django"));
        assert!(!ts.iter().any(|fw| fw.name == "Django"));
    }

    #[test]
    fn detect_frameworks_finds_spring_in_java() {
        let imports =
            vec!["import org.springframework.security.access.prepost.PreAuthorize;".into()];
        let found = detect_frameworks(&imports, Language::Java);
        assert!(found.iter().any(|fw| fw.name == "Spring Security"));
    }

    #[test]
    fn detect_frameworks_finds_django_via_either_signature() {
        for sig in ["from django.contrib.auth import login", "import django"] {
            let imports = vec![sig.into()];
            let found = detect_frameworks(&imports, Language::Python);
            assert!(
                found.iter().any(|fw| fw.name == "Django"),
                "missed Django for: {sig}"
            );
        }
    }

    #[test]
    fn detect_frameworks_finds_multiple() {
        let imports = vec![
            "import express from 'express';".into(),
            "import { Module } from '@nestjs/common';".into(),
        ];
        let found = detect_frameworks(&imports, Language::TypeScript);
        let names: Vec<&str> = found.iter().map(|fw| fw.name).collect();
        assert!(names.contains(&"Express"));
        assert!(names.contains(&"NestJS"));
    }

    #[test]
    fn language_fence_covers_all_languages() {
        for lang in [
            Language::TypeScript,
            Language::JavaScript,
            Language::Java,
            Language::Python,
            Language::Go,
            Language::CSharp,
            Language::Kotlin,
            Language::Ruby,
            Language::Php,
        ] {
            let fence = language_fence(lang);
            assert!(!fence.is_empty(), "language_fence empty for {lang:?}");
        }
    }
}
