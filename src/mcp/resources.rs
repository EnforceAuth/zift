//! MCP resource implementations.
//!
//! Resources are read-only documents identified by URI. We expose four kinds:
//!
//! - `rule://<rule_id>` — the full TOML-derived rule definition + docs
//! - `category://<auth_category>` — definition + canonical examples
//! - `prompt://system` — verbatim [`crate::deep::prompt::SYSTEM_PROMPT`]
//! - `prompt://schema` — verbatim [`crate::deep::prompt::output_schema`]
//!
//! Resources let an MCP-attached agent learn *how* Zift thinks about authz
//! by reading the same artifacts the deep-scan path uses.

use serde_json::json;

use crate::deep::prompt::{SYSTEM_PROMPT, output_schema};
use crate::mcp::protocol::{ResourceContent, ResourceDescriptor, ResourcesListResult};
use crate::mcp::server::ServerContext;
use crate::rules::PatternRule;
use crate::types::AuthCategory;

/// Enumerate every resource the server exposes. Order: prompts first
/// (singletons), then categories (taxonomy), then per-rule entries.
pub fn list_resources(ctx: &ServerContext) -> ResourcesListResult {
    let mut resources = vec![
        ResourceDescriptor {
            uri: "prompt://system".to_string(),
            name: "Deep-scan system prompt".to_string(),
            description: "The terse, token-economical authz definition + category \
                          taxonomy + output contract sent to every deep-scan request. \
                          Read this to understand how Zift frames the authz problem."
                .to_string(),
            mime_type: "text/plain",
        },
        ResourceDescriptor {
            uri: "prompt://schema".to_string(),
            name: "Deep-scan output schema".to_string(),
            description: "The JSON Schema every deep-scan response must validate \
                          against — the canonical SemanticFinding shape."
                .to_string(),
            mime_type: "application/json",
        },
    ];
    for category in ALL_CATEGORIES {
        resources.push(ResourceDescriptor {
            uri: format!("category://{}", category.slug()),
            name: format!("AuthCategory: {category}"),
            description: category_description(*category).to_string(),
            mime_type: "application/json",
        });
    }
    for rule in &ctx.rules {
        resources.push(ResourceDescriptor {
            uri: format!("rule://{}", rule.id),
            name: format!("Rule: {}", rule.id),
            description: rule.description.clone(),
            mime_type: "application/json",
        });
    }
    ResourcesListResult { resources }
}

/// Resolve a URI to its content. Returns `None` for unknown URIs (handled
/// at the dispatch layer as a JSON-RPC InvalidParams error).
pub fn read_resource(ctx: &ServerContext, uri: &str) -> Option<ResourceContent> {
    if uri == "prompt://system" {
        return Some(ResourceContent {
            uri: uri.to_string(),
            mime_type: "text/plain",
            text: SYSTEM_PROMPT.to_string(),
        });
    }
    if uri == "prompt://schema" {
        return Some(ResourceContent {
            uri: uri.to_string(),
            mime_type: "application/json",
            text: serde_json::to_string_pretty(&output_schema())
                .expect("output_schema is always serializable"),
        });
    }
    if let Some(slug) = uri.strip_prefix("category://") {
        let cat = category_from_slug(slug)?;
        let body = json!({
            "category": cat.slug(),
            "display_name": cat.to_string(),
            "description": category_description(cat),
            "examples": category_examples(cat),
        });
        return Some(ResourceContent {
            uri: uri.to_string(),
            mime_type: "application/json",
            text: serde_json::to_string_pretty(&body)
                .expect("category body is always serializable"),
        });
    }
    if let Some(rule_id) = uri.strip_prefix("rule://") {
        let rule = ctx.rules.iter().find(|r| r.id == rule_id)?;
        return Some(ResourceContent {
            uri: uri.to_string(),
            mime_type: "application/json",
            text: serde_json::to_string_pretty(&rule_to_json(rule))
                .expect("rule_to_json output is always serializable"),
        });
    }
    None
}

fn rule_to_json(rule: &PatternRule) -> serde_json::Value {
    json!({
        "id": rule.id,
        "languages": rule.languages,
        "category": rule.category,
        "confidence": rule.confidence,
        "description": rule.description,
        "query": rule.query_source,
        "rego_template": rule.rego_template,
    })
}

const ALL_CATEGORIES: &[AuthCategory] = &[
    AuthCategory::Rbac,
    AuthCategory::Abac,
    AuthCategory::Middleware,
    AuthCategory::BusinessRule,
    AuthCategory::Ownership,
    AuthCategory::FeatureGate,
    AuthCategory::Custom,
];

fn category_from_slug(slug: &str) -> Option<AuthCategory> {
    match slug {
        "rbac" => Some(AuthCategory::Rbac),
        "abac" => Some(AuthCategory::Abac),
        "middleware" => Some(AuthCategory::Middleware),
        "business_rule" => Some(AuthCategory::BusinessRule),
        "ownership" => Some(AuthCategory::Ownership),
        "feature_gate" => Some(AuthCategory::FeatureGate),
        "custom" => Some(AuthCategory::Custom),
        _ => None,
    }
}

fn category_description(c: AuthCategory) -> &'static str {
    match c {
        AuthCategory::Rbac => {
            "Role-based access control. The decision pivots on a \
                              role/permission/group attribute the user holds."
        }
        AuthCategory::Abac => {
            "Attribute-based access control. The decision pivots \
                              on subject/resource/environment attributes (user.tenant, \
                              resource.classification, request.time)."
        }
        AuthCategory::Middleware => {
            "Route-level guards or handler decorators that \
                                    short-circuit unauthenticated/unauthorized requests \
                                    before they reach business logic."
        }
        AuthCategory::BusinessRule => {
            "Domain-specific access rules that don't fit the \
                                      cleaner taxonomies — e.g. 'only the original author \
                                      can edit during the first 24 hours'."
        }
        AuthCategory::Ownership => {
            "Resource-owner checks: subject is allowed because \
                                   subject.id == resource.owner_id (or via a transitive \
                                   membership relation)."
        }
        AuthCategory::FeatureGate => {
            "Plan-, tenant-, or feature-flag-based gates. \
                                     Often misclassified as RBAC but distinguished by \
                                     pivoting on subscription/feature state, not roles."
        }
        AuthCategory::Custom => {
            "A pattern that doesn't fit any of the above. The \
                                deep-scan model is asked to be conservative when \
                                assigning this category."
        }
    }
}

fn category_examples(c: AuthCategory) -> Vec<&'static str> {
    match c {
        AuthCategory::Rbac => vec![
            "if user.role == 'admin' { ... }",
            "@PreAuthorize(\"hasRole('ADMIN')\")",
            "user.has_perm('orders:delete')",
        ],
        AuthCategory::Abac => vec![
            "if user.tenant == resource.tenant { ... }",
            "if request.region in user.allowed_regions { ... }",
        ],
        AuthCategory::Middleware => vec![
            "app.use('/admin', requireAuth)",
            "@UseGuards(AuthGuard)",
            "before_action :authenticate!",
        ],
        AuthCategory::BusinessRule => vec![
            "if order.created_at > now() - 24h && order.author_id == user.id { allow }",
            "if account.balance > 0 || user.has_credit_extension { allow }",
        ],
        AuthCategory::Ownership => vec![
            "if document.owner_id == user.id { ... }",
            "policy.allow if input.resource.owner == input.user.id",
        ],
        AuthCategory::FeatureGate => vec![
            "if user.plan in {'pro', 'enterprise'} { allow }",
            "if !flags.is_enabled('beta-feature', user) { return 403 }",
        ],
        AuthCategory::Custom => vec!["// Bespoke check: reach out to the model to classify"],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ZiftConfig;
    use crate::rules::load_rules;
    use std::path::PathBuf;

    fn test_ctx() -> ServerContext {
        let config = ZiftConfig::default();
        let rules = load_rules(None, &config).unwrap();
        ServerContext {
            scan_root: PathBuf::from("."),
            rules,
            config,
        }
    }

    #[test]
    fn list_resources_includes_required_singletons_and_taxonomies() {
        let ctx = test_ctx();
        let result = list_resources(&ctx);
        let uris: Vec<&str> = result.resources.iter().map(|r| r.uri.as_str()).collect();
        assert!(uris.contains(&"prompt://system"));
        assert!(uris.contains(&"prompt://schema"));
        // Every category exposed.
        for cat_slug in [
            "rbac",
            "abac",
            "middleware",
            "business_rule",
            "ownership",
            "feature_gate",
            "custom",
        ] {
            assert!(
                uris.iter().any(|u| *u == format!("category://{cat_slug}")),
                "missing category://{cat_slug}",
            );
        }
        // At least one rule.
        assert!(uris.iter().any(|u| u.starts_with("rule://")));
    }

    #[test]
    fn read_prompt_system_returns_canonical_constant() {
        let ctx = test_ctx();
        let r = read_resource(&ctx, "prompt://system").unwrap();
        assert_eq!(r.text, SYSTEM_PROMPT);
        assert_eq!(r.mime_type, "text/plain");
    }

    #[test]
    fn read_prompt_schema_returns_canonical_schema() {
        let ctx = test_ctx();
        let r = read_resource(&ctx, "prompt://schema").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&r.text).unwrap();
        assert_eq!(parsed, output_schema());
    }

    #[test]
    fn read_category_returns_definition_and_examples() {
        let ctx = test_ctx();
        let r = read_resource(&ctx, "category://rbac").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&r.text).unwrap();
        assert_eq!(parsed["category"], "rbac");
        assert!(!parsed["examples"].as_array().unwrap().is_empty());
    }

    #[test]
    fn read_rule_returns_definition() {
        let ctx = test_ctx();
        let r = read_resource(&ctx, "rule://ts-role-check-conditional").unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&r.text).unwrap();
        assert_eq!(parsed["id"], "ts-role-check-conditional");
        assert!(parsed["query"].is_string());
    }

    #[test]
    fn read_unknown_uri_returns_none() {
        let ctx = test_ctx();
        assert!(read_resource(&ctx, "rule://nonexistent").is_none());
        assert!(read_resource(&ctx, "category://nonexistent").is_none());
        assert!(read_resource(&ctx, "garbage://uri").is_none());
    }
}
