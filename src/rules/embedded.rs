use crate::error::Result;

use super::{parse_rule, PatternRule};

const EMBEDDED_RULES: &[(&str, &str)] = &[
    (
        "role-check-conditional",
        include_str!("../../rules/typescript/role-check-conditional.toml"),
    ),
    (
        "role-includes-check",
        include_str!("../../rules/typescript/role-includes-check.toml"),
    ),
    (
        "has-role-call",
        include_str!("../../rules/typescript/has-role-call.toml"),
    ),
    (
        "express-auth-middleware",
        include_str!("../../rules/typescript/express-auth-middleware.toml"),
    ),
    (
        "express-route-middleware",
        include_str!("../../rules/typescript/express-route-middleware.toml"),
    ),
    (
        "nestjs-use-guards",
        include_str!("../../rules/typescript/nestjs-use-guards.toml"),
    ),
    (
        "nestjs-roles-decorator",
        include_str!("../../rules/typescript/nestjs-roles-decorator.toml"),
    ),
    (
        "permission-check-call",
        include_str!("../../rules/typescript/permission-check-call.toml"),
    ),
    (
        "session-auth-check",
        include_str!("../../rules/typescript/session-auth-check.toml"),
    ),
    (
        "jwt-token-check",
        include_str!("../../rules/typescript/jwt-token-check.toml"),
    ),
    (
        "ownership-check",
        include_str!("../../rules/typescript/ownership-check.toml"),
    ),
    (
        "feature-gate-check",
        include_str!("../../rules/typescript/feature-gate-check.toml"),
    ),
];

pub fn load_embedded_rules() -> Result<Vec<PatternRule>> {
    let mut rules = Vec::with_capacity(EMBEDDED_RULES.len());
    for (name, content) in EMBEDDED_RULES {
        rules.push(parse_rule(content, name)?);
    }
    Ok(rules)
}
