use std::collections::HashSet;

use streaming_iterator::StreamingIterator;

use crate::types::Language;

/// Path substrings that indicate a policy/OPA enforcement module.
const POLICY_INDICATORS: &[&str] = &[
    "authz",
    "opa",
    "policy",
    "rego",
    "enforce",
    "open-policy-agent",
];

/// Check if an import source path indicates a policy/OPA module.
fn is_policy_path(source: &str) -> bool {
    let lower = source.to_lowercase();
    POLICY_INDICATORS.iter().any(|ind| lower.contains(ind))
}

/// Tree-sitter query for named imports: `import { foo } from 'bar'`
const TS_NAMED_IMPORT_QUERY: &str = r#"
(import_statement
  (import_clause
    (named_imports
      (import_specifier
        name: (identifier) @name)))
  source: (string) @source)
"#;

/// Tree-sitter query for default imports: `import foo from 'bar'`
const TS_DEFAULT_IMPORT_QUERY: &str = r#"
(import_statement
  (import_clause
    (identifier) @name)
  source: (string) @source)
"#;

/// Tree-sitter query for namespace imports: `import * as foo from 'bar'`
const TS_NAMESPACE_IMPORT_QUERY: &str = r#"
(import_statement
  (import_clause
    (namespace_import
      (identifier) @name))
  source: (string) @source)
"#;

/// Tree-sitter query for CommonJS `require()`: `const foo = require('bar')`
const TS_REQUIRE_QUERY: &str = r#"
((variable_declarator
   name: (identifier) @name
   value: (call_expression
     function: (identifier) @_fn
     arguments: (arguments
       (string) @source)))
 (#eq? @_fn "require"))
"#;

/// Tree-sitter query for destructured CommonJS require:
/// `const { foo } = require('bar')` and `const { foo: aliased } = require('bar')`.
/// Captures the binding actually used in code (the alias when renamed).
const TS_REQUIRE_DESTRUCTURED_QUERY: &str = r#"
((variable_declarator
   name: (object_pattern
     [
       (shorthand_property_identifier_pattern) @name
       (pair_pattern value: (identifier) @name)
     ])
   value: (call_expression
     function: (identifier) @_fn
     arguments: (arguments
       (string) @source)))
 (#eq? @_fn "require"))
"#;

/// Tree-sitter query for TypeScript `import = require()` syntax:
/// `import foo = require('bar')`. TypeScript-specific.
const TS_IMPORT_REQUIRE_QUERY: &str = r#"
(import_statement
  (import_require_clause
    (identifier) @name
    source: (string) @source))
"#;

/// Extract the set of function/identifier names imported from policy-related modules.
pub fn find_policy_imports(
    tree: &tree_sitter::Tree,
    source: &[u8],
    language: Language,
) -> HashSet<String> {
    let mut policy_names = HashSet::new();

    // Only TypeScript/JavaScript have import statements we can parse
    if !matches!(language, Language::TypeScript | Language::JavaScript) {
        return policy_names;
    }

    let ts_lang = tree.language();

    for query_src in [
        TS_NAMED_IMPORT_QUERY,
        TS_DEFAULT_IMPORT_QUERY,
        TS_NAMESPACE_IMPORT_QUERY,
        TS_REQUIRE_QUERY,
        TS_REQUIRE_DESTRUCTURED_QUERY,
        TS_IMPORT_REQUIRE_QUERY,
    ] {
        let Ok(query) = tree_sitter::Query::new(&ts_lang, query_src) else {
            continue;
        };

        let capture_names: Vec<String> = query
            .capture_names()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let name_idx = capture_names.iter().position(|n| n == "name");
        let source_idx = capture_names.iter().position(|n| n == "source");

        let (Some(name_idx), Some(source_idx)) = (name_idx, source_idx) else {
            continue;
        };

        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);

        while let Some(m) = matches.next() {
            let mut import_name = None;
            let mut import_source = None;

            for capture in m.captures {
                if capture.index == name_idx as u32 {
                    import_name = capture.node.utf8_text(source).ok();
                }
                if capture.index == source_idx as u32 {
                    import_source = capture.node.utf8_text(source).ok();
                }
            }

            if let (Some(name), Some(src)) = (import_name, import_source)
                && is_policy_path(src)
            {
                policy_names.insert(name.to_string());
            }
        }
    }

    policy_names
}

/// Check if a finding's code snippet references any of the policy-imported names.
pub fn is_enforcement_point(code_snippet: &str, policy_imports: &HashSet<String>) -> bool {
    policy_imports.iter().any(|name| {
        let pattern = format!(r"\b{}\b", regex::escape(name));
        regex::Regex::new(&pattern)
            .map(|re| re.is_match(code_snippet))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::parser;

    fn parse_ts(source: &str) -> tree_sitter::Tree {
        let mut ts_parser = tree_sitter::Parser::new();
        parser::parse_source(
            &mut ts_parser,
            source.as_bytes(),
            Language::TypeScript,
            false,
        )
        .unwrap()
    }

    #[test]
    fn detects_named_policy_import() {
        let source = r#"
import { authorize, authorizeWorkload } from '../../lib/authz';
import { Router } from 'express';
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authorize"));
        assert!(imports.contains("authorizeWorkload"));
        assert!(!imports.contains("Router"));
    }

    #[test]
    fn detects_default_policy_import() {
        let source = r#"
import opaClient from '@company/opa-client';
import express from 'express';
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("opaClient"));
        assert!(!imports.contains("express"));
    }

    #[test]
    fn no_policy_imports() {
        let source = r#"
import { Router } from 'express';
import { validateInput } from './utils';
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.is_empty());
    }

    #[test]
    fn enforcement_point_check() {
        let mut policy_imports = HashSet::new();
        policy_imports.insert("authorize".to_string());

        assert!(is_enforcement_point(
            r#"authorize(user, "configs:read", resource)"#,
            &policy_imports,
        ));
        assert!(!is_enforcement_point(
            r#"if (user.role === "admin")"#,
            &policy_imports,
        ));
    }

    #[test]
    fn case_sensitive_path_matching() {
        let source = r#"import { evaluate } from '../policy-engine';"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("evaluate"));
    }

    #[test]
    fn detects_namespace_policy_import() {
        let source = r#"
import * as authz from "../policy";
import * as utils from "./utils";
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authz"));
        assert!(!imports.contains("utils"));
    }

    #[test]
    fn detects_require_policy_import() {
        let source = r#"
const authz = require("../policy");
const express = require("express");
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authz"));
        assert!(!imports.contains("express"));
    }

    #[test]
    fn enforcement_point_check_namespace_import() {
        let source = r#"
import * as authz from "../policy";
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(is_enforcement_point(
            r#"authz.authorize(user, "configs:read", resource)"#,
            &imports,
        ));
        assert!(!is_enforcement_point(
            r#"if (user.role === "admin")"#,
            &imports,
        ));
    }

    #[test]
    fn detects_destructured_require_policy_import() {
        let source = r#"
const { authorize, can } = require("../policy");
const { Router } = require("express");
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authorize"));
        assert!(imports.contains("can"));
        assert!(!imports.contains("Router"));
    }

    #[test]
    fn detects_aliased_destructured_require_policy_import() {
        let source = r#"
const { authorize: auth } = require("../policy");
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        // We capture the binding actually used in code (the alias), not the original name.
        assert!(imports.contains("auth"));
        assert!(!imports.contains("authorize"));
    }

    #[test]
    fn detects_require_with_let_and_var() {
        let source = r#"
let authzLet = require("../policy");
var authzVar = require("../policy");
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authzLet"));
        assert!(imports.contains("authzVar"));
    }

    #[test]
    fn detects_ts_import_require_syntax() {
        let source = r#"
import authz = require("../policy");
import express = require("express");
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authz"));
        assert!(!imports.contains("express"));
    }
}
