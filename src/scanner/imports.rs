use std::collections::HashSet;

use streaming_iterator::StreamingIterator;

use crate::types::Language;

/// Path substrings that indicate a policy/OPA enforcement module.
const POLICY_INDICATORS: &[&str] = &[
    "authz",
    "opa",
    "policy",
    "rego",
    "cedar",
    "verifiedpermissions",
    "verified-permissions",
    "enforce",
    "open-policy-agent",
];

/// Check if an import source path indicates a policy/OPA module.
fn is_policy_path(source: &str) -> bool {
    let lower = source.to_lowercase();
    POLICY_INDICATORS.iter().any(|ind| lower.contains(ind))
}

/// Tree-sitter query for named imports: `import { foo } from 'bar'`
/// and aliased: `import { foo as bar } from 'baz'`.
/// Captures the binding actually used in code (the alias when renamed,
/// otherwise the original name).
const TS_NAMED_IMPORT_QUERY: &str = r#"
(import_statement
  (import_clause
    (named_imports
      [
        (import_specifier
          alias: (identifier) @name)
        (import_specifier
          !alias
          name: (identifier) @name)
      ]))
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

/// Extract the set of function/identifier names imported from policy-related
/// modules — plus any local identifiers those imports flow into via simple
/// assignment within the same file (one-hop intra-file data flow).
///
/// The motivation is real-world DI patterns. OPA/Cedar consumers commonly
/// stash a policy primitive on a struct field or local variable and call
/// it indirectly, so a textual `\bauthz\b` regex over the call site sees
/// nothing. The OCP corpus repo is a textbook case:
///
/// ```text
/// import "github.com/open-policy-agent/opa-control-plane/internal/authz"
/// // ...
/// db := &Database{accessFactory: authz.NewAccess}
/// // 40+ call sites later, in a different function:
/// d.accessFactory().WithPrincipal(p).WithResource(r)...
/// ```
///
/// Without propagation the bindings are `{authz}` and the call-site snippet
/// `d.accessFactory()...` matches nothing. With propagation we see the
/// `accessFactory: authz.NewAccess` edge and add `accessFactory` to the
/// binding set, so the chain matches via `\baccessFactory\b`.
///
/// Scope is deliberately tight:
/// - **One file at a time.** Cross-file flow (a binding exported from file A
///   used in file B) is out of scope; that's tracked separately as a future
///   improvement and would require a project-wide symbol table.
/// - **Syntactic only.** No type resolution, no callgraph. We just look at
///   assignment-shaped nodes and propagate iteratively until fixed point.
pub fn find_policy_imports(
    tree: &tree_sitter::Tree,
    source: &[u8],
    language: Language,
) -> HashSet<String> {
    let mut bindings = match language {
        Language::TypeScript | Language::JavaScript => find_ts_policy_imports(tree, source),
        Language::Go => find_go_policy_imports(tree, source),
        Language::Python => find_py_policy_imports(tree, source),
        Language::Java => find_java_policy_imports(tree, source),
        Language::CSharp => find_csharp_policy_imports(tree, source),
        // Other languages: no import detection yet.
        _ => HashSet::new(),
    };

    // No initial bindings → no propagation can find anything; skip the walk.
    if bindings.is_empty() {
        return bindings;
    }

    let edges = extract_propagation_edges(tree, source, language);
    propagate_to_fixed_point(&mut bindings, &edges);
    bindings
}

/// Iteratively grow `bindings` by adding any edge LHS whose RHS textually
/// mentions a known binding. Stops when no edge changed the set.
///
/// Performance note: an earlier draft called `is_enforcement_point` per
/// edge per iteration, which recompiles one regex *per binding* on every
/// call. On the OCP corpus repo that turned a 0.3s scan into 9.5s. We now
/// compile a single combined `\b(name1|name2|...)\b` regex per iteration —
/// rebuilt only when the binding set actually grows — which restores the
/// scan time to within a fraction of a second of the no-propagation path.
fn propagate_to_fixed_point(bindings: &mut HashSet<String>, edges: &[(String, String)]) {
    loop {
        let Some(re) = build_combined_binding_regex(bindings) else {
            return;
        };
        let mut grew = false;
        for (lhs, rhs) in edges {
            if !bindings.contains(lhs) && re.is_match(rhs) {
                bindings.insert(lhs.clone());
                grew = true;
            }
        }
        if !grew {
            return;
        }
    }
}

/// Compile a single `\b(a|b|c)\b` regex matching any binding name. Returns
/// `None` if there are no bindings (caller should short-circuit) or if the
/// alternation somehow fails to compile (defensive — `regex::escape` makes
/// every alternative a literal so this shouldn't happen in practice).
fn build_combined_binding_regex(bindings: &HashSet<String>) -> Option<regex::Regex> {
    if bindings.is_empty() {
        return None;
    }
    // Sorting is a cheap way to keep the compiled pattern stable for
    // identical sets — useful if we ever want to memoize across calls,
    // and harmless otherwise.
    let mut alts: Vec<String> = bindings.iter().map(|s| regex::escape(s)).collect();
    alts.sort();
    let pattern = format!(r"\b(?:{})\b", alts.join("|"));
    regex::Regex::new(&pattern).ok()
}

fn find_ts_policy_imports(tree: &tree_sitter::Tree, source: &[u8]) -> HashSet<String> {
    let mut policy_names = HashSet::new();
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

/// Walk every named descendant of `root` in pre-order. Avoids the borrow-checker
/// pain of recursive `TreeCursor` use by doing iterative traversal.
fn iter_named_descendants<F: FnMut(tree_sitter::Node)>(root: tree_sitter::Node, mut visit: F) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        visit(node);
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

/// Strip surrounding `"` or `` ` `` quotes from a Go-style string literal.
fn strip_go_string_quotes(s: &str) -> &str {
    let s = s.trim();
    s.strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .or_else(|| s.strip_prefix('`').and_then(|x| x.strip_suffix('`')))
        .unwrap_or(s)
}

/// Last `/`-separated segment of a Go import path. By Go convention, the
/// package name defaults to this when no alias is given. Real packages can
/// override this with `package foo`, but Zift only sees consumer source —
/// the basename heuristic matches >99% of real imports and only loses on
/// e.g. `gopkg.in/yaml.v3` (basename `yaml.v3`, package `yaml`), which
/// don't show up in policy-engine paths in practice.
fn go_path_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn find_go_policy_imports(tree: &tree_sitter::Tree, source: &[u8]) -> HashSet<String> {
    let mut policy_names = HashSet::new();

    iter_named_descendants(tree.root_node(), |node| {
        if node.kind() != "import_spec" {
            return;
        }
        let Some(path_node) = node.child_by_field_name("path") else {
            return;
        };
        let Ok(raw_path) = path_node.utf8_text(source) else {
            return;
        };
        let path = strip_go_string_quotes(raw_path);
        if !is_policy_path(path) {
            return;
        }

        // Optional alias: package_identifier (use it), dot/blank (skip).
        if let Some(name_node) = node.child_by_field_name("name") {
            // `. "..."` dot-imports merge names into the file scope; we'd
            // need the package's exported identifiers to capture bindings.
            // `_ "..."` is side-effect-only, no binding. Skip both.
            if name_node.kind() == "package_identifier"
                && let Ok(alias) = name_node.utf8_text(source)
            {
                policy_names.insert(alias.to_string());
            }
        } else {
            // No alias → binding is the path basename (Go's default package name).
            policy_names.insert(go_path_basename(path).to_string());
        }
    });

    policy_names
}

fn find_py_policy_imports(tree: &tree_sitter::Tree, source: &[u8]) -> HashSet<String> {
    let mut policy_names = HashSet::new();

    iter_named_descendants(tree.root_node(), |node| {
        match node.kind() {
            // `import x`, `import x.y`, `import x as y`, `import x.y as z`.
            "import_statement" => {
                let mut cursor = node.walk();
                for name_node in node.children_by_field_name("name", &mut cursor) {
                    process_py_import_name(name_node, source, &mut policy_names);
                }
            }
            // `from <module> import a, b as c, ...` (or `from . import ...`).
            // We deliberately don't try to handle `from foo import *` —
            // wildcard expansion would require resolving the module.
            "import_from_statement" => {
                let Some(module_node) = node.child_by_field_name("module_name") else {
                    return;
                };
                let Ok(module_text) = module_node.utf8_text(source) else {
                    return;
                };
                if !is_policy_path(module_text) {
                    return;
                }

                let mut cursor = node.walk();
                for name_node in node.children_by_field_name("name", &mut cursor) {
                    let binding = match name_node.kind() {
                        "aliased_import" => name_node
                            .child_by_field_name("alias")
                            .and_then(|n| n.utf8_text(source).ok()),
                        "dotted_name" => name_node.utf8_text(source).ok(),
                        _ => None,
                    };
                    if let Some(b) = binding {
                        // For `from x import a.b` the dotted_name is rare but
                        // legal-looking; the binding actually used in code is
                        // the first segment.
                        let head = b.split('.').next().unwrap_or(b);
                        policy_names.insert(head.to_string());
                    }
                }
            }
            _ => {}
        }
    });

    policy_names
}

fn process_py_import_name(node: tree_sitter::Node, source: &[u8], out: &mut HashSet<String>) {
    match node.kind() {
        "aliased_import" => {
            let Some(name_node) = node.child_by_field_name("name") else {
                return;
            };
            let Ok(module_text) = name_node.utf8_text(source) else {
                return;
            };
            if !is_policy_path(module_text) {
                return;
            }
            if let Some(alias_node) = node.child_by_field_name("alias")
                && let Ok(alias) = alias_node.utf8_text(source)
            {
                out.insert(alias.to_string());
            }
        }
        "dotted_name" => {
            let Ok(text) = node.utf8_text(source) else {
                return;
            };
            if !is_policy_path(text) {
                return;
            }
            // `import foo.bar.baz` — usage is `foo.bar.baz.x()`, binding is `foo`.
            if let Some(head) = text.split('.').next() {
                out.insert(head.to_string());
            }
        }
        _ => {}
    }
}

fn find_java_policy_imports(tree: &tree_sitter::Tree, source: &[u8]) -> HashSet<String> {
    let mut policy_names = HashSet::new();

    iter_named_descendants(tree.root_node(), |node| {
        if node.kind() != "import_declaration" {
            return;
        }

        // Wildcard import (`import com.foo.policy.*;`): we can't enumerate
        // exported names without a classpath resolver, so skip. Also skip
        // wildcard-static (`import static com.foo.Permissions.*;`).
        let mut cursor = node.walk();
        let has_wildcard = node
            .named_children(&mut cursor)
            .any(|c| c.kind() == "asterisk");
        if has_wildcard {
            return;
        }

        // The single non-wildcard payload is either `scoped_identifier` or `identifier`.
        let mut cursor = node.walk();
        let Some(target) = node
            .named_children(&mut cursor)
            .find(|c| matches!(c.kind(), "scoped_identifier" | "identifier"))
        else {
            return;
        };

        let Ok(full_text) = target.utf8_text(source) else {
            return;
        };
        if !is_policy_path(full_text) {
            return;
        }

        // For both `import com.foo.policy.Authorize;` and
        // `import static com.foo.policy.Permissions.check;`, the binding
        // referenced in code is the trailing identifier — `Authorize` /
        // `check`. For `scoped_identifier`, that's the `name` field; for a
        // bare `identifier` (rare in valid Java but legal in the grammar),
        // it's the node itself.
        let binding = match target.kind() {
            "scoped_identifier" => target
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source).ok()),
            _ => Some(full_text),
        };
        if let Some(b) = binding {
            policy_names.insert(b.to_string());
        }
    });

    policy_names
}

fn find_csharp_policy_imports(tree: &tree_sitter::Tree, source: &[u8]) -> HashSet<String> {
    let mut policy_names = HashSet::new();

    iter_named_descendants(tree.root_node(), |node| {
        if node.kind() != "using_directive" {
            return;
        }

        // `using Alias = Company.Policy.Authorizer;` binds `Alias`.
        if let Some(alias_node) = node.child_by_field_name("name") {
            let Some(target) = csharp_using_alias_target(node, alias_node) else {
                return;
            };
            let Ok(full_text) = target.utf8_text(source) else {
                return;
            };

            if is_policy_path(full_text)
                && let Ok(alias) = alias_node.utf8_text(source)
            {
                policy_names.insert(alias.to_string());
            }
        }
    });

    policy_names
}

fn csharp_using_alias_target<'a>(
    node: tree_sitter::Node<'a>,
    alias_node: tree_sitter::Node<'a>,
) -> Option<tree_sitter::Node<'a>> {
    for field in ["value", "target", "path", "type"] {
        if let Some(target) = node.child_by_field_name(field) {
            return Some(target);
        }
    }

    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.id() != alias_node.id() && csharp_node_can_be_policy_path(*child))
}

fn csharp_node_can_be_policy_path(node: tree_sitter::Node) -> bool {
    matches!(
        node.kind(),
        "qualified_name" | "identifier" | "generic_name" | "member_access_expression"
    )
}

/// Walk the tree once, collecting `(lhs_name, rhs_source_text)` edges from
/// assignment-shaped nodes. The propagation step then checks each RHS for
/// any current binding and adds the LHS if it matches.
///
/// We deliberately collect edges as `(String, String)` text rather than
/// `Node` references so the iteration in `propagate_to_fixed_point` doesn't
/// have to keep the `Tree` alive through closure plumbing — the tree's
/// borrow checker rules around `TreeCursor` make that more painful than
/// it's worth for the small number of edges per file (typically <500).
fn extract_propagation_edges(
    tree: &tree_sitter::Tree,
    source: &[u8],
    language: Language,
) -> Vec<(String, String)> {
    let mut edges: Vec<(String, String)> = Vec::new();

    iter_named_descendants(tree.root_node(), |node| match language {
        Language::TypeScript | Language::JavaScript => visit_ts_js_edge(node, source, &mut edges),
        Language::Go => visit_go_edge(node, source, &mut edges),
        Language::Python => visit_py_edge(node, source, &mut edges),
        Language::Java => visit_java_edge(node, source, &mut edges),
        Language::CSharp => visit_csharp_edge(node, source, &mut edges),
        _ => {}
    });

    edges
}

/// Push an edge if `lhs` is non-empty. Trims the LHS to be safe — RHS is
/// kept verbatim because the regex match doesn't care about whitespace.
fn push_edge(lhs: &str, rhs: &str, edges: &mut Vec<(String, String)>) {
    let lhs = lhs.trim();
    if !lhs.is_empty() {
        edges.push((lhs.to_string(), rhs.to_string()));
    }
}

fn go_lhs_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(source).ok().map(str::to_string),
        // `d.accessFactory = authz.X` — propagate the field name, since
        // any later `<anything>.accessFactory` will textually contain it.
        "selector_expression" => node
            .child_by_field_name("field")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::to_string),
        _ => None,
    }
}

fn collect_go_assignment_edges(
    left: tree_sitter::Node,
    right: tree_sitter::Node,
    source: &[u8],
    edges: &mut Vec<(String, String)>,
) {
    let mut left_cursor = left.walk();
    let lhs_nodes: Vec<tree_sitter::Node> = if left.kind() == "expression_list" {
        left.named_children(&mut left_cursor).collect()
    } else {
        vec![left]
    };

    let mut right_cursor = right.walk();
    let rhs_nodes: Vec<tree_sitter::Node> = if right.kind() == "expression_list" {
        right.named_children(&mut right_cursor).collect()
    } else {
        vec![right]
    };

    if rhs_nodes.len() == lhs_nodes.len() {
        for (lhs, rhs) in lhs_nodes.into_iter().zip(rhs_nodes) {
            if let Some(name) = go_lhs_name(lhs, source) {
                push_edge(&name, rhs.utf8_text(source).unwrap_or(""), edges);
            }
        }
    } else {
        let rhs = right.utf8_text(source).unwrap_or("");
        for lhs in lhs_nodes {
            if let Some(name) = go_lhs_name(lhs, source) {
                push_edge(&name, rhs, edges);
            }
        }
    }
}

fn visit_go_edge(node: tree_sitter::Node, source: &[u8], edges: &mut Vec<(String, String)>) {
    match node.kind() {
        // `x := <expr>` and `x, y := f()` both land here.
        "short_var_declaration" => {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };
            collect_go_assignment_edges(left, right, source, edges);
        }
        // `var x = <expr>`, `var x T = <expr>`, including grouped `var ( ... )`.
        "var_spec" => {
            let Some(value) = node.child_by_field_name("value") else {
                return;
            };
            let mut cursor = node.walk();
            let names: Vec<tree_sitter::Node> =
                node.children_by_field_name("name", &mut cursor).collect();

            let mut value_cursor = value.walk();
            let values: Vec<tree_sitter::Node> = if value.kind() == "expression_list" {
                value.named_children(&mut value_cursor).collect()
            } else {
                vec![value]
            };

            if names.len() == values.len() {
                for (name, value) in names.into_iter().zip(values) {
                    if let Ok(text) = name.utf8_text(source) {
                        push_edge(text, value.utf8_text(source).unwrap_or(""), edges);
                    }
                }
            } else {
                let rhs = value.utf8_text(source).unwrap_or("");
                for name in names {
                    if let Ok(text) = name.utf8_text(source) {
                        push_edge(text, rhs, edges);
                    }
                }
            }
        }
        // Plain assignment — only `=`, not compound ops like `+=` (those
        // don't introduce a fresh binding the way `=` can).
        "assignment_statement" => {
            let op = node
                .child_by_field_name("operator")
                .and_then(|n| n.utf8_text(source).ok());
            if op != Some("=") {
                return;
            }
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };
            collect_go_assignment_edges(left, right, source, edges);
        }
        // `&S{accessFactory: authz.NewAccess}` — the OCP-shaped DI case.
        // Treat the field name as a binding when its value mentions one.
        "keyed_element" => {
            let (Some(key), Some(value)) = (
                node.child_by_field_name("key"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };
            // `key` is `literal_element` wrapping the actual key expr; we
            // want it to be a bare identifier (struct field name), not a
            // computed/index key.
            let key_inner = key.named_child(0);
            let Some(ki) = key_inner else { return };
            if ki.kind() != "identifier" {
                return;
            }
            let lhs = ki.utf8_text(source).unwrap_or("");
            let rhs = value.utf8_text(source).unwrap_or("");
            push_edge(lhs, rhs, edges);
        }
        _ => {}
    }
}

/// Recursively pull simple identifier targets out of a Python pattern.
/// Handles bare `identifier` and (shallow) `pattern_list` / `tuple_pattern`
/// for `a, b = f()` style assignment. Non-identifier patterns (subscripts,
/// attribute targets) are skipped — they don't introduce a tracked binding.
fn collect_py_lhs_idents(
    pat: tree_sitter::Node,
    source: &[u8],
    rhs: &str,
    edges: &mut Vec<(String, String)>,
) {
    match pat.kind() {
        "identifier" => {
            if let Ok(text) = pat.utf8_text(source) {
                push_edge(text, rhs, edges);
            }
        }
        "pattern_list" | "tuple_pattern" | "list_pattern" => {
            let mut cursor = pat.walk();
            for child in pat.named_children(&mut cursor) {
                collect_py_lhs_idents(child, source, rhs, edges);
            }
        }
        // `self.x = ...` is `attribute`; treat the trailing attribute as a
        // binding so later `self.x()`-shaped calls textually match.
        "attribute" => {
            if let Some(attr) = pat.child_by_field_name("attribute")
                && let Ok(text) = attr.utf8_text(source)
            {
                push_edge(text, rhs, edges);
            }
        }
        _ => {}
    }
}

fn py_lhs_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(source).ok().map(str::to_string),
        "attribute" => node
            .child_by_field_name("attribute")
            .and_then(|attr| attr.utf8_text(source).ok())
            .map(str::to_string),
        _ => None,
    }
}

fn py_sequence_children(node: tree_sitter::Node) -> Option<Vec<tree_sitter::Node>> {
    if !matches!(
        node.kind(),
        "pattern_list" | "tuple_pattern" | "list_pattern" | "expression_list" | "tuple" | "list"
    ) {
        return None;
    }

    let mut cursor = node.walk();
    Some(node.named_children(&mut cursor).collect())
}

fn collect_py_assignment_edges(
    left: tree_sitter::Node,
    right: tree_sitter::Node,
    source: &[u8],
    edges: &mut Vec<(String, String)>,
) {
    if let (Some(lhs_nodes), Some(rhs_nodes)) =
        (py_sequence_children(left), py_sequence_children(right))
        && lhs_nodes.len() == rhs_nodes.len()
    {
        for (lhs, rhs) in lhs_nodes.into_iter().zip(rhs_nodes) {
            if let Some(name) = py_lhs_name(lhs, source) {
                push_edge(&name, rhs.utf8_text(source).unwrap_or(""), edges);
            }
        }
        return;
    }

    let rhs = right.utf8_text(source).unwrap_or("");
    collect_py_lhs_idents(left, source, rhs, edges);
}

fn visit_py_edge(node: tree_sitter::Node, source: &[u8], edges: &mut Vec<(String, String)>) {
    match node.kind() {
        "assignment" => {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };
            collect_py_assignment_edges(left, right, source, edges);
        }
        // Walrus: `(x := f())`. Its `name` field is always a bare identifier.
        "named_expression" => {
            let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };
            let lhs = name.utf8_text(source).unwrap_or("");
            let rhs = value.utf8_text(source).unwrap_or("");
            push_edge(lhs, rhs, edges);
        }
        _ => {}
    }
}

fn visit_java_edge(node: tree_sitter::Node, source: &[u8], edges: &mut Vec<(String, String)>) {
    match node.kind() {
        // Covers both local declarations and field declarations — the
        // grammar uses `variable_declarator` for both.
        "variable_declarator" => {
            let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };
            if name.kind() != "identifier" {
                return;
            }
            let lhs = name.utf8_text(source).unwrap_or("");
            let rhs = value.utf8_text(source).unwrap_or("");
            push_edge(lhs, rhs, edges);
        }
        "assignment_expression" => {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };
            let rhs = right.utf8_text(source).unwrap_or("");
            let lhs_text = match left.kind() {
                "identifier" => left.utf8_text(source).ok().map(str::to_string),
                // `this.factory = authz.X;` — propagate `factory`.
                "field_access" => left
                    .child_by_field_name("field")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(str::to_string),
                _ => None,
            };
            if let Some(l) = lhs_text {
                push_edge(&l, rhs, edges);
            }
        }
        _ => {}
    }
}

fn csharp_lhs_name(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(source).ok().map(str::to_string),
        // `this.factory = Policy.X` — propagate `factory`.
        "member_access_expression" => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::to_string),
        _ => None,
    }
}

fn csharp_variable_declarator_value<'a>(
    node: tree_sitter::Node<'a>,
    name: tree_sitter::Node<'a>,
) -> Option<tree_sitter::Node<'a>> {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .find(|child| child.id() != name.id())
}

fn csharp_parent_type_text(node: tree_sitter::Node, source: &[u8]) -> Option<String> {
    node.parent()
        .filter(|parent| parent.kind() == "variable_declaration")
        .and_then(|parent| parent.child_by_field_name("type"))
        .and_then(|ty| ty.utf8_text(source).ok())
        .map(str::to_string)
}

fn visit_csharp_edge(node: tree_sitter::Node, source: &[u8], edges: &mut Vec<(String, String)>) {
    match node.kind() {
        // Covers local declarations and field declarations. C# grammar leaves
        // the initializer as the first non-name child of `variable_declarator`.
        "variable_declarator" => {
            let Some(name) = node.child_by_field_name("name") else {
                return;
            };
            if name.kind() != "identifier" {
                return;
            }
            let lhs = name.utf8_text(source).unwrap_or("");
            if let Some(value) = csharp_variable_declarator_value(node, name) {
                push_edge(lhs, value.utf8_text(source).unwrap_or(""), edges);
            } else if let Some(type_text) = csharp_parent_type_text(node, source) {
                push_edge(lhs, &type_text, edges);
            }
        }
        // Constructor/method DI: `Controller(Authz.IAuthorizer authz)`.
        "parameter" => {
            let (Some(name), Some(ty)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("type"),
            ) else {
                return;
            };
            if name.kind() != "identifier" {
                return;
            }
            let lhs = name.utf8_text(source).unwrap_or("");
            let rhs = ty.utf8_text(source).unwrap_or("");
            push_edge(lhs, rhs, edges);
        }
        "assignment_expression" => {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };
            if let Some(lhs) = csharp_lhs_name(left, source) {
                push_edge(&lhs, right.utf8_text(source).unwrap_or(""), edges);
            }
        }
        _ => {}
    }
}

fn visit_ts_js_edge(node: tree_sitter::Node, source: &[u8], edges: &mut Vec<(String, String)>) {
    match node.kind() {
        // `const x = ...`, `let x = ...`, `var x = ...`.
        "variable_declarator" => {
            let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };
            if name.kind() != "identifier" {
                return;
            }
            let lhs = name.utf8_text(source).unwrap_or("");
            let rhs = value.utf8_text(source).unwrap_or("");
            push_edge(lhs, rhs, edges);
        }
        // `x = expr`, `this.x = expr`.
        "assignment_expression" => {
            let (Some(left), Some(right)) = (
                node.child_by_field_name("left"),
                node.child_by_field_name("right"),
            ) else {
                return;
            };
            let rhs = right.utf8_text(source).unwrap_or("");
            let lhs_text = match left.kind() {
                "identifier" => left.utf8_text(source).ok().map(str::to_string),
                // `obj.factory = authz.X` — propagate `factory`.
                "member_expression" => left
                    .child_by_field_name("property")
                    .and_then(|n| n.utf8_text(source).ok())
                    .map(str::to_string),
                _ => None,
            };
            if let Some(l) = lhs_text {
                push_edge(&l, rhs, edges);
            }
        }
        // Object-literal pair: `{ factory: authz.X }`. Mirrors Go's
        // `keyed_element` — common in TS DI patterns where a service
        // bag is built inline.
        "pair" => {
            let (Some(key), Some(value)) = (
                node.child_by_field_name("key"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };
            // Only bare property identifiers; skip computed / string / number keys.
            if key.kind() != "property_identifier" {
                return;
            }
            let lhs = key.utf8_text(source).unwrap_or("");
            let rhs = value.utf8_text(source).unwrap_or("");
            push_edge(lhs, rhs, edges);
        }
        // TS class field: `class C { factory = authz.X; }`.
        "public_field_definition" => {
            let (Some(name), Some(value)) = (
                node.child_by_field_name("name"),
                node.child_by_field_name("value"),
            ) else {
                return;
            };
            if name.kind() != "property_identifier" {
                return;
            }
            let lhs = name.utf8_text(source).unwrap_or("");
            let rhs = value.utf8_text(source).unwrap_or("");
            push_edge(lhs, rhs, edges);
        }
        _ => {}
    }
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
    fn detects_aliased_named_policy_import() {
        let source = r#"
import { authorize as auth, Permission as Perm } from "../policy";
import { Router as R } from "express";
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        // For policy paths: capture the binding actually used in code (the alias),
        // not the original name.
        assert!(imports.contains("auth"));
        assert!(imports.contains("Perm"));
        assert!(!imports.contains("authorize"));
        assert!(!imports.contains("Permission"));
        // For non-policy paths: neither the alias nor the original name is captured,
        // regardless of how the import is renamed.
        assert!(!imports.contains("R"));
        assert!(!imports.contains("Router"));
    }

    #[test]
    fn detects_mixed_aliased_and_plain_named_imports() {
        let source = r#"
import { authorize, can as canDo, evaluate } from "../policy";
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authorize"));
        assert!(imports.contains("canDo"));
        assert!(imports.contains("evaluate"));
        assert!(!imports.contains("can"));
    }

    #[test]
    fn enforcement_point_check_aliased_named_import() {
        let source = r#"
import { authorize as auth } from "../policy";
"#;
        let tree = parse_ts(source);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        // The call uses the alias, so the regex must match the alias binding.
        assert!(is_enforcement_point(
            r#"if (!auth(req.user, "configs:read", req.params.id)) { return res.status(403).end(); }"#,
            &imports,
        ));
        assert!(!is_enforcement_point(
            r#"if (!authorize(req.user, "configs:read", req.params.id)) { return; }"#,
            &imports,
        ));
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

    fn parse_lang(source: &str, lang: Language) -> tree_sitter::Tree {
        let mut p = tree_sitter::Parser::new();
        parser::parse_source(&mut p, source.as_bytes(), lang, false).unwrap()
    }

    // ---------- Go ----------

    #[test]
    fn go_detects_unaliased_opa_import() {
        // OPA usage like `rego.New(...)` — the binding is the path basename,
        // which is what the OCP corpus repo actually does.
        let source = r#"
package main

import (
    "fmt"
    "github.com/open-policy-agent/opa/rego"
)
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("rego"));
        assert!(!imports.contains("fmt"));
    }

    #[test]
    fn go_detects_aliased_policy_import() {
        let source = r#"
package main

import (
    pol "github.com/example/authz"
    "fmt"
)
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("pol"));
        // The basename ("authz") must NOT also be captured when an alias shadows it.
        assert!(!imports.contains("authz"));
        assert!(!imports.contains("fmt"));
    }

    #[test]
    fn go_skips_blank_and_dot_imports() {
        // `_ "..."` is side-effect-only; `. "..."` merges names but we can't
        // resolve them. Both must produce no bindings, even if the path is
        // policy-y, otherwise we'd never detect their absence.
        let source = r#"
package main

import (
    _ "github.com/example/authz/init"
    . "github.com/example/policy/dsl"
)
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.is_empty(), "got: {imports:?}");
    }

    #[test]
    fn go_single_line_import() {
        let source = r#"
package main

import "github.com/open-policy-agent/opa/rego"
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("rego"));
    }

    #[test]
    fn go_enforcement_point_check() {
        let source = r#"
package main

import "github.com/open-policy-agent/opa/rego"
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(is_enforcement_point("rego.New(rego.Query(q))", &imports));
        assert!(!is_enforcement_point("user.Role == \"admin\"", &imports));
    }

    // ---------- Python ----------

    #[test]
    fn py_detects_from_module_import() {
        let source = r#"
from authz import check_permission, allow as can
from utils import nothing
"#;
        let tree = parse_lang(source, Language::Python);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Python);
        assert!(imports.contains("check_permission"));
        assert!(imports.contains("can"));
        assert!(!imports.contains("allow"));
        assert!(!imports.contains("nothing"));
    }

    #[test]
    fn py_detects_module_import_and_alias() {
        let source = r#"
import opa_client
import some.policy.engine as pol
import json
"#;
        let tree = parse_lang(source, Language::Python);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Python);
        // Bare `import opa_client` → binding is `opa_client`.
        assert!(imports.contains("opa_client"));
        // Aliased dotted module → binding is the alias.
        assert!(imports.contains("pol"));
        assert!(!imports.contains("some"));
        assert!(!imports.contains("json"));
    }

    #[test]
    fn py_skips_wildcard_import() {
        // We deliberately can't resolve `from x import *` — verify it's a no-op.
        let source = r#"
from authz import *
"#;
        let tree = parse_lang(source, Language::Python);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Python);
        assert!(imports.is_empty(), "got: {imports:?}");
    }

    #[test]
    fn py_enforcement_point_check() {
        let source = r#"
from authz import check_permission
"#;
        let tree = parse_lang(source, Language::Python);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Python);
        assert!(is_enforcement_point(
            r#"if check_permission(user, "orders:read"):"#,
            &imports,
        ));
        assert!(!is_enforcement_point(
            r#"if user.role == "admin":"#,
            &imports,
        ));
    }

    // ---------- Java ----------

    #[test]
    fn java_detects_class_import() {
        let source = r#"
package com.example;

import com.example.policy.Authorize;
import java.util.List;
"#;
        let tree = parse_lang(source, Language::Java);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Java);
        assert!(imports.contains("Authorize"));
        assert!(!imports.contains("List"));
    }

    #[test]
    fn java_detects_static_import() {
        // The binding referenced in code is the trailing identifier.
        let source = r#"
package com.example;

import static com.example.policy.Permissions.check;
"#;
        let tree = parse_lang(source, Language::Java);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Java);
        assert!(imports.contains("check"));
        // The class name on the way is NOT a binding.
        assert!(!imports.contains("Permissions"));
    }

    #[test]
    fn java_skips_wildcard() {
        // `import com.foo.policy.*` and `import static ...Permissions.*` —
        // can't enumerate without classpath resolution, so skip.
        let source = r#"
package com.example;

import com.example.policy.*;
import static com.example.policy.Permissions.*;
"#;
        let tree = parse_lang(source, Language::Java);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Java);
        assert!(imports.is_empty(), "got: {imports:?}");
    }

    #[test]
    fn java_enforcement_point_check() {
        let source = r#"
package com.example;

import com.example.policy.Authorize;
"#;
        let tree = parse_lang(source, Language::Java);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Java);
        assert!(is_enforcement_point(
            "Authorize.check(user, \"orders:read\")",
            &imports,
        ));
        assert!(!is_enforcement_point(
            "user.getRole().equals(\"ADMIN\")",
            &imports
        ));
    }

    // ---------- C# ----------

    #[test]
    fn csharp_detects_using_policy_alias() {
        let source = r#"
using Company.Authz;
using PolicyAlias = Company.Policy.Authorizer;
using System.Collections.Generic;
"#;
        let tree = parse_lang(source, Language::CSharp);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::CSharp);

        assert!(!imports.contains("Authz"), "got: {imports:?}");
        assert!(imports.contains("PolicyAlias"), "got: {imports:?}");
        assert!(!imports.contains("Collections"));
    }

    #[test]
    fn csharp_alias_checks_target_not_alias_name() {
        let source = r#"
using PolicyAlias = Company.Utils.Helper;
"#;
        let tree = parse_lang(source, Language::CSharp);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::CSharp);

        assert!(!imports.contains("PolicyAlias"), "got: {imports:?}");
    }

    #[test]
    fn csharp_enforcement_point_check() {
        let source = r#"
using PolicyAlias = Company.Policy.Authorizer;
"#;
        let tree = parse_lang(source, Language::CSharp);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::CSharp);

        assert!(is_enforcement_point(
            "PolicyAlias.AuthorizeAsync(User, doc, \"Read\")",
            &imports,
        ));
        assert!(!is_enforcement_point("User.IsInRole(\"Admin\")", &imports));
    }

    // ---------- Local data-flow propagation (option #2) ----------

    #[test]
    fn go_propagates_through_composite_literal_field() {
        // OCP-shaped: import `authz`, store its constructor on a struct
        // field, then call indirectly via `d.accessFactory()`.
        let source = r#"
package main

import "github.com/example/authz"

type Database struct {
    accessFactory func() Access
}

func New() *Database {
    return &Database{accessFactory: authz.NewAccess}
}

func (d *Database) check() {
    d.accessFactory().WithPrincipal("bob")
}
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("authz"));
        assert!(
            imports.contains("accessFactory"),
            "expected accessFactory to propagate from `accessFactory: authz.NewAccess` literal; got: {imports:?}"
        );
        assert!(is_enforcement_point(
            "d.accessFactory().WithPrincipal(\"bob\")",
            &imports,
        ));
    }

    #[test]
    fn go_propagates_through_short_var_decl() {
        let source = r#"
package main

import "github.com/example/authz"

func use() {
    fac := authz.NewAccess
    _ = fac()
}
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("fac"));
        assert!(is_enforcement_point("fac()", &imports));
    }

    #[test]
    fn go_multi_hop_propagation() {
        let source = r#"
package main

import "github.com/example/authz"

type S struct{ factory func() any }

func init() {
    s := &S{factory: authz.New}
    cached := s.factory
    _ = cached
}
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("factory"));
        assert!(
            imports.contains("cached"),
            "expected multi-hop authz → factory → cached; got: {imports:?}"
        );
    }

    #[test]
    fn go_does_not_cross_contaminate_paired_short_var_decl() {
        let source = r#"
package main

import "github.com/example/authz"

func init() {
    factory, localCheck := authz.New, func() bool { return true }
    _ = factory
    _ = localCheck
}
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("factory"));
        assert!(
            !imports.contains("localCheck"),
            "localCheck came from the second RHS and must not inherit authz; got: {imports:?}"
        );
    }

    #[test]
    fn go_does_not_cross_contaminate_paired_var_spec() {
        let source = r#"
package main

import "github.com/example/authz"

var factory, localCheck = authz.New, func() bool { return true }
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.contains("factory"));
        assert!(
            !imports.contains("localCheck"),
            "localCheck came from the second RHS and must not inherit authz; got: {imports:?}"
        );
    }

    #[test]
    fn go_no_propagation_without_policy_import() {
        let source = r#"
package main

import "github.com/example/utils"

func use() {
    fac := utils.NewThing
    _ = fac()
}
"#;
        let tree = parse_lang(source, Language::Go);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Go);
        assert!(imports.is_empty(), "got: {imports:?}");
    }

    #[test]
    fn py_propagates_through_assignment_and_attribute() {
        let source = r#"
from authz import check_orders_permission

class Service:
    def __init__(self):
        self.guard = check_orders_permission

    def run(self, user):
        self.guard(user)

helper = check_orders_permission
"#;
        let tree = parse_lang(source, Language::Python);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Python);
        assert!(imports.contains("check_orders_permission"));
        assert!(imports.contains("guard"), "got: {imports:?}");
        assert!(imports.contains("helper"), "got: {imports:?}");
        assert!(is_enforcement_point("self.guard(user)", &imports));
    }

    #[test]
    fn py_does_not_cross_contaminate_paired_assignment() {
        let source = r#"
from authz import check_orders_permission

guard, local_check = check_orders_permission, lambda user: True
"#;
        let tree = parse_lang(source, Language::Python);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Python);
        assert!(imports.contains("guard"));
        assert!(
            !imports.contains("local_check"),
            "local_check came from the second RHS and must not inherit authz; got: {imports:?}"
        );
    }

    #[test]
    fn java_propagates_through_field_initializer() {
        let source = r#"
package com.example;

import com.example.policy.Authorize;

public class Service {
    private final Authorize guard = Authorize.INSTANCE;

    public boolean check(User u) {
        return guard.hasRole("admin");
    }
}
"#;
        let tree = parse_lang(source, Language::Java);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Java);
        assert!(imports.contains("Authorize"));
        assert!(imports.contains("guard"), "got: {imports:?}");
        assert!(is_enforcement_point("guard.hasRole(\"admin\")", &imports));
    }

    #[test]
    fn java_propagates_through_assignment_expression() {
        let source = r#"
package com.example;

import com.example.policy.SomePolicy;

public class Service {
    private Object factory;

    public Service() {
        this.factory = SomePolicy.create();
    }
}
"#;
        let tree = parse_lang(source, Language::Java);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::Java);
        assert!(imports.contains("SomePolicy"));
        assert!(
            imports.contains("factory"),
            "expected this.factory propagation; got: {imports:?}"
        );
    }

    #[test]
    fn ts_propagates_through_object_pair_and_field() {
        let source = r#"
import { authorize } from '../lib/authz';

class Service {
    guard = authorize;
}

const bag = { check: authorize };
const direct = authorize;
"#;
        let tree = parse_lang(source, Language::TypeScript);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.contains("authorize"));
        assert!(imports.contains("guard"), "class field: {imports:?}");
        assert!(imports.contains("check"), "object pair: {imports:?}");
        assert!(imports.contains("direct"), "var decl: {imports:?}");
    }

    #[test]
    fn csharp_propagates_through_constructor_di_parameter_and_field() {
        let source = r#"
using Authz = Company.Policy.Authorizer;

public class Service {
    private readonly Authz _authz;

    public Service(Authz authz) {
        _authz = authz;
    }

    public Task Check(User user, Document doc) {
        return _authz.AuthorizeAsync(user, doc, "Read");
    }
}
"#;
        let tree = parse_lang(source, Language::CSharp);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::CSharp);

        assert!(imports.contains("Authz"), "got: {imports:?}");
        assert!(
            imports.contains("authz"),
            "parameter type should seed constructor DI parameter; got: {imports:?}"
        );
        assert!(
            imports.contains("_authz"),
            "field assignment should propagate from constructor parameter; got: {imports:?}"
        );
        assert!(is_enforcement_point(
            r#"_authz.AuthorizeAsync(user, doc, "Read")"#,
            &imports,
        ));
    }

    #[test]
    fn csharp_propagates_through_object_initializer_and_local_variable() {
        let source = r#"
using Policy = Company.Policy;

public class Service {
    public void Build() {
        var direct = Policy.Authorizer;
        var bag = new AccessBag { Checker = direct };
        bag.Checker.AuthorizeAsync(User, doc, "Read");
    }
}
"#;
        let tree = parse_lang(source, Language::CSharp);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::CSharp);

        assert!(imports.contains("Policy"), "got: {imports:?}");
        assert!(imports.contains("direct"), "local var: {imports:?}");
        assert!(
            imports.contains("Checker"),
            "object initializer: {imports:?}"
        );
        assert!(is_enforcement_point(
            r#"bag.Checker.AuthorizeAsync(User, doc, "Read")"#,
            &imports,
        ));
    }

    #[test]
    fn propagation_is_a_no_op_when_no_policy_imports() {
        // Defense in depth: even if the file is full of assignments, with
        // no policy bindings to seed from, propagation must do nothing.
        let source = r#"
import { Router } from 'express';
const app = Router;
const handler = app;
const cached = handler;
"#;
        let tree = parse_lang(source, Language::TypeScript);
        let imports = find_policy_imports(&tree, source.as_bytes(), Language::TypeScript);
        assert!(imports.is_empty(), "got: {imports:?}");
    }
}
