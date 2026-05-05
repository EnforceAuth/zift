//! Audit for `summary.enforcement_points` (PR-followup #12).
//!
//! Corpus shakedown reported `enforcement_points: 0` on every run. The
//! follow-up plan called for verifying the metric on a fixture that *does*
//! ship a policy-engine import — the corpora it reported 0 against simply
//! had no externalized authz, so 0 was correct, but we wanted a regression
//! test pinning the behavior in place.
//!
//! These tests exercise the real `scanner::scan` end-to-end: a synthetic
//! file that imports from a path containing `authz` and calls the imported
//! name should produce one `enforcement_points` increment and zero inline
//! findings (the call is already routed through a policy engine, so we
//! don't flag it again).

use std::fs;

use tempfile::tempdir;

use zift::cli::ScanArgs;
use zift::config::ZiftConfig;
use zift::rules;
use zift::scanner;

#[test]
fn enforcement_points_increments_when_call_routes_through_policy_import() {
    let dir = tempdir().unwrap();
    // Import path contains "authz" → `find_policy_imports` captures `authorize`
    // as a policy-bound name. The subsequent `authorize("orders:read")` call
    // matches `ts-authorize-function-call` structurally, but because
    // `is_enforcement_point` sees `authorize` from the policy import, the
    // finding is rerouted into the enforcement-point counter rather than the
    // findings list.
    fs::write(
        dir.path().join("orders.ts"),
        r#"import { authorize } from '../lib/authz';

export function listOrders(user: User) {
  if (authorize("orders:read")) {
    return db.orders.find();
  }
  return null;
}
"#,
    )
    .unwrap();

    let config = ZiftConfig::default();
    let loaded_rules = rules::load_rules(None, &config).expect("embedded rules load");
    let args = ScanArgs {
        path: dir.path().to_path_buf(),
        ..ScanArgs::default()
    };

    let result = scanner::scan(dir.path(), &loaded_rules, &args, &config).unwrap();

    assert_eq!(
        result.enforcement_points,
        1,
        "expected the policy-imported authorize() call to count as an enforcement point; \
         got {} (findings: {:?})",
        result.enforcement_points,
        result
            .findings
            .iter()
            .map(|f| (f.pattern_rule.clone(), f.line_start))
            .collect::<Vec<_>>(),
    );
    // The same call should NOT also appear as an inline finding — that's
    // the whole point of the enforcement-point shortcut. (Other rules in
    // unrelated files could still fire; we only assert the single rule the
    // fixture targets is gone.)
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.pattern_rule.as_deref() == Some("ts-authorize-function-call")),
        "policy-routed call leaked into findings: {:?}",
        result.findings,
    );
}

#[test]
fn enforcement_points_is_zero_without_policy_imports() {
    // Counterpart to the test above: identical call site, but the import
    // path doesn't look like a policy module (`utils` instead of `authz`).
    // The call should fall through to the structural finding path and the
    // enforcement-point counter should stay at 0. This pins the behavior
    // the corpus shakedown actually saw — none of the five corpora shipped
    // policy imports, so 0 was the correct answer.
    let dir = tempdir().unwrap();
    fs::write(
        dir.path().join("orders.ts"),
        r#"import { authorize } from '../lib/utils';

export function listOrders(user: User) {
  if (authorize("orders:read")) {
    return db.orders.find();
  }
  return null;
}
"#,
    )
    .unwrap();

    let config = ZiftConfig::default();
    let loaded_rules = rules::load_rules(None, &config).expect("embedded rules load");
    let args = ScanArgs {
        path: dir.path().to_path_buf(),
        ..ScanArgs::default()
    };

    let result = scanner::scan(dir.path(), &loaded_rules, &args, &config).unwrap();

    assert_eq!(result.enforcement_points, 0);
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.pattern_rule.as_deref() == Some("ts-authorize-function-call")),
        "structural rule should have fired without the policy-import shortcut; \
         got: {:?}",
        result
            .findings
            .iter()
            .map(|f| f.pattern_rule.clone())
            .collect::<Vec<_>>(),
    );
}

/// Helper: run a scan against a single-file fixture and return the result.
fn scan_fixture(filename: &str, contents: &str) -> zift::scanner::ScanResult {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join(filename), contents).unwrap();

    let config = ZiftConfig::default();
    let loaded_rules = rules::load_rules(None, &config).expect("embedded rules load");
    let args = ScanArgs {
        path: dir.path().to_path_buf(),
        ..ScanArgs::default()
    };
    zift::scanner::scan(dir.path(), &loaded_rules, &args, &config).unwrap()
}

#[test]
fn enforcement_points_increments_for_go_opa_import() {
    // Mirrors what we saw in the OCP corpus repo: an unaliased OPA import
    // where the binding (`rego`) is the path basename, used at a call site
    // (`rego.New(...)`) that the `go-opa-rego-eval` rule structurally matches.
    let result = scan_fixture(
        "decide.go",
        r#"package main

import (
    "fmt"
    "github.com/open-policy-agent/opa/rego"
)

func decide() {
    _ = rego.New(rego.Query("data.authz.allow"))
    fmt.Println("decided")
}
"#,
    );

    assert_eq!(
        result.enforcement_points,
        1,
        "expected the OPA rego.New() call to count as an enforcement point; \
         got {} (findings: {:?})",
        result.enforcement_points,
        result
            .findings
            .iter()
            .map(|f| (f.pattern_rule.clone(), f.line_start))
            .collect::<Vec<_>>(),
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.pattern_rule.as_deref() == Some("go-opa-rego-eval")),
        "policy-routed call leaked into findings: {:?}",
        result.findings,
    );
}

#[test]
fn go_policy_propagation_does_not_suppress_unrelated_paired_assignment() {
    let result = scan_fixture(
        "mixed.go",
        r#"package main

import "github.com/example/authz"

func check() {
    factory, RequirePermission := authz.NewAccess, func(string) bool { return true }
    _ = factory
    if RequirePermission("orders:read") {
        return
    }
}
"#,
    );

    assert_eq!(
        result.enforcement_points,
        0,
        "unrelated second assignment target should not be counted as externalized; findings: {:?}",
        result
            .findings
            .iter()
            .map(|f| (f.pattern_rule.clone(), f.line_start))
            .collect::<Vec<_>>(),
    );
    assert!(
        result
            .findings
            .iter()
            .any(|f| f.pattern_rule.as_deref() == Some("go-permission-check-call")),
        "local RequirePermission call should remain an embedded finding; got: {:?}",
        result
            .findings
            .iter()
            .map(|f| (f.pattern_rule.clone(), f.line_start))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn enforcement_points_increments_for_python_authz_import() {
    // Use a `check_*_permission` shape so it actually trips a structural rule
    // (`py-check-helper-call`) — without a matching rule there's no candidate
    // finding for the import shortcut to reroute, so the counter stays at 0.
    let result = scan_fixture(
        "views.py",
        r#"from authz import check_orders_permission

def list_orders(user):
    check_orders_permission(user)
    return db.orders.find()
"#,
    );

    assert!(
        result.enforcement_points >= 1,
        "expected the Python check_permission() call to count as an enforcement point; \
         got {} (findings: {:?})",
        result.enforcement_points,
        result
            .findings
            .iter()
            .map(|f| (f.pattern_rule.clone(), f.line_start))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn enforcement_points_increments_for_java_authz_import() {
    // `Authorize.hasRole("admin")` trips `java-has-role-call` structurally; the
    // policy-import shortcut should reroute it because the receiver `Authorize`
    // is bound to the policy module.
    let result = scan_fixture(
        "OrderService.java",
        r#"package com.example;

import com.example.policy.Authorize;

public class OrderService {
    public boolean list(User user) {
        return Authorize.hasRole("admin");
    }
}
"#,
    );

    assert!(
        result.enforcement_points >= 1,
        "expected the Java Authorize.check() call to count as an enforcement point; \
         got {} (findings: {:?})",
        result.enforcement_points,
        result
            .findings
            .iter()
            .map(|f| (f.pattern_rule.clone(), f.line_start))
            .collect::<Vec<_>>(),
    );
}

#[test]
fn enforcement_points_increments_for_csharp_policy_di() {
    // The C# import tracker seeds `Authz` from the policy alias, then propagates
    // through constructor DI (`authz`) and the backing field (`_authz`). The
    // resulting `_authz.AuthorizeAsync(...)` call is externalized, so it should
    // count as an enforcement point rather than an embedded finding.
    let result = scan_fixture(
        "OrderController.cs",
        r#"using Authz = Company.Policy.Authorizer;

public class OrderController {
    private readonly Authz _authz;

    public OrderController(Authz authz) {
        _authz = authz;
    }

    public async Task<IActionResult> List(User user, Document document) {
        var result = await _authz.AuthorizeAsync(user, document, "CanReadOrders");
        if (!result.Succeeded) {
            return Forbid();
        }
        return Ok();
    }
}
"#,
    );

    assert!(
        result.enforcement_points >= 1,
        "expected the C# policy DI AuthorizeAsync call to count as an enforcement point; \
         got {} (findings: {:?})",
        result.enforcement_points,
        result
            .findings
            .iter()
            .map(|f| (f.pattern_rule.clone(), f.line_start))
            .collect::<Vec<_>>(),
    );
    assert!(
        !result
            .findings
            .iter()
            .any(|f| f.pattern_rule.as_deref()
                == Some("csharp-authorization-service-authorize-async")),
        "policy-routed C# call leaked into findings: {:?}",
        result.findings,
    );
}
