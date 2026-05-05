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
