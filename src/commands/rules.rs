use crate::cli::{RulesAction, RulesArgs};
use crate::config::ZiftConfig;
use crate::error::Result;
use crate::rules;
use crate::scanner::parser as ts_parser;
use crate::types::Language;

pub fn execute(args: RulesArgs, config: ZiftConfig) -> Result<()> {
    match args.action {
        RulesAction::List => {
            let loaded = rules::load_rules(None, &config)?;
            if loaded.is_empty() {
                println!("No pattern rules loaded.");
                return Ok(());
            }
            println!("{:<35} {:<15} {:<10} Languages", "ID", "Category", "Confidence");
            println!("{}", "-".repeat(80));
            for rule in &loaded {
                let langs: Vec<String> = rule.languages.iter().map(|l| l.to_string()).collect();
                println!(
                    "{:<35} {:<15} {:<10} {}",
                    rule.id,
                    rule.category.to_string(),
                    rule.confidence.to_string(),
                    langs.join(", "),
                );
            }
            println!("\n{} rules loaded.", loaded.len());
        }
        RulesAction::Validate => {
            let loaded = rules::load_rules(None, &config)?;
            let mut errors = 0;
            for rule in &loaded {
                // Validate tree-sitter queries against all grammar variants
                for lang in &rule.languages {
                    let variants: &[bool] = if *lang == Language::TypeScript {
                        &[false, true] // validate against both TS and TSX grammars
                    } else {
                        &[false]
                    };
                    for &is_tsx_jsx in variants {
                        let ts_lang = ts_parser::get_language(*lang, is_tsx_jsx)?;
                        if let Err(e) =
                            tree_sitter::Query::new(&ts_lang, &rule.query_source)
                        {
                            let suffix = if is_tsx_jsx { "/tsx" } else { "" };
                            eprintln!("FAIL  {}  ({lang}{suffix}): query: {e}", rule.id);
                            errors += 1;
                        }
                    }
                }
                // Validate Rego template if present
                if let Some(ref tmpl) = rule.rego_template {
                    let result = crate::rego::validator::validate_template(tmpl);
                    if !result.valid {
                        let err = result.error.unwrap_or_default();
                        eprintln!("FAIL  {}  rego_template: {err}", rule.id);
                        errors += 1;
                    }
                }
            }
            if errors == 0 {
                println!("All {} rules validated successfully.", loaded.len());
            } else {
                eprintln!("{errors} rule(s) failed validation.");
                std::process::exit(1);
            }
        }
        RulesAction::Test => {
            let loaded = rules::load_rules(None, &config)?;
            let mut passed = 0;
            let mut failed = 0;

            for rule in &loaded {
                for (i, test) in rule.tests.iter().enumerate() {
                    let Some(default_lang) = rule.languages.first().copied() else {
                        eprintln!("FAIL  {}[{i}]: rule has no languages configured", rule.id);
                        failed += 1;
                        continue;
                    };
                    let lang = test.language.unwrap_or(default_lang);
                    let variants: Vec<bool> = if lang == Language::TypeScript {
                        vec![false, true] // test against both TS and TSX grammars
                    } else {
                        vec![false]
                    };
                    for is_tsx_jsx in variants {
                        let ts_lang = ts_parser::get_language(lang, is_tsx_jsx)?;

                        let mut parser = tree_sitter::Parser::new();
                        let tree = match ts_parser::parse_source(
                            &mut parser,
                            test.input.as_bytes(),
                            lang,
                            is_tsx_jsx,
                        ) {
                            Ok(t) => t,
                            Err(e) => {
                                let suffix = if is_tsx_jsx { "/tsx" } else { "" };
                                eprintln!("FAIL  {}[{i}] ({lang}{suffix}): parse error: {e}", rule.id);
                                failed += 1;
                                continue;
                            }
                        };

                        let compiled = match crate::scanner::matcher::compile_rule(rule, &ts_lang) {
                            Ok(c) => c,
                            Err(e) => {
                                let suffix = if is_tsx_jsx { "/tsx" } else { "" };
                                eprintln!("FAIL  {}[{i}] ({lang}{suffix}): compile error: {e}", rule.id);
                                failed += 1;
                                continue;
                            }
                        };

                        let findings = match crate::scanner::matcher::execute_query(
                            &compiled,
                            &tree,
                            test.input.as_bytes(),
                            std::path::Path::new("test"),
                            lang,
                        ) {
                            Ok(f) => f,
                            Err(e) => {
                                let suffix = if is_tsx_jsx { "/tsx" } else { "" };
                                eprintln!("FAIL  {}[{i}] ({lang}{suffix}): query error: {e}", rule.id);
                                failed += 1;
                                continue;
                            }
                        };

                        let matched = !findings.is_empty();
                        if matched == test.expect_match {
                            passed += 1;
                        } else {
                            let suffix = if is_tsx_jsx { "/tsx" } else { "" };
                            eprintln!(
                                "FAIL  {}[{i}] ({lang}{suffix}): expected match={}, got match={}",
                                rule.id, test.expect_match, matched,
                            );
                            failed += 1;
                        }
                    }
                }
            }

            println!("{passed} passed, {failed} failed.");
            if failed > 0 {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}
