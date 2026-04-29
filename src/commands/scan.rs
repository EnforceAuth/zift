use crate::cli::{OutputFormat, ScanArgs};
use crate::config::ZiftConfig;
use crate::deep;
use crate::error::{Result, ZiftError};
use crate::output;
use crate::rules;
use crate::scanner;

pub fn execute(args: ScanArgs, config: ZiftConfig) -> Result<()> {
    if matches!(args.format, OutputFormat::Sarif) {
        return Err(ZiftError::General(
            "SARIF output not yet implemented".into(),
        ));
    }

    let path = args.path.canonicalize().map_err(|e| {
        ZiftError::General(format!(
            "failed to resolve path '{}': {e}",
            args.path.display()
        ))
    })?;
    tracing::info!("scanning {}", path.display());

    // Build deep-scan runtime config eagerly so we fail fast on bad config
    // (missing --base-url / --model) before running an entire structural scan.
    let deep_runtime = if args.deep {
        Some(deep::config::build(&args, &config)?)
    } else {
        None
    };

    // Warn about explicitly requested languages that lack parser support
    for lang in &args.language {
        if !scanner::parser::is_language_supported(*lang) {
            eprintln!(
                "warning: {lang} scanning is not yet supported — {lang} files will be skipped"
            );
        }
    }

    let loaded_rules = rules::load_rules(args.rules_dir.as_deref(), &config)?;
    tracing::info!("loaded {} pattern rules", loaded_rules.len());

    let mut result = scanner::scan(&path, &loaded_rules, &args, &config)?;

    if let Some(runtime) = deep_runtime.as_ref() {
        tracing::info!(
            "running deep scan: base_url={} model={} concurrency={}",
            runtime.base_url,
            runtime.model,
            runtime.max_concurrent
        );
        let semantic = deep::run(&result.findings, &path, runtime)?;
        if !semantic.is_empty() {
            result.findings = deep::merge::merge(result.findings, semantic);
        }
    }

    let stdout = std::io::stdout();
    let mut writer: Box<dyn std::io::Write> = if let Some(ref out_path) = args.output {
        Box::new(std::fs::File::create(out_path)?)
    } else {
        Box::new(stdout.lock())
    };

    match args.format {
        OutputFormat::Text => output::text::print(
            &result.findings,
            &path,
            result.enforcement_points,
            &mut writer,
        )?,
        OutputFormat::Json => output::json::print(
            &result.findings,
            &path,
            result.enforcement_points,
            &mut writer,
        )?,
        OutputFormat::Sarif => unreachable!("pre-checked above"),
    }

    Ok(())
}
