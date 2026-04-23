use crate::cli::{OutputFormat, ScanArgs};
use crate::config::ZiftConfig;
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

    if args.deep {
        eprintln!(
            "warning: --deep (LLM-assisted) is not yet implemented, running structural scan only"
        );
    }

    let loaded_rules = rules::load_rules(args.rules_dir.as_deref(), &config)?;
    tracing::info!("loaded {} pattern rules", loaded_rules.len());

    let result = scanner::scan(&path, &loaded_rules, &args, &config)?;

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
