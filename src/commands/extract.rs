use std::io::Read;

use serde::Deserialize;

use crate::cli::ExtractArgs;
use crate::config::ZiftConfig;
use crate::error::{Result, ZiftError};
use crate::rego::{self, templates};
use crate::types::Finding;

/// Minimal struct for deserializing scan output — we only need the findings.
#[derive(Deserialize)]
struct ScanInput {
    findings: Vec<Finding>,
}

pub fn execute(args: ExtractArgs, config: ZiftConfig) -> Result<()> {
    // Resolve config fallbacks
    let package_prefix = config
        .extract
        .package_prefix
        .as_deref()
        .filter(|_| args.package_prefix == "app") // only use config if CLI is default
        .unwrap_or(&args.package_prefix);

    let output_dir = config
        .extract
        .output_dir
        .as_ref()
        .filter(|_| args.output_dir.to_str() == Some("./policies/generated"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| args.output_dir.clone());

    // Read findings
    let mut findings = read_findings(&args)?;
    tracing::info!("loaded {} findings", findings.len());

    // Filter by confidence
    if let Some(min) = args.min_confidence {
        findings.retain(|f| f.confidence >= min);
        tracing::info!("{} findings after confidence filter", findings.len());
    }

    if findings.is_empty() {
        eprintln!("No findings to extract.");
        return Ok(());
    }

    // Ensure every finding has a rego_stub
    for finding in &mut findings {
        if finding.rego_stub.is_none() {
            finding.rego_stub = Some(templates::generate_default_stub(
                finding.category,
                &finding.code_snippet,
            ));
        }
    }

    // Group and generate files
    let rego_files = rego::group_findings(&findings, package_prefix, &output_dir);

    // Write files and validate
    let mut total_files = 0;
    let mut validation_warnings = 0;
    for rego_file in &rego_files {
        // Validate generated Rego syntax
        let validation = rego::validator::validate_rego(&rego_file.content);
        let status = if validation.valid { "OK" } else { "WARN" };

        if let Some(parent) = rego_file.output_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&rego_file.output_path, &rego_file.content)?;
        total_files += 1;
        eprintln!(
            "  [{status}] {} ({} findings) → {}",
            rego_file.package_name,
            rego_file.finding_count,
            rego_file.output_path.display(),
        );
        if let Some(err) = validation.error {
            eprintln!("       ⚠ Rego parse warning: {err}");
            validation_warnings += 1;
        }
    }

    eprintln!(
        "\nGenerated {total_files} Rego files from {} findings.",
        findings.len(),
    );
    if validation_warnings > 0 {
        eprintln!(
            "{validation_warnings} file(s) have Rego syntax warnings — review before deploying.",
        );
    }

    Ok(())
}

fn read_findings(args: &ExtractArgs) -> Result<Vec<Finding>> {
    let json_str = if let Some(ref path) = args.input {
        std::fs::read_to_string(path)?
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| ZiftError::General(format!("failed to read stdin: {e}")))?;
        buf
    };

    // Try parsing as ScanReport (with findings wrapper) first, then as bare Vec<Finding>
    if let Ok(report) = serde_json::from_str::<ScanInput>(&json_str) {
        Ok(report.findings)
    } else {
        serde_json::from_str::<Vec<Finding>>(&json_str)
            .map_err(|e| ZiftError::General(format!("failed to parse findings JSON: {e}")))
    }
}
