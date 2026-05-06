use std::io::Read;
use std::path::Path;

use serde::Deserialize;

use crate::cli::ExtractArgs;
use crate::config::ZiftConfig;
use crate::error::{Result, ZiftError};
use crate::types::{Finding, PolicyEngine};

/// Minimal struct for deserializing scan output — we only need the findings.
#[derive(Deserialize)]
struct ScanInput {
    findings: Vec<Finding>,
}

pub fn execute(args: ExtractArgs, config: ZiftConfig) -> Result<()> {
    // Resolve config fallbacks. The CLI default for `policy_prefix` is
    // "app"; if the user didn't override that on the command line, defer to
    // `[extract] package_prefix` from the config.
    let policy_prefix = config
        .extract
        .package_prefix
        .as_deref()
        .filter(|_| args.policy_prefix == "app")
        .unwrap_or(&args.policy_prefix);

    let output_dir = config
        .extract
        .output_dir
        .as_ref()
        .filter(|_| args.output_dir.to_str() == Some("./policies/generated"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| args.output_dir.clone());

    let mut findings = read_findings(&args)?;
    tracing::info!("loaded {} findings", findings.len());

    if let Some(min) = args.min_confidence {
        findings.retain(|f| f.confidence >= min);
        tracing::info!("{} findings after confidence filter", findings.len());
    }

    if findings.is_empty() {
        eprintln!("No findings to extract.");
        return Ok(());
    }

    match args.engine {
        PolicyEngine::Rego => extract_rego(&mut findings, policy_prefix, &output_dir),
        PolicyEngine::Cedar => extract_cedar(&mut findings, policy_prefix, &output_dir),
    }
}

fn extract_rego(findings: &mut [Finding], policy_prefix: &str, output_dir: &Path) -> Result<()> {
    use crate::rego::{self, templates};

    for finding in findings.iter_mut() {
        if finding.policy_output(PolicyEngine::Rego).is_none() {
            let stub = templates::generate_default_stub(finding.category, &finding.code_snippet);
            finding.set_policy_output(PolicyEngine::Rego, stub);
        }
    }

    let rego_files = rego::group_findings(findings, policy_prefix, output_dir);

    // Canonicalize once before writing any files. Each generated file shares
    // the same `output_dir`, so canonicalizing per-file inside the loop was
    // redundant work and a stray `output_dir` rename mid-loop would break
    // anyway.
    std::fs::create_dir_all(output_dir)?;
    let canonical_output_dir = output_dir.canonicalize().map_err(|e| {
        ZiftError::General(format!(
            "failed to resolve output dir '{}': {e}",
            output_dir.display()
        ))
    })?;

    let mut total_files = 0;
    let mut validation_warnings = 0;
    for rego_file in &rego_files {
        let validation = rego::validator::validate_rego(&rego_file.content);
        let status = if validation.valid { "OK" } else { "WARN" };

        write_policy_file(
            &rego_file.output_path,
            &rego_file.content,
            &canonical_output_dir,
        )?;
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

fn extract_cedar(findings: &mut [Finding], policy_prefix: &str, output_dir: &Path) -> Result<()> {
    use crate::cedar::{self, templates};

    // Mirror of the Rego pre-fill: if a finding has no Cedar policy_output
    // yet (e.g. it came from an older scan, or its rule has no Cedar
    // template), synthesize one from the category default. This keeps Cedar
    // coverage at 100% — no rule produces zero output.
    for finding in findings.iter_mut() {
        if finding.policy_output(PolicyEngine::Cedar).is_none() {
            let stub = templates::generate_default_stub(finding.category, &finding.code_snippet);
            finding.set_policy_output(PolicyEngine::Cedar, stub);
        }
    }

    let cedar_files = cedar::group_findings(findings, policy_prefix, output_dir);

    std::fs::create_dir_all(output_dir)?;
    let canonical_output_dir = output_dir.canonicalize().map_err(|e| {
        ZiftError::General(format!(
            "failed to resolve output dir '{}': {e}",
            output_dir.display()
        ))
    })?;

    let mut total_files = 0;
    let mut validation_warnings = 0;
    for cedar_file in &cedar_files {
        let validation = cedar::validator::validate_cedar(&cedar_file.content);
        let status = if validation.valid { "OK" } else { "WARN" };

        write_policy_file(
            &cedar_file.output_path,
            &cedar_file.content,
            &canonical_output_dir,
        )?;
        total_files += 1;
        eprintln!(
            "  [{status}] {} ({} findings) → {}",
            cedar_file.label,
            cedar_file.finding_count,
            cedar_file.output_path.display(),
        );
        if let Some(err) = validation.error {
            eprintln!("       ⚠ Cedar parse warning: {err}");
            validation_warnings += 1;
        }
    }

    eprintln!(
        "\nGenerated {total_files} Cedar files from {} findings.",
        findings.len(),
    );
    if validation_warnings > 0 {
        eprintln!(
            "{validation_warnings} file(s) have Cedar syntax warnings — review before deploying.",
        );
    }
    Ok(())
}

/// Write a policy file with TOCTOU-safe path-traversal containment.
/// Canonicalise the parent (which we just created) and verify it stays
/// inside the already-canonicalized `output_dir` before writing. Callers
/// canonicalize `output_dir` once before the per-file loop and pass it in
/// here.
fn write_policy_file(output_path: &Path, content: &str, canonical_output_dir: &Path) -> Result<()> {
    let parent = output_path.parent().ok_or_else(|| {
        ZiftError::General(format!(
            "output path '{}' has no parent",
            output_path.display()
        ))
    })?;
    std::fs::create_dir_all(parent)?;
    let canonical_parent = parent.canonicalize().map_err(|e| {
        ZiftError::General(format!(
            "failed to resolve parent dir '{}': {e}",
            parent.display()
        ))
    })?;
    if !canonical_parent.starts_with(canonical_output_dir) {
        return Err(ZiftError::General(format!(
            "output path '{}' escapes output directory '{}'",
            output_path.display(),
            canonical_output_dir.display()
        )));
    }
    std::fs::write(output_path, content)?;
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

    if let Ok(report) = serde_json::from_str::<ScanInput>(&json_str) {
        Ok(report.findings)
    } else {
        serde_json::from_str::<Vec<Finding>>(&json_str)
            .map_err(|e| ZiftError::General(format!("failed to parse findings JSON: {e}")))
    }
}
