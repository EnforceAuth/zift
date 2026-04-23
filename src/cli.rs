use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::types::{AuthCategory, Confidence, Language};

#[derive(Parser, Debug)]
#[command(
    name = "zift",
    version,
    about = "Scan codebases for embedded authorization logic and generate Rego policies for OPA"
)]
#[command(args_conflicts_with_subcommands = true)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,

    #[command(flatten)]
    pub scan_args: Option<ScanArgs>,

    /// Increase logging verbosity (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Path to config file
    #[arg(long, default_value = ".zift.toml", global = true)]
    pub config: PathBuf,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Scan a codebase for embedded authorization logic
    Scan(ScanArgs),

    /// Generate Rego files from findings
    Extract(ExtractArgs),

    /// Generate a detailed report
    Report(ReportArgs),

    /// List, validate, or test pattern rules
    Rules(RulesArgs),

    /// Create a .zift.toml configuration file
    Init(InitArgs),
}

// -- Scan --

#[derive(Debug, Clone, Default, clap::Args)]
pub struct ScanArgs {
    /// Path to scan
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Enable LLM-assisted semantic analysis
    #[arg(long)]
    pub deep: bool,

    /// Filter to specific language(s)
    #[arg(short, long)]
    pub language: Vec<Language>,

    /// Filter to specific auth category(s)
    #[arg(short, long)]
    pub category: Vec<AuthCategory>,

    /// Minimum confidence level
    #[arg(long)]
    pub confidence: Option<Confidence>,

    /// Glob patterns to exclude
    #[arg(short, long)]
    pub exclude: Vec<String>,

    /// Output format
    #[arg(short, long, default_value = "text")]
    pub format: OutputFormat,

    /// Write findings to file (default: stdout)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Additional pattern rules directory
    #[arg(long)]
    pub rules_dir: Option<PathBuf>,

    // -- Deep scan options --
    /// LLM provider (requires --deep)
    #[arg(long)]
    pub provider: Option<LlmProvider>,

    /// Model to use (requires --deep)
    #[arg(long)]
    pub model: Option<String>,

    /// Maximum spend limit for LLM calls (requires --deep)
    #[arg(long)]
    pub max_cost: Option<f64>,

    /// API key (or set ZIFT_API_KEY / provider-specific env vars)
    #[arg(long, env = "ZIFT_API_KEY")]
    pub api_key: Option<String>,
}

// -- Extract --

#[derive(Debug, clap::Args)]
pub struct ExtractArgs {
    /// Findings file (default: stdin)
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Directory for generated .rego files
    #[arg(long, default_value = "./policies/generated")]
    pub output_dir: PathBuf,

    /// Rego package prefix
    #[arg(long, default_value = "app")]
    pub package_prefix: String,

    /// Skip findings below this confidence
    #[arg(long)]
    pub min_confidence: Option<Confidence>,
}

// -- Report --

#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Findings file (default: stdin)
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Report format
    #[arg(short, long, default_value = "text")]
    pub format: ReportFormat,
}

// -- Rules --

#[derive(Debug, clap::Args)]
pub struct RulesArgs {
    #[command(subcommand)]
    pub action: RulesAction,
}

#[derive(Debug, Subcommand)]
pub enum RulesAction {
    /// List all loaded pattern rules
    List,
    /// Check rules for syntax errors
    Validate,
    /// Run rules against test fixtures
    Test,
}

// -- Init --

#[derive(Debug, clap::Args)]
pub struct InitArgs {
    /// Directory to create .zift.toml in
    #[arg(default_value = ".")]
    pub path: PathBuf,
}

// -- Value enums --

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Text,
    Html,
    Markdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LlmProvider {
    Anthropic,
    Openai,
    Ollama,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scan_no_subcommand() {
        let cli = Cli::try_parse_from(["zift", "."]).unwrap();
        assert!(cli.command.is_none());
        let scan = cli.scan_args.unwrap();
        assert_eq!(scan.path, PathBuf::from("."));
        assert!(!scan.deep);
    }

    #[test]
    fn default_scan_no_args() {
        let cli = Cli::try_parse_from(["zift"]).unwrap();
        assert!(cli.command.is_none());
        // No positional arg means scan_args is None; dispatch uses unwrap_or_default
        assert!(cli.scan_args.is_none());
    }

    #[test]
    fn explicit_scan_subcommand() {
        let cli = Cli::try_parse_from(["zift", "scan", "src/"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Scan(_))));
        if let Some(Command::Scan(args)) = cli.command {
            assert_eq!(args.path, PathBuf::from("src/"));
        }
    }

    #[test]
    fn scan_with_deep_flag() {
        let cli = Cli::try_parse_from(["zift", "--deep", "."]).unwrap();
        let scan = cli.scan_args.unwrap();
        assert!(scan.deep);
    }

    #[test]
    fn scan_with_language_filter() {
        let cli = Cli::try_parse_from(["zift", "-l", "java", "-l", "typescript", "."]).unwrap();
        let scan = cli.scan_args.unwrap();
        assert_eq!(scan.language.len(), 2);
    }

    #[test]
    fn extract_subcommand() {
        let cli = Cli::try_parse_from([
            "zift",
            "extract",
            "--input",
            "findings.json",
            "--package-prefix",
            "myapp",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Extract(_))));
    }

    #[test]
    fn report_subcommand() {
        let cli = Cli::try_parse_from([
            "zift",
            "report",
            "--input",
            "findings.json",
            "-f",
            "markdown",
        ])
        .unwrap();
        assert!(matches!(cli.command, Some(Command::Report(_))));
    }

    #[test]
    fn rules_list_subcommand() {
        let cli = Cli::try_parse_from(["zift", "rules", "list"]).unwrap();
        if let Some(Command::Rules(args)) = cli.command {
            assert!(matches!(args.action, RulesAction::List));
        } else {
            panic!("expected Rules command");
        }
    }

    #[test]
    fn init_subcommand() {
        let cli = Cli::try_parse_from(["zift", "init"]).unwrap();
        assert!(matches!(cli.command, Some(Command::Init(_))));
    }

    #[test]
    fn json_output_format() {
        let cli = Cli::try_parse_from(["zift", "-f", "json", "."]).unwrap();
        let scan = cli.scan_args.unwrap();
        assert_eq!(scan.format, OutputFormat::Json);
    }

    #[test]
    fn verbose_flag() {
        let cli = Cli::try_parse_from(["zift", "-vvv", "."]).unwrap();
        assert_eq!(cli.verbose, 3);
    }
}
