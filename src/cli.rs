use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use crate::types::{AuthCategory, Confidence, Language};

#[derive(Parser, Debug)]
#[command(
    name = "zift",
    version,
    about = "Sift through codebases for embedded authorization logic and generate Policy as Code"
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

    /// Generate Policy-as-Code files from findings
    Extract(ExtractArgs),

    /// Generate a detailed report
    Report(ReportArgs),

    /// List, validate, or test pattern rules
    Rules(RulesArgs),

    /// Create a .zift.toml configuration file
    Init(InitArgs),

    /// Run Zift as an MCP server over stdio
    ///
    /// Speaks JSON-RPC 2.0 per the Model Context Protocol spec. Agent hosts
    /// (Claude Code, Cursor, Continue, Cline, Zed, …) call Zift's tools to
    /// scan, render prompts, and validate policies — the host owns the model;
    /// Zift owns the authz expertise.
    Mcp(McpArgs),
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
    /// Base URL of an OpenAI-compatible chat-completions endpoint (requires --deep)
    ///
    /// Examples: http://localhost:11434/v1 (Ollama), http://localhost:1234/v1 (LM Studio),
    /// https://api.openai.com/v1, https://openrouter.ai/api/v1
    #[arg(long, requires = "deep")]
    pub base_url: Option<String>,

    /// Model name to send to the agent endpoint (requires --deep)
    #[arg(long, requires = "deep")]
    pub model: Option<String>,

    /// Maximum spend limit in USD (requires --deep)
    #[arg(long, requires = "deep")]
    pub max_cost: Option<f64>,

    /// API key for the agent endpoint (or set ZIFT_AGENT_API_KEY)
    ///
    /// NOTE: no `requires = "deep"` here — `ZIFT_AGENT_API_KEY` may live in
    /// the shell environment and would otherwise fail every non-deep
    /// invocation. Build-time validation in `deep::config::build` is enough.
    #[arg(long, env = "ZIFT_AGENT_API_KEY")]
    pub api_key: Option<String>,

    /// Shell command line for the subprocess transport (requires --deep)
    ///
    /// Selects the subprocess deep-mode transport: Zift writes a single
    /// JSON envelope `{system, user, schema}` to the command's stdin and
    /// reads the deep-mode JSON response from stdout. Use for agent CLIs
    /// that don't speak the OpenAI HTTP dialect — e.g. `claude -p
    /// --output-format json`, `aider`, or a custom wrapper script.
    ///
    /// Mutually exclusive with --base-url at config-build time (validated
    /// in deep::config::build).
    ///
    /// Examples:
    ///   --agent-cmd "claude -p --output-format json"
    ///   --agent-cmd "./scripts/my-agent.sh"
    #[arg(long, requires = "deep")]
    pub agent_cmd: Option<String>,
}

// -- Extract --

#[derive(Debug, clap::Args)]
pub struct ExtractArgs {
    /// Findings file (default: stdin)
    #[arg(short, long)]
    pub input: Option<PathBuf>,

    /// Directory for generated policy files
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

// -- Mcp --

#[derive(Debug, clap::Args)]
pub struct McpArgs {
    /// Additional pattern rules directory (overlays embedded rules)
    #[arg(long)]
    pub rules_dir: Option<PathBuf>,

    /// Default root used by the `scan_authz` tool when the agent doesn't
    /// supply an explicit path. Tools may scan paths inside this root only.
    #[arg(long, default_value = ".")]
    pub scan_root: PathBuf,
}

// -- Value enums --

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ReportFormat {
    Text,
    Html,
    Markdown,
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

    #[test]
    fn mcp_subcommand_default_scan_root() {
        let cli = Cli::try_parse_from(["zift", "mcp"]).unwrap();
        if let Some(Command::Mcp(args)) = cli.command {
            assert_eq!(args.scan_root, PathBuf::from("."));
            assert!(args.rules_dir.is_none());
        } else {
            panic!("expected Mcp command");
        }
    }

    #[test]
    fn mcp_subcommand_with_rules_dir_and_scan_root() {
        let cli = Cli::try_parse_from([
            "zift",
            "mcp",
            "--rules-dir",
            "./custom-rules",
            "--scan-root",
            "/repo",
        ])
        .unwrap();
        if let Some(Command::Mcp(args)) = cli.command {
            assert_eq!(
                args.rules_dir.as_deref(),
                Some(std::path::Path::new("./custom-rules"))
            );
            assert_eq!(args.scan_root, PathBuf::from("/repo"));
        } else {
            panic!("expected Mcp command");
        }
    }

    #[test]
    fn deep_scan_with_base_url() {
        let cli = Cli::try_parse_from([
            "zift",
            "scan",
            "--deep",
            "--base-url",
            "http://localhost:11434/v1",
            "--model",
            "qwen2.5-coder:14b",
            ".",
        ])
        .unwrap();
        if let Some(Command::Scan(args)) = cli.command {
            assert!(args.deep);
            assert_eq!(args.base_url.as_deref(), Some("http://localhost:11434/v1"));
            assert_eq!(args.model.as_deref(), Some("qwen2.5-coder:14b"));
        } else {
            panic!("expected Scan command");
        }
    }

    #[test]
    fn agent_cmd_requires_deep() {
        // Clap's `requires = "deep"` should reject `--agent-cmd` on
        // its own — without `--deep`, the subprocess transport never
        // gets exercised, so accepting the flag silently would mask a
        // misconfigured invocation.
        let result = Cli::try_parse_from([
            "zift",
            "scan",
            "--agent-cmd",
            "claude -p --output-format json",
            ".",
        ]);
        assert!(
            result.is_err(),
            "expected parse error for --agent-cmd without --deep, got: {result:?}",
        );
    }

    #[test]
    fn agent_cmd_with_deep_parses() {
        // Companion to `agent_cmd_requires_deep`: with `--deep` the
        // flag must round-trip into `ScanArgs`.
        let cli = Cli::try_parse_from([
            "zift",
            "scan",
            "--deep",
            "--agent-cmd",
            "claude -p --output-format json",
            ".",
        ])
        .unwrap();
        if let Some(Command::Scan(args)) = cli.command {
            assert!(args.deep);
            assert_eq!(
                args.agent_cmd.as_deref(),
                Some("claude -p --output-format json"),
            );
        } else {
            panic!("expected Scan command");
        }
    }
}
