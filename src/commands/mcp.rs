//! `zift mcp` subcommand entry point — wires CLI args to the MCP server.

use crate::cli::McpArgs;
use crate::config::ZiftConfig;
use crate::error::{Result, ZiftError};
use crate::mcp;
use crate::rules;

pub fn execute(args: McpArgs, config: ZiftConfig) -> Result<()> {
    // Resolve scan_root eagerly so we fail fast on a bad path. Subsequent
    // tool calls assume a valid, canonicalized root for path-containment
    // checks (defense against `..` traversal in `scan_path` arguments).
    let scan_root = args.scan_root.canonicalize().map_err(|e| {
        ZiftError::General(format!(
            "failed to resolve --scan-root '{}': {e}",
            args.scan_root.display()
        ))
    })?;

    // Pre-load rules so tool calls don't pay the parse cost on every request
    // and so a misconfigured rules-dir surfaces at startup, not later.
    let loaded_rules = rules::load_rules(args.rules_dir.as_deref(), &config)?;
    tracing::info!(
        "mcp: loaded {} pattern rules; scan_root={}",
        loaded_rules.len(),
        scan_root.display(),
    );

    mcp::server::run(mcp::server::ServerContext {
        scan_root,
        rules: loaded_rules,
        rules_dir: args.rules_dir,
        config,
    })
}
