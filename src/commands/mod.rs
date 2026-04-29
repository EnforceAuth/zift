mod extract;
mod init;
mod mcp;
mod report;
mod rules;
mod scan;

use crate::cli::{Cli, Command};
use crate::config::ZiftConfig;
use crate::error::Result;

pub fn dispatch(cli: Cli, config: ZiftConfig) -> Result<()> {
    match cli.command {
        Some(Command::Scan(args)) => scan::execute(args, config),
        Some(Command::Extract(args)) => extract::execute(args, config),
        Some(Command::Report(args)) => report::execute(args, config),
        Some(Command::Rules(args)) => rules::execute(args, config),
        Some(Command::Init(args)) => init::execute(args),
        Some(Command::Mcp(args)) => mcp::execute(args, config),
        None => {
            let mut args = cli.scan_args.unwrap_or_default();
            if args.path.as_os_str().is_empty() {
                args.path = ".".into();
            }
            scan::execute(args, config)
        }
    }
}
