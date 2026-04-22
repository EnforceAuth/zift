use crate::cli::ExtractArgs;
use crate::config::ZiftConfig;
use crate::error::Result;

pub fn execute(_args: ExtractArgs, _config: ZiftConfig) -> Result<()> {
    eprintln!("extract command not yet implemented");
    Ok(())
}
