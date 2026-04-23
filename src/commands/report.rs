use crate::cli::ReportArgs;
use crate::config::ZiftConfig;
use crate::error::Result;

pub fn execute(_args: ReportArgs, _config: ZiftConfig) -> Result<()> {
    eprintln!("Report not yet implemented.");
    Ok(())
}
