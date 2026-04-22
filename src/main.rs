mod cli;
mod commands;
mod config;
mod error;
mod logging;
mod output;
mod rules;
mod scanner;
mod types;

use clap::Parser;

use cli::Cli;

fn main() {
    let cli = Cli::parse();
    logging::init(cli.verbose);

    if let Err(e) = run(cli) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> error::Result<()> {
    let config = config::load_config(&cli.config)?;
    commands::dispatch(cli, config)
}
