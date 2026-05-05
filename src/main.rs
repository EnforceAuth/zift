use clap::Parser;

use zift::cli::Cli;

fn main() {
    if let Err(e) = zift::run(Cli::parse()) {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}
