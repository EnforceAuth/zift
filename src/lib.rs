//! Zift — static analysis for embedded authorization logic.
//!
//! This crate is published as both a binary (`zift`) and a library.
//!
//! # Stable public API
//!
//! The types below form the semver-committed surface. Everything else is
//! internal or opt-in via `--features unstable`.
//!
//! - [`cli`] — CLI argument types (`Cli`, `ScanArgs`, …)
//! - [`error`] — `ZiftError` and `Result<T>`
//! - [`types`] — core data types (`Finding`, `Language`, `AuthCategory`, …)
//! - [`rules`] — rule loading (read-only)
//! - [`rego`] — policy generation; `rego::validator` is the stable surface
//! - [`run`] — binary entry point

// Stable public API
pub mod cli;
pub mod error;
pub mod rego;
pub mod rules;
pub mod types;

// Internal implementation — not accessible to downstream crates; the binary
// reaches these only through `run()` below.
mod commands;
mod logging;

// Internal modules exposed conditionally when the `unstable` feature is
// enabled. Within this crate they are always reachable via `crate::…`.
#[cfg(feature = "unstable")]
pub mod config;
#[cfg(not(feature = "unstable"))]
mod config;

#[cfg(feature = "unstable")]
pub mod deep;
#[cfg(not(feature = "unstable"))]
mod deep;

#[cfg(feature = "unstable")]
pub mod mcp;
#[cfg(not(feature = "unstable"))]
mod mcp;

#[cfg(feature = "unstable")]
pub mod output;
#[cfg(not(feature = "unstable"))]
mod output;

#[cfg(feature = "unstable")]
pub mod scanner;
#[cfg(not(feature = "unstable"))]
mod scanner;

/// Entry point used by the `zift` binary.
///
/// Initialises logging, loads config, and dispatches the CLI command.
pub fn run(cli: cli::Cli) -> error::Result<()> {
    logging::init(cli.verbose);
    let cfg = config::load_config(&cli.config)?;
    commands::dispatch(cli, cfg)
}
