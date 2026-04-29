//! Zift — static analysis for embedded authorization logic.
//!
//! This crate is published as both a binary (`zift`) and a library. The
//! binary at `src/main.rs` is a thin shim over the library; downstream
//! consumers (e.g. the MCP server in PR 2) can depend on the library.

pub mod cli;
pub mod commands;
pub mod config;
pub mod deep;
pub mod error;
pub mod logging;
pub mod mcp;
pub mod output;
pub mod rego;
pub mod rules;
pub mod scanner;
pub mod types;
