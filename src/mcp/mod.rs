//! MCP (Model Context Protocol) server — Tier 1 deep-scan transport.
//!
//! See `plans/done/02-pr2-mcp-server.md` for the design. The server speaks
//! JSON-RPC 2.0 over stdio per the MCP spec (protocol version 2024-11-05),
//! exposing Zift's authz primitives — rule library, structural scanner,
//! prompt renderer, Rego validator — to any MCP-capable agent host
//! (Claude Code, Cursor, Continue, Cline, Zed, …).
//!
//! Architectural rule: this module is a transport. It contains zero authz
//! logic, zero prompt content, zero candidate-selection rules — those all
//! live under [`crate::deep`] and [`crate::rules`] and are imported here
//! verbatim.
//!
//! Coding rule: production code in this module forbids `.unwrap()`. Use
//! `.expect("…")` with a message that documents *why* the call is infallible,
//! or propagate the error. Tests are allowed to `unwrap` (panic = test
//! failure). Enforced by `clippy::unwrap_used` + `allow-unwrap-in-tests` in
//! the workspace `clippy.toml`.

#![warn(clippy::unwrap_used)]

pub mod jsonrpc;
pub mod protocol;
pub mod resources;
pub mod server;
pub mod tools;

/// MCP protocol version this server speaks. Pinned to a stable spec date
/// rather than tracking the floating "current" — agent hosts negotiate via
/// `initialize` and we want predictable behavior.
///
/// Spec: https://spec.modelcontextprotocol.io/specification/2024-11-05/
pub const MCP_PROTOCOL_VERSION: &str = "2024-11-05";

/// Server identifier reported in the `initialize` response.
pub const SERVER_NAME: &str = "zift";

/// Server version reported in the `initialize` response. Tracks the crate
/// version so agent hosts can correlate behavior with a release.
pub const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");
