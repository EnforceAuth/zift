//! MCP-specific request/response payloads layered on JSON-RPC 2.0.
//!
//! Only the subset of the spec we actually serve: `initialize`, `tools/list`,
//! `tools/call`, `resources/list`, `resources/read`, and the `ping` heartbeat.
//! Everything else returns Method Not Found.
//!
//! Spec: https://spec.modelcontextprotocol.io/specification/2024-11-05/

use serde::{Deserialize, Serialize};
use serde_json::Value;

// -- initialize -----------------------------------------------------------

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct InitializeParams {
    /// The protocol version the client wants to speak. We log it but do not
    /// hard-fail mismatches — the spec lets the server respond with its own
    /// version and the client decides whether to continue.
    #[serde(default)]
    pub protocol_version: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitializeResult {
    pub protocol_version: String,
    pub capabilities: ServerCapabilities,
    pub server_info: ServerInfo,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ServerCapabilities {
    /// Always advertised — `tools/list` and `tools/call` are implemented.
    pub tools: ToolsCapability,
    /// Always advertised — `resources/list` and `resources/read` are implemented.
    pub resources: ResourcesCapability,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCapability {
    /// Whether the tool list can change at runtime. We pre-load rules at
    /// startup so it's effectively static — emit `false` to set the agent
    /// host's expectation correctly.
    pub list_changed: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResourcesCapability {
    pub list_changed: bool,
    /// We don't push subscription notifications.
    pub subscribe: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ServerInfo {
    pub name: String,
    pub version: String,
}

// -- tools/list, tools/call ----------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ToolsListResult {
    pub tools: Vec<ToolDescriptor>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolDescriptor {
    pub name: &'static str,
    pub description: &'static str,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ToolsCallParams {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

/// MCP tools/call response. Tools return content blocks; we use plain text
/// blocks holding a JSON-stringified payload — the agent host parses it.
/// Error responses set `isError: true` and put the message in a text block.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolsCallResult {
    pub content: Vec<ContentBlock>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub is_error: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
}

impl ContentBlock {
    pub fn text(s: impl Into<String>) -> Self {
        ContentBlock::Text { text: s.into() }
    }
}

impl ToolsCallResult {
    pub fn ok(payload: Value) -> Self {
        let s = serde_json::to_string(&payload).expect("payload always serializable");
        Self {
            content: vec![ContentBlock::text(s)],
            is_error: false,
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock::text(message)],
            is_error: true,
        }
    }
}

// -- resources/list, resources/read --------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct ResourcesListResult {
    pub resources: Vec<ResourceDescriptor>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceDescriptor {
    pub uri: String,
    pub name: String,
    pub description: String,
    pub mime_type: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ResourcesReadParams {
    pub uri: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResourcesReadResult {
    pub contents: Vec<ResourceContent>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceContent {
    pub uri: String,
    pub mime_type: &'static str,
    pub text: String,
}
