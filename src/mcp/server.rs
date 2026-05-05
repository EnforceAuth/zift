//! MCP server dispatch loop.
//!
//! Single-client, single-threaded: stdio means one peer at a time, so there's
//! no need for concurrency or shared state guards. The loop reads a request,
//! dispatches to the appropriate handler, writes a response, repeats — until
//! the peer closes stdin (clean shutdown).
//!
//! Logging is via `tracing`, which writes to stderr by default — never stdout.
//! Tools and resource handlers must follow the same rule: stdout is the wire,
//! it must contain only JSON-RPC frames. (Audit done at PR review time;
//! `scanner::*` and `rules::*` already use only `tracing`.)

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde_json::{Value, json};

use crate::config::ZiftConfig;
use crate::error::Result;
use crate::mcp::jsonrpc::{Request, Response, error_code, read_request, write_response};
use crate::mcp::protocol::*;
use crate::mcp::{MCP_PROTOCOL_VERSION, SERVER_NAME, SERVER_VERSION, resources, tools};
use crate::rules::PatternRule;

/// State shared across MCP request handlers. Constructed once at startup;
/// immutable from the handlers' point of view (they only read).
pub struct ServerContext {
    /// Canonicalized scan-root path. Tool calls must stay inside this root.
    pub scan_root: PathBuf,
    /// Pre-loaded rule library (embedded + any `--rules-dir` overlay).
    pub rules: Vec<PatternRule>,
    pub config: ZiftConfig,
}

/// Run the MCP server against process stdin/stdout. Blocks until the peer
/// closes stdin or an unrecoverable I/O error occurs.
pub fn run(ctx: ServerContext) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    serve(&ctx, &mut reader, &mut writer)
}

/// Inner loop, parameterized over reader/writer for testability.
pub fn serve<R: BufRead, W: Write>(
    ctx: &ServerContext,
    reader: &mut R,
    writer: &mut W,
) -> Result<()> {
    tracing::info!(
        "mcp: server started (protocol={MCP_PROTOCOL_VERSION}, version={SERVER_VERSION})"
    );

    loop {
        let req = match read_request(reader) {
            Ok(Some(r)) => r,
            Ok(None) => {
                tracing::info!("mcp: peer closed stdin, shutting down");
                return Ok(());
            }
            Err(crate::mcp::jsonrpc::FrameError::Io(e)) => {
                // The peer dropped the pipe mid-message or the kernel buffer
                // failed — neither is a Zift bug, but we can't keep serving.
                tracing::warn!("mcp: stdio I/O error, shutting down: {e}");
                return Ok(());
            }
            Err(crate::mcp::jsonrpc::FrameError::Parse { message, .. }) => {
                // Per JSON-RPC 2.0: respond with a parse-error response (id: null)
                // and continue serving subsequent messages.
                let resp = Response::error(Value::Null, error_code::PARSE_ERROR, message);
                if let Err(e) = write_response(writer, &resp) {
                    tracing::warn!("mcp: failed to write parse-error response: {e}");
                    return Ok(());
                }
                continue;
            }
        };

        // Notifications (no `id`) get no response per the spec.
        let id = match req.id.clone() {
            Some(id) => id,
            None => {
                handle_notification(&req);
                continue;
            }
        };

        let resp = handle_request(ctx, &req, id);
        if let Err(e) = write_response(writer, &resp) {
            tracing::warn!("mcp: failed to write response, shutting down: {e}");
            return Ok(());
        }
    }
}

fn handle_notification(req: &Request) {
    // The only notification we expect is `notifications/initialized` — fire
    // it back to debug-level so it doesn't pollute stderr but is observable
    // when the user runs with `-vv`.
    tracing::debug!("mcp: received notification: {}", req.method);
}

/// Dispatch a single MCP request to its handler. Returns a fully-formed
/// `Response` ready to be written.
pub fn handle_request(ctx: &ServerContext, req: &Request, id: Value) -> Response {
    let result = match req.method.as_str() {
        "initialize" => handle_initialize(req)
            .map(|r| serde_json::to_value(r).expect("InitializeResult is always serializable")),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(serde_json::to_value(tools::list_tools())
            .expect("ToolsListResult is always serializable")),
        "tools/call" => handle_tools_call(ctx, req),
        "resources/list" => Ok(serde_json::to_value(resources::list_resources(ctx))
            .expect("ResourcesListResult is always serializable")),
        "resources/read" => handle_resources_read(ctx, req),
        other => {
            return Response::error(
                id,
                error_code::METHOD_NOT_FOUND,
                format!("unknown method: {other}"),
            );
        }
    };

    match result {
        Ok(value) => Response::success(id, value),
        Err(HandlerError::InvalidParams(msg)) => {
            Response::error(id, error_code::INVALID_PARAMS, msg)
        }
        Err(HandlerError::Internal(msg)) => Response::error(id, error_code::INTERNAL_ERROR, msg),
    }
}

/// Errors a handler can return at the JSON-RPC layer (distinct from tool
/// errors, which are surfaced inside a `tools/call` result with `isError: true`).
#[derive(Debug)]
#[allow(dead_code)] // `Internal` matched in dispatch; reserved for future handlers
pub enum HandlerError {
    InvalidParams(String),
    Internal(String),
}

fn handle_initialize(req: &Request) -> std::result::Result<InitializeResult, HandlerError> {
    let params: InitializeParams = match req.params.clone() {
        Some(p) => serde_json::from_value(p)
            .map_err(|e| HandlerError::InvalidParams(format!("initialize params: {e}")))?,
        None => InitializeParams::default(),
    };
    if let Some(client_version) = &params.protocol_version
        && client_version != MCP_PROTOCOL_VERSION
    {
        tracing::info!(
            "mcp: client requested protocol {client_version}, \
             server speaks {MCP_PROTOCOL_VERSION}; client decides whether to continue"
        );
    }
    Ok(InitializeResult {
        protocol_version: MCP_PROTOCOL_VERSION.to_string(),
        capabilities: ServerCapabilities {
            tools: ToolsCapability {
                list_changed: false,
            },
            resources: ResourcesCapability {
                list_changed: false,
                subscribe: false,
            },
        },
        server_info: ServerInfo {
            name: SERVER_NAME.to_string(),
            version: SERVER_VERSION.to_string(),
        },
    })
}

fn handle_tools_call(
    ctx: &ServerContext,
    req: &Request,
) -> std::result::Result<Value, HandlerError> {
    let params: ToolsCallParams = req
        .params
        .clone()
        .ok_or_else(|| HandlerError::InvalidParams("tools/call requires params".into()))
        .and_then(|p| {
            serde_json::from_value(p)
                .map_err(|e| HandlerError::InvalidParams(format!("tools/call params: {e}")))
        })?;

    let result = tools::dispatch(ctx, &params.name, &params.arguments);
    Ok(serde_json::to_value(result).expect("ToolsCallResult is always serializable"))
}

fn handle_resources_read(
    ctx: &ServerContext,
    req: &Request,
) -> std::result::Result<Value, HandlerError> {
    let params: ResourcesReadParams = req
        .params
        .clone()
        .ok_or_else(|| HandlerError::InvalidParams("resources/read requires params".into()))
        .and_then(|p| {
            serde_json::from_value(p)
                .map_err(|e| HandlerError::InvalidParams(format!("resources/read params: {e}")))
        })?;

    let content = resources::read_resource(ctx, &params.uri).ok_or_else(|| {
        HandlerError::InvalidParams(format!("unknown resource uri: {}", params.uri))
    })?;
    // MCP spec wraps every resources/read response as `{contents: [...]}`,
    // even for single-document URIs. Our resources are all singletons today,
    // but the wire shape is fixed by the spec.
    let result = ResourcesReadResult {
        contents: vec![content],
    };
    Ok(serde_json::to_value(result).expect("ResourcesReadResult is always serializable"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::load_rules;
    use std::io::Cursor;

    fn test_ctx() -> ServerContext {
        let config = ZiftConfig::default();
        let rules = load_rules(None, &config).unwrap();
        ServerContext {
            scan_root: std::env::current_dir().unwrap(),
            rules,
            config,
        }
    }

    fn rpc(method: &str, id: i64, params: Option<Value>) -> Vec<u8> {
        let mut body = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
        });
        if let Some(p) = params {
            body["params"] = p;
        }
        let mut bytes = serde_json::to_vec(&body).unwrap();
        bytes.push(b'\n');
        bytes
    }

    fn parse_responses(buf: &[u8]) -> Vec<Value> {
        String::from_utf8_lossy(buf)
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| serde_json::from_str(l).expect("each line should be valid JSON"))
            .collect()
    }

    #[test]
    fn serve_handshake_returns_initialize_result() {
        let ctx = test_ctx();
        let input = rpc(
            "initialize",
            1,
            Some(json!({"protocolVersion": "2024-11-05"})),
        );
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        serve(&ctx, &mut reader, &mut writer).unwrap();
        let resps = parse_responses(&writer);
        assert_eq!(resps.len(), 1);
        let r = &resps[0];
        assert_eq!(r["jsonrpc"], "2.0");
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
        assert_eq!(r["result"]["serverInfo"]["name"], SERVER_NAME);
        assert!(r["result"]["capabilities"]["tools"].is_object());
        assert!(r["result"]["capabilities"]["resources"].is_object());
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let ctx = test_ctx();
        let input = rpc("does/not/exist", 7, None);
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        serve(&ctx, &mut reader, &mut writer).unwrap();
        let resps = parse_responses(&writer);
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0]["error"]["code"], error_code::METHOD_NOT_FOUND);
    }

    #[test]
    fn parse_error_does_not_halt_loop() {
        // First line: garbage. Second line: valid ping. Server should reply
        // to both — parse error to the first, ok to the second.
        let mut input: Vec<u8> = b"not json\n".to_vec();
        input.extend(rpc("ping", 2, None));
        let ctx = test_ctx();
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        serve(&ctx, &mut reader, &mut writer).unwrap();
        let resps = parse_responses(&writer);
        assert_eq!(resps.len(), 2);
        assert_eq!(resps[0]["error"]["code"], error_code::PARSE_ERROR);
        assert_eq!(resps[0]["id"], Value::Null);
        assert_eq!(resps[1]["id"], 2);
        assert!(resps[1]["result"].is_object());
    }

    #[test]
    fn notification_produces_no_response() {
        // Spec: notifications (no id) MUST NOT produce a response.
        let ctx = test_ctx();
        let mut input = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
        }))
        .unwrap();
        input.push(b'\n');
        // Follow with a ping so we know the loop is still alive.
        input.extend(rpc("ping", 9, None));
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        serve(&ctx, &mut reader, &mut writer).unwrap();
        let resps = parse_responses(&writer);
        // Only the ping reply, not the notification.
        assert_eq!(resps.len(), 1);
        assert_eq!(resps[0]["id"], 9);
    }

    #[test]
    fn tools_list_returns_seven_tools() {
        let ctx = test_ctx();
        let input = rpc("tools/list", 1, None);
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        serve(&ctx, &mut reader, &mut writer).unwrap();
        let resps = parse_responses(&writer);
        let tool_names: Vec<&str> = resps[0]["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(tool_names.contains(&"scan_authz"));
        assert!(tool_names.contains(&"get_finding_context"));
        assert!(tool_names.contains(&"list_rules"));
        assert!(tool_names.contains(&"get_rule"));
        assert!(tool_names.contains(&"suggest_rego"));
        assert!(tool_names.contains(&"validate_rego"));
        assert!(tool_names.contains(&"analyze_snippet"));
    }

    #[test]
    fn resources_list_returns_static_singletons() {
        let ctx = test_ctx();
        let input = rpc("resources/list", 1, None);
        let mut reader = Cursor::new(input);
        let mut writer: Vec<u8> = Vec::new();
        serve(&ctx, &mut reader, &mut writer).unwrap();
        let resps = parse_responses(&writer);
        let uris: Vec<String> = resps[0]["result"]["resources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["uri"].as_str().unwrap().to_string())
            .collect();
        assert!(uris.contains(&"prompt://system".to_string()));
        assert!(uris.contains(&"prompt://schema".to_string()));
        // At least one rule:// and at least one category://
        assert!(uris.iter().any(|u| u.starts_with("rule://")));
        assert!(uris.iter().any(|u| u.starts_with("category://")));
    }
}
