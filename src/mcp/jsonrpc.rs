//! JSON-RPC 2.0 over stdio — wire types and line-delimited framing.
//!
//! The MCP spec layers JSON-RPC 2.0 over stdio with each message on its own
//! line (newline-delimited JSON), so framing is just `BufRead::read_line` →
//! parse → dispatch → `writeln!` on stdout. No Content-Length headers.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::io::{BufRead, Write};

/// Standard JSON-RPC 2.0 error codes (-32700 … -32600 reserved).
pub mod error_code {
    pub const PARSE_ERROR: i32 = -32700;
    pub const INVALID_REQUEST: i32 = -32600;
    pub const METHOD_NOT_FOUND: i32 = -32601;
    pub const INVALID_PARAMS: i32 = -32602;
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// A JSON-RPC request. `id` is absent for notifications.
#[derive(Debug, Clone, Deserialize)]
pub struct Request {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Option<Value>,
    /// `None` for notifications, `Some` for requests requiring a response.
    #[serde(default)]
    pub id: Option<Value>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Response {
    pub jsonrpc: &'static str,
    /// Echoed from the request. `Null` if the request id couldn't be parsed.
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorObject {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl Response {
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            result: None,
            error: Some(ErrorObject {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Read one line of input and parse it as a JSON-RPC request.
///
/// Returns:
/// - `Ok(Some(req))` — parsed a request
/// - `Ok(None)` — clean EOF (peer closed stdin); caller should shut down
/// - `Err(FrameError::Io)` — I/O failure on stdin
/// - `Err(FrameError::Parse)` — line was not valid JSON-RPC; caller should
///   respond with a parse-error response (id: null) and continue serving
pub fn read_request<R: BufRead>(reader: &mut R) -> Result<Option<Request>, FrameError> {
    let mut buf = String::new();
    let n = reader.read_line(&mut buf).map_err(FrameError::Io)?;
    if n == 0 {
        return Ok(None);
    }
    let trimmed = buf.trim();
    // Tolerate keepalive blanks — agent hosts sometimes send them between
    // sessions, and a strict parser rejecting them would break the loop.
    if trimmed.is_empty() {
        return read_request(reader);
    }
    let req: Request = serde_json::from_str(trimmed).map_err(|e| FrameError::Parse {
        message: e.to_string(),
        raw: trimmed.to_string(),
    })?;
    if req.jsonrpc != "2.0" {
        return Err(FrameError::Parse {
            message: format!("unexpected jsonrpc version: {}", req.jsonrpc),
            raw: trimmed.to_string(),
        });
    }
    Ok(Some(req))
}

/// Write a response as a single JSON line + `\n` and flush. The MCP spec
/// requires each message to be on its own line, so we serialize compactly
/// and append exactly one newline.
pub fn write_response<W: Write>(writer: &mut W, resp: &Response) -> std::io::Result<()> {
    let line = serde_json::to_string(resp).expect("Response always serializable");
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    Parse { message: String, raw: String },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "stdio I/O error: {e}"),
            FrameError::Parse { message, .. } => write!(f, "JSON-RPC parse error: {message}"),
        }
    }
}

impl std::error::Error for FrameError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_request_parses_a_well_formed_line() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut reader = Cursor::new(input.to_vec());
        let req = read_request(&mut reader).unwrap().unwrap();
        assert_eq!(req.method, "ping");
        assert_eq!(req.id, Some(Value::from(1)));
    }

    #[test]
    fn read_request_returns_none_on_clean_eof() {
        let mut reader = Cursor::new(Vec::new());
        let res = read_request(&mut reader).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn read_request_skips_blank_lines() {
        let input = b"\n\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut reader = Cursor::new(input.to_vec());
        let req = read_request(&mut reader).unwrap().unwrap();
        assert_eq!(req.method, "ping");
    }

    #[test]
    fn read_request_rejects_wrong_jsonrpc_version() {
        let input = b"{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}\n";
        let mut reader = Cursor::new(input.to_vec());
        let err = read_request(&mut reader).unwrap_err();
        assert!(matches!(err, FrameError::Parse { .. }));
    }

    #[test]
    fn read_request_returns_parse_error_on_garbage() {
        let input = b"not json\n";
        let mut reader = Cursor::new(input.to_vec());
        let err = read_request(&mut reader).unwrap_err();
        assert!(matches!(err, FrameError::Parse { .. }));
    }

    #[test]
    fn notification_has_no_id() {
        // Spec: notifications are requests with no `id` field at all.
        let input = b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n";
        let mut reader = Cursor::new(input.to_vec());
        let req = read_request(&mut reader).unwrap().unwrap();
        assert!(req.id.is_none());
        assert_eq!(req.method, "notifications/initialized");
    }

    #[test]
    fn write_response_appends_single_newline() {
        let resp = Response::success(Value::from(1), serde_json::json!({"ok": true}));
        let mut buf: Vec<u8> = Vec::new();
        write_response(&mut buf, &resp).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.ends_with('\n'));
        assert_eq!(s.matches('\n').count(), 1);
        // Ensure the body is valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(s.trim()).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 1);
        assert_eq!(parsed["result"]["ok"], true);
    }

    #[test]
    fn write_response_serializes_error_form() {
        let resp = Response::error(
            Value::from(2),
            error_code::METHOD_NOT_FOUND,
            "no such method",
        );
        let mut buf: Vec<u8> = Vec::new();
        write_response(&mut buf, &resp).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&buf).unwrap();
        assert_eq!(parsed["error"]["code"], -32601);
        assert_eq!(parsed["error"]["message"], "no such method");
        // Result field should be omitted on the error path.
        assert!(parsed.get("result").is_none() || parsed["result"].is_null());
    }
}
