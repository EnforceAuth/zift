//! OpenAI-compatible chat-completions HTTP client.
//!
//! POSTs to `{base_url}/chat/completions` with a structured-output request,
//! parses the response into [`SemanticFinding`]s. One client speaks to any
//! backend that exposes the OpenAI dialect (Ollama, LM Studio, llama.cpp,
//! vLLM, OpenRouter, OpenAI itself, Anthropic-via-proxy, …).
//!
//! On parse failure of the structured-output response, the client retries
//! once **without** `response_format` — many local servers (older Ollama,
//! llama.cpp's `server`) ignore that field and fall back to plain text or
//! emit JSON in the message body anyway. The retry strips the directive
//! and re-parses; if that still fails, we return [`DeepError::BadResponse`].

use crate::deep::config::DeepRuntime;
use crate::deep::error::DeepError;
use crate::deep::finding::SemanticFinding;
use crate::deep::prompt::RenderedPrompt;
use serde::Deserialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[derive(Debug)]
pub struct AnalyzeResponse {
    pub findings: Vec<SemanticFinding>,
    pub usage: TokenUsage,
}

pub struct OpenAiCompatibleClient {
    http: reqwest::blocking::Client,
    base_url: String,
    api_key: Option<String>,
    model: String,
    temperature: f32,
    /// Echoed into `DeepError::Timeout` so the user-visible error states the
    /// configured limit, not just "HTTP error".
    timeout_secs: u64,
}

impl OpenAiCompatibleClient {
    pub fn new(runtime: &DeepRuntime) -> Result<Self, DeepError> {
        let http = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(runtime.request_timeout_secs))
            .build()
            .map_err(|e| DeepError::Config(format!("failed to build HTTP client: {e}")))?;

        Ok(Self {
            http,
            base_url: runtime.base_url.trim_end_matches('/').to_string(),
            api_key: runtime.api_key.clone(),
            model: runtime.model.clone(),
            temperature: runtime.temperature,
            timeout_secs: runtime.request_timeout_secs,
        })
    }

    /// Send one prompt to the endpoint and parse the response. Retries once
    /// without `response_format` if the first attempt's content fails to
    /// parse as our findings schema.
    pub fn analyze(&self, prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError> {
        match self.try_analyze(prompt, true) {
            Ok(resp) => Ok(resp),
            Err(DeepError::BadResponse(msg)) => {
                tracing::debug!("deep: retrying without response_format after bad JSON: {msg}");
                self.try_analyze(prompt, false)
            }
            Err(other) => Err(other),
        }
    }

    fn try_analyze(
        &self,
        prompt: &RenderedPrompt,
        with_response_format: bool,
    ) -> Result<AnalyzeResponse, DeepError> {
        let url = format!("{}/chat/completions", self.base_url);

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user",   "content": prompt.user}
            ],
            "temperature": self.temperature,
        });
        if with_response_format {
            body["response_format"] = serde_json::json!({
                "type": "json_schema",
                "json_schema": {
                    "name": "zift_findings",
                    "strict": true,
                    "schema": prompt.schema,
                }
            });
        }

        let mut req = self.http.post(&url).json(&body);
        if let Some(key) = &self.api_key {
            req = req.bearer_auth(key);
        }

        // Distinguish timeouts from generic HTTP errors so the orchestrator
        // can surface a specific message ("request timed out after Ns")
        // rather than the opaque "HTTP error: ...".
        let response = match req.send() {
            Ok(r) => r,
            Err(e) if e.is_timeout() => {
                return Err(DeepError::Timeout {
                    secs: self.timeout_secs,
                });
            }
            Err(e) => return Err(DeepError::Http(e)),
        };
        let status = response.status();
        if !status.is_success() {
            let code = status.as_u16();
            // Auth errors get distinct surfacing.
            if code == 401 || code == 403 {
                return Err(DeepError::Config(format!(
                    "auth rejected by {} ({})",
                    self.base_url, status
                )));
            }
            // 400/422 on a request that included `response_format` is the
            // signature of a backend that hard-fails unsupported structured
            // output (vs. the more common case of silently ignoring it).
            // Surface as `BadResponse` so `analyze()`'s retry path strips
            // the schema and tries again. On the no-schema retry, this same
            // status code falls through to the generic Config error below.
            if with_response_format && (code == 400 || code == 422) {
                return Err(DeepError::BadResponse(format!(
                    "server rejected response_format ({status}); retrying without schema"
                )));
            }
            // 5xx is a transient/server-side failure, not misconfiguration.
            // Surface as `Transient` so the orchestrator's per-candidate
            // skip path takes it instead of aborting the entire deep run
            // (which `Config` would do — that bucket is reserved for
            // operator-actionable misconfiguration). NOT `BadResponse`,
            // because that triggers `analyze()`'s schema-fallback retry —
            // removing `response_format` cannot fix a 5xx, so retrying
            // just doubles traffic during outages.
            if status.is_server_error() {
                return Err(DeepError::Transient(format!(
                    "upstream {} from {}",
                    status, self.base_url
                )));
            }
            // 429 Too Many Requests is transient (rate-limit / quota), same
            // bucket as 5xx — skip the candidate, do NOT trigger the
            // schema-fallback retry (it would just re-hit the rate limit).
            if code == 429 {
                return Err(DeepError::Transient(format!(
                    "upstream rate-limited ({} from {})",
                    status, self.base_url
                )));
            }
            return Err(DeepError::Config(format!(
                "HTTP {} from {}",
                status, self.base_url
            )));
        }

        let body: ChatCompletionResponse = response
            .json()
            .map_err(|e| DeepError::BadResponse(format!("response was not valid JSON: {e}")))?;

        let content = body
            .choices
            .into_iter()
            .next()
            .and_then(|c| c.message.content)
            .ok_or_else(|| DeepError::BadResponse("response had no message content".into()))?;

        // Parse the message content as our findings envelope. Strip any
        // markdown fence first (some local models add them despite the
        // system prompt). Keep the returned error generic — the model may
        // have mirrored prompt content back, and we don't want user source
        // code (or other sensitive content) embedded in every BadResponse
        // error string. The truncated payload sample is emitted at debug
        // level instead, behind the operator's tracing filter.
        let content_clean = strip_markdown_fence(&content);
        let parsed: FindingsEnvelope = serde_json::from_str(content_clean).map_err(|e| {
            tracing::debug!(
                error = %e,
                preview = %truncate_for_log(&content),
                "deep: model response was not valid findings JSON",
            );
            DeepError::BadResponse("content was not valid findings JSON".into())
        })?;

        let usage = TokenUsage {
            input_tokens: body.usage.as_ref().map(|u| u.prompt_tokens).unwrap_or(0),
            output_tokens: body
                .usage
                .as_ref()
                .map(|u| u.completion_tokens)
                .unwrap_or(0),
        };

        Ok(AnalyzeResponse {
            findings: parsed.findings,
            usage,
        })
    }
}

/// Strip a leading/trailing markdown fence if present, regardless of the
/// optional language tag (` ```json `, ` ```javascript `, plain ` ``` `, …).
/// Some local models wrap JSON in fences despite system-prompt instructions
/// not to.
fn strip_markdown_fence(s: &str) -> &str {
    let trimmed = s.trim();
    let after_fence = match trimmed.strip_prefix("```") {
        Some(rest) => {
            // Drop the language tag (everything up to the first newline) if
            // any, then continue with the remaining content.
            match rest.find('\n') {
                Some(nl) => &rest[nl + 1..],
                None => rest,
            }
        }
        None => trimmed,
    };
    after_fence
        .trim_end()
        .strip_suffix("```")
        .unwrap_or(after_fence)
        .trim()
}

fn truncate_for_log(s: &str) -> String {
    const MAX: usize = 200;
    if s.len() <= MAX {
        s.to_string()
    } else {
        // Round down to a UTF-8 char boundary so we never panic on a
        // multi-byte char straddling MAX (likely on garbage model output).
        let cut = s.floor_char_boundary(MAX);
        format!("{}...", &s[..cut])
    }
}

// -- OpenAI response types -------------------------------------------------

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatChoice>,
    usage: Option<UsageStats>,
}

#[derive(Deserialize)]
struct ChatChoice {
    message: ChatMessage,
}

#[derive(Deserialize)]
struct ChatMessage {
    content: Option<String>,
}

#[derive(Deserialize)]
struct UsageStats {
    prompt_tokens: u32,
    completion_tokens: u32,
}

#[derive(Deserialize)]
struct FindingsEnvelope {
    findings: Vec<SemanticFinding>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_fence_handles_json_fence() {
        let raw = "```json\n{\"findings\": []}\n```";
        assert_eq!(strip_markdown_fence(raw), "{\"findings\": []}");
    }

    #[test]
    fn strip_fence_handles_plain_fence() {
        let raw = "```\n{\"findings\": []}\n```";
        assert_eq!(strip_markdown_fence(raw), "{\"findings\": []}");
    }

    #[test]
    fn strip_fence_passes_through_when_absent() {
        let raw = "{\"findings\": []}";
        assert_eq!(strip_markdown_fence(raw), raw);
    }

    #[test]
    fn strip_fence_handles_leading_whitespace() {
        let raw = "  \n```json\n{\"findings\": []}\n```\n  ";
        assert_eq!(strip_markdown_fence(raw), "{\"findings\": []}");
    }

    #[test]
    fn strip_fence_handles_alternative_language_tags() {
        for lang in ["javascript", "ts", "rust", "yaml"] {
            let raw = format!("```{lang}\n{{\"findings\": []}}\n```");
            assert_eq!(
                strip_markdown_fence(&raw),
                "{\"findings\": []}",
                "fence stripper failed for tag: {lang}"
            );
        }
    }

    #[test]
    fn truncate_for_log_short_string_passthrough() {
        assert_eq!(truncate_for_log("hello"), "hello");
    }

    #[test]
    fn truncate_for_log_long_string_clipped() {
        let long = "x".repeat(500);
        let truncated = truncate_for_log(&long);
        assert!(truncated.ends_with("..."));
        assert!(truncated.len() < long.len());
    }

    #[test]
    fn truncate_for_log_handles_multibyte_at_boundary() {
        // 198 ascii + a 4-byte emoji crossing byte 200. Naive [..200] would panic.
        let mut s = "x".repeat(198);
        s.push('🦀'); // 4 bytes
        s.push_str(&"y".repeat(50));
        let truncated = truncate_for_log(&s);
        // No panic, and we didn't slice mid-codepoint.
        assert!(truncated.ends_with("..."));
    }
}
