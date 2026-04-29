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

#![allow(dead_code)] // wired into the binary in commit 6

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

        let response = req.send()?;
        let status = response.status();
        if !status.is_success() {
            // Auth errors get distinct surfacing; everything else is generic.
            if status.as_u16() == 401 || status.as_u16() == 403 {
                return Err(DeepError::Config(format!(
                    "auth rejected by {} ({})",
                    self.base_url, status
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

        // Try to parse the message content as our findings envelope.
        // Some servers wrap JSON in markdown fences; strip those if present.
        let content_clean = strip_markdown_fence(&content);
        let parsed: FindingsEnvelope = serde_json::from_str(content_clean).map_err(|e| {
            DeepError::BadResponse(format!(
                "content was not valid findings JSON: {e}; got: {}",
                truncate_for_log(&content)
            ))
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

/// Strip a leading/trailing ```json``` (or ```) markdown fence if present.
/// Some local models wrap JSON in fences despite system-prompt instructions
/// not to.
fn strip_markdown_fence(s: &str) -> &str {
    let trimmed = s.trim();
    let after_fence = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .unwrap_or(trimmed);
    after_fence
        .trim()
        .strip_suffix("```")
        .unwrap_or(after_fence)
        .trim()
}

fn truncate_for_log(s: &str) -> String {
    const MAX: usize = 200;
    if s.len() <= MAX {
        s.to_string()
    } else {
        format!("{}...", &s[..MAX])
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
}
