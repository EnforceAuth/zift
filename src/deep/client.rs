//! OpenAI-compatible chat-completions HTTP client.
//!
//! POSTs to `{base_url}/chat/completions` with a structured-output request,
//! parses the response into [`SemanticFinding`]s. One client speaks to any
//! backend that exposes the OpenAI dialect (Ollama, LM Studio, llama.cpp,
//! vLLM, OpenRouter, OpenAI itself, Anthropic-via-proxy, …).
//!
//! Implementation lands in commit 5 (where reqwest enters the build).

#![allow(dead_code)]

use crate::deep::config::DeepRuntime;
use crate::deep::error::DeepError;
use crate::deep::finding::SemanticFinding;
use crate::deep::prompt::RenderedPrompt;

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

/// HTTP client for an OpenAI-compatible chat-completions endpoint.
///
/// Fields land in commit 5 (`reqwest::blocking::Client`, base_url, api_key,
/// model, temperature).
pub struct OpenAiCompatibleClient {
    // Body lands in commit 5.
}

impl OpenAiCompatibleClient {
    pub fn new(_runtime: &DeepRuntime) -> Result<Self, DeepError> {
        unimplemented!("OpenAiCompatibleClient::new: commit 5")
    }

    /// Send one prompt to the endpoint, return the parsed findings + usage.
    pub fn analyze(&self, _prompt: &RenderedPrompt) -> Result<AnalyzeResponse, DeepError> {
        unimplemented!("OpenAiCompatibleClient::analyze: commit 5")
    }
}
