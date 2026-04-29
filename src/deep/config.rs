//! Resolve CLI args + `.zift.toml` into a runtime config for the deep scan.
//!
//! Precedence (see plans/todo/01-pr1-deep-http-transport.md §2):
//!
//! - `base_url`, `model`, `max_cost`: CLI flag > `[deep]` config > default.
//! - `api_key`: CLI flag > `$ZIFT_AGENT_API_KEY` > unset. **Not** readable
//!   from `.zift.toml` — keys belong in env or CLI, not source-controlled
//!   files.

use crate::cli::ScanArgs;
use crate::config::ZiftConfig;
use crate::deep::error::DeepError;

/// Resolved runtime configuration for the deep (semantic) scan.
#[derive(Debug, Clone)]
pub struct DeepRuntime {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub max_cost_usd: Option<f64>,
    pub cost_per_1k_input: Option<f64>,
    pub cost_per_1k_output: Option<f64>,
    pub request_timeout_secs: u64,
    pub max_candidates: usize,
    pub max_concurrent: usize,
    pub temperature: f32,
    pub max_prompt_chars: usize,
}

const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 120;
const DEFAULT_MAX_CANDIDATES: usize = 50;
const DEFAULT_MAX_PROMPT_CHARS: usize = 16_000;
const DEFAULT_TEMPERATURE: f32 = 0.0;
const DEFAULT_REMOTE_CONCURRENCY: usize = 4;
const DEFAULT_LOCAL_CONCURRENCY: usize = 1;

/// Heuristic check: is this base_url pointing at a local server?
///
/// Used to auto-cap concurrency to 1 — single-GPU local servers serialize
/// internally, so parallelism > 1 just adds queue latency without throughput
/// gain. Users can override via explicit `[deep] max_concurrent = N`.
fn is_localhost(base_url: &str) -> bool {
    let lower = base_url.to_ascii_lowercase();
    lower.contains("://localhost")
        || lower.contains("://127.0.0.1")
        || lower.contains("://[::1]")
        || lower.contains("://0.0.0.0")
}

/// Resolve CLI args + config-file values into a [`DeepRuntime`].
///
/// Validates required fields; returns [`DeepError::Config`] on missing
/// `base_url` or `model`.
pub fn build(args: &ScanArgs, config: &ZiftConfig) -> Result<DeepRuntime, DeepError> {
    let base_url = args
        .base_url
        .clone()
        .or_else(|| config.deep.base_url.clone())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            DeepError::Config(
                "--base-url is required when --deep is set \
                 (or set [deep] base_url in .zift.toml)"
                    .into(),
            )
        })?;

    let model = args
        .model
        .clone()
        .or_else(|| config.deep.model.clone())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            DeepError::Config(
                "--model is required when --deep is set \
                 (or set [deep] model in .zift.toml)"
                    .into(),
            )
        })?;

    let api_key = args.api_key.clone().filter(|s| !s.is_empty());
    let max_cost_usd = args.max_cost.or(config.deep.max_cost);

    let max_concurrent = if is_localhost(&base_url) {
        DEFAULT_LOCAL_CONCURRENCY
    } else {
        DEFAULT_REMOTE_CONCURRENCY
    };

    Ok(DeepRuntime {
        base_url,
        model,
        api_key,
        max_cost_usd,
        cost_per_1k_input: None,
        cost_per_1k_output: None,
        request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        max_candidates: DEFAULT_MAX_CANDIDATES,
        max_concurrent,
        temperature: DEFAULT_TEMPERATURE,
        max_prompt_chars: DEFAULT_MAX_PROMPT_CHARS,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DeepConfig;

    fn args_with(
        base_url: Option<&str>,
        model: Option<&str>,
        api_key: Option<&str>,
        max_cost: Option<f64>,
    ) -> ScanArgs {
        ScanArgs {
            deep: true,
            base_url: base_url.map(String::from),
            model: model.map(String::from),
            api_key: api_key.map(String::from),
            max_cost,
            ..ScanArgs::default()
        }
    }

    fn config_with(deep: DeepConfig) -> ZiftConfig {
        ZiftConfig {
            deep,
            ..ZiftConfig::default()
        }
    }

    #[test]
    fn cli_wins_over_config() {
        let args = args_with(Some("http://cli/v1"), Some("cli-model"), None, None);
        let config = config_with(DeepConfig {
            base_url: Some("http://config/v1".into()),
            model: Some("config-model".into()),
            max_cost: Some(1.0),
        });
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.base_url, "http://cli/v1");
        assert_eq!(runtime.model, "cli-model");
    }

    #[test]
    fn config_used_when_cli_absent() {
        let args = args_with(None, None, None, None);
        let config = config_with(DeepConfig {
            base_url: Some("http://config/v1".into()),
            model: Some("config-model".into()),
            max_cost: Some(2.5),
        });
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.base_url, "http://config/v1");
        assert_eq!(runtime.model, "config-model");
        assert_eq!(runtime.max_cost_usd, Some(2.5));
    }

    #[test]
    fn cli_max_cost_wins_over_config() {
        let args = args_with(Some("http://x/v1"), Some("m"), None, Some(0.5));
        let config = config_with(DeepConfig {
            base_url: None,
            model: None,
            max_cost: Some(10.0),
        });
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.max_cost_usd, Some(0.5));
    }

    #[test]
    fn missing_base_url_errors() {
        let args = args_with(None, Some("m"), None, None);
        let err = build(&args, &ZiftConfig::default()).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn missing_model_errors() {
        let args = args_with(Some("http://x/v1"), None, None, None);
        let err = build(&args, &ZiftConfig::default()).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn empty_base_url_treated_as_missing() {
        let args = args_with(Some(""), Some("m"), None, None);
        let err = build(&args, &ZiftConfig::default()).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn empty_api_key_normalized_to_none() {
        let args = args_with(Some("http://x/v1"), Some("m"), Some(""), None);
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert!(runtime.api_key.is_none());
    }

    #[test]
    fn localhost_caps_concurrency_to_one() {
        let args = args_with(Some("http://localhost:11434/v1"), Some("m"), None, None);
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.max_concurrent, DEFAULT_LOCAL_CONCURRENCY);
    }

    #[test]
    fn loopback_ipv4_caps_concurrency_to_one() {
        let args = args_with(Some("http://127.0.0.1:11434/v1"), Some("m"), None, None);
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.max_concurrent, DEFAULT_LOCAL_CONCURRENCY);
    }

    #[test]
    fn loopback_ipv6_caps_concurrency_to_one() {
        let args = args_with(Some("http://[::1]:8080/v1"), Some("m"), None, None);
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.max_concurrent, DEFAULT_LOCAL_CONCURRENCY);
    }

    #[test]
    fn remote_uses_default_concurrency() {
        let args = args_with(Some("https://api.openai.com/v1"), Some("m"), None, None);
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.max_concurrent, DEFAULT_REMOTE_CONCURRENCY);
    }

    #[test]
    fn default_timeouts_and_limits() {
        let args = args_with(Some("https://x/v1"), Some("m"), None, None);
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.request_timeout_secs, DEFAULT_REQUEST_TIMEOUT_SECS);
        assert_eq!(runtime.max_candidates, DEFAULT_MAX_CANDIDATES);
        assert_eq!(runtime.max_prompt_chars, DEFAULT_MAX_PROMPT_CHARS);
        assert_eq!(runtime.temperature, DEFAULT_TEMPERATURE);
    }
}
