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
use crate::types::Language;

/// Resolved runtime configuration for the deep (semantic) scan.
///
/// `Debug` is implemented manually to redact `api_key` — derive(Debug) would
/// allow the secret to leak through any `tracing::debug!("{runtime:?}")`
/// call site (none today, but defense in depth).
#[derive(Clone)]
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
    /// Glob exclude patterns merged from `--exclude` and `[scan].exclude`.
    /// Forwarded to cold-region file discovery so deep mode honors the same
    /// scope users set for the structural pass.
    pub excludes: Vec<String>,
    /// Language filter from `--language`. Empty == all languages. Forwarded
    /// to cold-region file discovery.
    pub language_filter: Vec<Language>,
}

impl std::fmt::Debug for DeepRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepRuntime")
            .field("base_url", &self.base_url)
            .field("model", &self.model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field("max_cost_usd", &self.max_cost_usd)
            .field("cost_per_1k_input", &self.cost_per_1k_input)
            .field("cost_per_1k_output", &self.cost_per_1k_output)
            .field("request_timeout_secs", &self.request_timeout_secs)
            .field("max_candidates", &self.max_candidates)
            .field("max_concurrent", &self.max_concurrent)
            .field("temperature", &self.temperature)
            .field("max_prompt_chars", &self.max_prompt_chars)
            .field("excludes", &self.excludes)
            .field("language_filter", &self.language_filter)
            .finish()
    }
}

/// Reject NaN, infinite, or negative values in cost-related config so
/// downstream spend tracking cannot receive nonsense (e.g. `f64::NAN`
/// silently propagates through arithmetic and breaks the cap).
fn validate_non_negative_finite(name: &str, v: Option<f64>) -> Result<Option<f64>, DeepError> {
    if let Some(x) = v
        && (!x.is_finite() || x < 0.0)
    {
        return Err(DeepError::Config(format!(
            "{name} must be a non-negative finite number (got {x})"
        )));
    }
    Ok(v)
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
    let max_cost_usd =
        validate_non_negative_finite("max_cost", args.max_cost.or(config.deep.max_cost))?;
    let cost_per_1k_input =
        validate_non_negative_finite("cost_per_1k_input", config.deep.cost_per_1k_input)?;
    let cost_per_1k_output =
        validate_non_negative_finite("cost_per_1k_output", config.deep.cost_per_1k_output)?;

    // Warn if a cap is set but no rates are configured — the tracker
    // short-circuits when both rates are 0, so the cap would never bind.
    let no_rates =
        cost_per_1k_input.unwrap_or(0.0) == 0.0 && cost_per_1k_output.unwrap_or(0.0) == 0.0;
    if max_cost_usd.is_some() && no_rates {
        tracing::warn!(
            "--max-cost is set but [deep] cost_per_1k_input / \
             cost_per_1k_output are not configured in .zift.toml — spend \
             tracking is a no-op without rates"
        );
    }

    let max_concurrent = if is_localhost(&base_url) {
        DEFAULT_LOCAL_CONCURRENCY
    } else {
        DEFAULT_REMOTE_CONCURRENCY
    };

    // Merge excludes from config + CLI; preserve CLI ordering after config.
    let mut excludes = config.scan.exclude.clone();
    excludes.extend(args.exclude.iter().cloned());

    Ok(DeepRuntime {
        base_url,
        model,
        api_key,
        max_cost_usd,
        cost_per_1k_input,
        cost_per_1k_output,
        request_timeout_secs: DEFAULT_REQUEST_TIMEOUT_SECS,
        max_candidates: DEFAULT_MAX_CANDIDATES,
        max_concurrent,
        temperature: DEFAULT_TEMPERATURE,
        max_prompt_chars: DEFAULT_MAX_PROMPT_CHARS,
        excludes,
        language_filter: args.language.clone(),
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
            ..DeepConfig::default()
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
            ..DeepConfig::default()
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
            ..DeepConfig::default()
        });
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.max_cost_usd, Some(0.5));
    }

    #[test]
    fn negative_cost_field_rejected() {
        let args = args_with(Some("http://x/v1"), Some("m"), None, Some(-1.0));
        let err = build(&args, &ZiftConfig::default()).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn nan_cost_rate_rejected() {
        let args = args_with(Some("http://x/v1"), Some("m"), None, None);
        let config = config_with(DeepConfig {
            cost_per_1k_input: Some(f64::NAN),
            ..DeepConfig::default()
        });
        let err = build(&args, &config).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn infinite_cost_rate_rejected() {
        let args = args_with(Some("http://x/v1"), Some("m"), None, None);
        let config = config_with(DeepConfig {
            cost_per_1k_output: Some(f64::INFINITY),
            ..DeepConfig::default()
        });
        let err = build(&args, &config).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn debug_format_redacts_api_key() {
        let runtime = DeepRuntime {
            base_url: "http://x/v1".into(),
            model: "m".into(),
            api_key: Some("sk-supersecret".into()),
            max_cost_usd: None,
            cost_per_1k_input: None,
            cost_per_1k_output: None,
            request_timeout_secs: 60,
            max_candidates: 50,
            max_concurrent: 1,
            temperature: 0.0,
            max_prompt_chars: 16_000,
            excludes: Vec::new(),
            language_filter: Vec::new(),
        };
        let formatted = format!("{runtime:?}");
        assert!(!formatted.contains("sk-supersecret"));
        assert!(formatted.contains("<redacted>"));
    }

    #[test]
    fn cost_rates_loaded_from_config() {
        let args = args_with(Some("http://x/v1"), Some("m"), None, Some(1.0));
        let config = config_with(DeepConfig {
            cost_per_1k_input: Some(0.0002),
            cost_per_1k_output: Some(0.0008),
            ..DeepConfig::default()
        });
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.cost_per_1k_input, Some(0.0002));
        assert_eq!(runtime.cost_per_1k_output, Some(0.0008));
    }

    #[test]
    fn excludes_merged_from_cli_and_config() {
        let mut args = args_with(Some("http://x/v1"), Some("m"), None, None);
        args.exclude = vec!["cli/**".into()];
        let mut zcfg = ZiftConfig::default();
        zcfg.scan.exclude = vec!["config/**".into()];
        zcfg.deep = DeepConfig {
            ..DeepConfig::default()
        };
        let runtime = build(&args, &zcfg).unwrap();
        assert_eq!(runtime.excludes, vec!["config/**", "cli/**"]);
    }

    #[test]
    fn language_filter_passed_through() {
        use crate::types::Language;
        let mut args = args_with(Some("http://x/v1"), Some("m"), None, None);
        args.language = vec![Language::Java, Language::Python];
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(
            runtime.language_filter,
            vec![Language::Java, Language::Python]
        );
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
