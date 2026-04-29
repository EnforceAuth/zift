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

/// Which transport [`crate::deep::run`] dispatches to per request.
///
/// Resolution lives in [`build`] — `--agent-cmd` on the CLI implies
/// [`DeepMode::Subprocess`], `--base-url` implies [`DeepMode::Http`], and
/// `[deep] mode = "..."` in `.zift.toml` is honored when no CLI flag
/// pins the choice. Default is [`DeepMode::Http`] — preserves the
/// behavior shipped in PR 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeepMode {
    /// OpenAI-compatible chat-completions over HTTP. PR 1's transport.
    Http,
    /// Spawn an arbitrary command per request; speak the JSON envelope
    /// contract over stdin/stdout. PR 3's transport.
    Subprocess,
}

/// Resolved runtime configuration for the deep (semantic) scan.
///
/// `Debug` is implemented manually to redact `api_key` — derive(Debug) would
/// allow the secret to leak through any `tracing::debug!("{runtime:?}")`
/// call site (none today, but defense in depth).
#[derive(Clone)]
pub struct DeepRuntime {
    /// Selected transport. See [`DeepMode`].
    pub mode: DeepMode,
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
    /// Shell command line invoked per request when [`Self::mode`] is
    /// [`DeepMode::Subprocess`]. `None` for HTTP. Validated to be present
    /// in [`build`] when subprocess mode is selected.
    pub agent_cmd: Option<String>,
    /// Per-request timeout for the subprocess transport. Distinct from
    /// [`Self::request_timeout_secs`] (HTTP) because LLM CLIs are
    /// noticeably slower than HTTP — `claude -p` cold-starts can take
    /// 30+ seconds before producing a token.
    pub agent_timeout_secs: u64,
}

impl std::fmt::Debug for DeepRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeepRuntime")
            .field("mode", &self.mode)
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
            .field("agent_cmd", &self.agent_cmd)
            .field("agent_timeout_secs", &self.agent_timeout_secs)
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
/// Subprocess agents (e.g. `claude -p`) cold-start much slower than raw
/// HTTP — 30s+ before the first token is normal. 600s (10 min) is the
/// plan-recommended ceiling: generous, not pathological.
const DEFAULT_AGENT_TIMEOUT_SECS: u64 = 600;

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

/// Resolve which transport mode to use from CLI flags, config, and
/// inference. Locked rules:
///
/// - `--agent-cmd` on the CLI **always** selects subprocess. It is
///   mutually exclusive with `--base-url` (different transports;
///   accepting both would just hide the conflict).
/// - `--base-url` on the CLI **always** selects HTTP.
/// - With no CLI override, an explicit `[deep] mode = "..."` wins.
/// - With neither, infer from which `[deep]` fields are populated. If
///   both are populated, demand the user disambiguate — silently picking
///   one would let a typo flip the transport.
pub(crate) fn resolve_mode(args: &ScanArgs, config: &ZiftConfig) -> Result<DeepMode, DeepError> {
    let cli_agent = args.agent_cmd.as_deref().is_some_and(|s| !s.is_empty());
    let cli_base_url = args.base_url.as_deref().is_some_and(|s| !s.is_empty());

    if cli_agent && cli_base_url {
        return Err(DeepError::Config(
            "--agent-cmd and --base-url are mutually exclusive — they select \
             different transports (subprocess vs HTTP); pass exactly one"
                .into(),
        ));
    }
    if cli_agent {
        return Ok(DeepMode::Subprocess);
    }
    if cli_base_url {
        return Ok(DeepMode::Http);
    }

    if let Some(m) = config.deep.mode.as_deref().map(str::trim)
        && !m.is_empty()
    {
        return match m.to_ascii_lowercase().as_str() {
            "http" => Ok(DeepMode::Http),
            "subprocess" => Ok(DeepMode::Subprocess),
            other => Err(DeepError::Config(format!(
                "[deep] mode must be \"http\" or \"subprocess\" (got {other:?})"
            ))),
        };
    }

    // No CLI flag, no config mode — infer from which fields are populated.
    // Prefer the field the user actually configured; demand disambiguation
    // if both are set so a stale field doesn't silently flip transports.
    let cfg_agent = config
        .deep
        .agent_cmd
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    let cfg_base = config
        .deep
        .base_url
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty());
    match (cfg_agent, cfg_base) {
        (true, false) => Ok(DeepMode::Subprocess),
        (false, true) => Ok(DeepMode::Http),
        // Default when nothing is configured: HTTP. The Http branch will then
        // hard-fail on missing base_url/model — same behavior as PR 1 shipped.
        (false, false) => Ok(DeepMode::Http),
        (true, true) => Err(DeepError::Config(
            "[deep] sets both base_url and agent_cmd — set [deep] mode = \"http\" \
             or \"subprocess\" to disambiguate, or pass --base-url / --agent-cmd \
             on the CLI"
                .into(),
        )),
    }
}

/// Resolve CLI args + config-file values into a [`DeepRuntime`].
///
/// Branches on transport mode (see [`resolve_mode`]). Returns
/// [`DeepError::Config`] on missing required fields per the selected
/// mode (`base_url`/`model` for HTTP, `agent_cmd` for subprocess).
pub fn build(args: &ScanArgs, config: &ZiftConfig) -> Result<DeepRuntime, DeepError> {
    let mode = resolve_mode(args, config)?;

    let api_key = args.api_key.clone().filter(|s| !s.is_empty());
    let max_cost_usd =
        validate_non_negative_finite("max_cost", args.max_cost.or(config.deep.max_cost))?;
    let cost_per_1k_input =
        validate_non_negative_finite("cost_per_1k_input", config.deep.cost_per_1k_input)?;
    let cost_per_1k_output =
        validate_non_negative_finite("cost_per_1k_output", config.deep.cost_per_1k_output)?;

    // Warn if a cap is set but no rates are configured — the tracker
    // short-circuits when both rates are 0, so the cap would never bind.
    // Subprocess transport doesn't track tokens at all, so the warning is
    // even more relevant there: spend ceilings have no effect on agent
    // CLIs unless the user wraps them in something that returns usage.
    let no_rates =
        cost_per_1k_input.unwrap_or(0.0) == 0.0 && cost_per_1k_output.unwrap_or(0.0) == 0.0;
    if max_cost_usd.is_some() && no_rates {
        tracing::warn!(
            "--max-cost is set but [deep] cost_per_1k_input / \
             cost_per_1k_output are not configured in .zift.toml — spend \
             tracking is a no-op without rates"
        );
    }

    // Merge excludes from config + CLI; preserve CLI ordering after config.
    let mut excludes = config.scan.exclude.clone();
    excludes.extend(args.exclude.iter().cloned());

    match mode {
        DeepMode::Http => build_http(
            args,
            config,
            api_key,
            max_cost_usd,
            cost_per_1k_input,
            cost_per_1k_output,
            excludes,
        ),
        DeepMode::Subprocess => build_subprocess(
            args,
            config,
            api_key,
            max_cost_usd,
            cost_per_1k_input,
            cost_per_1k_output,
            excludes,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_http(
    args: &ScanArgs,
    config: &ZiftConfig,
    api_key: Option<String>,
    max_cost_usd: Option<f64>,
    cost_per_1k_input: Option<f64>,
    cost_per_1k_output: Option<f64>,
    excludes: Vec<String>,
) -> Result<DeepRuntime, DeepError> {
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
    // Parse the URL eagerly so a typo (`htp://...`, missing scheme, etc.)
    // hard-fails at config-build time instead of surfacing later as a
    // per-candidate `DeepError::Http` skip — which would silently fall back
    // to structural-only output and hide the misconfiguration from the user.
    let parsed = url::Url::parse(&base_url).map_err(|e| {
        DeepError::Config(format!("--base-url is not a valid URL ({base_url:?}): {e}"))
    })?;
    // The deep client speaks HTTP; reject `file://`, `ftp://`, etc. up-front
    // rather than letting the request fail downstream as an opaque transport
    // error.
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(DeepError::Config(format!(
            "--base-url must use http or https (got {:?} in {base_url:?})",
            parsed.scheme()
        )));
    }

    // Trim before the emptiness check so whitespace-only values like "   "
    // are treated as missing — otherwise the failure moves from config-build
    // (clear, actionable) to request-time as an opaque upstream rejection.
    let model = args
        .model
        .clone()
        .or_else(|| config.deep.model.clone())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            DeepError::Config(
                "--model is required when --deep is set \
                 (or set [deep] model in .zift.toml)"
                    .into(),
            )
        })?;

    let max_concurrent = if is_localhost(&base_url) {
        DEFAULT_LOCAL_CONCURRENCY
    } else {
        DEFAULT_REMOTE_CONCURRENCY
    };

    Ok(DeepRuntime {
        mode: DeepMode::Http,
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
        agent_cmd: None,
        agent_timeout_secs: DEFAULT_AGENT_TIMEOUT_SECS,
    })
}

#[allow(clippy::too_many_arguments)]
fn build_subprocess(
    args: &ScanArgs,
    config: &ZiftConfig,
    api_key: Option<String>,
    max_cost_usd: Option<f64>,
    cost_per_1k_input: Option<f64>,
    cost_per_1k_output: Option<f64>,
    excludes: Vec<String>,
) -> Result<DeepRuntime, DeepError> {
    let agent_cmd = args
        .agent_cmd
        .clone()
        .or_else(|| config.deep.agent_cmd.clone())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            DeepError::Config(
                "subprocess mode requires --agent-cmd \
                 (or [deep] agent_cmd in .zift.toml)"
                    .into(),
            )
        })?;

    let agent_timeout_secs = config
        .deep
        .agent_timeout_secs
        .unwrap_or(DEFAULT_AGENT_TIMEOUT_SECS);

    // Subprocess agents serialize internally on the agent's side (one
    // `claude -p` invocation, one model call); spawning N of them in
    // parallel rarely improves throughput and frequently competes for
    // the agent's own rate-limit budget. Default to 1; users override
    // via shell tooling, not Zift.
    let max_concurrent = DEFAULT_LOCAL_CONCURRENCY;

    Ok(DeepRuntime {
        mode: DeepMode::Subprocess,
        // base_url and model are HTTP-only. Empty in subprocess mode —
        // the HTTP client is never instantiated, so these never reach
        // the wire. Documented on `DeepRuntime`.
        base_url: String::new(),
        model: String::new(),
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
        agent_cmd: Some(agent_cmd),
        agent_timeout_secs,
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
            mode: DeepMode::Http,
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
            agent_cmd: None,
            agent_timeout_secs: 600,
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
    fn whitespace_only_model_treated_as_missing() {
        // Without trim, "   " sneaks past `!is_empty()` and the failure moves
        // to request time as an opaque upstream rejection — defeating the
        // fail-fast config contract.
        for model in ["   ", "\t", "\n", " \t\n "] {
            let args = args_with(Some("http://x/v1"), Some(model), None, None);
            let err = build(&args, &ZiftConfig::default()).unwrap_err();
            assert!(
                matches!(err, DeepError::Config(_)),
                "expected Config error for model={model:?}, got: {err:?}",
            );
        }
    }

    #[test]
    fn empty_base_url_treated_as_missing() {
        let args = args_with(Some(""), Some("m"), None, None);
        let err = build(&args, &ZiftConfig::default()).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn malformed_base_url_rejected_at_build_time() {
        // A typo without a scheme would otherwise reach `client.rs` and fail
        // there as `DeepError::Http`, which the orchestrator silently skips
        // per-candidate — masking the misconfiguration. Catch it up front.
        let args = args_with(Some("not a url"), Some("m"), None, None);
        let err = build(&args, &ZiftConfig::default()).unwrap_err();
        assert!(
            matches!(err, DeepError::Config(ref msg) if msg.contains("not a valid URL")),
            "expected Config(<not a valid URL>), got: {err:?}",
        );
    }

    #[test]
    fn non_http_scheme_rejected_at_build_time() {
        // The deep client speaks HTTP. `file://`, `ftp://`, etc. parse as
        // valid URLs but have no business reaching the request layer — surface
        // them as `Config` up front so the user gets a clear error instead of
        // an opaque transport failure.
        for url in ["file:///etc/passwd", "ftp://example.com/", "ws://x/v1"] {
            let args = args_with(Some(url), Some("m"), None, None);
            let err = build(&args, &ZiftConfig::default()).unwrap_err();
            assert!(
                matches!(err, DeepError::Config(ref msg) if msg.contains("must use http or https")),
                "expected Config(<must use http or https>) for {url}, got: {err:?}",
            );
        }
    }

    #[test]
    fn well_formed_base_urls_accepted() {
        // Sanity: the validator must not regress on real-world base URLs.
        for url in [
            "http://localhost:11434/v1",
            "https://api.openai.com/v1",
            "http://127.0.0.1:8080/v1",
            "http://[::1]:8080/v1",
        ] {
            let args = args_with(Some(url), Some("m"), None, None);
            assert!(
                build(&args, &ZiftConfig::default()).is_ok(),
                "validator rejected real-world URL: {url}",
            );
        }
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

    // -- Subprocess mode resolution ---------------------------------------

    fn subprocess_args(agent_cmd: Option<&str>) -> ScanArgs {
        ScanArgs {
            deep: true,
            agent_cmd: agent_cmd.map(String::from),
            ..ScanArgs::default()
        }
    }

    #[test]
    fn cli_agent_cmd_selects_subprocess_mode() {
        let args = subprocess_args(Some("claude -p --output-format json"));
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.mode, DeepMode::Subprocess);
        assert_eq!(
            runtime.agent_cmd.as_deref(),
            Some("claude -p --output-format json")
        );
        // base_url and model are HTTP-only — empty in subprocess mode.
        assert!(runtime.base_url.is_empty());
        assert!(runtime.model.is_empty());
    }

    #[test]
    fn cli_agent_cmd_and_base_url_are_mutually_exclusive() {
        // Both pin different transports; refuse to silently pick one.
        let mut args = subprocess_args(Some("claude -p"));
        args.base_url = Some("http://x/v1".into());
        args.model = Some("m".into());
        let err = build(&args, &ZiftConfig::default()).unwrap_err();
        assert!(
            matches!(err, DeepError::Config(ref msg) if msg.contains("mutually exclusive")),
            "expected Config(<mutually exclusive>), got: {err:?}",
        );
    }

    #[test]
    fn config_mode_subprocess_requires_agent_cmd() {
        // Explicit `mode = "subprocess"` without `agent_cmd` is a hard
        // error — otherwise the failure moves to spawn-time as an opaque
        // empty-command crash.
        let config = config_with(DeepConfig {
            mode: Some("subprocess".into()),
            ..DeepConfig::default()
        });
        // No CLI flags — fall through to config.
        let args = ScanArgs {
            deep: true,
            ..ScanArgs::default()
        };
        let err = build(&args, &config).unwrap_err();
        assert!(
            matches!(err, DeepError::Config(ref msg) if msg.contains("agent_cmd")),
            "expected Config(<agent_cmd>), got: {err:?}",
        );
    }

    #[test]
    fn config_agent_cmd_without_explicit_mode_infers_subprocess() {
        // Single populated transport field → infer that mode. No need to
        // require users to spell out `mode = "subprocess"` redundantly.
        let config = config_with(DeepConfig {
            agent_cmd: Some("claude -p".into()),
            ..DeepConfig::default()
        });
        let args = ScanArgs {
            deep: true,
            ..ScanArgs::default()
        };
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.mode, DeepMode::Subprocess);
        assert_eq!(runtime.agent_cmd.as_deref(), Some("claude -p"));
    }

    #[test]
    fn config_with_both_transport_fields_demands_disambiguation() {
        // Both base_url AND agent_cmd are populated, no explicit mode —
        // refuse to silently pick. A stale config field would otherwise
        // flip the transport and the user would never notice until the
        // wrong agent ran.
        let config = config_with(DeepConfig {
            base_url: Some("http://x/v1".into()),
            agent_cmd: Some("claude -p".into()),
            model: Some("m".into()),
            ..DeepConfig::default()
        });
        let args = ScanArgs {
            deep: true,
            ..ScanArgs::default()
        };
        let err = build(&args, &config).unwrap_err();
        assert!(
            matches!(err, DeepError::Config(ref msg) if msg.contains("disambiguate")),
            "expected Config(<disambiguate>), got: {err:?}",
        );
    }

    #[test]
    fn invalid_mode_string_rejected() {
        let config = config_with(DeepConfig {
            mode: Some("rest".into()),
            ..DeepConfig::default()
        });
        let args = ScanArgs {
            deep: true,
            ..ScanArgs::default()
        };
        let err = build(&args, &config).unwrap_err();
        assert!(matches!(err, DeepError::Config(_)));
    }

    #[test]
    fn cli_agent_cmd_overrides_config_mode_http() {
        // Edge: config says http, CLI says agent_cmd. CLI wins.
        let config = config_with(DeepConfig {
            mode: Some("http".into()),
            base_url: Some("http://x/v1".into()),
            model: Some("m".into()),
            ..DeepConfig::default()
        });
        let args = subprocess_args(Some("claude -p"));
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.mode, DeepMode::Subprocess);
    }

    #[test]
    fn subprocess_caps_concurrency_to_one() {
        let args = subprocess_args(Some("claude -p"));
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.max_concurrent, DEFAULT_LOCAL_CONCURRENCY);
    }

    #[test]
    fn subprocess_default_timeout_is_600s() {
        let args = subprocess_args(Some("claude -p"));
        let runtime = build(&args, &ZiftConfig::default()).unwrap();
        assert_eq!(runtime.agent_timeout_secs, DEFAULT_AGENT_TIMEOUT_SECS);
        assert_eq!(runtime.agent_timeout_secs, 600);
    }

    #[test]
    fn subprocess_timeout_loaded_from_config() {
        let config = config_with(DeepConfig {
            agent_cmd: Some("claude -p".into()),
            agent_timeout_secs: Some(120),
            ..DeepConfig::default()
        });
        let args = ScanArgs {
            deep: true,
            ..ScanArgs::default()
        };
        let runtime = build(&args, &config).unwrap();
        assert_eq!(runtime.agent_timeout_secs, 120);
    }

    #[test]
    fn whitespace_only_agent_cmd_treated_as_missing() {
        for cmd in ["   ", "\t", "\n", " \t\n "] {
            let args = subprocess_args(Some(cmd));
            let err = build(&args, &ZiftConfig::default()).unwrap_err();
            assert!(
                matches!(err, DeepError::Config(_)),
                "expected Config error for agent_cmd={cmd:?}, got: {err:?}",
            );
        }
    }

    #[test]
    fn subprocess_inherits_excludes_and_language_filter() {
        // Cold-region discovery is mode-agnostic — both transports must
        // honor the same scope filters, otherwise subprocess users would
        // get a different file set than HTTP users from the same config.
        let mut zcfg = ZiftConfig::default();
        zcfg.scan.exclude = vec!["vendor/**".into()];
        let mut args = subprocess_args(Some("claude -p"));
        args.exclude = vec!["cli/**".into()];
        args.language = vec![Language::Java];
        let runtime = build(&args, &zcfg).unwrap();
        assert_eq!(runtime.excludes, vec!["vendor/**", "cli/**"]);
        assert_eq!(runtime.language_filter, vec![Language::Java]);
    }
}
