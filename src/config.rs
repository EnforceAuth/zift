use std::path::Path;

use serde::Deserialize;

use crate::error::{Result, ZiftError};

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ZiftConfig {
    pub scan: ScanConfig,
    pub deep: DeepConfig,
    pub extract: ExtractConfig,
    pub rules: RulesConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ScanConfig {
    pub exclude: Vec<String>,
    pub languages: Vec<String>,
    pub min_confidence: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct DeepConfig {
    /// OpenAI-compatible chat-completions endpoint, e.g. "http://localhost:11434/v1".
    pub base_url: Option<String>,
    /// Model name to send to the agent endpoint.
    pub model: Option<String>,
    /// Maximum spend limit in USD.
    pub max_cost: Option<f64>,
    // NOTE: api_key is intentionally NOT readable from this file — keys belong
    // in $ZIFT_AGENT_API_KEY or --api-key, not checked into source control.
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ExtractConfig {
    pub package_prefix: Option<String>,
    pub output_dir: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct RulesConfig {
    pub additional: Vec<String>,
}

pub fn load_config(path: &Path) -> Result<ZiftConfig> {
    if !path.exists() {
        tracing::debug!("no config file at {}, using defaults", path.display());
        return Ok(ZiftConfig::default());
    }

    let content = std::fs::read_to_string(path)?;
    let config: ZiftConfig = toml::from_str(&content).map_err(|e| ZiftError::ConfigParse {
        path: path.to_path_buf(),
        source: e,
    })?;

    tracing::debug!("loaded config from {}", path.display());
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = ZiftConfig::default();
        assert!(config.scan.exclude.is_empty());
        assert!(config.deep.base_url.is_none());
        assert!(config.extract.package_prefix.is_none());
    }

    #[test]
    fn parse_full_config() {
        let toml = r#"
[scan]
exclude = ["vendor/**", "node_modules/**"]
languages = ["java", "typescript"]
min_confidence = "medium"

[deep]
base_url = "http://localhost:11434/v1"
model = "qwen2.5-coder:14b"
max_cost = 5.00

[extract]
package_prefix = "app.authz"
output_dir = "./policies/generated"

[rules]
additional = ["./custom-rules"]
"#;
        let config: ZiftConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.scan.exclude.len(), 2);
        assert_eq!(config.scan.languages, vec!["java", "typescript"]);
        assert_eq!(
            config.deep.base_url.as_deref(),
            Some("http://localhost:11434/v1")
        );
        assert_eq!(config.deep.model.as_deref(), Some("qwen2.5-coder:14b"));
        assert_eq!(config.deep.max_cost, Some(5.0));
        assert_eq!(config.extract.package_prefix.as_deref(), Some("app.authz"));
        assert_eq!(config.rules.additional, vec!["./custom-rules"]);
    }

    #[test]
    fn parse_partial_config() {
        let toml = r#"
[scan]
exclude = ["vendor/**"]
"#;
        let config: ZiftConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.scan.exclude, vec!["vendor/**"]);
        assert!(config.scan.languages.is_empty());
        assert!(config.deep.base_url.is_none());
    }

    #[test]
    fn missing_config_file_returns_defaults() {
        let config = load_config(Path::new("nonexistent.toml")).unwrap();
        assert!(config.scan.exclude.is_empty());
    }
}
