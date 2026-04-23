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
    pub provider: Option<String>,
    pub model: Option<String>,
    pub max_cost: Option<f64>,
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
        assert!(config.deep.provider.is_none());
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
provider = "anthropic"
model = "claude-sonnet-4-20250514"
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
        assert_eq!(config.deep.provider.as_deref(), Some("anthropic"));
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
        assert!(config.deep.provider.is_none());
    }

    #[test]
    fn missing_config_file_returns_defaults() {
        let config = load_config(Path::new("nonexistent.toml")).unwrap();
        assert!(config.scan.exclude.is_empty());
    }
}
