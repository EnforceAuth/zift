use crate::cli::InitArgs;
use crate::error::{Result, ZiftError};

const DEFAULT_CONFIG: &str = r#"[scan]
exclude = ["vendor/**", "node_modules/**", "target/**"]
# languages = ["java", "typescript", "python"]
# min_confidence = "medium"

# [deep]
# base_url = "http://localhost:11434/v1"   # Ollama, LM Studio, OpenAI-compatible
# model    = "your-model-name"
# max_cost = 5.00                           # USD spend ceiling (requires rates below)
# cost_per_1k_input  = 0.00015              # e.g. gpt-4o-mini input
# cost_per_1k_output = 0.0006               # e.g. gpt-4o-mini output
# # API key: set $ZIFT_AGENT_API_KEY in your environment, or pass --api-key.
# # Do NOT put the key in this file — it gets checked into source control.

[extract]
package_prefix = "app.authz"
output_dir = "./policies/generated"

# [rules]
# additional = ["./custom-rules"]
"#;

pub fn execute(args: InitArgs) -> Result<()> {
    let path = args.path.join(".zift.toml");

    if path.exists() {
        return Err(ZiftError::General(format!(
            "config file already exists: {}",
            path.display()
        )));
    }

    std::fs::write(&path, DEFAULT_CONFIG)?;
    println!("Created {}", path.display());
    Ok(())
}
