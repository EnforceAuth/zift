use crate::cli::InitArgs;
use crate::error::{Result, ZiftError};

const DEFAULT_CONFIG: &str = r#"[scan]
exclude = ["vendor/**", "node_modules/**", "target/**"]
# languages = ["java", "typescript", "python"]
# min_confidence = "medium"

# [deep]
# # mode = "http"   # or "subprocess" — usually inferred from the fields below.
#
# # ----- HTTP transport (default) -----
# base_url = "http://localhost:11434/v1"   # Ollama, LM Studio, OpenAI-compatible
# model    = "your-model-name"
# max_cost = 5.00                           # USD spend ceiling (requires rates below)
# cost_per_1k_input  = 0.00015              # e.g. gpt-4o-mini input
# cost_per_1k_output = 0.0006               # e.g. gpt-4o-mini output
# # API key: set $ZIFT_AGENT_API_KEY in your environment, or pass --api-key.
# # Do NOT put the key in this file — it gets checked into source control.
#
# # ----- Subprocess transport -----
# # Zift writes a JSON envelope (system/user/schema) to the command's stdin
# # and reads {"findings": [...]} from its stdout. For `claude -p`, `aider`,
# # or any wrapper script.
# agent_cmd          = "claude -p --output-format json"
# agent_timeout_secs = 600                  # default 600 (LLM CLIs can be slow)

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
