use crate::cli::InitArgs;
use crate::error::{Result, ZiftError};

const DEFAULT_CONFIG: &str = r#"[scan]
exclude = ["vendor/**", "node_modules/**", "target/**"]
# languages = ["java", "typescript", "python"]
# min_confidence = "medium"

# [deep]
# provider = "anthropic"
# model = "claude-sonnet-4-20250514"
# max_cost = 5.00

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
