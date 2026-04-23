use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use ignore::overrides::OverrideBuilder;

use crate::types::Language;

#[derive(Debug)]
pub struct DiscoveredFile {
    pub path: PathBuf,
    pub language: Language,
    pub is_tsx_jsx: bool,
}

pub fn detect_language(path: &Path) -> Option<(Language, bool)> {
    let ext = path.extension()?.to_str()?;
    match ext {
        "ts" => Some((Language::TypeScript, false)),
        "tsx" => Some((Language::TypeScript, true)),
        "js" | "mjs" | "cjs" => Some((Language::JavaScript, false)),
        "jsx" => Some((Language::JavaScript, true)),
        "java" => Some((Language::Java, false)),
        _ => None,
    }
}

pub fn discover_files(
    root: &Path,
    exclude_patterns: &[String],
    language_filter: &[Language],
) -> Vec<DiscoveredFile> {
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .follow_links(false)
        .parents(true);

    // Add exclude overrides
    if !exclude_patterns.is_empty() {
        let mut overrides = OverrideBuilder::new(root);
        for pattern in exclude_patterns {
            // Negate the pattern so it becomes an exclusion
            let _ = overrides.add(&format!("!{pattern}"));
        }
        if let Ok(ov) = overrides.build() {
            builder.overrides(ov);
        }
    }

    let mut files = Vec::new();
    for entry in builder.build().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if let Some((lang, is_tsx_jsx)) = detect_language(path) {
            // Apply language filter
            if !language_filter.is_empty() && !language_filter.contains(&lang) {
                continue;
            }
            files.push(DiscoveredFile {
                path: path.to_path_buf(),
                language: lang,
                is_tsx_jsx,
            });
        }
    }

    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detect_typescript_extensions() {
        assert_eq!(
            detect_language(Path::new("foo.ts")),
            Some((Language::TypeScript, false))
        );
        assert_eq!(
            detect_language(Path::new("foo.tsx")),
            Some((Language::TypeScript, true))
        );
    }

    #[test]
    fn detect_javascript_extensions() {
        assert_eq!(
            detect_language(Path::new("foo.js")),
            Some((Language::JavaScript, false))
        );
        assert_eq!(
            detect_language(Path::new("foo.mjs")),
            Some((Language::JavaScript, false))
        );
        assert_eq!(
            detect_language(Path::new("foo.jsx")),
            Some((Language::JavaScript, true))
        );
    }

    #[test]
    fn detect_java_extension() {
        assert_eq!(
            detect_language(Path::new("Foo.java")),
            Some((Language::Java, false))
        );
    }

    #[test]
    fn detect_unknown_extension() {
        assert_eq!(detect_language(Path::new("foo.rs")), None);
        assert_eq!(detect_language(Path::new("foo.py")), None);
    }

    #[test]
    fn discover_respects_language_filter() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.ts"), "let x = 1;").unwrap();
        fs::write(dir.path().join("b.js"), "let y = 2;").unwrap();

        let files = discover_files(dir.path(), &[], &[Language::TypeScript]);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].language, Language::TypeScript);
    }
}
