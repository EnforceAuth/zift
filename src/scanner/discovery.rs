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

/// Extension → language map for languages with structural parser support.
/// Used by the structural scanning pass.
pub fn detect_language(path: &Path) -> Option<(Language, bool)> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "ts" => Some((Language::TypeScript, false)),
        "tsx" => Some((Language::TypeScript, true)),
        "js" | "mjs" | "cjs" => Some((Language::JavaScript, false)),
        "jsx" => Some((Language::JavaScript, true)),
        "java" => Some((Language::Java, false)),
        _ => None,
    }
}

/// Extension → language map covering **all** languages in the [`Language`]
/// enum, including those without structural parser support yet (Python, Go,
/// C#, Kotlin, Ruby, PHP). Used by the deep (semantic) scan, which can run
/// regex-based cold-region detection on any language regardless of grammar
/// availability.
pub fn detect_language_for_deep(path: &Path) -> Option<(Language, bool)> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "ts" => Some((Language::TypeScript, false)),
        "tsx" => Some((Language::TypeScript, true)),
        "js" | "mjs" | "cjs" => Some((Language::JavaScript, false)),
        "jsx" => Some((Language::JavaScript, true)),
        "java" => Some((Language::Java, false)),
        "py" | "pyi" => Some((Language::Python, false)),
        "go" => Some((Language::Go, false)),
        "cs" => Some((Language::CSharp, false)),
        "kt" | "kts" => Some((Language::Kotlin, false)),
        "rb" | "rake" => Some((Language::Ruby, false)),
        "php" | "phtml" => Some((Language::Php, false)),
        _ => None,
    }
}

pub fn discover_files(
    root: &Path,
    exclude_patterns: &[String],
    language_filter: &[Language],
) -> Vec<DiscoveredFile> {
    discover_with(root, exclude_patterns, language_filter, detect_language)
}

/// Discover source files for the deep (semantic) scan. Behaves identically
/// to [`discover_files`] but emits files in **all** languages from the
/// [`Language`] enum, not only structurally-supported ones.
pub fn discover_files_for_deep(
    root: &Path,
    exclude_patterns: &[String],
    language_filter: &[Language],
) -> Vec<DiscoveredFile> {
    discover_with(
        root,
        exclude_patterns,
        language_filter,
        detect_language_for_deep,
    )
}

fn discover_with<F>(
    root: &Path,
    exclude_patterns: &[String],
    language_filter: &[Language],
    detect: F,
) -> Vec<DiscoveredFile>
where
    F: Fn(&Path) -> Option<(Language, bool)>,
{
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(true)
        .git_ignore(true)
        .git_global(true)
        .follow_links(false)
        .parents(true);

    if !exclude_patterns.is_empty() {
        let mut overrides = OverrideBuilder::new(root);
        for pattern in exclude_patterns {
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
        if let Some((lang, is_tsx_jsx)) = detect(path) {
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

    #[test]
    fn detect_language_for_deep_covers_all_languages() {
        assert_eq!(
            detect_language_for_deep(Path::new("foo.py")),
            Some((Language::Python, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("foo.pyi")),
            Some((Language::Python, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("foo.go")),
            Some((Language::Go, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("Foo.cs")),
            Some((Language::CSharp, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("Foo.kt")),
            Some((Language::Kotlin, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("foo.kts")),
            Some((Language::Kotlin, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("foo.rb")),
            Some((Language::Ruby, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("Rakefile.rake")),
            Some((Language::Ruby, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("foo.php")),
            Some((Language::Php, false))
        );
        assert_eq!(
            detect_language_for_deep(Path::new("foo.phtml")),
            Some((Language::Php, false))
        );
        // Structural extensions still work in the deep map.
        assert_eq!(
            detect_language_for_deep(Path::new("foo.ts")),
            Some((Language::TypeScript, false))
        );
        // Genuinely unknown extensions still return None.
        assert_eq!(detect_language_for_deep(Path::new("foo.rs")), None);
        assert_eq!(detect_language_for_deep(Path::new("foo.txt")), None);
    }

    #[test]
    fn structural_detect_language_does_not_pick_up_python() {
        // Sanity: the structural detector must NOT include Python — otherwise
        // the structural pass would try to parse files for which it has no
        // grammar. The deep detector picks them up; the structural one doesn't.
        assert_eq!(detect_language(Path::new("foo.py")), None);
        assert_eq!(detect_language(Path::new("foo.go")), None);
    }

    #[test]
    fn discover_for_deep_picks_up_extra_languages() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.ts"), "let x = 1;").unwrap();
        fs::write(dir.path().join("b.py"), "x = 1\n").unwrap();
        fs::write(dir.path().join("c.go"), "package main\n").unwrap();

        let structural = discover_files(dir.path(), &[], &[]);
        assert_eq!(structural.len(), 1, "structural sees only TS");

        let deep = discover_files_for_deep(dir.path(), &[], &[]);
        assert_eq!(deep.len(), 3, "deep sees TS + Python + Go");
    }
}
