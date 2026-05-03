use tree_sitter::Tree;

use crate::error::{Result, ZiftError};
use crate::types::Language;

/// Returns true if the language has tree-sitter parser support.
pub fn is_language_supported(lang: Language) -> bool {
    get_language(lang, false).is_ok()
}

pub fn get_language(lang: Language, is_tsx_jsx: bool) -> Result<tree_sitter::Language> {
    match (lang, is_tsx_jsx) {
        (Language::TypeScript, false) => Ok(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        (Language::TypeScript, true) => Ok(tree_sitter_typescript::LANGUAGE_TSX.into()),
        (Language::JavaScript, _) => Ok(tree_sitter_javascript::LANGUAGE.into()),
        (Language::Java, _) => Ok(tree_sitter_java::LANGUAGE.into()),
        (Language::Python, _) => Ok(tree_sitter_python::LANGUAGE.into()),
        (Language::Go, _) => Ok(tree_sitter_go::LANGUAGE.into()),
        _ => Err(ZiftError::General(format!(
            "language {lang:?} not yet supported"
        ))),
    }
}

pub fn parse_source(
    parser: &mut tree_sitter::Parser,
    source: &[u8],
    lang: Language,
    is_tsx_jsx: bool,
) -> Result<Tree> {
    let ts_lang = get_language(lang, is_tsx_jsx)?;
    parser
        .set_language(&ts_lang)
        .map_err(|e| ZiftError::General(format!("failed to set parser language: {e}")))?;

    parser
        .parse(source, None)
        .ok_or_else(|| ZiftError::General("tree-sitter parse returned None".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_typescript() {
        let mut parser = tree_sitter::Parser::new();
        let source = b"const x: number = 42;";
        let tree = parse_source(&mut parser, source, Language::TypeScript, false).unwrap();
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parse_tsx() {
        let mut parser = tree_sitter::Parser::new();
        let source = b"const App = () => <div>Hello</div>;";
        let tree = parse_source(&mut parser, source, Language::TypeScript, true).unwrap();
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parse_javascript() {
        let mut parser = tree_sitter::Parser::new();
        let source = b"const x = 42;";
        let tree = parse_source(&mut parser, source, Language::JavaScript, false).unwrap();
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn parse_java() {
        let mut parser = tree_sitter::Parser::new();
        let source = b"public class Foo { public void bar() {} }";
        let tree = parse_source(&mut parser, source, Language::Java, false).unwrap();
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn java_is_supported() {
        assert!(is_language_supported(Language::Java));
    }

    #[test]
    fn parse_python() {
        let mut parser = tree_sitter::Parser::new();
        let source = b"def is_admin(user):\n    return user.role == 'admin'\n";
        let tree = parse_source(&mut parser, source, Language::Python, false).unwrap();
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn python_is_supported() {
        assert!(is_language_supported(Language::Python));
    }

    #[test]
    fn parse_go() {
        let mut parser = tree_sitter::Parser::new();
        let source = b"package main\n\nfunc main() {\n\tprintln(\"hi\")\n}\n";
        let tree = parse_source(&mut parser, source, Language::Go, false).unwrap();
        assert!(!tree.root_node().has_error());
    }

    #[test]
    fn go_is_supported() {
        assert!(is_language_supported(Language::Go));
    }

    #[test]
    fn unsupported_language_returns_error() {
        // C# has no structural grammar wired up yet — kept as the canary
        // that `unsupported_language_returns_error` keeps testing what its
        // name says it does. (Was Go before v0.2 added Go support.)
        assert!(get_language(Language::CSharp, false).is_err());
        assert!(!is_language_supported(Language::CSharp));
    }
}
