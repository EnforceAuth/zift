use tree_sitter::Tree;

use crate::error::{Result, ZiftError};
use crate::types::Language;

pub fn get_language(lang: Language, is_tsx_jsx: bool) -> tree_sitter::Language {
    match (lang, is_tsx_jsx) {
        (Language::TypeScript, false) => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        (Language::TypeScript, true) => tree_sitter_typescript::LANGUAGE_TSX.into(),
        (Language::JavaScript, _) => tree_sitter_javascript::LANGUAGE.into(),
        _ => unimplemented!("language {:?} not yet supported", lang),
    }
}

pub fn parse_source(
    parser: &mut tree_sitter::Parser,
    source: &[u8],
    lang: Language,
    is_tsx_jsx: bool,
) -> Result<Tree> {
    let ts_lang = get_language(lang, is_tsx_jsx);
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
}
