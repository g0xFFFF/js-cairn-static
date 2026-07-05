from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ParseResult:
    parser: str
    tree: Any | None
    ok: bool
    error: str | None = None


class JSParser:
    def parse(self, code: str) -> ParseResult:
        tree_sitter = self._parse_tree_sitter(code)
        if tree_sitter.ok:
            return tree_sitter
        return ParseResult(parser="text-fallback", tree=None, ok=True, error=tree_sitter.error)

    def _parse_tree_sitter(self, code: str) -> ParseResult:
        try:
            from tree_sitter import Language, Parser  # type: ignore
            import tree_sitter_javascript  # type: ignore

            parser = Parser()
            language = Language(tree_sitter_javascript.language())
            if hasattr(parser, "set_language"):
                parser.set_language(language)
            else:
                parser.language = language
            tree = parser.parse(code.encode("utf-8", errors="ignore"))
            return ParseResult(parser="tree-sitter-javascript", tree=tree, ok=True)
        except Exception as exc:
            return ParseResult(parser="tree-sitter-unavailable", tree=None, ok=False, error=str(exc))
