from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .constants import clean_param_name
from .parser import JSParser
from .utils import strip_quotes


@dataclass(frozen=True)
class ASTObjectField:
    name: str
    expr: str
    kind: str


@dataclass(frozen=True)
class ASTArgument:
    text: str
    kind: str
    string_value: str | None = None
    object_fields: dict[str, ASTObjectField] | None = None


@dataclass(frozen=True)
class ASTCallExpression:
    callee: str
    args: list[str]
    semantic_args: list[ASTArgument]
    snippet: str
    offset: int


class JSASTVisitor:
    """Small tree-sitter visitor for request-relevant JavaScript calls.

    The legacy extractor is intentionally regex-tolerant. This visitor adds a
    real AST pass for call expressions so computed members and optional chains
    are not missed by text patterns.
    """

    def __init__(self, code: str) -> None:
        self.code = code
        self._encoded = code.encode("utf-8", errors="ignore")
        self._parse = JSParser().parse(code)

    def call_expressions(self) -> list[ASTCallExpression]:
        tree = self._parse.tree
        if tree is None:
            return []
        calls: list[ASTCallExpression] = []
        self._walk(tree.root_node, calls)
        return calls

    def _walk(self, node: Any, calls: list[ASTCallExpression]) -> None:
        if node.type == "call_expression":
            call = self._to_call(node)
            if call is not None:
                calls.append(call)
        for child in node.children:
            self._walk(child, calls)

    def _to_call(self, node: Any) -> ASTCallExpression | None:
        arguments = next((child for child in node.children if child.type == "arguments"), None)
        if arguments is None:
            return None
        callee_node = next((child for child in node.children if child is not arguments), None)
        if callee_node is None:
            return None
        return ASTCallExpression(
            callee=self._text(callee_node),
            args=[self._text(child) for child in arguments.named_children],
            semantic_args=[self._argument(child) for child in arguments.named_children],
            snippet=self._text(node),
            offset=self._char_offset(node.start_byte),
        )

    def _argument(self, node: Any) -> ASTArgument:
        return ASTArgument(
            text=self._text(node),
            kind=node.type,
            string_value=self._literal_value(node),
            object_fields=self._object_fields(node) if node.type == "object" else None,
        )

    def _literal_value(self, node: Any) -> str | None:
        if node.type == "string":
            return strip_quotes(self._text(node))
        if node.type == "template_string":
            return self._template_value(node)
        return None

    def _template_value(self, node: Any) -> str:
        parts: list[str] = []
        for child in node.named_children:
            if child.type == "string_fragment":
                parts.append(self._text(child))
            elif child.type == "template_substitution":
                expr = next((grand for grand in child.named_children), None)
                parts.append("{" + clean_param_name(self._text(expr) if expr is not None else "param") + "}")
        return "".join(parts)

    def _object_fields(self, node: Any) -> dict[str, ASTObjectField]:
        fields: dict[str, ASTObjectField] = {}
        for child in node.named_children:
            if child.type == "pair":
                name = self._property_name(child)
                value = child.named_children[-1] if child.named_children else None
                if not name or value is None:
                    continue
                fields[name] = ASTObjectField(name=name, expr=self._text(value), kind=value.type)
                continue
            if child.type in {"shorthand_property_identifier", "identifier"}:
                name = self._text(child)
                fields[name] = ASTObjectField(name=name, expr=name, kind=child.type)
        return fields

    def _property_name(self, pair: Any) -> str | None:
        if not pair.named_children:
            return None
        key = pair.named_children[0]
        if key.type in {"property_identifier", "identifier", "shorthand_property_identifier"}:
            return self._text(key)
        if key.type == "string":
            return strip_quotes(self._text(key))
        if key.type == "computed_property_name":
            inner = next((child for child in key.named_children), None)
            if inner is not None and inner.type == "string":
                return strip_quotes(self._text(inner))
        return None

    def _text(self, node: Any) -> str:
        return self._encoded[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")

    def _char_offset(self, byte_offset: int) -> int:
        return len(self._encoded[:byte_offset].decode("utf-8", errors="ignore"))


def expression_object_fields(expr: str | None) -> dict[str, ASTObjectField]:
    visitor, node = expression_visitor_node(expr)
    if node is None or node.type != "object":
        return {}
    return visitor._object_fields(node)


def expression_literal_value(expr: str | None) -> str | None:
    visitor, node = expression_visitor_node(expr)
    if node is None:
        return None
    return visitor._literal_value(node)


def first_expression_node(expr: str | None) -> Any | None:
    return expression_visitor_node(expr)[1]


def expression_visitor_node(expr: str | None) -> tuple[JSASTVisitor, Any | None]:
    visitor = JSASTVisitor(f"({expr or ''})")
    if not expr:
        return visitor, None
    tree = visitor._parse.tree
    if tree is None:
        return visitor, None
    nodes = list(tree.root_node.named_children)
    if not nodes:
        return visitor, None
    current = nodes[0]
    while current.type in {"expression_statement", "parenthesized_expression"} and current.named_children:
        current = current.named_children[0]
    return visitor, current
