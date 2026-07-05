from __future__ import annotations

import re
from typing import Callable

from .utils import extract_balanced, split_top_level_args, strip_quotes


class ConstantTable:
    def __init__(self, *, progress: Callable[[str], None] | None = None) -> None:
        self.values: dict[str, str] = {}
        self.object_values: dict[str, dict[str, str]] = {}
        self.property_values: dict[str, set[str]] = {}
        self.progress = progress

    def learn(self, code: str) -> None:
        self._learn_string_constants(code)
        self._learn_object_constants(code)

    def resolve_expr(self, expr: str) -> str | None:
        expr = expr.strip()
        if not expr:
            return None
        if expr[0:1] in "'\"`":
            return self.resolve_template(strip_quotes(expr))
        if expr in self.values:
            return self.values[expr]
        member = re.fullmatch(r"([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)", expr)
        if member:
            return self.object_values.get(member.group(1), {}).get(member.group(2))
        chain_property = extract_property_tail(expr)
        if chain_property:
            candidates = self.property_values.get(chain_property, set())
            if len(candidates) == 1:
                return next(iter(candidates))
        plus_parts = split_string_concat(expr)
        if plus_parts:
            resolved: list[str] = []
            for part in plus_parts:
                value = self.resolve_expr(part)
                if value is None:
                    value = template_param(part)
                resolved.append(value)
            return "".join(resolved)
        return None

    def resolve_template(self, value: str) -> str:
        return re.sub(r"\$\{([^}]+)\}", lambda m: "{" + clean_param_name(m.group(1)) + "}", value)

    def _learn_string_constants(self, code: str) -> None:
        pattern = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,700})[;\n]", re.S)
        rounds = 0
        max_rounds = 6
        changed = True
        while changed and rounds < max_rounds:
            rounds += 1
            changed = False
            for match in pattern.finditer(code):
                name = match.group(1)
                expr = match.group(2)
                if expr.lstrip().startswith(("{", "[", "function")):
                    continue
                value = self.resolve_expr(expr)
                if value is not None and self.values.get(name) != value:
                    self.values[name] = value
                    changed = True
        if changed and self.progress:
            self.progress(
                f"  constant learning capped at {max_rounds} rounds; "
                f"strings={len(self.values)}"
            )

    def _learn_object_constants(self, code: str) -> None:
        pattern = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\{", re.S)
        for match in pattern.finditer(code):
            name = match.group(1)
            balanced = extract_balanced(code, match.end() - 1, "{", "}")
            if not balanced:
                continue
            body = balanced[0]
            fields: dict[str, str] = {}
            for part in split_top_level_args(body):
                field = re.match(r"\s*([A-Za-z_$][\w$]*|['\"][^'\"]+['\"])\s*:\s*(.+?)\s*$", part, re.S)
                if not field:
                    shorthand = part.strip()
                    if re.match(r"^[A-Za-z_$][\w$]*$", shorthand):
                        fields[shorthand] = shorthand
                    continue
                key = strip_quotes(field.group(1))
                expr = field.group(2).strip()
                value = self.resolve_expr(expr)
                fields[key] = value if value is not None else expr
            if fields:
                self.object_values[name] = fields
                for key, value in fields.items():
                    if isinstance(value, str) and looks_like_constant_value(value):
                        self.property_values.setdefault(key, set()).add(value)


def split_string_concat(expr: str) -> list[str] | None:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escape = False
    for idx, ch in enumerate(expr):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "+" and depth == 0:
            parts.append(expr[start:idx].strip())
            start = idx + 1
    if not parts:
        return None
    parts.append(expr[start:].strip())
    return parts


def clean_param_name(expr: str) -> str:
    expr = expr.strip()
    expr = re.sub(r"[^\w$.]+", "_", expr)
    return expr.split(".")[-1] or "param"


def template_param(expr: str) -> str:
    return "{" + clean_param_name(expr) + "}"


def extract_property_tail(expr: str) -> str | None:
    expr = expr.strip()
    dotted = re.search(r"\.([A-Za-z_$][\w$]*)\s*$", expr)
    if dotted:
        return dotted.group(1)
    bracketed = re.search(r"\[['\"]([A-Za-z_$][\w$]*)['\"]\]\s*$", expr)
    if bracketed:
        return bracketed.group(1)
    return None


def looks_like_constant_value(value: str) -> bool:
    return value.startswith("/") or value.startswith("http://") or value.startswith("https://")
