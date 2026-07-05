from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable


JS_EXTENSIONS = {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue"}
HTML_EXTENSIONS = {".html", ".htm"}


def stable_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def stable_id(prefix: str, *parts: object) -> str:
    digest = stable_hash("|".join(str(p) for p in parts))[:12]
    return f"{prefix}_{digest}"


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def write_json(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def iter_source_files(root: Path) -> Iterable[Path]:
    if root.is_file():
        yield root
        return
    skip = {"node_modules", "dist", "build", ".git", ".next", ".nuxt", "coverage"}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip for part in path.parts):
            continue
        if path.suffix.lower() in JS_EXTENSIONS | HTML_EXTENSIONS:
            yield path


def line_col_from_offset(text: str, offset: int) -> tuple[int, int]:
    offset = max(0, min(offset, len(text)))
    line = text.count("\n", 0, offset) + 1
    last_newline = text.rfind("\n", 0, offset)
    column = offset + 1 if last_newline == -1 else offset - last_newline
    return line, column


def extract_balanced(text: str, start: int, opener: str = "(", closer: str = ")") -> tuple[str, int] | None:
    if start >= len(text) or text[start] != opener:
        return None
    depth = 0
    quote: str | None = None
    escape = False
    for idx in range(start, len(text)):
        ch = text[idx]
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start + 1 : idx], idx + 1
    return None


def split_top_level_args(text: str) -> list[str]:
    args: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    escape = False
    pairs = {"(": ")", "{": "}", "[": "]"}
    closing = set(pairs.values())
    for idx, ch in enumerate(text):
        if quote:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == quote:
                quote = None
            continue
        if ch in ("'", '"', "`"):
            quote = ch
            continue
        if ch in pairs:
            depth += 1
        elif ch in closing:
            depth -= 1
        elif ch == "," and depth == 0:
            args.append(text[start:idx].strip())
            start = idx + 1
    tail = text[start:].strip()
    if tail:
        args.append(tail)
    return args


def strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"`":
        return value[1:-1]
    return value


def is_probably_third_party(url_or_path: str | None) -> bool:
    if not url_or_path:
        return False
    lower = url_or_path.lower()
    markers = ["cdn.", "jquery", "lodash", "moment", "vendor", "polyfill", "analytics", "sentry"]
    return any(marker in lower for marker in markers)


def normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
