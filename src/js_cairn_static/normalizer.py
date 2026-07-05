from __future__ import annotations

import re


def is_minified(code: str) -> bool:
    if not code:
        return False
    lines = code.splitlines() or [code]
    avg = sum(len(line) for line in lines) / max(len(lines), 1)
    return avg > 500 or (len(lines) < 5 and len(code) > 5000)


def normalize_js(code: str) -> str:
    try:
        import jsbeautifier  # type: ignore

        return jsbeautifier.beautify(code)
    except Exception:
        return lightweight_beautify(code)


def lightweight_beautify(code: str) -> str:
    code = re.sub(r";", ";\n", code)
    code = re.sub(r"\{", "{\n", code)
    code = re.sub(r"\}", "\n}\n", code)
    return code


def source_map_url(code: str) -> str | None:
    match = re.search(r"sourceMappingURL=([^\s*]+)", code)
    return match.group(1) if match else None
