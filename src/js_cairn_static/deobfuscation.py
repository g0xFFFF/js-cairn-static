from __future__ import annotations

import re


class DeobfuscationHints:
    def extract_strings(self, code: str, *, min_len: int = 4, limit: int = 5000) -> list[str]:
        strings: list[str] = []
        for match in re.finditer(r"(['\"])(.{%d,300}?)\1" % min_len, code, re.S):
            value = match.group(2)
            if "/" in value or "api" in value.lower() or any(k in value.lower() for k in ["user", "admin", "token", "role"]):
                strings.append(value)
            if len(strings) >= limit:
                break
        return sorted(set(strings))

    def endpoint_like_strings(self, code: str) -> list[str]:
        strings = self.extract_strings(code)
        return [s for s in strings if re.search(r"(^/|https?://|api/|graphql)", s, re.I)]
