from __future__ import annotations

import re

from .models import APIAsset, ParamLocation


USER_INPUT_PATTERNS = [
    r"\broute\.query\b",
    r"\broute\.params\b",
    r"\brouter\.query\b",
    r"\blocation\.(?:search|hash|href)\b",
    r"\blocalStorage\b",
    r"\bsessionStorage\b",
    r"\bdocument\.cookie\b",
    r"\bevent\.data\b",
    r"\binput\.value\b",
    r"\bform\.",
    r"\bthis\.form\b",
    r"\bvalues\.",
    r"\bURLSearchParams\b",
]


class DataflowAnalyzer:
    """Lightweight dataflow for API params.

    This intentionally keeps a bounded scope. It marks likely user-controlled
    params and records simple flows/transforms for downstream LLM review.
    """

    def analyze(self, code: str, apis: list[APIAsset]) -> None:
        assignments = self._collect_assignments(code)
        for api in apis:
            for param in api.params:
                expr = param.source_expr or param.name
                flow = self._trace(expr, assignments)
                if flow:
                    param.flow = flow
                joined = " -> ".join(flow or [expr])
                param.user_controllable = self._is_user_controlled(joined, param.location)
                param.transforms = self._transforms(joined)

    def _collect_assignments(self, code: str) -> dict[str, str]:
        assignments: dict[str, str] = {}
        pattern = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,500})[;\n]", re.S)
        for match in pattern.finditer(code):
            assignments[match.group(1)] = match.group(2).strip()
        return assignments

    def _trace(self, expr: str, assignments: dict[str, str], depth: int = 4) -> list[str]:
        flow = [expr]
        current = expr.split(".", 1)[0].strip()
        seen = {current}
        for _ in range(depth):
            if current not in assignments:
                break
            next_expr = assignments[current]
            flow.append(next_expr)
            next_name = next_expr.split(".", 1)[0].strip()
            if next_name in seen:
                break
            seen.add(next_name)
            current = next_name
        return flow

    def _is_user_controlled(self, flow: str, location: ParamLocation) -> bool:
        if location in {ParamLocation.body, ParamLocation.query, ParamLocation.path}:
            if re.search(r"\b(form|values|params|query|input|route)\b", flow, re.I):
                return True
        return any(re.search(pattern, flow) for pattern in USER_INPUT_PATTERNS)

    def _transforms(self, flow: str) -> list[str]:
        transforms = []
        for marker in ["JSON.stringify", "encodeURIComponent", "encrypt", "sign", "md5", "sha1", "sha256", "btoa"]:
            if marker in flow:
                transforms.append(marker)
        return transforms
