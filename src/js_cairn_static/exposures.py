from __future__ import annotations

import re

from .models import ExposureFinding, JSAsset, Location
from .utils import line_col_from_offset, stable_id


PATTERNS: list[tuple[str, str, re.Pattern[str], int]] = [
    ("url", "absolute_url", re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I), 60),
    ("ip", "ipv4", re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?::\d{1,5})?(?![\d.])"), 50),
    ("email", "email", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), 30),
    ("jwt", "jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}"), 90),
    ("token", "github_token", re.compile(r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,255}"), 95),
    ("token", "gitlab_token", re.compile(r"glpat-[A-Za-z0-9\-=_]{20,22}"), 95),
    ("cloud_key", "aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 95),
    ("cloud_key", "aliyun_access_key", re.compile(r"\bLTAI[A-Za-z0-9]{12,30}\b"), 95),
    ("credential", "credential_assignment", re.compile(r"(?i)\b[\w-]*(?:pwd|pass|password|passwd|secret|token|api[_-]?key)[\w-]*\s*[:=]\s*['\"]([^'\"\s,]{6,})['\"]"), 85),
    ("document", "document_file", re.compile(r"['\"]([^'\"]+\.(?:pdf|docx?|xlsx?|pptx?|zip|rar|7z|apk|exe|csv|txt)(?:\?[^'\"]*)?)['\"]", re.I), 35),
]


def collect_exposures(assets: list[JSAsset], *, limit_per_kind: int = 200) -> list[ExposureFinding]:
    findings: list[ExposureFinding] = []
    counts: dict[str, int] = {}
    seen: set[tuple[str, str]] = set()
    for asset in assets:
        source = asset.path or asset.url or asset.asset_id
        code = asset.raw_code or asset.normalized_code
        for kind, name, pattern, severity in PATTERNS:
            if counts.get(kind, 0) >= limit_per_kind:
                continue
            for match in pattern.finditer(code):
                value = match.group(0).strip("'\"")
                if is_noise(kind, value):
                    continue
                key = (kind, value)
                if key in seen:
                    continue
                seen.add(key)
                counts[kind] = counts.get(kind, 0) + 1
                line, column = line_col_from_offset(code, match.start())
                findings.append(
                    ExposureFinding(
                        id=stable_id("exp", kind, value, source),
                        kind=kind,
                        name=name,
                        value=value,
                        source=source,
                        severity=severity,
                        confidence=0.85,
                        location=Location(file=source, url=asset.url, line=line, column=column),
                    )
                )
                if counts[kind] >= limit_per_kind:
                    break
    return sorted(findings, key=lambda item: item.severity, reverse=True)


def is_noise(kind: str, value: str) -> bool:
    lower = value.lower()
    if kind == "url" and lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2")):
        return True
    if kind == "ip" and (lower.startswith("0.0.0.0") or lower.startswith("255.255.255.255")):
        return True
    return False
