from __future__ import annotations

import re

from .models import FingerprintFinding, JSAsset


BODY_PATTERNS: list[tuple[str, str, str, str]] = [
    ("builder", "Webpack", r"(?:webpackJsonp|__webpack_require__|webpack-dev-server)"),
    ("framework", "Vue", r"(?:__VUE__|vue-router|vuex|new\s+Vue\s*\()"),
    ("framework", "React", r"(?:ReactDOM|__REACT_DEVTOOLS_GLOBAL_HOOK__)"),
    ("framework", "Angular", r"(?:ng-version|angular\.module)"),
    ("framework", "Django", r"csrfmiddlewaretoken"),
    ("technology", "Java", r"(?:JSESSIONID|jeesite)"),
    ("technology", "PHP", r"PHPSESSID"),
    ("security", "HSTS", r"strict-transport-security"),
    ("cdn", "Cloudflare CDN", r"cdnjs\.cloudflare\.com|cloudflare"),
    ("cdn", "jsDelivr CDN", r"cdn\.jsdelivr\.net"),
]


def collect_fingerprints(assets: list[JSAsset]) -> list[FingerprintFinding]:
    seen: set[tuple[str, str]] = set()
    findings: list[FingerprintFinding] = []
    for asset in assets:
        source = asset.path or asset.url or asset.asset_id
        text = asset.raw_code or asset.normalized_code
        for category, name, pattern in BODY_PATTERNS:
            if (category, name) in seen:
                continue
            match = re.search(pattern, text, re.I)
            if not match:
                continue
            seen.add((category, name))
            findings.append(
                FingerprintFinding(
                    category=category,
                    name=name,
                    source=source,
                    confidence=0.8,
                    evidence=match.group(0)[:120],
                )
            )
    return findings
