from __future__ import annotations

import re

from .models import APIAsset, APIParam


TAG_PATTERNS: list[tuple[str, list[str]]] = [
    ("privilege", ["role", "isadmin", "admin", "permission", "privilege", "scope", "authority"]),
    ("identity", ["userid", "uid", "accountid", "memberid", "openid", "ownerid", "customerid"]),
    ("tenant", ["tenantid", "orgid", "companyid", "workspaceid", "projectid"]),
    ("money", ["price", "amount", "balance", "fee", "pay", "refund", "withdraw", "coupon", "credit"]),
    ("state", ["status", "state", "step", "stage", "workflow", "approved", "enabled", "disabled"]),
    ("file", ["file", "path", "filename", "key", "object", "download", "upload"]),
    ("url", ["url", "uri", "link", "redirect", "next", "returnurl", "callback", "webhook", "target"]),
    ("query", ["sql", "where", "filter", "sort", "order", "search", "keyword"]),
    ("config", ["config", "setting", "feature", "flag", "switch"]),
]


class RiskSemanticTagger:
    def tag(self, apis: list[APIAsset]) -> None:
        for api in apis:
            tags = set(api.risk_tags)
            haystack = f"{api.method} {api.url} " + " ".join(p.name for p in api.params)
            for tag, words in TAG_PATTERNS:
                if any(word in compact(haystack) for word in words):
                    tags.add(tag)
            for param in api.params:
                self._tag_param(param)
                tags.update(param.risk_tags)
            if api.client == "request_wrapper":
                tags.add("wrapped_request")
            if any(t in api.transforms for t in ["encrypt", "sign", "CryptoJS", "JSEncrypt", "md5", "sha256"]):
                tags.add("signed_or_encrypted")
            if re.search(r"\b(admin|manage|internal)\b", api.url, re.I):
                tags.add("admin_surface")
            if any(p.user_controllable for p in api.params) and tags:
                tags.add("user_controlled_sensitive_param")
            api.risk_tags = sorted(tags)
            api.priority = score_api(api)

    def _tag_param(self, param: APIParam) -> None:
        tags = set(param.risk_tags)
        name = compact(param.name)
        for tag, words in TAG_PATTERNS:
            if any(word in name for word in words):
                tags.add(tag)
        if param.user_controllable and tags:
            tags.add("user_controlled")
        param.risk_tags = sorted(tags)


def compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def score_api(api: APIAsset) -> int:
    score = int(api.confidence * 30)
    tag_weights = {
        "privilege": 25,
        "money": 22,
        "tenant": 22,
        "identity": 18,
        "file": 18,
        "url": 16,
        "state": 14,
        "admin_surface": 20,
        "signed_or_encrypted": 8,
        "user_controlled_sensitive_param": 18,
    }
    for tag in api.risk_tags:
        score += tag_weights.get(tag, 4)
    if api.method in {"POST", "PUT", "PATCH", "DELETE"}:
        score += 10
    if len(api.params) >= 3:
        score += 5
    return min(score, 100)
