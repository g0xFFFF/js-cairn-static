from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .utils import write_json


@dataclass(frozen=True)
class BurpTemplateArtifacts:
    out_dir: Path
    json_path: Path
    http_path: Path


def export_burp_templates(
    api_assets_path: Path,
    *,
    base_url: str,
    out_dir: Path,
    limit: int | None = None,
) -> BurpTemplateArtifacts:
    payload = json.loads(api_assets_path.read_text(encoding="utf-8"))
    apis = payload.get("apis", [])
    if limit is not None:
        apis = apis[:limit]

    records = [build_burp_record(api, base_url) for api in apis]
    json_path = out_dir / "bp_seed_requests.json"
    http_path = out_dir / "bp_seed_requests.http"
    out_dir.mkdir(parents=True, exist_ok=True)
    write_json(json_path, {"target": payload.get("target"), "base_url": base_url, "requests": records})
    http_path.write_text(render_http_templates(records), encoding="utf-8")
    return BurpTemplateArtifacts(out_dir=out_dir, json_path=json_path, http_path=http_path)


def build_burp_record(api: dict[str, Any], base_url: str) -> dict[str, Any]:
    api = normalize_api_shape(api)
    parsed = urlsplit(base_url)
    method = str(api.get("method") or "GET").upper()
    path = normalize_template_path(str(api.get("path") or api.get("url") or "/"))
    query_params = [param_stub(param) for param in api.get("params", []) if param.get("location") == "query"]
    path_params = [param_stub(param) for param in api.get("params", []) if param.get("location") == "path"]
    body_params = [param_stub(param) for param in api.get("params", []) if param.get("location") == "body"]
    body_keys = [str(name) for name in api.get("body_keys", []) if str(name).strip()]
    body = build_body_template(method, body_params, body_keys, api.get("body_template"))
    query_string = build_query_string(query_params)
    request_target = path + query_string
    headers = build_headers(method, parsed.netloc, api.get("headers", []), body is not None, api.get("header_values"))
    return {
        "id": api.get("id"),
        "endpoint": f"{method} {path}",
        "method": method,
        "url": f"{parsed.scheme}://{parsed.netloc}{request_target}",
        "path_template": path,
        "path_params": path_params,
        "query_params": query_params,
        "body_template": body,
        "header_candidates": sorted(set(str(item) for item in api.get("headers", []) if str(item).strip())),
        "risk_tags": api.get("risk_tags", []),
        "priority": api.get("priority", 0),
        "raw_http": render_raw_http(method, request_target, headers, body),
    }


def normalize_api_shape(api: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(api)
    params = normalized.get("params", [])
    if isinstance(params, dict):
        flat_params: list[dict[str, Any]] = []
        for location, items in params.items():
            for item in items or []:
                if isinstance(item, dict):
                    flat_params.append({"location": location, **item})
        normalized["params"] = flat_params
    normalized.setdefault("path", normalized.get("url"))
    normalized.setdefault("body_keys", normalized.get("possible_body_fields", []))
    return normalized


def build_headers(method: str, host: str, header_candidates: list[Any], has_body: bool, header_values: dict[str, Any] | None = None) -> list[str]:
    headers = [
        f"Host: {host}",
        "User-Agent: Mozilla/5.0",
        "Accept: application/json, text/plain, */*",
        "Connection: close",
    ]
    if has_body and method in {"POST", "PUT", "PATCH", "DELETE"}:
        headers.append("Content-Type: application/json")
    for name in header_candidates:
        compact = str(name).strip()
        if compact and ":" not in compact:
            value = "__REPLACE_ME__"
            if header_values:
                for key, raw in header_values.items():
                    if key.lower() == compact.lower():
                        value = str(raw)
                        break
            headers.append(f"{compact}: {value}")
    return headers


def build_query_string(query_params: list[dict[str, Any]]) -> str:
    if not query_params:
        return ""
    pieces = [f"{item['name']}={item['value']}" for item in query_params]
    return "?" + "&".join(pieces)


def build_body_template(
    method: str,
    body_params: list[dict[str, Any]],
    body_keys: list[str],
    body_template: dict[str, Any] | list[Any] | None = None,
) -> dict[str, Any] | list[Any] | None:
    if body_template is not None:
        return body_template
    if method not in {"POST", "PUT", "PATCH", "DELETE"} and not body_params and not body_keys:
        return None
    result: dict[str, Any] = {}
    for item in body_params:
        result[item["name"]] = item["value"]
    for key in body_keys:
        result.setdefault(key, placeholder_for_name(key))
    if not result and method in {"POST", "PUT", "PATCH", "DELETE"}:
        result["__BODY_FROM_RUNTIME__"] = "__MISSING_FIELD_DISCOVERY__"
    return result


def render_raw_http(method: str, request_target: str, headers: list[str], body: dict[str, Any] | None) -> str:
    lines = [f"{method} {request_target} HTTP/1.1", *headers, ""]
    if body is not None:
        lines.append(json.dumps(body, ensure_ascii=False, indent=2))
    return "\n".join(lines).rstrip() + "\n"


def render_http_templates(records: list[dict[str, Any]]) -> str:
    blocks: list[str] = []
    for record in records:
        blocks.append(f"### {record['endpoint']}\n{record['raw_http']}")
    return "\n\n".join(blocks).rstrip() + "\n"


def normalize_template_path(path: str) -> str:
    value = path.strip() or "/"
    if not value.startswith("/"):
        value = "/" + value
    return re.sub(r"\{([^}]+)\}", lambda m: f"{{{{{m.group(1)}}}}}", value)


def param_stub(param: dict[str, Any]) -> dict[str, Any]:
    name = str(param.get("name") or "unknown")
    return {
        "name": name,
        "location": param.get("location"),
        "value": param.get("value", placeholder_for_name(name)),
        "risk_tags": param.get("risk_tags", []),
    }


def placeholder_for_name(name: str) -> str:
    compact = name.lower()
    if any(token in compact for token in ("id", "uid", "code", "no", "num")):
        return "1"
    if any(token in compact for token in ("status", "enabled", "flag", "type", "mode")):
        return "test"
    if "file" in compact or "path" in compact:
        return "test"
    return "test"
