from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

from .bp_templates import build_burp_record, normalize_api_shape
from .utils import stable_id, write_json


@dataclass(frozen=True)
class LLMInputArtifacts:
    out_dir: Path
    inventory_path: Path
    llm_input_path: Path


def infer_base_url(
    api_assets_path: Path,
    network_capture: Path | None = None,
    hook_events: Path | None = None,
) -> str | None:
    try:
        payload = json.loads(api_assets_path.read_text(encoding="utf-8"))
        target = str(payload.get("target") or "").strip()
        parsed = urlparse(target)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass

    for path in (network_capture, hook_events):
        if not path or not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        items = data.get("requests") or data.get("events") or []
        for item in items:
            url = str(item.get("url") or "").strip()
            parsed = urlparse(url)
            if parsed.scheme and parsed.netloc:
                return f"{parsed.scheme}://{parsed.netloc}"
    return None


def export_llm_api_test_input(
    api_assets_path: Path,
    *,
    out_dir: Path,
    base_url: str,
    network_capture: Path | None = None,
    hook_events: Path | None = None,
    limit: int | None = None,
) -> LLMInputArtifacts:
    source = json.loads(api_assets_path.read_text(encoding="utf-8"))
    static_apis = source.get("apis", [])
    if limit is not None:
        static_apis = static_apis[:limit]

    runtime_requests = load_runtime_requests(network_capture, hook_events)
    runtime_groups = group_runtime_requests(runtime_requests)

    records = build_merged_records(static_apis, runtime_groups, base_url=base_url)
    inventory = {
        "target": source.get("target"),
        "base_url": base_url,
        "summary": {
            "static_api_count": len(static_apis),
            "runtime_request_count": len(runtime_requests),
            "merged_api_count": len(records),
            "runtime_only_count": sum(1 for record in records if record["source"] == "runtime_only"),
            "runtime_enriched_count": sum(1 for record in records if record["runtime_seen"]),
        },
        "apis": records,
    }

    llm_input = {
        "target": source.get("target"),
        "base_url": base_url,
        "instructions": {
            "purpose": "Feed only API/param/request-template context to the LLM for automated penetration-test planning.",
            "do_not_send_full_js": True,
        },
        "apis": records,
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    inventory_path = out_dir / "api_inventory.json"
    llm_input_path = out_dir / "llm_api_test_input.json"
    write_json(inventory_path, inventory)
    write_json(llm_input_path, llm_input)
    return LLMInputArtifacts(out_dir=out_dir, inventory_path=inventory_path, llm_input_path=llm_input_path)


def build_merged_records(static_apis: list[dict[str, Any]], runtime_groups: dict[tuple[str, str], dict[str, Any]], *, base_url: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    used_runtime_keys: set[tuple[str, str]] = set()

    for api in static_apis:
        method = str(api.get("method") or "GET").upper()
        path = str(api.get("path") or api.get("url") or "/")
        runtime = match_runtime_group(runtime_groups, method, path)
        if runtime:
            used_runtime_keys.add((runtime["method"], runtime["normalized_path"]))
        merged = merge_api_record(api, runtime, base_url=base_url)
        records.append(merged)

    for runtime in runtime_groups.values():
        key = (runtime["method"], runtime["normalized_path"])
        if key in used_runtime_keys:
            continue
        records.append(runtime_only_record(runtime, base_url=base_url))

    records.sort(key=lambda item: (-int(item.get("priority", 0)), item["method"], item["path"]))
    return records


def merge_api_record(api: dict[str, Any], runtime: dict[str, Any] | None, *, base_url: str) -> dict[str, Any]:
    api = normalize_api_shape(api)
    method = str(api.get("method") or "GET").upper()
    path = str(api.get("path") or api.get("url") or "/")
    path_params = unique_param_names([p["name"] for p in api.get("params", []) if p.get("location") == "path"])
    query_params = unique_param_names([p["name"] for p in api.get("params", []) if p.get("location") == "query"])
    body_params = unique_param_names(
        [p["name"] for p in api.get("params", []) if p.get("location") == "body"] + list(api.get("body_keys", []))
    )
    header_params = unique_param_names(list(api.get("headers", [])))
    query_value_map = {p["name"]: p.get("value") for p in api.get("params", []) if p.get("location") == "query" and p.get("value") is not None}
    body_template = None
    header_value_map: dict[str, Any] = {}
    sample_request = None

    if runtime:
        path_params = unique_param_names(path_params + runtime["path_params"])
        query_params = unique_param_names(query_params + runtime["query_params"])
        body_params = unique_param_names(body_params + runtime["body_params"])
        header_params = unique_param_names(header_params + runtime["header_candidates"])
        query_value_map.update(runtime.get("query_value_map", {}))
        body_template = runtime.get("body_template")
        header_value_map.update(runtime.get("header_value_map", {}))
        sample_request = runtime["sample_request"]

    burp_seed = build_burp_record(
        {
            "id": api.get("id"),
            "method": method,
            "path": path,
            "params": (
                [{"name": name, "location": "path", "risk_tags": []} for name in path_params]
                + [{"name": name, "location": "query", "risk_tags": [], "value": query_value_map.get(name, placeholder_value(name))} for name in query_params]
                + [{"name": name, "location": "body", "risk_tags": [], "value": placeholder_value(name)} for name in body_params]
            ),
            "body_keys": body_params,
            "body_template": body_template,
            "headers": header_params,
            "header_values": header_value_map,
            "risk_tags": api.get("risk_tags", []),
            "priority": api.get("priority", 0),
        },
        base_url,
    )

    return {
        "id": api.get("id"),
        "source": "static+runtime" if runtime else "static_only",
        "method": method,
        "path": path,
        "endpoint": f"{method} {path}",
        "priority": api.get("priority", 0),
        "risk_tags": api.get("risk_tags", []),
        "params": {
            "path": path_params,
            "query": query_params,
            "body": body_params,
            "headers": header_params,
        },
        "runtime_seen": bool(runtime),
        "runtime_samples": runtime["sample_count"] if runtime else 0,
        "sample_request": sample_request,
        "request_template": {
            "url": burp_seed["url"],
            "raw_http": burp_seed["raw_http"],
            "body_template": burp_seed["body_template"],
            "query_params": burp_seed["query_params"],
            "path_params": burp_seed["path_params"],
        },
        "evidence_refs": api.get("evidence_refs", []),
    }


def runtime_only_record(runtime: dict[str, Any], *, base_url: str) -> dict[str, Any]:
    path = runtime["original_path"]
    method = runtime["method"]
    burp_seed = build_burp_record(
        {
            "id": stable_id("runtime", method, path),
            "method": method,
            "path": path,
            "params": (
                [{"name": name, "location": "path", "risk_tags": []} for name in runtime["path_params"]]
                + [{"name": name, "location": "query", "risk_tags": [], "value": runtime.get("query_value_map", {}).get(name, placeholder_value(name))} for name in runtime["query_params"]]
                + [{"name": name, "location": "body", "risk_tags": [], "value": placeholder_value(name)} for name in runtime["body_params"]]
            ),
            "body_keys": runtime["body_params"],
            "body_template": runtime.get("body_template"),
            "headers": runtime["header_candidates"],
            "header_values": runtime.get("header_value_map", {}),
            "risk_tags": [],
            "priority": 20,
        },
        base_url,
    )
    return {
        "id": stable_id("runtime", method, path),
        "source": "runtime_only",
        "method": method,
        "path": path,
        "endpoint": f"{method} {path}",
        "priority": 20,
        "risk_tags": [],
        "params": {
            "path": runtime["path_params"],
            "query": runtime["query_params"],
            "body": runtime["body_params"],
            "headers": runtime["header_candidates"],
        },
        "runtime_seen": True,
        "runtime_samples": runtime["sample_count"],
        "sample_request": runtime["sample_request"],
        "request_template": {
            "url": burp_seed["url"],
            "raw_http": burp_seed["raw_http"],
            "body_template": burp_seed["body_template"],
            "query_params": burp_seed["query_params"],
            "path_params": burp_seed["path_params"],
        },
        "evidence_refs": [],
    }


def load_runtime_requests(network_capture: Path | None, hook_events: Path | None) -> list[dict[str, Any]]:
    requests: list[dict[str, Any]] = []
    if network_capture and network_capture.exists():
        data = json.loads(network_capture.read_text(encoding="utf-8"))
        for item in data.get("requests", []):
            requests.append(
                {
                    "method": str(item.get("method") or "GET").upper(),
                    "url": str(item.get("url") or ""),
                    "headers": item.get("request_headers") or {},
                    "body": item.get("post_data_sample"),
                    "source": "network_capture",
                }
            )
    if hook_events and hook_events.exists():
        data = json.loads(hook_events.read_text(encoding="utf-8"))
        for item in data.get("events", []):
            url = str(item.get("url") or "")
            if not url:
                continue
            requests.append(
                {
                    "method": str(item.get("method") or "GET").upper(),
                    "url": url,
                    "headers": item.get("headers") or {},
                    "body": item.get("bodySample"),
                    "source": "hook_events",
                }
            )
    return requests


def group_runtime_requests(requests: list[dict[str, Any]]) -> dict[tuple[str, str], dict[str, Any]]:
    grouped: dict[tuple[str, str], dict[str, Any]] = {}
    for item in requests:
        path_info = split_runtime_url(item["url"])
        method = item["method"]
        normalized_path = normalize_path(path_info["path"])
        key = (method, normalized_path)
        row = grouped.setdefault(
            key,
            {
                "method": method,
                "normalized_path": normalized_path,
                "original_path": path_info["path"],
                "path_params": path_info["path_params"],
                "query_params": [],
                "query_value_map": {},
                "body_params": [],
                "body_template": None,
                "header_candidates": [],
                "header_value_map": {},
                "sample_count": 0,
                "sample_request": None,
            },
        )
        body_info = infer_body_info(item["body"])
        row["sample_count"] += 1
        row["query_params"] = unique_param_names(row["query_params"] + path_info["query_params"])
        row["query_value_map"].update(merge_scalar_map(row["query_value_map"], path_info["query_value_map"]))
        row["path_params"] = unique_param_names(row["path_params"] + path_info["path_params"])
        row["body_params"] = unique_param_names(row["body_params"] + body_info["params"])
        row["body_template"] = richer_template(row["body_template"], body_info["template"])
        row["header_candidates"] = unique_param_names(row["header_candidates"] + interesting_headers(item.get("headers") or {}))
        row["header_value_map"].update(merge_scalar_map(row["header_value_map"], interesting_header_values(item.get("headers") or {})))
        if row["sample_request"] is None:
            row["sample_request"] = {
                "source": item["source"],
                "url": item["url"],
                "body_sample": item["body"],
            }
    return grouped


def split_runtime_url(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    path = parsed.path or "/"
    query_pairs = list(parse_qsl(parsed.query, keep_blank_values=True))
    query_params = [key for key, _ in query_pairs]
    query_value_map = {key: value for key, value in query_pairs}
    path_params: list[str] = []
    for part in [p for p in path.split("/") if p]:
        if part.isdigit() or looks_like_id(part):
            path_params.append("id")
    return {"path": path, "query_params": query_params, "query_value_map": query_value_map, "path_params": path_params}


def normalize_path(path: str) -> str:
    parts = []
    for part in path.split("/"):
        if not part:
            continue
        if part.isdigit() or looks_like_id(part):
            parts.append("{id}")
        else:
            parts.append(part)
    return "/" + "/".join(parts)


def match_runtime_group(runtime_groups: dict[tuple[str, str], dict[str, Any]], method: str, path: str) -> dict[str, Any] | None:
    normalized_path = normalize_path(path)
    direct = runtime_groups.get((method, normalized_path))
    if direct:
        return direct
    for (runtime_method, runtime_path), row in runtime_groups.items():
        if runtime_method != method:
            continue
        if template_matches(path, runtime_path) or template_matches(runtime_path, normalized_path):
            return row
    return None


def infer_body_info(body: Any) -> dict[str, Any]:
    if not body:
        return {"params": [], "template": None}
    if isinstance(body, dict):
        return {"params": collect_leaf_keys(body), "template": body}
    text = str(body).strip()
    if not text:
        return {"params": [], "template": None}
    try:
        loaded = json.loads(text)
        if isinstance(loaded, (dict, list)):
            return {"params": collect_leaf_keys(loaded), "template": loaded}
    except Exception:
        pass
    if "&" in text and "=" in text:
        data = {key: value for key, value in parse_qsl(text, keep_blank_values=True)}
        return {"params": list(data.keys()), "template": data}
    multipart = re.findall(r'name=\"([^\"]+)\"', text)
    if multipart:
        return {"params": multipart, "template": {name: "__MULTIPART_FIELD__" for name in multipart}}
    pairs = re.findall(r'\"([A-Za-z0-9_.-]+)\"\s*:', text)
    if pairs:
        return {"params": pairs, "template": None}
    return {"params": [], "template": None}


def interesting_headers(headers: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key in headers:
        compact = str(key).strip()
        if re.search(r"(authorization|token|csrf|sign|nonce|trace|ticket|session)", compact, re.I):
            names.append(compact)
    return names


def interesting_header_values(headers: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for key, value in headers.items():
        compact = str(key).strip()
        if re.search(r"(authorization|token|csrf|sign|nonce|trace|ticket|session)", compact, re.I):
            values[compact] = value
    return values


def unique_param_names(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        compact = str(value).strip()
        if not compact or compact in seen:
            continue
        seen.add(compact)
        result.append(compact)
    return result


def collect_leaf_keys(value: Any, prefix: str = "") -> list[str]:
    result: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            result.append(name)
            result.extend(collect_leaf_keys(child, name))
    elif isinstance(value, list) and value:
        result.extend(collect_leaf_keys(value[0], prefix))
    return unique_param_names(result)


def richer_template(current: Any, candidate: Any) -> Any:
    if candidate is None:
        return current
    if current is None:
        return candidate
    return candidate if template_score(candidate) > template_score(current) else current


def template_score(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, dict):
        return len(collect_leaf_keys(value)) + len(value)
    if isinstance(value, list):
        return len(value) + (template_score(value[0]) if value else 0)
    return 1


def merge_scalar_map(current: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    result = dict(current)
    for key, value in candidate.items():
        if key not in result or result[key] in {"", None}:
            result[key] = value
    return result


def placeholder_value(name: str) -> str:
    compact = name.lower()
    if any(token in compact for token in ("id", "uid", "code", "no", "num")):
        return "1"
    return "test"


def looks_like_id(value: str) -> bool:
    return len(value) >= 16 and all(ch.isalnum() or ch in "-_" for ch in value)


def template_matches(template: str, path: str) -> bool:
    t_parts = [p for p in template.split("/") if p]
    p_parts = [p for p in path.split("/") if p]
    if len(t_parts) != len(p_parts):
        return False
    for t, p in zip(t_parts, p_parts):
        if t.startswith("{") and t.endswith("}"):
            continue
        if t != p:
            return False
    return True
