"""请求提取层：从 JS 表达式中恢复 fetch / axios / XHR / wrapper 请求语义。"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Callable

from .ast_visitor import ASTCallExpression, JSASTVisitor, expression_literal_value, expression_object_fields
from .constants import ConstantTable, clean_param_name
from .models import APIAsset, APIParam, Evidence, Location, ParamLocation, WrapperCandidate
from .utils import extract_balanced, line_col_from_offset, normalize_ws, split_top_level_args, stable_id, strip_quotes


HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
DIRECT_CLIENTS = ["fetch", "axios", "$.ajax", "jQuery.ajax"]
WRAPPER_NAME_RE = re.compile(r"\b(request|http|ajax|api|service|client|requester|httpClient|apiClient)\b", re.I)
ENDPOINT_HINT_RE = re.compile(r"['\"`]((?:https?://[^'\"`]+)|(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]{3,}))['\"`]")
REQUEST_METHOD_NAMES = ("get", "post", "put", "patch", "delete", "head", "options", "request")


@dataclass
class ProbeResult:
    quick_hits: list[str] = field(default_factory=list)
    candidate_endpoints: list[str] = field(default_factory=list)
    direct_client_calls: int = 0
    instance_client_calls: int = 0
    request_like_calls: int = 0

    @property
    def signal_score(self) -> int:
        return self.direct_client_calls * 3 + self.instance_client_calls * 3 + self.request_like_calls * 2 + len(self.candidate_endpoints)

    def summary(self) -> str:
        return (
            f"direct={self.direct_client_calls}, instance={self.instance_client_calls}, "
            f"request_like={self.request_like_calls}, endpoint_hints={len(self.candidate_endpoints)}"
        )


@dataclass
class WrapperFunctionTemplate:
    name: str
    params: list[str]
    body: str
    start: int
    end: int
    url_expr: str
    method_expr: str | None = None
    params_expr: str | None = None
    body_expr: str | None = None
    headers_expr: str | None = None
    client: str = "request_wrapper"


class ExtractionContext:
    def __init__(
        self,
        code: str,
        file_ref: str | None = None,
        progress: Callable[[str], None] | None = None,
        *,
        learn_constants: bool = True,
    ) -> None:
        self.code = code
        self.file_ref = file_ref
        self.constants = ConstantTable(progress=progress)
        if learn_constants:
            self.constants.learn(code)


class RequestExtractor:
    def probe(self, code: str) -> ProbeResult:
        probe = ProbeResult()
        if re.search(r"\bfetch\s*\(", code):
            probe.quick_hits.append("fetch")
        if re.search(r"\baxios\.(?:get|post|put|patch|delete|head|options|request)\s*\(", code):
            probe.quick_hits.append("axios.method")
        if re.search(r"\baxios\.create\s*\(", code):
            probe.quick_hits.append("axios.create")
        if re.search(r"(?:this\.)?\$http\.(?:get|post|put|patch|delete|request)\s*\(", code):
            probe.quick_hits.append("$http.instance")
        if re.search(r"\b(?:request|service|client|apiClient|httpClient)\.(?:get|post|put|patch|delete|request)\s*\(", code, re.I):
            probe.quick_hits.append("named.instance")
        probe.direct_client_calls = len(re.findall(r"\bfetch\s*\(", code)) + len(
            re.findall(r"\baxios\.(?:get|post|put|patch|delete|head|options|request)\s*\(", code, re.I)
        )
        probe.instance_client_calls = len(
            re.findall(
                r"\b(?:this\.)?\$?[A-Za-z_$][\w$]*(?:\.\$?[A-Za-z_$][\w$]*)*\.(?:get|post|put|patch|delete|head|options|request)\s*\(",
                code,
                re.I,
            )
        )
        probe.request_like_calls = len(re.findall(r"\b(?:request|service|client|apiClient|httpClient|ajax)\s*\(", code, re.I))
        seen: set[str] = set()
        for match in ENDPOINT_HINT_RE.finditer(code):
            hint = normalize_url_template(match.group(1))
            if not looks_like_endpoint_hint(hint):
                continue
            if hint in seen:
                continue
            seen.add(hint)
            probe.candidate_endpoints.append(hint)
            if len(probe.candidate_endpoints) >= 25:
                break
        return probe

    def extract(self, ctx: ExtractionContext, wrappers: list[WrapperCandidate], *, mode: str = "full") -> list[APIAsset]:
        if mode == "skip":
            return []
        apis: list[APIAsset] = []
        if mode == "full":
            apis.extend(self._extract_ast_calls(ctx))
            apis.extend(self._extract_cross_function_wrapper_calls(ctx))
        apis.extend(self._extract_fetch(ctx))
        apis.extend(self._extract_axios_methods(ctx))
        apis.extend(self._extract_axios_config(ctx))
        apis.extend(self._extract_callable_axios_alias_config(ctx))
        apis.extend(self._extract_http_client_instance_methods(ctx))
        apis.extend(self._extract_http_client_instance_config_calls(ctx))
        apis.extend(self._extract_named_request_clients(ctx))
        apis.extend(self._extract_ajax(ctx))
        if mode == "full":
            apis.extend(self._extract_wrappers(ctx, wrappers))
        return merge_api_assets(apis)

    def _extract_cross_function_wrapper_calls(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        templates = discover_wrapper_function_templates(ctx)
        if not templates:
            return result
        for template in templates:
            for match in re.finditer(rf"\b{re.escape(template.name)}\s*\(", ctx.code):
                if is_function_definition_prefix(ctx.code, match.start()) or template.start <= match.start() <= template.end:
                    continue
                balanced = extract_balanced(ctx.code, match.end() - 1)
                if not balanced:
                    continue
                args = split_top_level_args(balanced[0])
                api = api_from_wrapper_template_call(ctx, template, args, match.start(), balanced[0])
                if api:
                    result.append(api)
        return result

    def _extract_ast_calls(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        clients = discover_http_client_names(ctx.code)
        for call in JSASTVisitor(ctx.code).call_expressions():
            callee = normalize_ast_callee(call.callee)
            method_target = ast_method_target(callee)

            if is_ast_fetch_call(callee):
                api = self._api_from_fetch_call(ctx, call)
                if api:
                    result.append(api)
                continue

            if method_target:
                instance_expr, method_name = method_target
                if instance_expr in {"axios"}:
                    api = self._api_from_method_call(ctx, call, method_name, "axios")
                elif instance_expr in {"$", "jQuery"} and method_name == "AJAX":
                    api = self._api_from_config_call(ctx, call, "jquery.ajax")
                elif is_http_client_expr(instance_expr, clients):
                    client_name = instance_expr.split(".")[-1]
                    api = self._api_from_method_call(ctx, call, method_name, f"http_client_instance:{client_name}")
                else:
                    api = None
                if api:
                    result.append(api)
                continue

            callable_client = ast_callable_client(callee, clients)
            if callable_client:
                api = self._api_from_config_call(ctx, call, callable_client)
                if api:
                    result.append(api)
        return result

    def _api_from_fetch_call(self, ctx: ExtractionContext, call: ASTCallExpression) -> APIAsset | None:
        if not call.args:
            return None
        url = resolve_url(call.args[0], ctx.constants)
        if not url:
            return None
        method = "GET"
        params: list[APIParam] = extract_params_from_url(url)
        body_raw = None
        possible_body_fields: list[str] = []
        transforms: list[str] = []
        headers: list[str] = []
        if len(call.args) > 1:
            method = extract_object_field(call.args[1], "method", ctx.constants) or method
            body_expr = extract_object_field_expr(call.args[1], "body")
            body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, call.offset)
            params.extend(body_params)
            headers = extract_headers(call.args[1])
            transforms.extend(extract_transforms(call.args[1]))
        return make_api(
            ctx,
            call.offset,
            method,
            url,
            "fetch",
            params,
            headers,
            transforms,
            snippet=call.snippet,
            body_raw=body_raw,
            possible_body_fields=possible_body_fields,
        )

    def _api_from_method_call(
        self,
        ctx: ExtractionContext,
        call: ASTCallExpression,
        method_name: str,
        client: str,
    ) -> APIAsset | None:
        if not call.args:
            return None
        if method_name == "REQUEST":
            return self._api_from_config_call(ctx, call, client)

        url = resolve_url(call.args[0], ctx.constants)
        if not url:
            return None
        params = extract_params_from_url(url)
        headers: list[str] = []
        body_raw = None
        possible_body_fields: list[str] = []
        transforms = extract_transforms(call.snippet)
        if method_name == "GET" and len(call.args) > 1:
            params.extend(params_from_params_object(call.args[1], ctx.constants))
            headers.extend(extract_headers(call.args[1]))
        elif len(call.args) > 1:
            body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, call.args[1], call.offset)
            params.extend(body_params)
            if len(call.args) > 2:
                headers.extend(extract_headers(call.args[2]))
        return make_api(
            ctx,
            call.offset,
            method_name,
            url,
            client,
            params,
            headers,
            transforms,
            snippet=call.snippet,
            body_raw=body_raw,
            possible_body_fields=possible_body_fields,
        )

    def _api_from_config_call(self, ctx: ExtractionContext, call: ASTCallExpression, client: str) -> APIAsset | None:
        if not call.args or not call.args[0].lstrip().startswith("{"):
            return None
        config = call.args[0]
        url = extract_object_field(config, "url", ctx.constants) or extract_object_field(config, "path", ctx.constants)
        if not url:
            return None
        method = (
            extract_object_field(config, "method", ctx.constants)
            or extract_object_field(config, "type", ctx.constants)
            or "GET"
        )
        params = extract_params_from_url(url)
        params.extend(params_from_params_object(extract_object_field_expr(config, "params") or "", ctx.constants))
        body_expr = extract_object_field_expr(config, "data") or extract_object_field_expr(config, "body")
        body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, call.offset)
        params.extend(body_params)
        return make_api(
            ctx,
            call.offset,
            method,
            url,
            client,
            params,
            extract_headers(config),
            extract_transforms(config),
            snippet=call.snippet,
            body_raw=body_raw,
            possible_body_fields=possible_body_fields,
        )

    def _extract_fetch(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        for match in re.finditer(r"\bfetch\s*\(", ctx.code):
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args:
                continue
            url = resolve_url(args[0], ctx.constants)
            if not url:
                continue
            method = "GET"
            params: list[APIParam] = extract_params_from_url(url)
            body_raw = None
            possible_body_fields: list[str] = []
            transforms: list[str] = []
            if len(args) > 1:
                method = extract_object_field(args[1], "method", ctx.constants) or method
                body_expr = extract_object_field_expr(args[1], "body")
                body_raw, inferred_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
                possible_body_fields.extend(inferred_body_fields)
                params.extend(body_params)
                headers = extract_headers(args[1])
                transforms.extend(extract_transforms(args[1]))
            else:
                headers = []
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method,
                    url,
                    "fetch",
                    params,
                    headers,
                    transforms,
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_axios_methods(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        pattern = re.compile(r"\baxios\.(get|post|put|patch|delete|head|options)\s*\(", re.I)
        for match in pattern.finditer(ctx.code):
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args:
                continue
            method = match.group(1).upper()
            url = resolve_url(args[0], ctx.constants)
            if not url:
                continue
            params = extract_params_from_url(url)
            headers: list[str] = []
            body_raw = None
            possible_body_fields: list[str] = []
            transforms: list[str] = []
            if method == "GET" and len(args) > 1:
                params.extend(params_from_params_object(args[1], ctx.constants))
                headers.extend(extract_headers(args[1]))
            elif len(args) > 1:
                body_raw, inferred_body_fields, body_params = analyze_body_payload(ctx, args[1], match.start())
                possible_body_fields.extend(inferred_body_fields)
                params.extend(body_params)
                if len(args) > 2:
                    headers.extend(extract_headers(args[2]))
            transforms.extend(extract_transforms(balanced[0]))
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method,
                    url,
                    "axios",
                    params,
                    headers,
                    transforms,
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_axios_config(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        for match in re.finditer(r"\baxios\s*\(", ctx.code):
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args or not args[0].lstrip().startswith("{"):
                continue
            url = extract_object_field(args[0], "url", ctx.constants)
            if not url:
                continue
            method = extract_object_field(args[0], "method", ctx.constants) or "GET"
            params = extract_params_from_url(url)
            params.extend(params_from_params_object(extract_object_field_expr(args[0], "params") or "", ctx.constants))
            body_expr = extract_object_field_expr(args[0], "data") or extract_object_field_expr(args[0], "body")
            body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
            params.extend(body_params)
            headers = extract_headers(args[0])
            transforms = extract_transforms(args[0])
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method,
                    url,
                    "axios",
                    params,
                    headers,
                    transforms,
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_callable_axios_alias_config(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        pattern = re.compile(
            r"(?:Object\s*\(\s*[^)]*\[\s*['\"]axios['\"]\s*\]\s*\)|[A-Za-z_$][\w$]*(?:\[['\"]axios['\"]\])?)\s*\(",
            re.I,
        )
        for match in pattern.finditer(ctx.code):
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args or not args[0].lstrip().startswith("{"):
                continue
            url = extract_object_field(args[0], "url", ctx.constants)
            if not url:
                continue
            method = extract_object_field(args[0], "method", ctx.constants) or "GET"
            params = extract_params_from_url(url)
            params.extend(params_from_params_object(extract_object_field_expr(args[0], "params") or "", ctx.constants))
            body_expr = extract_object_field_expr(args[0], "data") or extract_object_field_expr(args[0], "body")
            body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
            params.extend(body_params)
            headers = extract_headers(args[0])
            transforms = extract_transforms(args[0])
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method,
                    url,
                    "axios_callable_alias",
                    params,
                    headers,
                    transforms,
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_http_client_instance_methods(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        clients = discover_http_client_names(ctx.code)
        if not clients:
            return result
        pattern = re.compile(
            r"\b((?:this\.)?\$?[A-Za-z_$][\w$]*(?:\.\$?[A-Za-z_$][\w$]*)*)\.(get|post|put|patch|delete|head|options|request)\s*\(",
            re.I,
        )
        for match in pattern.finditer(ctx.code):
            instance_expr = match.group(1)
            if not is_http_client_expr(instance_expr, clients):
                continue
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args:
                continue
            method_name = match.group(2).upper()
            client_name = instance_expr.split(".")[-1]
            if method_name == "REQUEST":
                if not args[0].lstrip().startswith("{"):
                    continue
                url = extract_object_field(args[0], "url", ctx.constants)
                if not url:
                    continue
                method = extract_object_field(args[0], "method", ctx.constants) or "GET"
                params = extract_params_from_url(url)
                params.extend(params_from_params_object(extract_object_field_expr(args[0], "params") or "", ctx.constants))
                body_expr = extract_object_field_expr(args[0], "data") or extract_object_field_expr(args[0], "body")
                body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
                params.extend(body_params)
                headers = extract_headers(args[0])
                transforms = extract_transforms(args[0])
                result.append(
                    make_api(
                        ctx,
                        match.start(),
                        method,
                        url,
                        f"http_client_instance:{client_name}",
                        params,
                        headers,
                        transforms,
                        snippet=balanced[0],
                        body_raw=body_raw,
                        possible_body_fields=possible_body_fields,
                    )
                )
                continue

            url = resolve_url(args[0], ctx.constants)
            if not url:
                continue
            params = extract_params_from_url(url)
            headers: list[str] = []
            body_raw = None
            possible_body_fields: list[str] = []
            transforms: list[str] = []
            if method_name == "GET" and len(args) > 1:
                params.extend(params_from_params_object(args[1], ctx.constants))
                headers.extend(extract_headers(args[1]))
            elif len(args) > 1:
                body_raw, inferred_body_fields, body_params = analyze_body_payload(ctx, args[1], match.start())
                possible_body_fields.extend(inferred_body_fields)
                params.extend(body_params)
                if len(args) > 2:
                    headers.extend(extract_headers(args[2]))
            transforms.extend(extract_transforms(balanced[0]))
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method_name,
                    url,
                    f"http_client_instance:{client_name}",
                    params,
                    headers,
                    transforms,
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_http_client_instance_config_calls(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        clients = discover_http_client_names(ctx.code)
        pattern = re.compile(r"\b((?:this\.)?\$?[A-Za-z_$][\w$]*(?:\.\$?[A-Za-z_$][\w$]*)*)\s*\(", re.I)
        for match in pattern.finditer(ctx.code):
            instance_expr = match.group(1)
            if not is_http_client_expr(instance_expr, clients):
                continue
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args or not args[0].lstrip().startswith("{"):
                continue
            url = extract_object_field(args[0], "url", ctx.constants)
            if not url:
                continue
            method = extract_object_field(args[0], "method", ctx.constants) or "GET"
            params = extract_params_from_url(url)
            params.extend(params_from_params_object(extract_object_field_expr(args[0], "params") or "", ctx.constants))
            body_expr = extract_object_field_expr(args[0], "data") or extract_object_field_expr(args[0], "body")
            body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
            params.extend(body_params)
            headers = extract_headers(args[0])
            transforms = extract_transforms(args[0])
            client_name = instance_expr.split(".")[-1]
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method,
                    url,
                    f"http_client_instance:{client_name}",
                    params,
                    headers,
                    transforms,
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_named_request_clients(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        pattern = re.compile(r"\b(request|service|client|apiClient|httpClient|requester|ajax)\s*\(", re.I)
        for match in pattern.finditer(ctx.code):
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args or not args[0].lstrip().startswith("{"):
                continue
            url = extract_object_field(args[0], "url", ctx.constants) or extract_object_field(args[0], "path", ctx.constants)
            if not url:
                continue
            method = extract_object_field(args[0], "method", ctx.constants) or extract_object_field(args[0], "type", ctx.constants) or "GET"
            params = extract_params_from_url(url)
            params.extend(params_from_params_object(extract_object_field_expr(args[0], "params") or "", ctx.constants))
            body_expr = extract_object_field_expr(args[0], "data") or extract_object_field_expr(args[0], "body")
            body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
            params.extend(body_params)
            headers = extract_headers(args[0])
            transforms = extract_transforms(args[0])
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method,
                    url,
                    f"named_request_client:{match.group(1)}",
                    params,
                    headers,
                    transforms,
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_ajax(self, ctx: ExtractionContext) -> list[APIAsset]:
        result: list[APIAsset] = []
        for match in re.finditer(r"(?:\$|jQuery)\.ajax\s*\(", ctx.code):
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args:
                continue
            config = args[0]
            url = extract_object_field(config, "url", ctx.constants)
            if not url:
                continue
            method = extract_object_field(config, "method", ctx.constants) or extract_object_field(config, "type", ctx.constants) or "GET"
            params = extract_params_from_url(url)
            body_expr = extract_object_field_expr(config, "data")
            body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
            params.extend(body_params)
            headers = extract_headers(config)
            result.append(
                make_api(
                    ctx,
                    match.start(),
                    method,
                    url,
                    "jquery.ajax",
                    params,
                    headers,
                    extract_transforms(config),
                    snippet=balanced[0],
                    body_raw=body_raw,
                    possible_body_fields=possible_body_fields,
                )
            )
        return result

    def _extract_wrappers(self, ctx: ExtractionContext, wrappers: list[WrapperCandidate]) -> list[APIAsset]:
        result: list[APIAsset] = []
        names = {w.name: w for w in wrappers}
        if not names:
            return result
        pattern = re.compile(r"\b(" + "|".join(re.escape(name) for name in names) + r")\s*\(")
        for match in pattern.finditer(ctx.code):
            name = match.group(1)
            balanced = extract_balanced(ctx.code, match.end() - 1)
            if not balanced:
                continue
            args = split_top_level_args(balanced[0])
            if not args:
                continue
            url = None
            method = "GET"
            params: list[APIParam] = []
            headers: list[str] = []
            body_raw = None
            possible_body_fields: list[str] = []
            if args[0].lstrip().startswith("{"):
                url = extract_object_field(args[0], "url", ctx.constants) or extract_object_field(args[0], "path", ctx.constants)
                method = extract_object_field(args[0], "method", ctx.constants) or extract_object_field(args[0], "type", ctx.constants) or method
                params.extend(params_from_params_object(extract_object_field_expr(args[0], "params") or "", ctx.constants))
                body_expr = extract_object_field_expr(args[0], "data") or extract_object_field_expr(args[0], "body")
                body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, body_expr, match.start())
                params.extend(body_params)
                headers = extract_headers(args[0])
            elif len(args) >= 1:
                url = resolve_url(args[0], ctx.constants)
                if len(args) >= 2 and args[1].strip().upper().strip("'\"") in HTTP_METHODS:
                    method = strip_quotes(args[1]).upper()
                elif len(args) >= 2:
                    body_raw, possible_body_fields, body_params = analyze_body_payload(ctx, args[1], match.start())
                    params.extend(body_params)
            if not url:
                continue
            params = extract_params_from_url(url) + params
            api = make_api(
                ctx,
                match.start(),
                method,
                url,
                "request_wrapper",
                params,
                headers,
                extract_transforms(balanced[0]),
                snippet=balanced[0],
                body_raw=body_raw,
                possible_body_fields=possible_body_fields,
            )
            api.wrapper = name
            api.confidence = min(0.95, api.confidence + names[name].confidence * 0.2)
            result.append(api)
        return result


class WrapperDetector:
    def detect(self, ctx: ExtractionContext) -> list[WrapperCandidate]:
        candidates: list[WrapperCandidate] = []
        function_pattern = re.compile(
            r"(?:function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>)\s*\{",
            re.S,
        )
        for match in function_pattern.finditer(ctx.code):
            name = match.group(1) or match.group(3)
            params = [p.strip() for p in (match.group(2) or match.group(4) or "").split(",") if p.strip()]
            body = extract_balanced(ctx.code, match.end() - 1, "{", "}")
            if not body:
                continue
            body_text = body[0]
            score = 0.0
            backend = None
            if re.search(r"\baxios\b", body_text):
                score += 0.35
                backend = "axios"
            if re.search(r"\bfetch\s*\(", body_text):
                score += 0.35
                backend = "fetch"
            if re.search(r"XMLHttpRequest", body_text):
                score += 0.35
                backend = "xhr"
            if WRAPPER_NAME_RE.search(name):
                score += 0.25
            if re.search(r"\b(url|method|data|params|headers)\b", body_text):
                score += 0.2
            if "Promise" in body_text or ".then(" in body_text or "async" in ctx.code[max(0, match.start() - 20) : match.start() + 20]:
                score += 0.1
            if score < 0.45:
                continue
            headers = sorted(set(re.findall(r"['\"](Authorization|X-CSRF-Token|X-Requested-With|token|csrf|sign)['\"]", body_text, re.I)))
            candidate = WrapperCandidate(
                wrapper_id=stable_id("wrap", ctx.file_ref, name, match.start()),
                name=name,
                defined_in=ctx.file_ref,
                backend=backend,
                params=params,
                adds_headers=headers,
                has_interceptor="interceptor" in body_text,
                has_sign_logic=bool(re.search(r"\b(sign|signature|md5|sha\d*)\b", body_text, re.I)),
                has_encrypt_logic=bool(re.search(r"\b(encrypt|CryptoJS|JSEncrypt|AES|RSA)\b", body_text, re.I)),
                confidence=min(score, 0.98),
                evidence=[make_evidence(ctx, match.start(), body_text[:500], min(score, 0.98), "wrapper_detector")],
            )
            candidates.append(candidate)
        return candidates


class CallGraphExtractor:
    def extract(self, ctx: ExtractionContext) -> list[tuple[str, str, int]]:
        edges: list[tuple[str, str, int]] = []
        function_pattern = re.compile(r"(?:function\s+([A-Za-z_$][\w$]*)|(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\()", re.S)
        for match in function_pattern.finditer(ctx.code):
            caller = match.group(1) or match.group(2)
            body_start = ctx.code.find("{", match.end())
            if body_start == -1:
                continue
            body = extract_balanced(ctx.code, body_start, "{", "}")
            if not body:
                continue
            for call in re.finditer(r"\b([A-Za-z_$][\w$]*)\s*\(", body[0]):
                callee = call.group(1)
                if callee in {"if", "for", "while", "switch", "catch", "function"}:
                    continue
                edges.append((caller, callee, body_start + call.start()))
        return edges


def discover_wrapper_function_templates(ctx: ExtractionContext) -> list[WrapperFunctionTemplate]:
    templates: list[WrapperFunctionTemplate] = []
    seen: set[tuple[str, int]] = set()
    for name, params, body, start, end in iter_named_function_bodies(ctx.code):
        template = wrapper_template_from_body(ctx, name, params, body, start, end)
        if not template:
            continue
        key = (template.name, template.start)
        if key in seen:
            continue
        seen.add(key)
        templates.append(template)
    return templates


def iter_named_function_bodies(code: str) -> list[tuple[str, list[str], str, int, int]]:
    functions: list[tuple[str, list[str], str, int, int]] = []
    patterns = [
        re.compile(r"\b(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{", re.S),
        re.compile(r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{", re.S),
        re.compile(r"\b(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?([A-Za-z_$][\w$]*)\s*=>\s*\{", re.S),
    ]
    for pattern in patterns:
        for match in pattern.finditer(code):
            balanced = extract_balanced(code, match.end() - 1, "{", "}")
            if not balanced:
                continue
            body, end = balanced
            raw_params = match.group(2)
            params = [part.strip() for part in raw_params.split(",") if part.strip()]
            functions.append((match.group(1), params, body, match.start(), end))
    return functions


def wrapper_template_from_body(
    ctx: ExtractionContext,
    name: str,
    params: list[str],
    body: str,
    start: int,
    end: int,
) -> WrapperFunctionTemplate | None:
    call_pattern = re.compile(r"\b(axios|request|service|client|apiClient|httpClient|requester|ajax)\s*\(", re.I)
    for match in call_pattern.finditer(body):
        balanced = extract_balanced(body, match.end() - 1)
        if not balanced:
            continue
        args = split_top_level_args(balanced[0])
        if not args or not args[0].lstrip().startswith("{"):
            continue
        config = args[0]
        url_expr = extract_object_field_expr(config, "url") or extract_object_field_expr(config, "path")
        if not url_expr:
            continue
        return WrapperFunctionTemplate(
            name=name,
            params=params,
            body=body,
            start=start,
            end=end,
            url_expr=url_expr,
            method_expr=extract_object_field_expr(config, "method") or extract_object_field_expr(config, "type"),
            params_expr=extract_object_field_expr(config, "params"),
            body_expr=extract_object_field_expr(config, "data") or extract_object_field_expr(config, "body"),
            headers_expr=extract_object_field_expr(config, "headers"),
            client=f"cross_function_wrapper:{name}",
        )
    return None


def api_from_wrapper_template_call(
    ctx: ExtractionContext,
    template: WrapperFunctionTemplate,
    args: list[str],
    offset: int,
    snippet: str,
) -> APIAsset | None:
    bindings = {name: args[index] for index, name in enumerate(template.params) if index < len(args)}
    url = resolve_bound_url(template.url_expr, bindings, ctx.constants)
    if not url:
        return None
    method = resolve_bound_method(template.method_expr, bindings, ctx.constants) or "GET"
    params = extract_params_from_url(url)
    params.extend(params_from_params_object(resolve_bound_expr(template.params_expr, bindings), ctx.constants))
    body_raw, possible_body_fields, body_params = analyze_body_payload(
        ctx,
        resolve_bound_expr(template.body_expr, bindings),
        offset,
    )
    params.extend(body_params)
    headers = (
        extract_headers("{" + f"headers: {resolve_bound_expr(template.headers_expr, bindings)}" + "}")
        if template.headers_expr
        else []
    )
    api = make_api(
        ctx,
        offset,
        method,
        url,
        template.client,
        params,
        headers,
        extract_transforms(snippet + " " + template.body),
        snippet=snippet,
        body_raw=body_raw,
        possible_body_fields=possible_body_fields,
    )
    api.wrapper = template.name
    api.confidence = 0.9
    return api


def resolve_bound_url(expr: str | None, bindings: dict[str, str], constants: ConstantTable) -> str | None:
    bound = resolve_bound_expr(expr, bindings)
    return resolve_url(bound, constants) if bound else None


def resolve_bound_method(expr: str | None, bindings: dict[str, str], constants: ConstantTable) -> str | None:
    bound = resolve_bound_expr(expr, bindings)
    if not bound:
        return None
    value = constants.resolve_expr(bound)
    if value:
        return value.upper()
    literal = expression_literal_value(bound)
    if literal:
        return literal.upper()
    tail = re.search(r"\.([A-Za-z]+)$", bound.strip())
    if tail:
        return tail.group(1).upper()
    return strip_quotes(bound).upper()


def resolve_bound_expr(expr: str | None, bindings: dict[str, str]) -> str | None:
    if not expr:
        return None
    stripped = expr.strip()
    if stripped in bindings:
        return bindings[stripped]
    if not bindings:
        return stripped
    result = stripped
    for name, value in sorted(bindings.items(), key=lambda item: len(item[0]), reverse=True):
        result = re.sub(rf"\b{re.escape(name)}\b", value, result)
    return result


def is_function_definition_prefix(code: str, offset: int) -> bool:
    prefix = code[max(0, offset - 32):offset]
    return bool(re.search(r"(?:function|const|let|var)\s+$", prefix))


def resolve_url(expr: str, constants: ConstantTable) -> str | None:
    expr = expr.strip()
    value = constants.resolve_expr(expr)
    if value:
        normalized = normalize_url_template(value)
        return normalized if is_probable_api_url(normalized) else None
    literal = expression_literal_value(expr)
    if literal:
        normalized = normalize_url_template(literal)
        return normalized if is_probable_api_url(normalized) else None
    if re.match(r"['\"`][^'\"`]*(?:/|http|api)[^'\"`]*['\"`]$", expr, re.I):
        normalized = normalize_url_template(strip_quotes(expr))
        return normalized if is_probable_api_url(normalized) else None
    return None


def normalize_url_template(url: str) -> str:
    url = url.strip()
    # 打包或格式化后的 template literal 可能混入换行和空白，先压平再还原参数占位。
    url = re.sub(r"\s+", "", url)
    url = re.sub(r"\$\{([^}]+)\}", lambda m: "{" + clean_param_name(m.group(1)) + "}", url)
    url = re.sub(r":([A-Za-z_][\w]*)", r"{\1}", url)
    return url


def extract_object_field(obj: str, field: str, constants: ConstantTable) -> str | None:
    expr = extract_object_field_expr(obj, field)
    if not expr:
        return None
    value = constants.resolve_expr(expr)
    if value is not None:
        if field in {"method", "type"}:
            return value.upper()
        normalized = normalize_url_template(value)
        return normalized if is_probable_api_url(normalized) else None
    literal = expression_literal_value(expr)
    if literal is not None:
        if field in {"method", "type"}:
            return literal.upper()
        normalized = normalize_url_template(literal)
        return normalized if is_probable_api_url(normalized) else None
    if field in {"method", "type"}:
        method_tail = re.search(r"\.([A-Za-z]+)$", expr.strip())
        if method_tail:
            return method_tail.group(1).upper()
        return strip_quotes(expr).upper()
    return None


def extract_object_field_expr(obj: str | None, field: str) -> str | None:
    if not obj:
        return None
    ast_fields = expression_object_fields(obj)
    if field in ast_fields:
        return ast_fields[field].expr
    match = re.search(rf"(?:{re.escape(field)}|['\"]{re.escape(field)}['\"])\s*:\s*", obj)
    if not match:
        return None
    start = match.end()
    tail = obj[start:]
    pieces = split_top_level_args(tail)
    return pieces[0] if pieces else None


def extract_params_from_url(url: str) -> list[APIParam]:
    params: list[APIParam] = []
    for name in re.findall(r"\{([^}]+)\}", url):
        params.append(APIParam(name=name, location=ParamLocation.path, source_expr=name))
    query = url.split("?", 1)[1] if "?" in url else ""
    for name in re.findall(r"[?&]?([A-Za-z_$][\w$.-]*)=", query):
        params.append(APIParam(name=name, location=ParamLocation.query, source_expr=name))
    return params


def params_from_params_object(expr: str | None, constants: ConstantTable) -> list[APIParam]:
    return params_from_object_expr(expr, constants, ParamLocation.query)


def params_from_body_expr(expr: str | None, constants: ConstantTable) -> list[APIParam]:
    if not expr:
        return []
    expr = expr.strip()
    json_arg = re.search(r"JSON\.stringify\s*\(", expr)
    if json_arg:
        balanced = extract_balanced(expr, json_arg.end() - 1)
        if balanced:
            return params_from_object_expr(balanced[0], constants, ParamLocation.body)
    if "FormData" in expr:
        return []
    return params_from_object_expr(expr, constants, ParamLocation.body)


def analyze_body_payload(ctx: ExtractionContext, expr: str | None, offset: int) -> tuple[str | None, list[str], list[APIParam]]:
    if not expr:
        return None, [], []
    expr = trim_expression_suffix(expr)
    params = params_from_body_expr(expr, ctx.constants)
    possible_fields = [param.name for param in params if param.location == ParamLocation.body]
    body_raw = None if expr.startswith("{") else normalize_ws(expr)
    if not possible_fields and re.fullmatch(r"[A-Za-z_$][\w$]*", expr):
        possible_fields.extend(infer_identifier_body_fields(ctx.code, expr, offset, ctx.constants))
    return body_raw, dedupe_names(possible_fields), params


def params_from_object_expr(expr: str | None, constants: ConstantTable, location: ParamLocation) -> list[APIParam]:
    if not expr:
        return []
    expr = trim_expression_suffix(expr)
    if expr in constants.object_values:
        return [
            APIParam(name=key, location=location, source_expr=value, flow=[expr, key])
            for key, value in constants.object_values[expr].items()
        ]
    ast_fields = expression_object_fields(expr)
    if ast_fields:
        return [
            APIParam(name=key, location=location, source_expr=field.expr, flow=[key])
            for key, field in ast_fields.items()
        ]
    if not expr.startswith("{"):
        return []
    params: list[APIParam] = []
    body = expr[1:-1] if expr.endswith("}") else expr[1:]
    for field in re.finditer(r"([A-Za-z_$][\w$]*|['\"][^'\"]+['\"])\s*:", body):
        key = strip_quotes(field.group(1))
        params.append(APIParam(name=key, location=location, source_expr=key, flow=[key]))
    return params


def infer_identifier_body_fields(code: str, expr: str, offset: int, constants: ConstantTable) -> list[str]:
    function_name, param_index = find_enclosing_function_param(code, offset, expr)
    if function_name is None or param_index is None:
        return []
    return infer_callsite_object_fields(code, function_name, param_index, constants)


def find_enclosing_function_param(code: str, offset: int, param_name: str) -> tuple[str | None, int | None]:
    pattern = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*\{", re.S)
    found_name = None
    found_index = None
    for match in pattern.finditer(code):
        balanced = extract_balanced(code, match.end() - 1, "{", "}")
        if not balanced:
            continue
        body_text, body_end = balanced
        if not (match.start() <= offset <= body_end):
            continue
        params = [part.strip() for part in match.group(2).split(",") if part.strip()]
        for index, name in enumerate(params):
            if name == param_name:
                found_name = match.group(1)
                found_index = index
    return found_name, found_index


def infer_callsite_object_fields(code: str, function_name: str, arg_index: int, constants: ConstantTable) -> list[str]:
    fields: list[str] = []
    pattern = re.compile(rf"\b{re.escape(function_name)}\s*\(")
    for match in pattern.finditer(code):
        prefix = code[max(0, match.start() - 20):match.start()]
        if re.search(r"\bfunction\s+$", prefix):
            continue
        balanced = extract_balanced(code, match.end() - 1)
        if not balanced:
            continue
        args = split_top_level_args(balanced[0])
        if arg_index >= len(args):
            continue
        fields.extend(extract_possible_object_fields(args[arg_index], constants))
    return dedupe_names(fields)


def extract_possible_object_fields(expr: str, constants: ConstantTable) -> list[str]:
    expr = trim_expression_suffix(expr)
    if not expr:
        return []
    if expr.startswith("{"):
        return [param.name for param in params_from_object_expr(expr, constants, ParamLocation.body)]
    if expr in constants.object_values:
        return list(constants.object_values[expr].keys())
    return []


def trim_expression_suffix(expr: str) -> str:
    value = expr.strip().rstrip(",")
    while value and value[-1] in "}])":
        opens = value.count("{") + value.count("(") + value.count("[")
        closes = value.count("}") + value.count(")") + value.count("]")
        if closes <= opens:
            break
        value = value[:-1].rstrip().rstrip(",")
    return value


def extract_headers(config: str) -> list[str]:
    headers: set[str] = set()
    header_expr = extract_object_field_expr(config, "headers") or config
    ast_fields = expression_object_fields(header_expr)
    headers.update(name for name in ast_fields if re.search(r"(Token|Authorization|Sign|Nonce|CSRF|Trace|Requested)", name, re.I))
    for match in re.finditer(r"['\"]([A-Za-z0-9_-]*(?:Token|Authorization|Sign|Nonce|CSRF|Trace|Requested)[A-Za-z0-9_-]*)['\"]\s*:", header_expr, re.I):
        headers.add(match.group(1))
    return sorted(headers)


def extract_transforms(text: str) -> list[str]:
    transforms: list[str] = []
    names = ["JSON.stringify", "encodeURIComponent", "btoa", "encrypt", "sign", "md5", "sha1", "sha256", "CryptoJS", "JSEncrypt"]
    for name in names:
        if name in text:
            transforms.append(name)
    return sorted(set(transforms))


def make_api(
    ctx: ExtractionContext,
    offset: int,
    method: str,
    url: str,
    client: str,
    params: list[APIParam],
    headers: list[str],
    transforms: list[str],
    *,
    snippet: str,
    body_raw: str | None = None,
    possible_body_fields: list[str] | None = None,
) -> APIAsset:
    method = (method or "GET").strip().upper()
    if method not in HTTP_METHODS:
        method = "GET"
    api_id = stable_id("api", method, url, ctx.file_ref, offset)
    return APIAsset(
        id=api_id,
        method=method,
        url=url,
        url_template=url.split("?", 1)[0],
        client=client,
        body_raw=body_raw,
        possible_body_fields=dedupe_names(possible_body_fields or []),
        params=dedupe_params(params),
        headers=sorted(set(headers)),
        transforms=sorted(set(transforms)),
        evidence=[make_evidence(ctx, offset, snippet[:800], 0.85, "static_ast_or_text")],
        confidence=0.85,
    )


def make_evidence(ctx: ExtractionContext, offset: int, snippet: str, confidence: float, kind: str) -> Evidence:
    line, column = line_col_from_offset(ctx.code, offset)
    return Evidence(
        type=kind,
        location=Location(file=ctx.file_ref, line=line, column=column),
        code=normalize_ws(snippet),
        confidence=confidence,
    )


def dedupe_params(params: list[APIParam]) -> list[APIParam]:
    seen: set[tuple[str, ParamLocation]] = set()
    result: list[APIParam] = []
    for param in params:
        key = (param.name, param.location)
        if key in seen:
            continue
        seen.add(key)
        result.append(param)
    return result


def merge_api_assets(apis: list[APIAsset]) -> list[APIAsset]:
    merged: dict[tuple[str, str], APIAsset] = {}
    for api in apis:
        key = (api.method, api.url)
        if key not in merged:
            merged[key] = api
            continue
        existing = merged[key]
        existing.params = dedupe_params(existing.params + api.params)
        existing.headers = sorted(set(existing.headers + api.headers))
        existing.transforms = sorted(set(existing.transforms + api.transforms))
        if not existing.body_raw and api.body_raw:
            existing.body_raw = api.body_raw
        if not existing.wrapper and api.wrapper:
            existing.wrapper = api.wrapper
        if existing.client in {"axios", "request_wrapper", "named_request_client:request"} and api.client.startswith("cross_function_wrapper:"):
            existing.client = api.client
        existing.possible_body_fields = dedupe_names(existing.possible_body_fields + api.possible_body_fields)
        existing.evidence.extend(api.evidence)
        existing.confidence = max(existing.confidence, api.confidence)
    return list(merged.values())


def dedupe_names(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        compact = value.strip()
        if not compact or compact in seen:
            continue
        seen.add(compact)
        result.append(compact)
    return result


def discover_http_client_names(code: str) -> set[str]:
    clients: set[str] = set()
    create_pattern = re.compile(
        r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{1,700})[;\n]",
        re.S,
    )
    alias_pattern = re.compile(r"\b((?:this\.)?\$?[A-Za-z_$][\w$]*(?:\.\$?[A-Za-z_$][\w$]*)*)\s*=\s*([A-Za-z_$][\w$]*)\b")
    for match in create_pattern.finditer(code):
        name = match.group(1)
        expr = match.group(2)
        compact = normalize_ws(expr)
        if "axios" in compact.lower() and ".create(" in compact:
            clients.add(name)
    changed = True
    while changed:
        changed = False
        for match in alias_pattern.finditer(code):
            lhs = match.group(1)
            rhs = match.group(2)
            if rhs in clients and lhs not in clients:
                clients.add(lhs)
                changed = True
    return clients


def normalize_ast_callee(callee: str) -> str:
    return normalize_ws(callee).replace("?.", ".")


def is_ast_fetch_call(callee: str) -> bool:
    return callee in {"fetch", "window.fetch", "globalThis.fetch", "self.fetch"}


def ast_method_target(callee: str) -> tuple[str, str] | None:
    bracket = re.fullmatch(r"(.+?)\[['\"]([A-Za-z_$][\w$]*)['\"]\]", callee)
    if bracket and bracket.group(2).lower() in REQUEST_METHOD_NAMES + ("ajax",):
        return bracket.group(1), bracket.group(2).upper()

    dotted = re.fullmatch(r"(.+)\.([A-Za-z_$][\w$]*)", callee)
    if not dotted:
        return None
    method = dotted.group(2).lower()
    if method not in REQUEST_METHOD_NAMES + ("ajax",):
        return None
    return dotted.group(1), method.upper()


def ast_callable_client(callee: str, clients: set[str]) -> str | None:
    if callee == "axios":
        return "axios"
    if re.fullmatch(r"request|service|client|apiClient|httpClient|requester|ajax", callee, re.I):
        return f"named_request_client:{callee}"
    if is_http_client_expr(callee, clients):
        return f"http_client_instance:{callee.split('.')[-1]}"
    return None


def is_http_client_expr(expr: str, clients: set[str]) -> bool:
    if expr in clients:
        return True
    tail = expr.split(".")[-1]
    if tail in clients:
        return True
    return bool(re.fullmatch(r"\$?http|service|api|client|request|requester|axios|ajax", tail, re.I))


def looks_like_endpoint_hint(value: str) -> bool:
    compact = value.lower()
    if compact.startswith("http://") or compact.startswith("https://"):
        return True
    if not compact.startswith("/"):
        return False
    interesting = ("api", "analysis", "merchant", "user", "order", "pay", "login", "query", "list", "detail", "save", "update", "delete")
    return any(token in compact for token in interesting)


def is_probable_api_url(value: str) -> bool:
    compact = value.strip()
    lower = compact.lower()
    if not compact or len(compact) > 240:
        return False
    if re.search(r"\b(function|prototype|return|var|const|let)\b|;", lower):
        return False
    if any(ch in compact for ch in ("'", '"', "`")):
        return False
    if lower.startswith(("http://", "https://")):
        return True
    if lower.startswith("/"):
        if re.search(r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(?:$|\?)", lower):
            return False
        return True
    if lower.startswith(("api/", "app/", "unionpay/", "admin/", "auth/", "uaa/")):
        return True
    return False
