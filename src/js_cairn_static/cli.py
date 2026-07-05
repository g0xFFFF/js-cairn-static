"""命令行入口：把 one-shot、静态扫描、运行时采集和导出流程串起来。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import StaticAnalyzer
from .bp_templates import export_burp_templates
from .llm_input import export_llm_api_test_input, infer_base_url
from .login_state import save_login_state
from .models import APIAsset, APIParam, ExposureFinding, FingerprintFinding
from .runtime_capture import capture_runtime
from .utils import write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="js-cairn-static", description="One-shot JS/API attack surface miner.")
    sub = parser.add_subparsers(dest="command", required=True)

    oneshot = sub.add_parser("oneshot", help="one-shot API collection flow")
    oneshot.add_argument("target", help="target URL/path")
    oneshot.add_argument("--out-dir", default="out/oneshot", help="one-shot output directory")
    oneshot.add_argument("--storage-state", help="optional Playwright storage_state.json; defaults to out/auth/storage_state.json if present")
    oneshot.add_argument("--base-url", help="base URL used to build request templates when target is a local path")
    oneshot.add_argument("--no-runtime", action="store_true", help="skip Playwright runtime capture for URL targets")
    oneshot.add_argument("--capture-runtime", action="store_true", help=argparse.SUPPRESS)
    oneshot.add_argument("--show-browser", action="store_true", help="run Playwright with a visible browser window")
    oneshot.add_argument("--browser-timeout", type=int, default=30000, help="Playwright navigation timeout in milliseconds")
    oneshot.add_argument("--runtime-wait", type=int, default=3000, help="post-load runtime capture wait in milliseconds")
    oneshot.add_argument("--strict-ssl", action="store_true", help="enable TLS certificate verification for HTTPS targets")
    oneshot.add_argument("--max-remote-assets", type=int, default=48, help="maximum number of remote JS assets to download")
    oneshot.add_argument("--limit", type=int, help="maximum APIs to keep in final BP/LLM exports")
    oneshot.add_argument("--quiet", action="store_true", help="suppress progress output")

    scan = sub.add_parser("scan", help="scan a URL, directory, or JS/HTML file into api_assets.json")
    scan.add_argument("target", help="target URL/path")
    scan.add_argument("--out", default="out/api_assets.json", help="output JSON path")
    scan.add_argument("--summary", action="store_true", help="print compact summary")
    scan.add_argument("--strict-ssl", action="store_true", help="enable TLS certificate verification for HTTPS targets")
    scan.add_argument("--verbose-json", action="store_true", help="write the full analysis report instead of concise API JSON")
    scan.add_argument("--show-browser", action="store_true", help="run Playwright with a visible browser window")
    scan.add_argument("--browser-timeout", type=int, default=30000, help="Playwright navigation timeout in milliseconds")
    scan.add_argument("--pause-on-browser-fail", action="store_true", help="keep visible browser open and wait for Enter if navigation fails")
    scan.add_argument("--max-remote-assets", type=int, default=48, help="maximum number of remote JS assets to download")
    scan.add_argument("--quiet", action="store_true", help="suppress progress output")

    capture = sub.add_parser("capture", help="capture runtime network and hook events with Playwright")
    capture.add_argument("url", help="page URL")
    capture.add_argument("--out-dir", default="out/runtime", help="output directory")
    capture.add_argument("--storage-state", help="optional Playwright storage_state.json")
    capture.add_argument("--show-browser", action="store_true", help="show browser window")
    capture.add_argument("--timeout", type=int, default=30000, help="navigation timeout in milliseconds")
    capture.add_argument("--wait", type=int, default=3000, help="post-load wait in milliseconds")

    login = sub.add_parser("login-state", help="open browser for manual login and save Playwright storage_state")
    login.add_argument("url", help="login URL")
    login.add_argument("--out", default="out/auth/storage_state.json", help="storage_state output path")
    login.add_argument("--timeout", type=int, default=120000, help="login timeout in milliseconds")
    login.add_argument("--headless", action="store_true", help="run without visible browser, mainly for tests")

    bp = sub.add_parser("export-bp", help="export Burp/HTTP request seed templates from api_assets.json")
    bp.add_argument("--input", help="api_assets.json path")
    bp.add_argument("--workspace", help="workspace directory containing artifacts/api_assets.json")
    bp.add_argument("--base-url", help="base URL used to build raw HTTP requests; defaults to target origin")
    bp.add_argument("--out-dir", help="output directory; defaults to <workspace>/artifacts/bp or out/bp")
    bp.add_argument("--limit", type=int, help="maximum API assets to export")

    llm = sub.add_parser("export-llm-input", help="merge AST and Playwright captures into compact LLM API test input")
    llm.add_argument("--input", help="api_assets.json path")
    llm.add_argument("--workspace", help="workspace directory containing artifacts/api_assets.json")
    llm.add_argument("--base-url", help="base URL used to build request templates; defaults to target origin")
    llm.add_argument("--out-dir", help="output directory; defaults to <workspace>/artifacts/llm_input or out/llm_input")
    llm.add_argument("--runtime-dir", help="directory containing network_capture.json and hook_events.json")
    llm.add_argument("--network-capture", help="optional network_capture.json path")
    llm.add_argument("--hook-events", help="optional hook_events.json path")
    llm.add_argument("--limit", type=int, help="maximum static API assets to include before runtime merge")

    return parser


KNOWN_COMMANDS = {"oneshot", "scan", "capture", "login-state", "export-bp", "export-llm-input"}


def normalize_argv(argv: list[str] | None) -> list[str] | None:
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw or raw[0] in KNOWN_COMMANDS or raw[0] in {"-h", "--help"}:
        return raw
    # 面向实战使用时，最短命令应该直接跑 one-shot，而不是强迫用户多写子命令。
    return ["oneshot", *raw]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(normalize_argv(argv))

    if args.command == "oneshot":
        progress = None if args.quiet else make_progress_reporter()
        out_dir = Path(args.out_dir)
        artifacts_dir = out_dir / "artifacts"
        runtime_dir = out_dir / "runtime"
        api_assets_path = artifacts_dir / "api_assets.json"

        report = StaticAnalyzer(
            verify_ssl=should_verify_ssl(args.target, args.strict_ssl),
            progress=progress,
            show_browser=args.show_browser,
            browser_timeout_ms=args.browser_timeout,
            max_remote_assets=args.max_remote_assets,
        ).analyze(args.target)
        write_json(api_assets_path, build_concise_output(report))

        network_capture = None
        hook_events = None
        runtime_error = None
        # URL 目标默认跑运行时采集；本地文件/目录默认只做静态层，避免误开浏览器。
        should_capture = (is_url_target(args.target) and not args.no_runtime) or args.capture_runtime
        if should_capture:
            try:
                runtime = capture_runtime(
                    args.target,
                    runtime_dir,
                    storage_state=resolve_storage_state(args.storage_state),
                    headless=not args.show_browser,
                    timeout_ms=args.browser_timeout,
                    wait_ms=args.runtime_wait,
                )
                network_capture = runtime.network_capture_path
                hook_events = runtime.hook_events_path
            except Exception as exc:
                runtime_error = str(exc)

        # base_url 优先从运行时请求推断；本地扫描没有真实 origin 时使用稳定占位。
        base_url = args.base_url or infer_base_url(api_assets_path, network_capture, hook_events) or default_base_url_for_target(args.target)

        bp_artifacts = export_burp_templates(api_assets_path, base_url=base_url, out_dir=artifacts_dir / "bp", limit=args.limit)
        llm_artifacts = export_llm_api_test_input(
            api_assets_path,
            base_url=base_url,
            out_dir=artifacts_dir / "llm_input",
            network_capture=network_capture,
            hook_events=hook_events,
            limit=args.limit,
        )

        print(f"api_assets: {api_assets_path}")
        if network_capture:
            print(f"network_capture: {network_capture}")
            print(f"hook_events: {hook_events}")
        elif runtime_error:
            print(f"runtime_capture: skipped ({runtime_error})")
        print(f"bp_json: {bp_artifacts.json_path}")
        print(f"bp_http: {bp_artifacts.http_path}")
        print(f"api_inventory: {llm_artifacts.inventory_path}")
        print(f"llm_input: {llm_artifacts.llm_input_path}")
        return 0

    if args.command == "scan":
        progress = None if args.quiet else make_progress_reporter()
        report = StaticAnalyzer(
            verify_ssl=should_verify_ssl(args.target, args.strict_ssl),
            progress=progress,
            show_browser=args.show_browser,
            browser_timeout_ms=args.browser_timeout,
            pause_on_browser_fail=args.pause_on_browser_fail,
            max_remote_assets=args.max_remote_assets,
        ).analyze(args.target)
        output = report.model_dump(mode="json") if args.verbose_json else build_concise_output(report)
        write_json(Path(args.out), output)
        if args.summary:
            print_summary(report)
        else:
            print(f"Wrote {args.out}")
        return 0

    if args.command == "capture":
        artifacts = capture_runtime(
            args.url,
            Path(args.out_dir),
            storage_state=Path(args.storage_state) if args.storage_state else None,
            headless=not args.show_browser,
            timeout_ms=args.timeout,
            wait_ms=args.wait,
        )
        print(f"network_capture: {artifacts.network_capture_path}")
        print(f"hook_events: {artifacts.hook_events_path}")
        print(f"requests: {artifacts.request_count}")
        print(f"hook_events_count: {artifacts.hook_event_count}")
        return 0

    if args.command == "login-state":
        result = save_login_state(args.url, Path(args.out), timeout_ms=args.timeout, headless=args.headless)
        print(f"storage_state: {result.storage_state_path}")
        return 0

    if args.command == "export-bp":
        api_assets_path = resolve_api_assets_path(args.input, args.workspace)
        base_url = args.base_url or infer_base_url(api_assets_path)
        if not base_url:
            raise SystemExit("Unable to infer --base-url. Provide --base-url explicitly or ensure api_assets.json target is a full URL.")
        out_dir = Path(args.out_dir) if args.out_dir else default_artifact_subdir(args.workspace, "bp", fallback="out/bp")
        artifacts = export_burp_templates(api_assets_path, base_url=base_url, out_dir=out_dir, limit=args.limit)
        print(f"bp_json: {artifacts.json_path}")
        print(f"bp_http: {artifacts.http_path}")
        return 0

    if args.command == "export-llm-input":
        api_assets_path = resolve_api_assets_path(args.input, args.workspace)
        network_capture, hook_events = resolve_runtime_capture_paths(args.runtime_dir, args.network_capture, args.hook_events)
        base_url = args.base_url or infer_base_url(api_assets_path, network_capture, hook_events)
        if not base_url:
            raise SystemExit("Unable to infer --base-url. Provide --base-url explicitly or ensure api_assets.json / runtime capture contains full URLs.")
        out_dir = Path(args.out_dir) if args.out_dir else default_artifact_subdir(args.workspace, "llm_input", fallback="out/llm_input")
        artifacts = export_llm_api_test_input(
            api_assets_path,
            base_url=base_url,
            out_dir=out_dir,
            network_capture=network_capture,
            hook_events=hook_events,
            limit=args.limit,
        )
        print(f"api_inventory: {artifacts.inventory_path}")
        print(f"llm_input: {artifacts.llm_input_path}")
        return 0

    return 1


def print_summary(report) -> None:
    print(f"target: {report.target}")
    print(f"assets: {len(report.assets)}")
    print(f"wrappers: {len(report.wrappers)}")
    print(f"apis: {len(report.apis)}")
    print(f"clusters: {len(report.clusters)}")
    print(f"exposures: {len(report.exposures)}")
    print(f"fingerprints: {len(report.fingerprints)}")
    print("top apis:")
    for api in report.apis[:10]:
        print(f"- [{api.priority:03d}] {api.method} {api.url_template} tags={','.join(api.risk_tags)}")


def make_progress_reporter():
    def report(message: str) -> None:
        print(f"[js-cairn-static] {message}", file=sys.stderr, flush=True)

    return report


def is_https_target(target: str) -> bool:
    return target.lower().startswith("https://")


def is_url_target(target: str) -> bool:
    return target.lower().startswith(("http://", "https://"))


def default_base_url_for_target(target: str) -> str:
    return "http://example.local" if not is_url_target(target) else ""


def resolve_storage_state(value: str | None) -> Path | None:
    if value:
        path = Path(value)
        return path if path.exists() else None
    default = Path("out/auth/storage_state.json")
    return default if default.exists() else None


def should_verify_ssl(target: str, strict_ssl: bool) -> bool:
    return strict_ssl if is_https_target(target) else False


def build_concise_output(report) -> dict:
    exposures = getattr(report, "exposures", [])
    fingerprints = getattr(report, "fingerprints", [])
    return {
        "target": report.target,
        "summary": {
            "assets": len(report.assets),
            "apis": len(report.apis),
            "clusters": len(report.clusters),
            "wrappers": len(report.wrappers),
            "exposures": len(exposures),
            "fingerprints": len(fingerprints),
        },
        "apis": [serialize_api_concise(api) for api in report.apis],
        "exposures": [serialize_exposure_concise(item) for item in exposures[:200]],
        "fingerprints": [serialize_fingerprint_concise(item) for item in fingerprints],
        "diagnostics": report.diagnostics,
    }


def serialize_api_concise(api: APIAsset) -> dict:
    return {
        "id": api.id,
        "url": api.url_template,
        "path": api.url_template,
        "method": api.method,
        "client": api.client,
        "wrapper": api.wrapper,
        "cluster": api.cluster,
        "priority": api.priority,
        "confidence": api.confidence,
        "risk_tags": api.risk_tags,
        "headers": api.headers,
        "transforms": api.transforms,
        "body_raw": api.body_raw,
        "body_keys": api.possible_body_fields,
        "possible_body_fields": api.possible_body_fields,
        "params": {
            "path": [serialize_param_concise(param) for param in api.params if param.location.value == "path"],
            "query": [serialize_param_concise(param) for param in api.params if param.location.value == "query"],
            "body": [serialize_param_concise(param) for param in api.params if param.location.value == "body"],
            "header": [serialize_param_concise(param) for param in api.params if param.location.value == "header"],
            "cookie": [serialize_param_concise(param) for param in api.params if param.location.value == "cookie"],
            "unknown": [serialize_param_concise(param) for param in api.params if param.location.value == "unknown"],
        },
        "evidence_refs": [
            {"type": ev.type, "file": ev.location.file or ev.location.url, "line": ev.location.line, "confidence": ev.confidence}
            for ev in api.evidence[:5]
        ],
    }


def serialize_param_concise(param: APIParam) -> dict:
    return {
        "name": param.name,
        "type_hint": param.type_hint,
        "user_controllable": param.user_controllable,
        "risk_tags": param.risk_tags,
    }


def serialize_exposure_concise(item: ExposureFinding) -> dict:
    return {
        "kind": item.kind,
        "name": item.name,
        "value": item.value,
        "source": item.source,
        "severity": item.severity,
        "confidence": item.confidence,
        "line": item.location.line,
    }


def serialize_fingerprint_concise(item: FingerprintFinding) -> dict:
    return {
        "category": item.category,
        "name": item.name,
        "source": item.source,
        "confidence": item.confidence,
        "evidence": item.evidence,
    }


def resolve_api_assets_path(input_path: str | None, workspace: str | None) -> Path:
    if input_path:
        return Path(input_path)
    if workspace:
        return Path(workspace) / "artifacts" / "api_assets.json"
    raise SystemExit("Missing api assets input. Provide --input or --workspace.")


def default_artifact_subdir(workspace: str | None, name: str, *, fallback: str) -> Path:
    if workspace:
        return Path(workspace) / "artifacts" / name
    return Path(fallback)


def resolve_runtime_capture_paths(runtime_dir: str | None, network_capture: str | None, hook_events: str | None) -> tuple[Path | None, Path | None]:
    network = Path(network_capture) if network_capture else None
    hooks = Path(hook_events) if hook_events else None
    if runtime_dir:
        runtime_root = Path(runtime_dir)
        network = network or runtime_root / "network_capture.json"
        hooks = hooks or runtime_root / "hook_events.json"
    return network, hooks


if __name__ == "__main__":
    raise SystemExit(main())


