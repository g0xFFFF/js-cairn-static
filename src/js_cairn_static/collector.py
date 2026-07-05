"""资源收集层：负责把入口页面、本地文件和远程 JS 转成统一的 JSAsset。"""

from __future__ import annotations

import ssl
import re
import subprocess
from pathlib import Path
from typing import Callable
from urllib.error import URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from .models import AssetKind, JSAsset
from .normalizer import is_minified, normalize_js, source_map_url
from .utils import HTML_EXTENSIONS, JS_EXTENSIONS, iter_source_files, read_text, stable_hash, stable_id
from .vendor_rules import is_probably_third_party, vendor_penalty


class JSCollector:
    def __init__(
        self,
        *,
        verify_ssl: bool = True,
        progress: Callable[[str], None] | None = None,
        show_browser: bool = False,
        browser_timeout_ms: int = 30000,
        pause_on_browser_fail: bool = False,
        max_remote_assets: int = 48,
    ) -> None:
        self.verify_ssl = verify_ssl
        self.progress = progress
        self.show_browser = show_browser
        self.browser_timeout_ms = browser_timeout_ms
        self.pause_on_browser_fail = pause_on_browser_fail
        self.max_remote_assets = max_remote_assets

    def collect(self, target: str) -> list[JSAsset]:
        if target.startswith(("http://", "https://")):
            return self.collect_url(target)
        return self.collect_path(Path(target))

    def collect_path(self, root: Path) -> list[JSAsset]:
        assets: list[JSAsset] = []
        source_files = list(iter_source_files(root))
        self._emit(f"collecting local files: {len(source_files)} candidate assets")
        for index, path in enumerate(source_files, start=1):
            self._emit(f"reading asset {index}/{len(source_files)}: {path}")
            code = read_text(path)
            suffix = path.suffix.lower()
            if suffix in HTML_EXTENSIONS:
                assets.extend(self._assets_from_html(code, base=str(path), source_path=str(path)))
                continue
            if suffix in JS_EXTENSIONS:
                assets.append(self._make_asset(code, path=str(path), kind=AssetKind.script))
        return dedupe_assets(assets)

    def collect_url(self, url: str) -> list[JSAsset]:
        self._emit(f"fetching entry page: {url}")
        browser_assets = self._collect_url_with_playwright(url)
        if browser_assets is not None:
            return dedupe_assets(browser_assets)
        html = fetch_text(url, verify_ssl=self.verify_ssl, progress=self.progress)
        assets = [self._make_asset(html, url=url, kind=AssetKind.html)]
        assets.extend(self._assets_from_html(html, base=url))
        return dedupe_assets(assets)

    def _assets_from_html(
        self,
        html: str,
        base: str,
        source_path: str | None = None,
        *,
        remote_script_sources: dict[str, str] | None = None,
        fetch_remote: bool = True,
    ) -> list[JSAsset]:
        assets: list[JSAsset] = []
        remote_urls: set[str] = set()
        remote_candidates: list[tuple[str, str]] = []
        for idx, script in enumerate(re.finditer(r"<script\b([^>]*)>(.*?)</script>", html, re.I | re.S)):
            attrs, body = script.group(1), script.group(2)
            src = re.search(r"\bsrc\s*=\s*['\"]([^'\"]+)['\"]", attrs, re.I)
            if src and base.startswith(("http://", "https://")):
                script_url = urljoin(base, src.group(1))
                remote_urls.add(script_url)
                remote_candidates.append(("script", script_url))
            elif src and source_path:
                candidate = Path(source_path).parent / src.group(1)
                if candidate.exists():
                    assets.append(self._make_asset(read_text(candidate), path=str(candidate), kind=AssetKind.script))
            elif body.strip():
                assets.append(
                    self._make_asset(
                        body,
                        path=source_path,
                        url=base if base.startswith(("http://", "https://")) else None,
                        kind=AssetKind.inline_script,
                    )
                )
        if base.startswith(("http://", "https://")):
            for asset_url in extract_remote_js_links(html, base):
                if asset_url in remote_urls:
                    continue
                remote_urls.add(asset_url)
                remote_candidates.append(("linked", asset_url))
            assets.extend(
                self._collect_remote_candidates(
                    remote_candidates,
                    base=base,
                    remote_script_sources=remote_script_sources or {},
                    fetch_remote=fetch_remote,
                )
            )
        return assets

    def _collect_url_with_playwright(self, url: str) -> list[JSAsset] | None:
        try:
            from playwright.sync_api import sync_playwright  # type: ignore
        except Exception as exc:
            self._emit(f"playwright unavailable; falling back to HTTP collectors: {summarize_exception(exc)}")
            return None

        self._emit("collecting remote assets with Playwright browser context")
        captured_scripts: dict[str, str] = {}
        try:
            with sync_playwright() as playwright:
                self._emit(f"launching Playwright Chromium (headless={not self.show_browser})")
                browser = playwright.chromium.launch(headless=not self.show_browser, slow_mo=250 if self.show_browser else 0)
                try:
                    context = browser.new_context(ignore_https_errors=not self.verify_ssl)
                    try:
                        page = context.new_page()

                        def handle_response(response) -> None:
                            try:
                                if response.request.resource_type != "script":
                                    return
                                if response.status >= 400:
                                    self._emit(f"playwright script response {response.status}: {response.url}")
                                    return
                                captured_scripts[response.url] = response.text()
                            except Exception as exc:
                                self._emit(f"playwright script capture failed: {response.url} ({summarize_exception(exc)})")

                        page.on("response", handle_response)
                        self._emit(f"playwright navigating to: {url}")
                        try:
                            page.goto(url, wait_until="domcontentloaded", timeout=self.browser_timeout_ms)
                        except Exception:
                            if self.show_browser and self.pause_on_browser_fail:
                                self._emit(
                                    "playwright navigation failed; browser left open for inspection. "
                                    "Press Enter in this terminal to close it and continue fallback."
                                )
                                try:
                                    input()
                                except EOFError:
                                    pass
                            raise
                        try:
                            page.wait_for_load_state("networkidle", timeout=5000)
                        except Exception:
                            pass
                        html = page.content()
                    finally:
                        context.close()
                finally:
                    browser.close()
        except Exception as exc:
            self._emit(f"playwright collection failed; falling back to HTTP collectors: {summarize_exception(exc)}")
            return None

        assets = [self._make_asset(html, url=url, kind=AssetKind.html)]
        assets.extend(
            self._assets_from_html(
                html,
                base=url,
                remote_script_sources=captured_scripts,
                fetch_remote=False,
            )
        )
        # 运行时动态加载的脚本不一定会留在最终 DOM 中，必须单独并入资产池。
        for script_url, code in captured_scripts.items():
            if any(asset.url == script_url for asset in assets):
                continue
            assets.append(self._make_asset(code, url=script_url, kind=AssetKind.script, first_seen_page=url))
        self._emit(f"playwright collection complete: html + {len(captured_scripts)} script responses")
        return assets

    def _collect_remote_candidates(
        self,
        candidates: list[tuple[str, str]],
        *,
        base: str,
        remote_script_sources: dict[str, str],
        fetch_remote: bool,
    ) -> list[JSAsset]:
        if not candidates:
            return []
        ranked = sorted(candidates, key=lambda item: remote_asset_budget_score(item[1], item[0]), reverse=True)
        assets: list[JSAsset] = []
        skipped = 0
        fetched = 0
        for origin, asset_url in ranked:
            role = classify_remote_js_url(asset_url, origin)
            priority = remote_asset_budget_score(asset_url, origin)
            preloaded = remote_script_sources.get(asset_url)
            if preloaded is not None:
                assets.append(
                    self._make_asset(
                        preloaded,
                        url=asset_url,
                        kind=AssetKind.script,
                        first_seen_page=base,
                        asset_role=role,
                        fetch_priority=priority,
                    )
                )
                fetched += 1
                continue
            if not fetch_remote:
                skipped += 1
                continue
            if fetched >= self.max_remote_assets:
                skipped += 1
                continue
            if should_skip_remote_fetch(role, priority):
                skipped += 1
                continue
            try:
                label = "script" if origin == "script" else "linked js"
                self._emit(f"fetching {label} asset [{role}, p={priority}]: {asset_url}")
                code = fetch_text(asset_url, verify_ssl=self.verify_ssl, progress=self.progress)
                assets.append(
                    self._make_asset(
                        code,
                        url=asset_url,
                        kind=AssetKind.script,
                        first_seen_page=base,
                        asset_role=role,
                        fetch_priority=priority,
                    )
                )
                fetched += 1
            except Exception:
                skipped += 1
                continue
        if skipped:
            self._emit(
                f"remote asset budget applied: fetched={fetched}, skipped={skipped}, "
                f"max_remote_assets={self.max_remote_assets}"
            )
        return assets

    def _make_asset(
        self,
        code: str,
        *,
        path: str | None = None,
        url: str | None = None,
        kind: AssetKind,
        first_seen_page: str | None = None,
        asset_role: str | None = None,
        fetch_priority: int | None = None,
    ) -> JSAsset:
        normalized = normalize_js(code) if kind != AssetKind.html else code
        ref = url or path or kind.value
        parsed = urlparse(url or "")
        cross_origin = bool(parsed.netloc and first_seen_page and parsed.netloc not in first_seen_page)
        third_party = bool(is_probably_third_party(url or path) or cross_origin)
        role = asset_role or classify_remote_js_url(url or path or "", "script")
        priority = fetch_priority if fetch_priority is not None else remote_asset_budget_score(url or path or "", "script")
        return JSAsset(
            asset_id=stable_id("js", ref, stable_hash(code)[:16]),
            kind=kind,
            url=url,
            path=path,
            asset_role=role,
            fetch_priority=priority,
            hash=stable_hash(code),
            size=len(code),
            raw_code=code,
            normalized_code=normalized,
            source_map_url=source_map_url(code),
            first_seen_page=first_seen_page,
            third_party=third_party,
            minified=is_minified(code),
        )

    def _emit(self, message: str) -> None:
        if self.progress:
            self.progress(message)


def fetch_text(url: str, *, verify_ssl: bool = True, progress: Callable[[str], None] | None = None) -> str:
    errors: list[Exception] = []

    if verify_ssl:
        try:
            return _fetch_httpx(url, verify_ssl=True)
        except Exception as exc:
            errors.append(exc)
            if should_retry_insecure(url, exc):
                if progress:
                    progress(
                        f"TLS issue detected via httpx ({summarize_exception(exc)}); "
                        f"retrying without certificate verification: {url}"
                    )
                return fetch_text(url, verify_ssl=False, progress=progress)
            raise

    strategies = [
        ("httpx", lambda: _fetch_httpx(url, verify_ssl=False)),
        ("requests", lambda: _fetch_requests(url, verify_ssl=False)),
        ("urllib", lambda: _fetch_urllib(url, verify_ssl=False)),
        ("curl.exe", lambda: _fetch_curl(url)),
    ]
    for name, strategy in strategies:
        try:
            if progress:
                progress(f"fetch attempt via {name}: {url}")
            text = strategy()
            if progress:
                progress(f"fetch success via {name}: {url}")
            return text
        except Exception as exc:
            errors.append(exc)
            if progress:
                progress(f"fetch failed via {name}: {summarize_exception(exc)}")
            continue
    raise RuntimeError(build_fetch_error_message(url, errors))


def should_retry_insecure(url: str, exc: Exception) -> bool:
    if not url.lower().startswith("https://"):
        return False
    if isinstance(exc, ssl.SSLError):
        return True
    if isinstance(exc, URLError) and isinstance(exc.reason, ssl.SSLError):
        return True
    text = repr(exc).upper()
    retry_markers = [
        "CERTIFICATE_VERIFY_FAILED",
        "UNEXPECTED_EOF_WHILE_READING",
        "WRONG_VERSION_NUMBER",
        "TLSV1_ALERT",
        "SSLV3_ALERT",
    ]
    return any(marker in text for marker in retry_markers)


def _fetch_httpx(url: str, *, verify_ssl: bool) -> str:
    import httpx  # type: ignore

    with httpx.Client(follow_redirects=True, timeout=20, verify=verify_ssl) as client:
        response = client.get(url)
        response.raise_for_status()
        return response.text


def _fetch_requests(url: str, *, verify_ssl: bool) -> str:
    import requests  # type: ignore

    response = requests.get(
        url,
        timeout=20,
        allow_redirects=True,
        verify=verify_ssl,
        headers={"User-Agent": "js-cairn-static/0.1"},
    )
    response.raise_for_status()
    response.encoding = response.encoding or response.apparent_encoding or "utf-8"
    return response.text


def _fetch_urllib(url: str, *, verify_ssl: bool) -> str:
    req = Request(url, headers={"User-Agent": "js-cairn-static/0.1"})
    context = None if verify_ssl else ssl._create_unverified_context()
    with urlopen(req, timeout=20, context=context) as response:  # noqa: S310 - user-provided scanner target
        return response.read().decode("utf-8", errors="ignore")


def _fetch_curl(url: str) -> str:
    result = subprocess.run(
        ["curl.exe", "-k", "-L", "--silent", "--show-error", url],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
    )
    return result.stdout


def build_fetch_error_message(url: str, errors: list[Exception]) -> str:
    if not errors:
        return f"failed to fetch {url}"
    summaries = [f"{type(exc).__name__}: {exc}" for exc in errors[-4:]]
    return f"failed to fetch {url} after fallbacks: {' | '.join(summaries)}"


def summarize_exception(exc: Exception, *, limit: int = 180) -> str:
    text = str(exc).strip() or repr(exc)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text


def dedupe_assets(assets: list[JSAsset]) -> list[JSAsset]:
    seen: set[str] = set()
    result: list[JSAsset] = []
    for asset in assets:
        if asset.hash in seen:
            continue
        seen.add(asset.hash)
        result.append(asset)
    return result


def extract_remote_js_links(html: str, base: str) -> list[str]:
    urls: list[str] = []
    seen: set[str] = set()
    link_pattern = re.compile(r"<link\b([^>]+)>", re.I | re.S)
    for match in link_pattern.finditer(html):
        attrs = match.group(1)
        href = re.search(r"\bhref\s*=\s*['\"]([^'\"]+)['\"]", attrs, re.I)
        rel = re.search(r"\brel\s*=\s*['\"]([^'\"]+)['\"]", attrs, re.I)
        if not href or not rel:
            continue
        rel_value = rel.group(1).lower()
        if rel_value not in {"prefetch", "preload", "modulepreload"}:
            continue
        target = href.group(1)
        if ".js" not in target.lower():
            continue
        resolved = urljoin(base, target)
        if resolved in seen:
            continue
        seen.add(resolved)
        urls.append(resolved)
    return sorted(urls, key=score_remote_js_url, reverse=True)


def score_remote_js_url(url: str) -> int:
    return remote_asset_budget_score(url, "linked")


def remote_asset_budget_score(url: str, origin: str) -> int:
    ref = url.lower()
    score = 0
    role = classify_remote_js_url(url, origin)
    role_weights = {
        "entry_bundle": 130,
        "business_chunk": 110,
        "numbered_chunk": 70,
        "runtime_chunk": 60,
        "vendor_chunk": -40,
        "third_party_lib": -90,
        "unknown": 20,
    }
    score += role_weights.get(role, 0)
    if re.search(r"/js/\d+\.js$", ref):
        score += 15
    if ref.endswith(".min.js"):
        score -= 15
    score -= vendor_penalty(url)
    return score


def classify_remote_js_url(url: str, origin: str) -> str:
    ref = (url or "").lower()
    name = ref.rsplit("/", 1)[-1]
    if any(token in name for token in ("app.js", "main.js")):
        return "entry_bundle"
    if any(token in name for token in ("runtime", "manifest")):
        return "runtime_chunk"
    if any(token in ref for token in ("chunk-vendors", "vendor")):
        return "vendor_chunk"
    if any(token in ref for token in ("lodash", "vue", "react", "moment", "jquery", "antd", "polyfill", "sentry", "axios.")):
        return "third_party_lib"
    if re.search(r"/js/[a-z][a-z0-9_-]*\.js$", ref) and name not in {"app.js", "main.js"}:
        return "business_chunk"
    if re.search(r"/js/\d+\.js$", ref):
        return "numbered_chunk"
    if origin == "script":
        return "entry_bundle"
    return "unknown"


def should_skip_remote_fetch(role: str, priority: int) -> bool:
    return role in {"third_party_lib"} or priority < 0
