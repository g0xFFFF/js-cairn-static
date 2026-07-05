from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .utils import write_json


@dataclass(frozen=True)
class RuntimeCaptureArtifacts:
    out_dir: Path
    network_capture_path: Path
    hook_events_path: Path
    storage_state_path: Path | None
    request_count: int
    hook_event_count: int


def capture_runtime(
    url: str,
    out_dir: Path,
    *,
    storage_state: Path | None = None,
    headless: bool = True,
    timeout_ms: int = 30000,
    wait_ms: int = 3000,
) -> RuntimeCaptureArtifacts:
    """Capture runtime network requests and JS hook events with Playwright.

    This function is capture-only. It does not mutate application state beyond normal page load.
    User actions and state-changing workflows should be implemented through an explicit policy gate.
    """

    out_dir.mkdir(parents=True, exist_ok=True)
    network_capture_path = out_dir / "network_capture.json"
    hook_events_path = out_dir / "hook_events.json"
    effective_storage_state = storage_state if storage_state and storage_state.exists() else None

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - depends on optional browser runtime
        raise RuntimeError("Playwright is required for runtime capture. Install it and run: python -m playwright install chromium") from exc

    requests: list[dict[str, Any]] = []
    hook_events: list[dict[str, Any]] = []

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context_kwargs: dict[str, Any] = {"ignore_https_errors": True}
        if effective_storage_state:
            context_kwargs["storage_state"] = str(effective_storage_state)
        context = browser.new_context(**context_kwargs)
        context.add_init_script(render_runtime_hook_js())
        page = context.new_page()
        page.set_default_timeout(timeout_ms)

        def on_response(resp) -> None:
            req = resp.request
            if should_skip_runtime_url(req.url):
                return
            try:
                post_data = req.post_data
            except Exception:
                post_data = None
            requests.append(
                {
                    "method": req.method,
                    "url": req.url,
                    "resource_type": req.resource_type,
                    "request_headers": dict(req.headers),
                    "post_data_sample": post_data[:4096] if isinstance(post_data, str) else post_data,
                    "response_status": resp.status,
                    "response_headers": dict(resp.headers),
                    "page_url": page.url,
                }
            )

        page.on("response", on_response)
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        try:
            page.wait_for_load_state("networkidle", timeout=min(timeout_ms, 10000))
        except Exception:
            pass
        page.wait_for_timeout(wait_ms)
        try:
            hook_events = page.evaluate("window.__JS_CAIRN_HOOK_EVENTS__ || []")
        except Exception:
            hook_events = []
        browser.close()

    write_json(network_capture_path, {"url": url, "requests": requests})
    write_json(hook_events_path, {"url": url, "events": hook_events})
    return RuntimeCaptureArtifacts(
        out_dir=out_dir,
        network_capture_path=network_capture_path,
        hook_events_path=hook_events_path,
        storage_state_path=effective_storage_state,
        request_count=len(requests),
        hook_event_count=len(hook_events),
    )


def should_skip_runtime_url(url: str) -> bool:
    lower = url.lower().split("?", 1)[0]
    static_suffixes = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".css", ".map")
    noise = ("/analytics", "/sentry", "/beacon", "/favicon")
    return lower.endswith(static_suffixes) or any(item in lower for item in noise)


def render_runtime_hook_js() -> str:
    return r'''(() => {
  const events = [];
  const maxBodyLength = 4096;
  window.__JS_CAIRN_HOOK_EVENTS__ = events;
  function safeClone(value) { try { return JSON.parse(JSON.stringify(value)); } catch (_) { return String(value); } }
  function pushEvent(event) { try { events.push({ ...event, capturedAt: new Date().toISOString() }); if (events.length > 1000) events.shift(); } catch (_) {} }
  if (window.fetch && !window.fetch.__jsCairnHooked) {
    const rawFetch = window.fetch;
    const hookedFetch = async function(input, init = {}) {
      const startedAt = Date.now();
      const stack = new Error().stack;
      try {
        const response = await rawFetch.apply(this, arguments);
        const cloned = response.clone();
        let sample = null;
        const contentType = cloned.headers.get('content-type') || '';
        if (contentType.includes('json') || contentType.includes('text')) {
          try { sample = (await cloned.text()).slice(0, maxBodyLength); } catch (_) {}
        }
        pushEvent({ hookType: 'fetch', method: (init && init.method) || 'GET', url: typeof input === 'string' ? input : input && input.url, requestInitKeys: init ? Object.keys(init) : [], status: response.status, responseContentType: contentType, responseSample: sample, stack, costMs: Date.now() - startedAt });
        return response;
      } catch (error) {
        pushEvent({ hookType: 'fetch_error', message: String(error), stack, costMs: Date.now() - startedAt });
        throw error;
      }
    };
    hookedFetch.__jsCairnHooked = true;
    window.fetch = hookedFetch;
  }
  if (window.XMLHttpRequest && !XMLHttpRequest.prototype.__jsCairnHooked) {
    const rawOpen = XMLHttpRequest.prototype.open;
    const rawSend = XMLHttpRequest.prototype.send;
    const rawSetRequestHeader = XMLHttpRequest.prototype.setRequestHeader;
    XMLHttpRequest.prototype.open = function(method, url) { this.__jsCairn = { method, url, headers: {}, stack: new Error().stack }; return rawOpen.apply(this, arguments); };
    XMLHttpRequest.prototype.setRequestHeader = function(name, value) { if (this.__jsCairn) this.__jsCairn.headers[String(name).toLowerCase()] = String(value); return rawSetRequestHeader.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function(body) {
      const startedAt = Date.now();
      this.addEventListener('loadend', () => {
        const meta = this.__jsCairn || {};
        pushEvent({ hookType: 'xhr', method: meta.method, url: meta.url, headers: safeClone(meta.headers || {}), bodySample: typeof body === 'string' ? body.slice(0, maxBodyLength) : null, status: this.status, responseType: this.responseType || 'text', stack: meta.stack, costMs: Date.now() - startedAt });
      });
      return rawSend.apply(this, arguments);
    };
    XMLHttpRequest.prototype.__jsCairnHooked = true;
  }
})();
'''
