from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class LoginStateResult:
    url: str
    storage_state_path: Path


def save_login_state(url: str, out: Path, *, timeout_ms: int = 120000, headless: bool = False) -> LoginStateResult:
    """Open a browser for manual login and persist Playwright storage_state.

    The caller completes login in the opened browser. This avoids putting passwords,
    MFA secrets, or CAPTCHA bypass logic into code.
    """

    out.parent.mkdir(parents=True, exist_ok=True)
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover
        raise RuntimeError("Playwright is required. Install it and run: python -m playwright install chromium") from exc

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()
        page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        if headless:
            page.wait_for_timeout(min(timeout_ms, 10000))
        else:
            print("Complete login in the browser, then press Enter here to save storage_state...")
            input()
        context.storage_state(path=str(out))
        browser.close()
    return LoginStateResult(url=url, storage_state_path=out)
