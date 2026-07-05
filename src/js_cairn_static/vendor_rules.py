from __future__ import annotations

import re


THIRD_PARTY_FILE_PATTERNS = [
    re.compile(pattern, re.I)
    for pattern in [
        r"^jquery(?:[.-]\d[\w.-]*)?(?:\.min)?\.js$",
        r"^(?:vue|vue-router|vuex|react|react-dom)(?:[.-]\d[\w.-]*)?(?:\.min)?\.js$",
        r"^bootstrap(?:\.bundle)?(?:[.-]\d[\w.-]*)?(?:\.min)?\.js$",
        r"^(?:lodash|moment|axios|echarts|chart|highcharts|element-ui|antd?)(?:[.-]\d[\w.-]*)?(?:\.min)?\.js$",
        r"^(?:polyfill|modernizr|underscore|backbone|select2|tinymce|jsencrypt)(?:[.-]\d[\w.-]*)?(?:\.min)?\.js$",
        r"^(?:zh|en|zh-cn|zh-tw|ja|ko)(?:[.-]\d[\w.-]*)?(?:\.min)?\.js$",
    ]
]

THIRD_PARTY_MARKERS = {
    "cdn.",
    "cdnjs",
    "jsdelivr",
    "unpkg",
    "bootcdn",
    "node_modules",
    "jquery",
    "lodash",
    "moment",
    "polyfill",
    "sentry",
}


def filename_of(url_or_path: str | None) -> str:
    ref = (url_or_path or "").split("?", 1)[0].replace("\\", "/")
    return ref.rsplit("/", 1)[-1].lower()


def is_probably_third_party(url_or_path: str | None) -> bool:
    ref = (url_or_path or "").lower()
    name = filename_of(ref)
    if any(marker in ref for marker in THIRD_PARTY_MARKERS):
        return True
    return any(pattern.match(name) for pattern in THIRD_PARTY_FILE_PATTERNS)


def vendor_penalty(url_or_path: str | None) -> int:
    name = filename_of(url_or_path)
    if any(pattern.match(name) for pattern in THIRD_PARTY_FILE_PATTERNS):
        return 70
    if is_probably_third_party(url_or_path):
        return 50
    return 0
