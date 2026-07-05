from __future__ import annotations

from pathlib import Path


class SourceMapResolver:
    """Optional source-map adapter.

    The static report keeps generated locations even when this dependency is
    unavailable. When `sourcemap` is installed, callers can extend this class
    to rewrite generated bundle locations to original source files.
    """

    def resolve_file(self, map_path: Path) -> dict[str, str]:
        try:
            import sourcemap  # type: ignore  # noqa: F401
        except Exception:
            return {}
        if not map_path.exists():
            return {}
        return {"source_map": str(map_path)}
