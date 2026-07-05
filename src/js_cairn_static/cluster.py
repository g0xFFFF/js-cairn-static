from __future__ import annotations

import re
from collections import defaultdict

from .models import APIAsset, APISemanticCluster
from .utils import stable_id


class APIClusterer:
    def cluster(self, apis: list[APIAsset]) -> list[APISemanticCluster]:
        buckets: dict[str, list[APIAsset]] = defaultdict(list)
        for api in apis:
            label = self._label(api)
            buckets[label].append(api)
            api.cluster = label
        clusters: list[APISemanticCluster] = []
        for label, group in buckets.items():
            tags = sorted({tag for api in group for tag in api.risk_tags})
            priority = max((api.priority for api in group), default=0)
            clusters.append(
                APISemanticCluster(
                    id=stable_id("cluster", label),
                    label=label,
                    api_ids=[api.id for api in group],
                    tags=tags,
                    priority=priority,
                )
            )
        return sorted(clusters, key=lambda item: item.priority, reverse=True)

    def _label(self, api: APIAsset) -> str:
        path = api.url_template.split("?", 1)[0]
        parts = [p for p in re.split(r"[/{}:_-]+", path.lower()) if p and not p.isdigit()]
        if not parts:
            return "root"
        for part in parts:
            if part not in {"api", "v1", "v2", "v3", "admin"}:
                return part
        return parts[-1]
