"""The instant-query endpoint of the Prometheus HTTP API (Prometheus, VictoriaMetrics, ...)."""

import json
import ssl
import urllib.parse
from typing import Any

from advisory_map.common import http


class PrometheusAPI:
    def __init__(self, url: str, ca_file: str | None = None) -> None:
        self.url = url
        self.context = ssl.create_default_context(cafile=ca_file)

    def query(self, promql: str) -> list[dict[str, Any]]:
        """An instant query's series."""
        response = http.get(
            f"{self.url}/api/v1/query?{urllib.parse.urlencode({'query': promql})}", context=self.context
        )
        result = json.loads(response.body)
        if result.get("status") != "success":
            raise RuntimeError(f"query {promql!r} failed: {result.get('error')}")
        return result["data"]["result"]
