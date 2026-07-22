"""OpenAPI/Swagger crawler plugin — discovers API endpoints from specs."""

from __future__ import annotations

import json
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import CrawlPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

OPENAPI_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api/swagger.json",
    "/api/swagger.yaml",
    "/api/v1/swagger.json",
    "/api/v1/openapi.json",
    "/v1/docs",
    "/v2/docs",
    "/v3/docs",
    "/docs/openapi.json",
    "/swagger-ui.json",
]


class OpenApiCrawlerPlugin(CrawlPlugin):
    """Discover API endpoints from OpenAPI/Swagger specifications."""

    plugin_name = "open_api"
    brief_description = "Discover endpoints from OpenAPI/Swagger specs"

    async def crawl(self, freq: Any, http: HttpEngine) -> list:
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest
        from xfweb.core.data.url import parse_url

        discovered: list[FuzzableRequest] = []

        for path in OPENAPI_PATHS:
            url = f"{freq.url.origin}{path}"
            resp = await http.get(url)

            if resp.status_code == 200:
                try:
                    spec = resp.json
                    if "paths" in spec or "openapi" in spec or "swagger" in spec:
                        logger.info("xfweb.openapi.found", url=url)
                        endpoints = self._parse_endpoints(spec, freq.url.origin)
                        for ep_url in endpoints:
                            discovered.append(FuzzableRequest.from_url(parse_url(ep_url)))
                except Exception:
                    pass

        return discovered

    def _parse_endpoints(self, spec: dict[str, Any], base_url: str) -> list[str]:
        urls: list[str] = []
        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method in methods:
                if method in ("get", "post", "put", "delete", "patch"):
                    urls.append(f"{base_url}{path}")
        return urls
