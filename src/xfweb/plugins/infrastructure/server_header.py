"""Server header analysis plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import InfrastructurePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

SERVER_HEADERS_TO_CHECK = [
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-cache", "x-debug-token", "x-debug-token-link",
    "x-rack-cache", "x-runtime", "x-version",
]


class ServerHeaderPlugin(InfrastructurePlugin):
    """Analyze server response headers for information disclosure."""

    plugin_name = "server_header"
    brief_description = "Analyze server headers for version info and misconfigurations"

    async def discover(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)

        interesting_headers: dict[str, str] = {}
        for header_name in SERVER_HEADERS_TO_CHECK:
            value = resp.headers.get(header_name)
            if value:
                interesting_headers[header_name] = value

        if interesting_headers:
            for h, v in interesting_headers.items():
                logger.info(
                    "xfweb.server_header.info_disclosure",
                    url=freq.url.raw_url,
                    header=h,
                    value=v,
                )
