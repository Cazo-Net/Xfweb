"""HTTP methods audit plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import InfrastructurePlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class AllowedMethodsPlugin(InfrastructurePlugin):
    """Discover allowed HTTP methods on each endpoint."""

    plugin_name = "allowed_methods"
    brief_description = "Discover allowed HTTP methods via OPTIONS"

    async def discover(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.options(freq.url.raw_url)
        allow = resp.headers.get("allow", "")
        if allow:
            methods = [m.strip() for m in allow.split(",")]
            dangerous = [m for m in methods if m.upper() in ("DELETE", "PUT", "TRACE", "TRACK", "DEBUG")]
            if dangerous:
                logger.warning(
                    "xfweb.allowed_methods.dangerous",
                    url=freq.url.raw_url,
                    methods=dangerous,
                )
            else:
                logger.info(
                    "xfweb.allowed_methods.found",
                    url=freq.url.raw_url,
                    methods=methods,
                )
