"""HTTP methods (htaccess) audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class HtaccessMethodsPlugin(AuditPlugin):
    """Test for dangerous HTTP methods (TRACE, DELETE, PUT, OPTIONS)."""

    plugin_name = "htaccess_methods"
    brief_description = "Detect dangerous HTTP methods enabled on the server"

    DANGEROUS_METHODS = ["TRACE", "TRACK", "DEBUG", "OPTIONS", "PUT", "DELETE"]

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        for method in self.DANGEROUS_METHODS:
            resp = await http._request(method, freq.url.raw_url)
            if resp.status_code in (200, 204):
                logger.warning(
                    "xfweb.htaccess_methods.dangerous",
                    url=freq.url.raw_url,
                    method=method,
                )
            elif method == "OPTIONS" and resp.status_code == 200:
                allow = resp.headers.get("allow", "")
                dangerous_found = [m for m in self.DANGEROUS_METHODS if m in allow.upper()]
                if dangerous_found:
                    logger.warning(
                        "xfweb.htaccess_methods.options_disclosure",
                        url=freq.url.raw_url,
                        allowed_methods=dangerous_found,
                    )
