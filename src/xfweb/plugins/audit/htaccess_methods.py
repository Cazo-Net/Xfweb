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
                self.report_finding(
                    name=f"Dangerous HTTP method '{method}' enabled",
                    severity="low" if method in ("OPTIONS", "PUT", "DELETE") else "medium",
                    url=freq.url.raw_url,
                    description=f"HTTP method {method} is allowed on this endpoint. "
                    f"This could allow unauthorized data modification.",
                    evidence=f"Method: {method}\nStatus: {resp.status_code}",
                    http_request={"method": method, "url": freq.url.raw_url},
                    http_response={"status": resp.status_code},
                    remediation=f"Disable the {method} method if not required. "
                    "Configure server access controls.",
                )
            elif method == "OPTIONS" and resp.status_code == 200:
                allow = resp.headers.get("allow", "")
                dangerous_found = [m for m in self.DANGEROUS_METHODS if m in allow.upper()]
                if dangerous_found:
                    self.report_finding(
                        name=f"Dangerous HTTP methods disclosed via OPTIONS",
                        severity="low",
                        url=freq.url.raw_url,
                        description=f"OPTIONS response reveals dangerous methods: {dangerous_found}",
                        evidence=f"Allow header: {allow}",
                        http_request={"method": "OPTIONS", "url": freq.url.raw_url},
                        http_response={"status": resp.status_code},
                        remediation="Restrict allowed HTTP methods to only those required.",
                    )
