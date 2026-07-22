"""FrontPage Server Extensions detection plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class FrontpagePlugin(AuditPlugin):
    """Detect FrontPage Server Extensions (FPSE)."""

    plugin_name = "frontpage"
    brief_description = "Detect FrontPage Server Extensions"

    FPSE_PATHS = [
        "/_vti_bin/_vti_aut/author.dll",
        "/_vti_bin/_vti_aut/author.exe",
        "/_vti_inf.html",
        "/_vti_bin/shtml.dll/shtml.inf",
    ]

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        base = f"{freq.url.scheme}://{freq.url.hostname}"
        for path in self.FPSE_PATHS:
            resp = await http.get(f"{base}{path}")
            if resp.status_code == 200 and ("fpse" in resp.text.lower() or "_vti_" in resp.text.lower()):
                logger.warning("xfweb.frontpage.detected", url=f"{base}{path}")
                return
