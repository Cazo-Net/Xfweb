"""Content Security Policy analysis plugin."""

from __future__ import annotations

import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GrepPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class CspPlugin(GrepPlugin):
    """Analyze Content Security Policy headers for weaknesses."""

    plugin_name = "csp"
    brief_description = "Analyze CSP headers for misconfigurations and weaknesses"

    async def grep(self, freq: Any, http: HttpEngine) -> None:
        resp = await http.get(freq.url.raw_url)
        csp = resp.headers.get("content-security-policy", "")

        if not csp:
            logger.info(
                "xfweb.csp.missing",
                url=freq.url.raw_url,
                description="No Content-Security-Policy header found",
            )
            return

        issues: list[str] = []

        if "'unsafe-inline'" in csp:
            issues.append("unsafe-inline allows inline scripts/styles")

        if "'unsafe-eval'" in csp:
            issues.append("unsafe-eval allows eval()")

        if "'unsafe-hashes'" in csp:
            issues.append("unsafe-hashes weakens CSP")

        if re.search(r"script-src\s+[^;]*\*", csp):
            issues.append("Wildcard in script-src allows any script source")

        if re.search(r"connect-src\s+[^;]*\*", csp):
            issues.append("Wildcard in connect-src allows any connection target")

        if "frame-ancestors" not in csp:
            issues.append("Missing frame-ancestors directive (clickjacking risk)")

        if "report-uri" not in csp and "report-to" not in csp:
            issues.append("No report-uri or report-to directive")

        if issues:
            for issue in issues:
                logger.info(
                    "xfweb.csp.issue",
                    url=freq.url.raw_url,
                    issue=issue,
                )
