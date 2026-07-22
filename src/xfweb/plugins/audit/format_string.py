"""Format string vulnerability audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

FORMAT_STRING_PAYLOADS = [
    ("%s%s%s%s%s", "s"),
    ("%x%x%x%x%x", "x"),
    ("%n%n%n%n%n", "n"),
    ("%08x.%08x.%08x.%08x.%08x", "x"),
    ("{0.__class__.__bases__}", "python"),
    ("{{7*7}}", "template"),
]


class FormatStringPlugin(AuditPlugin):
    """Detect format string vulnerabilities."""

    plugin_name = "format_string"
    brief_description = "Detect format string injection vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return
        tasks = [self._test_param(freq, p, v, http) for p, v in params.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        params: dict[str, str] = {}
        if freq.post_data and isinstance(freq.post_data, str):
            for pair in freq.post_data.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        if freq.url.query:
            for pair in freq.url.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v
        return params

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine) -> None:
        baseline = await http.get(freq.url.raw_url)

        for payload, indicator in FORMAT_STRING_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={payload}",
            )
            resp = await http.get(modified_url)
            if resp.status_code >= 500 and resp.status_code != baseline.status_code:
                logger.warning("xfweb.format_string.vuln_found", url=freq.url.raw_url, param=param)
                return
            if indicator == "python" and "__class__" in resp.text:
                logger.warning("xfweb.format_string.vuln_found", url=freq.url.raw_url, param=param)
                return
