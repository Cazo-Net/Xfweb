"""Server-Side Request Forgery (SSRF) audit plugin."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

SSRF_PAYLOADS = [
    ("http://127.0.0.1", ["localhost", "127.0.0.1"]),
    ("http://localhost", ["localhost"]),
    ("http://[::1]", ["localhost"]),
    ("http://0x7f000001", ["localhost"]),
    ("http://2130706433", ["localhost"]),
    ("http://127.0.0.1:22", ["SSH", "OpenSSH"]),
    ("http://127.0.0.1:3306", ["MySQL"]),
    ("http://127.0.0.1:6379", ["redis_version"]),
    ("http://169.254.169.254/latest/meta-data/", ["ami-id", "instance-id"]),
    ("http://metadata.google.internal/", ["metadata"]),
]


class SsrfPlugin(AuditPlugin):
    """Server-Side Request Forgery vulnerability detector."""

    plugin_name = "ssrf"
    brief_description = "Detect SSRF vulnerabilities including cloud metadata access"

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
        for payload, markers in SSRF_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={payload}",
            )
            resp = await http.get(modified_url)

            if resp.status_code == 200 and any(marker in resp.text for marker in markers):
                logger.warning(
                    "xfweb.ssrf.vuln_found",
                    url=freq.url.raw_url,
                    param=param,
                    payload=payload,
                )
                return
