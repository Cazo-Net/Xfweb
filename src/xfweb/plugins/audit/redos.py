"""Regular Expression Denial of Service (ReDoS) audit plugin."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

REDOS_PAYLOADS = [
    "a" * 30 + "!",
    "a" * 50 + "!",
    "a" * 100 + "!",
    "a" * 30 + "a" * 30,
    "ab" * 50 + "c",
    "a" * 25 + "\n" * 25,
    "(" * 50 + ")" * 50,
    "a!" * 50,
]


class ReDoSPlugin(AuditPlugin):
    """Detect Regular Expression Denial of Service vulnerabilities."""

    plugin_name = "redos"
    brief_description = "Detect ReDoS vulnerabilities via crafted inputs"

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

        for payload in REDOS_PAYLOADS:
            start = time.monotonic()
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}", f"{param}={payload}",
            )
            resp = await http.get(modified_url)
            elapsed = time.monotonic() - start

            if elapsed > 5.0:
                self.report_finding(
                    name=f"ReDoS via '{param}' parameter",
                    severity="medium",
                    url=freq.url.raw_url,
                    description=f"Regular expression denial of service in parameter '{param}'. "
                    f"Server took {elapsed:.1f}s to process the payload.",
                    parameter=param,
                    evidence=f"Payload length: {len(payload)}\nElapsed: {elapsed:.1f}s\n"
                    f"Payload: {repr(payload[:100])}",
                    http_request={"method": freq.method, "url": modified_url},
                    http_response={"status": resp.status_code},
                    remediation="Fix vulnerable regular expressions. Use non-backtracking "
                    "regex engines. Apply input length limits.",
                )
                return
