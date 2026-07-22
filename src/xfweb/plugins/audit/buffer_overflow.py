"""Buffer overflow detection audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

BUFFER_SIZES = [
    ("short", "A" * 100),
    ("medium", "A" * 1000),
    ("long", "A" * 5000),
    ("very_long", "A" * 10000),
]

ERROR_PATTERNS = [
    "segmentation fault", "core dumped", "stack smashing",
    "buffer overflow", "memory violation", "fatal error",
    "application error",
]


class BufferOverflowPlugin(AuditPlugin):
    """Detect buffer overflow vulnerabilities via oversized inputs."""

    plugin_name = "buffer_overflow"
    brief_description = "Detect buffer overflow vulnerabilities via oversized inputs"

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

        for label, payload in BUFFER_SIZES:
            modified_url = freq.url.raw_url.replace(f"{param}={value}", f"{param}={payload}")
            resp = await http.get(modified_url)
            if resp.status_code >= 500:
                self.report_finding(
                    name=f"Buffer overflow via '{param}' ({label} input)",
                    severity="medium",
                    url=freq.url.raw_url,
                    description=f"Server returned 500 error with {label} input ({len(payload)} chars) "
                    f"in parameter '{param}'. Possible buffer overflow.",
                    parameter=param,
                    evidence=f"Input size: {len(payload)} chars\nStatus: {resp.status_code}",
                    http_request={"method": freq.method, "url": modified_url},
                    http_response={"status": resp.status_code},
                    remediation="Validate input length limits. Use safe string handling functions.",
                )
                return
            for pattern in ERROR_PATTERNS:
                if pattern in resp.text.lower() and pattern not in baseline.text.lower():
                    self.report_finding(
                        name=f"Buffer overflow error via '{param}'",
                        severity="medium",
                        url=freq.url.raw_url,
                        description=f"Error pattern '{pattern}' triggered by oversized input in '{param}'.",
                        parameter=param,
                        evidence=f"Error pattern: {pattern}\nInput size: {len(payload)}",
                        http_request={"method": freq.method, "url": modified_url},
                        http_response={"status": resp.status_code},
                        remediation="Validate input length. Use memory-safe languages/functions.",
                    )
                    return
