"""Open redirect / global redirect audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

logger = structlog.get_logger()

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "https://evil.com%2F..",
    "https://evil.com%00.example.com",
    "///evil.com",
    "https:evil.com",
]


class GlobalRedirectPlugin(AuditPlugin):
    """Detect open redirect vulnerabilities."""

    plugin_name = "global_redirect"
    brief_description = "Detect open redirect vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return
        tasks = [self._test_param(freq, p, v, http) for p, v in params.items()]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        return extract_params(freq)

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine) -> None:
        for payload in REDIRECT_PAYLOADS:
            modified_url = freq.url.raw_url.replace(f"{param}={value}", f"{param}={payload}")
            resp = await http.get(modified_url)
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("location", "")
                if "evil.com" in location:
                    self.report_finding(
                        name=f"Open redirect via '{param}'",
                        severity="high",
                        url=freq.url.raw_url,
                        description=f"Open redirect vulnerability in parameter '{param}'.",
                        parameter=param,
                        evidence=f"Payload: {payload}\nRedirect location: {location}",
                        http_request={"method": "GET", "url": modified_url},
                        http_response={"status": resp.status_code, "location": location},
                        remediation="Validate redirect URLs against a strict allowlist.",
                    )
                    return
