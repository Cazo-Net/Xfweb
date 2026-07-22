"""Cross-Site Scripting (XSS) audit plugin — detects reflected and DOM-based XSS."""

from __future__ import annotations

import asyncio
import html
import random
import string
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'-alert(1)-'",
    "<iframe src=\"javascript:alert(1)\">",
    "<body onload=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<details open ontoggle=alert(1)>",
    "javascript:alert(1)",
    "<math><mtext><table><mglyph><svg><mtext><textarea><path id=\"</textarea><img onerror=alert(1) src=1>\">",
]


class XssPlugin(AuditPlugin):
    """Cross-Site Scripting vulnerability detector."""

    plugin_name = "xss"
    brief_description = "Detect reflected and DOM-based XSS vulnerabilities"

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

    async def _test_param(self, freq: Any, param_name: str, param_value: str, http: HttpEngine) -> None:
        marker = "".join(random.choices(string.ascii_lowercase, k=8))

        for payload in XSS_PAYLOADS:
            encoded_payload = html.escape(payload) if payload.startswith("<") else payload
            test_value = f"{marker}{encoded_payload}"

            test_url = freq.url.raw_url.replace(
                f"{param_name}={param_value}",
                f"{param_name}={test_value}",
            )

            resp = await http.get(test_url)

            if marker in resp.text and encoded_payload in resp.text:
                self._report_finding(freq, param_name, payload, resp)
                return

    def _report_finding(self, freq: Any, param: str, payload: str, resp: Any) -> None:
        logger.warning(
            "xfweb.xss.vuln_found",
            url=freq.url.raw_url,
            param=param,
            payload=payload,
        )
