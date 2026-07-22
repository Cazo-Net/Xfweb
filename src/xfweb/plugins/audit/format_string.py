"""Format string vulnerability audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

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
        return extract_params(freq)

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine) -> None:
        baseline = await http.get(freq.url.raw_url)

        for payload, indicator in FORMAT_STRING_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={payload}",
            )
            resp = await http.get(modified_url)
            if resp.status_code >= 500 and resp.status_code != baseline.status_code:
                self.report_finding(
                    name=f"Format string vulnerability in '{param}'",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"Format string injection detected in parameter '{param}'. "
                    "The server returns a 500 error when format specifiers are injected.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nBaseline status: {baseline.status_code}\n"
                    f"Injected status: {resp.status_code}",
                    http_request={"method": freq.method, "url": freq.url.raw_url},
                    http_response={"status": resp.status_code},
                    remediation="Never pass user input as a format string. "
                    "Use parameterized formatting: format('%s', user_input).",
                )
                return
            if indicator == "python" and "__class__" in resp.text:
                self.report_finding(
                    name=f"Python format string injection in '{param}'",
                    severity="critical",
                    url=freq.url.raw_url,
                    description=f"Python format string injection in parameter '{param}'. "
                    "Object attribute access via format string confirmed.",
                    parameter=param,
                    evidence=f"Payload: {payload}\n__class__ found in response",
                    http_request={"method": freq.method, "url": freq.url.raw_url},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Never pass user input as a format string.",
                )
                return
