"""Eval injection audit plugin — detects code evaluation vulnerabilities."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

logger = structlog.get_logger()

EVAL_PAYLOADS = [
    ("1+1", "2"),
    ("1*6", "6"),
    (";alert(1)", "alert"),
    ("${7*7}", "49"),
    ("{{7*7}}", "49"),
    ("<%= 7*7 %>", "49"),
    ("7*7", "49"),
]


class EvalPlugin(AuditPlugin):
    """Eval injection vulnerability detector."""

    plugin_name = "eval"
    brief_description = "Detect code evaluation injection vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return

        tasks = []
        for param_name, param_value in params.items():
            tasks.append(self._test_param(freq, param_name, param_value, http))
        await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        return extract_params(freq)

    async def _test_param(self, freq: Any, param: str, value: str, http: HttpEngine) -> None:
        baseline = await http.get(freq.url.raw_url)

        for payload, expected in EVAL_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={payload}",
            )
            resp = await http.get(modified_url)

            if resp.status_code == 200 and expected in resp.text:
                if expected not in baseline.text or resp.text != baseline.text:
                    self.report_finding(
                        name=f"Code evaluation injection via '{param}'",
                        severity="critical",
                        url=freq.url.raw_url,
                        description=f"Code evaluation vulnerability in parameter '{param}'. "
                        f"The application evaluates user input as code.",
                        parameter=param,
                        evidence=f"Payload: {payload}\nExpected result '{expected}' found in response",
                        http_request={"method": freq.method, "url": modified_url},
                        http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                        remediation="Never evaluate user input as code. "
                        "Use safe parsing functions. Apply strict input validation.",
                    )
                    return
