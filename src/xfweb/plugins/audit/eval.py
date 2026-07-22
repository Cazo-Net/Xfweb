"""Eval injection audit plugin — detects code evaluation vulnerabilities."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

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

        for payload, expected in EVAL_PAYLOADS:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={payload}",
            )
            resp = await http.get(modified_url)

            if resp.status_code == 200 and expected in resp.text:
                if expected not in baseline.text or resp.text != baseline.text:
                    logger.warning(
                        "xfweb.eval.vuln_found",
                        url=freq.url.raw_url,
                        param=param,
                        payload=payload,
                    )
                    return
