"""OS Commanding (Command Injection) audit plugin."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

logger = structlog.get_logger()

COMMAND_PAYLOADS = [
    (";id", ["uid=", "gid="]),
    ("|id", ["uid=", "gid="]),
    ("||id", ["uid=", "gid="]),
    ("&&id", ["uid=", "gid="]),
    ("`id`", ["uid=", "gid="]),
    ("$(id)", ["uid=", "gid="]),
    (";cat /etc/passwd", ["root:"]),
    ("|cat /etc/passwd", ["root:"]),
]

WIN_COMMAND_PAYLOADS = [
    (";type C:\\Windows\\System32\\drivers\\etc\\hosts", ["localhost"]),
    ("|type C:\\Windows\\System32\\drivers\\etc\\hosts", ["localhost"]),
]


class OsCommandingPlugin(AuditPlugin):
    """OS Command Injection vulnerability detector."""

    plugin_name = "os_commanding"
    brief_description = "Detect OS command injection vulnerabilities"

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
        all_payloads = COMMAND_PAYLOADS + WIN_COMMAND_PAYLOADS

        for payload, markers in all_payloads:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={value}{payload}",
            )
            resp = await http.get(modified_url)

            if resp.status_code == 200 and any(marker in resp.text for marker in markers):
                self.report_finding(
                    name=f"OS Command Injection via '{param}'",
                    severity="critical",
                    url=freq.url.raw_url,
                    description=f"OS command injection detected in parameter '{param}'. "
                    f"Payload successfully executed a system command.",
                    parameter=param,
                    evidence=f"Payload: {payload}\nCommand output markers: {[m for m in markers if m in resp.text]}",
                    http_request={"method": freq.method, "url": modified_url},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Never pass user input to system commands. "
                    "Use parameterized APIs. Apply strict input validation.",
                )
                return
