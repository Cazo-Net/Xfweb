"""WebSocket hijacking detection plugin."""

from __future__ import annotations

from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import WebSocketPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class WebSocketHijackPlugin(WebSocketPlugin):
    """Test for Cross-Site WebSocket Hijacking (CSWSH)."""

    plugin_name = "websocket_hijacking"
    brief_description = "Detect cross-site WebSocket hijacking vulnerabilities"

    async def test_websocket(self, url: str, http: HttpEngine) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        result = await http.send_websocket(url)

        if result.get("connected"):
            findings.append({
                "name": "WebSocket Without Origin Validation",
                "severity": "medium",
                "description": (
                    "The WebSocket endpoint accepts connections without origin validation, "
                    "which may allow Cross-Site WebSocket Hijacking (CSWSH)."
                ),
                "url": url,
                "remediation": "Validate the Origin header on WebSocket upgrade requests.",
            })

        return findings
