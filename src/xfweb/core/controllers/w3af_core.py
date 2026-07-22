"""XfwebCore — the central orchestrator for all scanning activity.

This is the brain of Xfweb. It coordinates plugins, strategy, HTTP engine,
knowledge base, and worker pools to execute scans against web targets.
"""

from __future__ import annotations

import asyncio
import signal
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

import structlog

from xfweb import __version__
from xfweb.core.controllers.plugin_manager import PluginManager
from xfweb.core.controllers.strategy import ScanStrategy
from xfweb.core.data.kb.knowledge_base import KnowledgeBase
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.url.fuzzable_request import FuzzableRequest

logger = structlog.get_logger()


class ScanState(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    COMPLETED = "completed"
    ERROR = "error"


@dataclass
class ScanConfig:
    target: str
    profile: str | None = None
    plugins: list[str] = field(default_factory=list)
    exclude_plugins: list[str] = field(default_factory=list)
    max_threads: int = 30
    max_scan_time: int = 14400  # seconds (4 hours)
    max_discovery_time: int = 7200  # seconds (2 hours)
    rate_limit: float = 0.0  # requests per second, 0 = unlimited
    follow_redirects: bool = True
    max_redirect_depth: int = 5
    user_agent: str = f"Xfweb/{__version__}"
    extra_headers: dict[str, str] = field(default_factory=dict)
    proxy: str | None = None
    scope: list[str] = field(default_factory=list)
    exclude_scope: list[str] = field(default_factory=list)
    output_dir: Path = Path("xfweb_output")
    enable_ai: bool = False


class XfwebCore:
    """Main scanning engine — orchestrates the entire scan lifecycle."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.state = ScanState.STOPPED
        self.start_time: float = 0.0
        self.end_time: float = 0.0

        self.plugins = PluginManager()
        self.kb = KnowledgeBase()
        self.http = HttpEngine(
            user_agent=config.user_agent,
            rate_limit=config.rate_limit,
            proxy=config.proxy,
        )
        self.strategy = ScanStrategy(core=self)

        self._callbacks: list[Any] = []
        self._shutdown_event = asyncio.Event()

    @property
    def scan_duration(self) -> float:
        if self.start_time == 0.0:
            return 0.0
        end = self.end_time if self.end_time else time.time()
        return end - self.start_time

    def on_event(self, callback: Any) -> None:
        """Register a callback for scan events (for UI/API integration)."""
        self._callbacks.append(callback)

    async def _emit_event(self, event: str, data: dict[str, Any] | None = None) -> None:
        for cb in self._callbacks:
            if asyncio.iscoroutinefunction(cb):
                await cb(event, data)
            else:
                cb(event, data)

    async def start(self) -> None:
        """Start the scan."""
        logger.info("xfweb.scan.starting", target=self.config.target, version=__version__)
        self.state = ScanState.STARTING
        self.start_time = time.time()

        await self._emit_event("scan_start", {"target": self.config.target})

        try:
            await self._verify_target()
            self.plugins.load_plugins(
                include=self.config.plugins,
                exclude=self.config.exclude_plugins,
                enable_ai=self.config.enable_ai,
            )
            self.state = ScanState.RUNNING
            await self._emit_event("scan_running")

            await self.strategy.run()

            self.state = ScanState.COMPLETED
            self.end_time = time.time()
            await self._emit_event("scan_complete", {"duration": self.scan_duration})

        except asyncio.CancelledError:
            self.state = ScanState.STOPPING
            await self._emit_event("scan_cancelled")
        except Exception as exc:
            self.state = ScanState.ERROR
            self.end_time = time.time()
            logger.error("xfweb.scan.error", error=str(exc))
            await self._emit_event("scan_error", {"error": str(exc)})
            raise
        finally:
            await self.http.close()

    async def stop(self) -> None:
        """Gracefully stop the scan."""
        logger.info("xfweb.scan.stopping")
        self.state = ScanState.STOPPING
        self._shutdown_event.set()
        await self._emit_event("scan_stopping")

    async def _verify_target(self) -> None:
        """Verify the target is reachable before scanning."""
        from xfweb.core.data.url import parse_url

        url = parse_url(self.config.target)
        logger.info("xfweb.scan.verify_target", url=url.raw_url)

        try:
            response = await self.http.get(url.raw_url)
            logger.info(
                "xfweb.scan.target_reachable",
                status_code=response.status_code,
                server=response.headers.get("server", "unknown"),
            )
        except Exception as exc:
            raise ConnectionError(f"Target {self.config.target} is not reachable: {exc}") from exc

    def get_findings(self) -> list[dict[str, Any]]:
        """Get all findings from the knowledge base."""
        return self.kb.to_dicts()

    def get_stats(self) -> dict[str, Any]:
        """Get scan statistics."""
        return {
            "state": self.state.value,
            "duration": self.scan_duration,
            "findings": len(self.kb),
            "urls_crawled": self.http.urls_crawled,
            "requests_made": self.http.request_count,
            "errors": self.http.error_count,
            "plugins_loaded": self.plugins.loaded_count,
        }
