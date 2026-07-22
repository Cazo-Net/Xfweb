"""ScanStrategy — the multi-phase scanning pipeline.

Implements the producer-consumer architecture from w3af, modernized with asyncio:
1. Seed phase: Parse target URLs, discover initial attack surface
2. Discovery phase: Concurrent crawl workers + infrastructure plugins find new endpoints
3. Audit phase: Actively test discovered endpoints for vulnerabilities
4. Grep phase: Passively analyze all responses for sensitive data
5. Output phase: Generate reports
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from xfweb.core.controllers.w3af_core import XfwebCore

logger = structlog.get_logger()


class ScanStrategy:
    """Orchestrates the multi-phase scanning pipeline with concurrent workers."""

    def __init__(self, core: XfwebCore) -> None:
        self.core = core
        self._discovery_start: float = 0.0
        self._target_domain: str = ""
        self._target_subdomains: set[str] = set()

    async def run(self) -> None:
        """Execute the full scan pipeline."""
        logger.info("xfweb.strategy.start")

        seed_requests = self._seed()
        if not seed_requests:
            logger.warning("xfweb.strategy.no_seed_requests")
            return

        from urllib.parse import urlparse
        parsed = urlparse(self.core.config.target)
        self._target_domain = parsed.hostname or ""
        # Allow subdomains of target too
        parts = self._target_domain.split(".")
        for i in range(len(parts)):
            self._target_subdomains.add(".".join(parts[i:]))

        for req in seed_requests:
            self.core.kb.store_fuzzable_request(req)

        await self._emit("phase", {"phase": "discovery", "message": "Discovering endpoints..."})
        await self._discovery_phase(seed_requests)

        await self._emit("phase", {"phase": "audit", "message": "Testing for vulnerabilities..."})
        await self._audit_phase()

        await self._emit("phase", {"phase": "grep", "message": "Analyzing responses..."})
        await self._grep_phase()

        await self._emit("phase", {"phase": "output", "message": "Generating reports..."})
        await self._output_phase()

        await self._emit("phase", {"phase": "complete", "message": "Scan complete"})

        logger.info(
            "xfweb.strategy.complete",
            findings=len(self.core.kb),
            urls_crawled=self.core.http.urls_crawled,
            requests_made=self.core.http.request_count,
        )

    async def _emit(self, event: str, data: dict[str, Any] | None = None) -> None:
        """Emit a scan event."""
        await self.core._emit_event(event, data)

    def _seed(self) -> list[Any]:
        """Create initial FuzzableRequests from target URLs."""
        from xfweb.core.data.url import parse_url
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest

        urls = [parse_url(self.core.config.target)]
        requests = [FuzzableRequest.from_url(url) for url in urls]
        logger.info("xfweb.strategy.seed", count=len(requests))
        return requests

    def _is_expired(self) -> bool:
        """Check if scan time has expired."""
        if self.core.config.max_scan_time > 0:
            elapsed = time.time() - self.core.start_time
            if elapsed >= self.core.config.max_scan_time:
                logger.warning("xfweb.strategy.scan_timeout", elapsed=elapsed)
                return True
        return False

    def _is_in_scope(self, url: str) -> bool:
        """Check if a URL is within the target domain scope."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            if not host:
                return False
            # Exact match or subdomain of target
            return host == self._target_domain or host in self._target_subdomains
        except Exception:
            return False

    def _is_discovery_expired(self) -> bool:
        """Check if discovery phase time has expired."""
        if self.core.config.max_discovery_time > 0:
            elapsed = time.time() - self._discovery_start
            if elapsed >= self.core.config.max_discovery_time:
                logger.warning("xfweb.strategy.discovery_timeout", elapsed=elapsed)
                return True
        return False

    async def _discovery_phase(self, seed_requests: list[Any]) -> None:
        """Run concurrent crawl workers to discover endpoints."""
        logger.info("xfweb.strategy.discovery_start")
        self._discovery_start = time.time()

        crawl_plugins = self.core.plugins.get_plugins_by_category("crawl")
        infra_plugins = self.core.plugins.get_plugins_by_category("infrastructure")
        discovery_plugins = crawl_plugins + infra_plugins

        if not discovery_plugins:
            logger.warning("xfweb.strategy.no_discovery_plugins")
            return

        queue: asyncio.Queue[Any] = asyncio.Queue()
        for req in seed_requests:
            await queue.put(req)

        discovered: set[str] = set()
        max_pages = 500
        pages_crawled = 0
        pages_lock = asyncio.Lock()

        num_workers = min(10, self.core.config.max_threads)

        async def _crawl_worker(worker_id: int) -> None:
            nonlocal pages_crawled
            while True:
                if self._is_discovery_expired() or self._is_expired():
                    break
                if self.core.state.value != "running":
                    break

                try:
                    req = await asyncio.wait_for(queue.get(), timeout=1.0)
                except asyncio.TimeoutError:
                    break

                req_key = req.url.raw_url
                async with pages_lock:
                    if req_key in discovered:
                        queue.task_done()
                        continue
                    if pages_crawled >= max_pages:
                        queue.task_done()
                        break
                    discovered.add(req_key)
                    pages_crawled += 1

                for plugin in discovery_plugins:
                    try:
                        new_requests = await plugin.run(req, self.core.http)
                        if new_requests:
                            for new_req in new_requests:
                                new_url = new_req.url.raw_url
                                if not self._is_in_scope(new_url):
                                    continue
                                async with pages_lock:
                                    if new_url not in discovered and pages_crawled < max_pages:
                                        await queue.put(new_req)
                                        self.core.kb.store_fuzzable_request(new_req)
                    except Exception as exc:
                        logger.error(
                            "xfweb.strategy.discovery_error",
                            plugin=plugin.plugin_name,
                            error=str(exc),
                        )

                queue.task_done()

                # Emit progress periodically
                if pages_crawled % 10 == 0:
                    await self._emit("progress", {
                        "phase": "discovery",
                        "pages_crawled": pages_crawled,
                        "urls_in_queue": queue.qsize(),
                        "findings": len(self.core.kb),
                    })

        workers = [_crawl_worker(i) for i in range(num_workers)]
        await asyncio.gather(*workers, return_exceptions=True)

        logger.info("xfweb.strategy.discovery_complete", urls_found=len(discovered))

    async def _audit_phase(self) -> None:
        """Run audit plugins against all discovered endpoints."""
        logger.info("xfweb.strategy.audit_start")
        audit_plugins = self.core.plugins.get_plugins_by_category("audit")

        if not audit_plugins:
            logger.warning("xfweb.strategy.no_audit_plugins")
            return

        fuzzable_requests = self.core.kb.get_all_fuzzable_requests()
        total = len(fuzzable_requests)
        logger.info(
            "xfweb.strategy.audit_targets",
            count=total,
            plugins=len(audit_plugins),
        )

        semaphore = asyncio.Semaphore(self.core.config.max_threads)
        completed = 0

        async def _audit_one(req: Any) -> None:
            nonlocal completed
            if self._is_expired():
                return
            if self.core.state.value != "running":
                return

            async with semaphore:
                for plugin in audit_plugins:
                    try:
                        await plugin.run(req, self.core.http)
                    except Exception as exc:
                        logger.error(
                            "xfweb.strategy.audit_error",
                            plugin=plugin.plugin_name,
                            url=req.url.raw_url,
                            error=str(exc),
                        )

                completed += 1
                if completed % 20 == 0 or completed == total:
                    await self._emit("progress", {
                        "phase": "audit",
                        "tested": completed,
                        "total": total,
                        "findings": len(self.core.kb),
                    })

        tasks = [_audit_one(req) for req in fuzzable_requests]
        await asyncio.gather(*tasks, return_exceptions=True)
        logger.info("xfweb.strategy.audit_complete")

    async def _grep_phase(self) -> None:
        """Run grep plugins on all collected responses."""
        logger.info("xfweb.strategy.grep_start")
        grep_plugins = self.core.plugins.get_plugins_by_category("grep")

        if not grep_plugins:
            return

        responses = self.core.kb.get_all_responses()
        for response in responses:
            for plugin in grep_plugins:
                try:
                    await plugin.run(response, self.core.http)
                except Exception as exc:
                    logger.error(
                        "xfweb.strategy.grep_error",
                        plugin=plugin.plugin_name,
                        error=str(exc),
                    )

        logger.info("xfweb.strategy.grep_complete")

    async def _output_phase(self) -> None:
        """Run output plugins to generate reports."""
        logger.info("xfweb.strategy.output_start")
        output_plugins = self.core.plugins.get_plugins_by_category("output")

        findings = self.core.kb.to_dicts()
        for plugin in output_plugins:
            try:
                await plugin.generate(findings, self.core.config.output_dir)
            except Exception as exc:
                logger.error(
                    "xfweb.strategy.output_error",
                    plugin=plugin.plugin_name,
                    error=str(exc),
                )

        logger.info("xfweb.strategy.output_complete")
