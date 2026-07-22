"""ScanStrategy — the multi-phase scanning pipeline.

Implements the producer-consumer architecture from w3af, modernized with asyncio:
1. Seed phase: Parse target URLs, discover initial attack surface
2. Discovery phase: Crawl + infrastructure plugins find new endpoints
3. Audit phase: Actively test discovered endpoints for vulnerabilities
4. Grep phase: Passively analyze all responses for sensitive data
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from xfweb.core.controllers.w3af_core import XfwebCore

logger = structlog.get_logger()


class ScanStrategy:
    """Orchestrates the multi-phase scanning pipeline."""

    def __init__(self, core: XfwebCore) -> None:
        self.core = core

    async def run(self) -> None:
        """Execute the full scan pipeline."""
        logger.info("xfweb.strategy.start")

        seed_requests = self._seed()
        if not seed_requests:
            logger.warning("xfweb.strategy.no_seed_requests")
            return

        await self._discovery_phase(seed_requests)
        await self._audit_phase()
        await self._grep_phase()
        await self._output_phase()

        logger.info("xfweb.strategy.complete", findings=len(self.core.kb))

    def _seed(self) -> list:
        """Create initial FuzzableRequests from target URLs."""
        from xfweb.core.data.url import parse_url
        from xfweb.core.data.url.fuzzable_request import FuzzableRequest

        urls = [parse_url(self.core.config.target)]
        requests = [FuzzableRequest.from_url(url) for url in urls]
        logger.info("xfweb.strategy.seed", count=len(requests))
        return requests

    async def _discovery_phase(self, seed_requests: list) -> None:
        """Run crawl and infrastructure plugins to discover endpoints."""
        logger.info("xfweb.strategy.discovery_start")
        crawl_plugins = self.core.plugins.get_plugins_by_category("crawl")
        infra_plugins = self.core.plugins.get_plugins_by_category("infrastructure")
        discovery_plugins = crawl_plugins + infra_plugins

        if not discovery_plugins:
            logger.warning("xfweb.strategy.no_discovery_plugins")
            return

        queue: asyncio.Queue = asyncio.Queue()
        for req in seed_requests:
            await queue.put(req)

        discovered: set[str] = set()
        while not queue.empty() and self.core.state.value == "running":
            try:
                req = await asyncio.wait_for(queue.get(), timeout=1.0)
            except asyncio.TimeoutError:
                break

            req_key = req.url.raw_url
            if req_key in discovered:
                continue
            discovered.add(req_key)

            for plugin in discovery_plugins:
                try:
                    new_requests = await plugin.run(req, self.core.http)
                    for new_req in new_requests:
                        if new_req.url.raw_url not in discovered:
                            await queue.put(new_req)
                except Exception as exc:
                    logger.error(
                        "xfweb.strategy.discovery_error",
                        plugin=plugin.plugin_name,
                        error=str(exc),
                    )

        logger.info("xfweb.strategy.discovery_complete", urls_found=len(discovered))

    async def _audit_phase(self) -> None:
        """Run audit plugins against all discovered endpoints."""
        logger.info("xfweb.strategy.audit_start")
        audit_plugins = self.core.plugins.get_plugins_by_category("audit")

        if not audit_plugins:
            logger.warning("xfweb.strategy.no_audit_plugins")
            return

        fuzzable_requests = self.core.kb.get_all_fuzzable_requests()
        logger.info("xfweb.strategy.audit_targets", count=len(fuzzable_requests), plugins=len(audit_plugins))

        semaphore = asyncio.Semaphore(self.core.config.max_threads)

        async def _audit_one(req: Any) -> None:
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
