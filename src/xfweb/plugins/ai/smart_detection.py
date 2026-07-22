"""AI-powered audit plugin — uses LLM for smart payload generation and analysis."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AiPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()


class AiPayloadPlugin(AiPlugin):
    """AI-powered payload generation and vulnerability analysis."""

    plugin_name = "ai_payload"
    brief_description = "AI-powered smart payload generation and analysis"

    def __init__(self) -> None:
        super().__init__()
        self._engine: Any = None

    def _get_engine(self) -> Any:
        if self._engine is None:
            from xfweb.ai.engine import AiEngine
            self._engine = AiEngine(
                provider=self.options.get("provider", "openai"),
                api_key=self.options.get("api_key", ""),
            )
        return self._engine

    async def analyze(self, context: dict[str, Any], http: HttpEngine) -> dict[str, Any]:
        from xfweb.ai.engine import AiContext

        ai_ctx = AiContext(
            target_url=context.get("target_url", ""),
            plugin_name=context.get("plugin_name", ""),
            parameter=context.get("parameter", ""),
            current_payload=context.get("payload", ""),
            response_code=context.get("response_code", 0),
            response_body=context.get("response_body", ""),
        )

        engine = self._get_engine()

        payloads = await engine.generate_payloads(ai_ctx)
        analysis = await engine.analyze_response(ai_ctx)

        logger.info(
            "xfweb.ai.analyzed",
            url=ai_ctx.target_url,
            payloads_generated=len(payloads),
            is_anomaly=analysis.get("is_anomaly", False),
        )

        return {
            "generated_payloads": payloads,
            "analysis": analysis,
        }


class AiFalsePositiveReducer(AiPlugin):
    """AI-powered false positive reduction."""

    plugin_name = "ai_fp_reducer"
    brief_description = "AI-powered false positive reduction for scan findings"

    def __init__(self) -> None:
        super().__init__()
        self._engine: Any = None

    def _get_engine(self) -> Any:
        if self._engine is None:
            from xfweb.ai.engine import AiEngine
            self._engine = AiEngine(
                provider=self.options.get("provider", "openai"),
                api_key=self.options.get("api_key", ""),
            )
        return self._engine

    async def analyze(self, context: dict[str, Any], http: HttpEngine) -> dict[str, Any]:
        from xfweb.ai.engine import AiContext

        finding = context.get("finding", {})

        ai_ctx = AiContext(
            target_url=finding.get("url", ""),
            plugin_name=finding.get("plugin_name", ""),
            parameter=finding.get("parameter", ""),
            current_payload=finding.get("payload", ""),
            response_code=context.get("response_code", 0),
            response_body=context.get("response_body", ""),
        )

        engine = self._get_engine()
        reduced = await engine.reduce_false_positives(finding, ai_ctx)
        return reduced


class AiAnomalyDetector(AiPlugin):
    """AI-powered anomaly detection in HTTP responses."""

    plugin_name = "ai_anomaly"
    brief_description = "AI-powered anomaly detection for vulnerability confirmation"

    def __init__(self) -> None:
        super().__init__()
        self._detector: Any = None

    def _get_detector(self) -> Any:
        if self._detector is None:
            from xfweb.ai.engine import AnomalyDetector
            self._detector = AnomalyDetector()
        return self._detector

    async def analyze(self, context: dict[str, Any], http: HttpEngine) -> dict[str, Any]:
        detector = self._get_detector()

        is_baseline = context.get("is_baseline", False)
        url = context.get("url", "")

        if is_baseline:
            detector.set_baseline(
                url=url,
                response_length=context.get("response_length", 0),
                response_code=context.get("response_code", 0),
                headers=context.get("headers", {}),
            )
            return {"baseline_set": True}

        result = detector.detect_anomaly(
            url=url,
            response_length=context.get("response_length", 0),
            response_code=context.get("response_code", 0),
            body=context.get("body", ""),
            payload=context.get("payload", ""),
        )

        if result["is_anomaly"]:
            logger.info(
                "xfweb.ai.anomaly_detected",
                url=url,
                score=result["score"],
                reasons=result["reasons"],
            )

        return result


class AiVulnChainer(AiPlugin):
    """AI-powered vulnerability chaining engine."""

    plugin_name = "ai_vuln_chain"
    brief_description = "AI-powered vulnerability chaining for multi-step exploits"

    def __init__(self) -> None:
        super().__init__()
        self._engine: Any = None

    def _get_engine(self) -> Any:
        if self._engine is None:
            from xfweb.ai.engine import AiEngine
            self._engine = AiEngine(
                provider=self.options.get("provider", "openai"),
                api_key=self.options.get("api_key", ""),
            )
        return self._engine

    async def analyze(self, context: dict[str, Any], http: HttpEngine) -> dict[str, Any]:
        findings = context.get("findings", [])
        engine = self._get_engine()
        chains = await engine.chain_vulnerabilities(findings)
        return {"chains": chains, "chain_count": len(chains)}
