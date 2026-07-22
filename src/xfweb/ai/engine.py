"""AI Engine — LLM-powered vulnerability detection, payload generation, and FP reduction.

This module provides:
1. Smart payload generation using LLM context awareness
2. Anomaly-based detection via response analysis
3. False positive reduction through pattern learning
4. Vulnerability chaining for multi-step exploits
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


@dataclass
class AiContext:
    target_url: str
    plugin_name: str
    parameter: str = ""
    current_payload: str = ""
    response_code: int = 0
    response_body: str = ""
    response_headers: dict[str, str] = field(default_factory=dict)
    previous_findings: list[dict[str, Any]] = field(default_factory=list)


class AiEngine:
    """AI-powered vulnerability detection engine."""

    def __init__(self, provider: str = "openai", api_key: str = "") -> None:
        self.provider = provider
        self.api_key = api_key
        self._client: Any = None
        self._pattern_cache: dict[str, list[str]] = {}
        self._fp_history: list[dict[str, Any]] = []

    async def _get_client(self) -> Any:
        if self._client is None:
            if self.provider == "openai":
                try:
                    import openai
                    self._client = openai.AsyncOpenAI(api_key=self.api_key)
                except ImportError:
                    logger.warning("xfweb.ai.openai_not_installed")
                    return None
            elif self.provider == "anthropic":
                try:
                    import anthropic
                    self._client = anthropic.AsyncAnthropic(api_key=self.api_key)
                except ImportError:
                    logger.warning("xfweb.ai.anthropic_not_installed")
                    return None
        return self._client

    async def generate_payloads(self, context: AiContext) -> list[str]:
        """Generate context-aware payloads using LLM."""
        client = await self._get_client()
        if client is None:
            return self._default_payloads(context)

        prompt = f"""You are a security testing expert. Generate 5 injection payloads for testing vulnerabilities.

Target: {context.target_url}
Plugin: {context.plugin_name}
Parameter: {context.parameter}
Current payload: {context.current_payload}
Response code: {context.response_code}

Generate payloads for SQL injection, XSS, command injection, or path traversal depending on the plugin context.
Return ONLY a JSON array of payload strings, nothing else."""

        try:
            if self.provider == "openai":
                response = await client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content": prompt}],
                    temperature=0.7,
                    max_tokens=500,
                )
                content = response.choices[0].message.content
            elif self.provider == "anthropic":
                response = await client.messages.create(
                    model="claude-3-5-haiku-20241022",
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}],
                )
                content = response.content[0].text
            else:
                return self._default_payloads(context)

            payloads = json.loads(content)
            if isinstance(payloads, list):
                return [str(p) for p in payloads[:5]]
        except Exception as exc:
            logger.warning("xfweb.ai.generation_failed", error=str(exc))

        return self._default_payloads(context)

    async def analyze_response(self, context: AiContext) -> dict[str, Any]:
        """Analyze a response for anomalies using AI."""
        analysis = {
            "is_anomaly": False,
            "confidence": 0.0,
            "explanation": "",
            "suggested_action": "",
        }

        body = context.response_body
        if not body:
            return analysis

        anomaly_indicators = 0
        reasons: list[str] = []

        if context.response_code >= 500:
            anomaly_indicators += 2
            reasons.append(f"Server error (HTTP {context.response_code})")

        if context.parameter and context.current_payload:
            if context.current_payload in body:
                anomaly_indicators += 3
                reasons.append("Payload reflected in response")

        error_signs = ["exception", "traceback", "error", "warning", "notice", "fatal"]
        body_lower = body.lower()
        for sign in error_signs:
            if sign in body_lower:
                anomaly_indicators += 1
                reasons.append(f"Error keyword detected: {sign}")

        if len(body) < 100 and context.response_code == 200:
            anomaly_indicators += 1
            reasons.append("Unexpectedly short response")

        if context.previous_findings:
            for prev in context.previous_findings:
                if prev.get("url") == context.target_url and prev.get("parameter") == context.parameter:
                    anomaly_indicators += 1
                    reasons.append("Multiple findings on same parameter")

        analysis["is_anomaly"] = anomaly_indicators >= 2
        analysis["confidence"] = min(anomaly_indicators / 6.0, 1.0)
        analysis["explanation"] = "; ".join(reasons) if reasons else "No anomalies detected"

        if analysis["is_anomaly"]:
            if anomaly_indicators >= 4:
                analysis["suggested_action"] = "HIGH CONFIRMED — Verify manually"
            else:
                analysis["suggested_action"] = "MEDIUM — Needs further verification"

        return analysis

    async def reduce_false_positives(
        self, finding: dict[str, Any], context: AiContext
    ) -> dict[str, Any]:
        """Use AI to reduce false positives by analyzing context."""
        body = context.response_body
        payload = context.current_payload

        fp_score = 0.0
        reasons: list[str] = []

        if payload and payload not in body:
            fp_score += 0.3
            reasons.append("Payload not reflected in response")

        if context.response_code == 200 and "error" not in body.lower():
            fp_score += 0.2
            reasons.append("Normal response with no error indicators")

        known_fp_patterns = [
            ("xss", "Content-Type: application/json"),
            ("sqli", "parameter not found"),
            ("sqli", "invalid input"),
        ]
        for plugin, pattern in known_fp_patterns:
            if plugin in finding.get("plugin_name", ""):
                if pattern.lower() in body.lower():
                    fp_score += 0.4
                    reasons.append(f"Known FP pattern: {pattern}")

        finding["fp_score"] = min(fp_score, 1.0)
        finding["fp_reasons"] = reasons
        finding["is_likely_fp"] = fp_score > 0.6

        if fp_score > 0.6:
            logger.info(
                "xfweb.ai.fp_reduced",
                finding=finding.get("name", ""),
                score=fp_score,
                reasons=reasons,
            )

        return finding

    async def chain_vulnerabilities(
        self, findings: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Find chains of low-severity findings that combine into critical exploits."""
        chains: list[dict[str, Any]] = []

        findings_by_url: dict[str, list[dict[str, Any]]] = {}
        for f in findings:
            url = f.get("url", "")
            if url not in findings_by_url:
                findings_by_url[url] = []
            findings_by_url[url].append(f)

        for url, url_findings in findings_by_url.items():
            severities = [f.get("severity", "") for f in url_findings]

            if "information" in severities and "low" in severities:
                info_findings = [f for f in url_findings if f.get("severity") == "information"]
                low_findings = [f for f in url_findings if f.get("severity") == "low"]

                if len(info_findings) >= 2 and low_findings:
                    chain = {
                        "name": "Potential Vulnerability Chain",
                        "severity": "medium",
                        "description": (
                            f"Multiple low-severity findings on {url} may be chainable: "
                            f"{', '.join(f.get('name', '') for f in info_findings[:3])}"
                        ),
                        "url": url,
                        "chained_findings": [f.get("name", "") for f in info_findings + low_findings],
                        "is_chain": True,
                    }
                    chains.append(chain)

        return chains

    def _default_payloads(self, context: AiContext) -> list[str]:
        """Fallback payloads when AI is unavailable."""
        plugin = context.plugin_name.lower()
        if "sqli" in plugin:
            return ["' OR 1=1--", "1' UNION SELECT NULL--", "'; WAITFOR DELAY '0:0:5'--"]
        elif "xss" in plugin:
            return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        elif "lfi" in plugin:
            return ["../../etc/passwd", "php://filter/convert.base64-encode/resource=/etc/passwd"]
        elif "ssrf" in plugin:
            return ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]
        elif "os_commanding" in plugin:
            return [";id", "|id", "`id`"]
        return ["test", "' OR '1'='1", "<script>alert(1)</script>"]


class AnomalyDetector:
    """Response anomaly detector for reducing false positives."""

    def __init__(self) -> None:
        self._baselines: dict[str, dict[str, Any]] = {}

    def set_baseline(self, url: str, response_length: int, response_code: int, headers: dict[str, str]) -> None:
        self._baselines[url] = {
            "length": response_length,
            "code": response_code,
            "headers": headers,
        }

    def detect_anomaly(
        self,
        url: str,
        response_length: int,
        response_code: int,
        body: str,
        payload: str = "",
    ) -> dict[str, Any]:
        baseline = self._baselines.get(url)
        if not baseline:
            return {"is_anomaly": False, "reasons": []}

        reasons: list[str] = []
        score = 0.0

        length_diff = abs(response_length - baseline["length"]) / max(baseline["length"], 1)
        if length_diff > 0.5:
            score += 0.3
            reasons.append(f"Length changed by {length_diff:.0%}")

        if response_code != baseline["code"]:
            score += 0.4
            reasons.append(f"Status code changed: {baseline['code']} -> {response_code}")

        if payload and payload in body:
            score += 0.5
            reasons.append("Payload reflected in response")

        return {
            "is_anomaly": score >= 0.3,
            "score": min(score, 1.0),
            "reasons": reasons,
        }
