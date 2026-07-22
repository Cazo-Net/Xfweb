"""Comprehensive tests for Xfweb AI engine."""

import pytest
from xfweb.ai.engine import AiEngine, AiContext, AnomalyDetector


@pytest.fixture
def sample_context():
    return AiContext(
        target_url="https://example.com/search?q=test",
        plugin_name="sqli",
        parameter="q",
        current_payload="' OR 1=1--",
        response_code=200,
        response_body="<html>results</html>",
    )


class TestAiContext:
    def test_default(self):
        ctx = AiContext(target_url="https://a.com", plugin_name="xss")
        assert ctx.target_url == "https://a.com"
        assert ctx.parameter == ""
        assert ctx.response_code == 0
        assert ctx.previous_findings == []


class TestAiEngine:
    @pytest.mark.asyncio
    async def test_default_payloads_sqli(self):
        engine = AiEngine()
        ctx = AiContext(target_url="https://a.com", plugin_name="sqli")
        payloads = await engine.generate_payloads(ctx)
        assert len(payloads) > 0
        assert any("OR" in p for p in payloads)

    @pytest.mark.asyncio
    async def test_default_payloads_xss(self):
        engine = AiEngine()
        ctx = AiContext(target_url="https://a.com", plugin_name="xss")
        payloads = await engine.generate_payloads(ctx)
        assert any("<script>" in p for p in payloads)

    @pytest.mark.asyncio
    async def test_default_payloads_lfi(self):
        engine = AiEngine()
        ctx = AiContext(target_url="https://a.com", plugin_name="lfi")
        payloads = await engine.generate_payloads(ctx)
        assert any("etc/passwd" in p for p in payloads)

    @pytest.mark.asyncio
    async def test_default_payloads_ssrf(self):
        engine = AiEngine()
        ctx = AiContext(target_url="https://a.com", plugin_name="ssrf")
        payloads = await engine.generate_payloads(ctx)
        assert any("127.0.0.1" in p for p in payloads)

    @pytest.mark.asyncio
    async def test_analyze_response_anomaly(self):
        engine = AiEngine()
        ctx = AiContext(
            target_url="https://a.com",
            plugin_name="sqli",
            parameter="id",
            current_payload="' OR 1=1--",
            response_code=500,
            response_body="Traceback: exception at line 42",
        )
        result = await engine.analyze_response(ctx)
        assert result["is_anomaly"] is True
        assert result["confidence"] > 0.0

    @pytest.mark.asyncio
    async def test_analyze_response_normal(self):
        engine = AiEngine()
        ctx = AiContext(
            target_url="https://a.com",
            plugin_name="sqli",
            parameter="id",
            response_code=200,
            response_body="Normal page content, nothing unusual.",
        )
        result = await engine.analyze_response(ctx)
        assert result["is_anomaly"] is False

    @pytest.mark.asyncio
    async def test_reduce_false_positives_reflected(self):
        engine = AiEngine()
        finding = {"name": "XSS", "severity": "medium", "plugin_name": "xss"}
        ctx = AiContext(
            target_url="https://a.com",
            plugin_name="xss",
            parameter="q",
            current_payload="<script>alert(1)</script>",
            response_code=200,
            response_body="Content-Type: application/json response body",
        )
        result = await engine.reduce_false_positives(finding, ctx)
        assert result["is_likely_fp"] is True

    @pytest.mark.asyncio
    async def test_reduce_false_positives_confirmed(self):
        engine = AiEngine()
        finding = {"name": "XSS", "severity": "medium", "plugin_name": "xss"}
        ctx = AiContext(
            target_url="https://a.com",
            plugin_name="xss",
            parameter="q",
            current_payload="<script>alert(1)</script>",
            response_code=200,
            response_body='Result: <script>alert(1)</script> found',
        )
        result = await engine.reduce_false_positives(finding, ctx)
        assert result["is_likely_fp"] is False

    @pytest.mark.asyncio
    async def test_chain_vulnerabilities(self):
        engine = AiEngine()
        findings = [
            {"name": "HTML comments", "severity": "information", "url": "https://a.com"},
            {"name": "Passwords in comments", "severity": "information", "url": "https://a.com"},
            {"name": "Weak password", "severity": "low", "url": "https://a.com"},
        ]
        chains = await engine.chain_vulnerabilities(findings)
        assert len(chains) > 0
        assert chains[0]["severity"] == "medium"


class TestAnomalyDetector:
    def test_no_baseline(self):
        detector = AnomalyDetector()
        result = detector.detect_anomaly("https://a.com", 100, 200, "body")
        assert result["is_anomaly"] is False

    def test_baseline_set_and_anomaly(self):
        detector = AnomalyDetector()
        detector.set_baseline("https://a.com", 1000, 200, {"content-type": "text/html"})
        result = detector.detect_anomaly(
            "https://a.com", 5000, 500, "exception error", "' OR 1=1--"
        )
        assert result["is_anomaly"] is True
        assert len(result["reasons"]) > 0

    def test_baseline_set_no_anomaly(self):
        detector = AnomalyDetector()
        detector.set_baseline("https://a.com", 1000, 200, {"content-type": "text/html"})
        result = detector.detect_anomaly("https://a.com", 1010, 200, "normal page content")
        assert result["is_anomaly"] is False
