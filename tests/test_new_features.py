"""Tests for param_extractor, KB limits, scope validation, and session management."""

import pytest
from xfweb.core.data.parsers.param_extractor import extract_params
from xfweb.core.data.kb.knowledge_base import KnowledgeBase, Finding, Severity
from xfweb.core.data.url import parse_url
from xfweb.core.data.url.fuzzable_request import FuzzableRequest


def _make_freq(query: str = "", post_data: str | None = None, method: str = "GET") -> FuzzableRequest:
    url = parse_url(f"https://example.com/page?{query}" if query else "https://example.com/page")
    freq = FuzzableRequest.from_parts(url=url, method=method, post_data=post_data)
    return freq


# ── param_extractor ─────────────────────────────────────────────────────


class TestParamExtractor:
    def test_query_string(self):
        freq = _make_freq("name=alice&id=42")
        params = extract_params(freq)
        assert params["name"] == "alice"
        assert params["id"] == "42"

    def test_url_encoded_post(self):
        freq = _make_freq(post_data="user=admin&pass=secret")
        params = extract_params(freq)
        assert params["user"] == "admin"
        assert params["pass"] == "secret"

    def test_json_post(self):
        freq = _make_freq(post_data='{"user":"admin","pass":"secret"}', method="POST")
        params = extract_params(freq)
        assert params["user"] == "admin"
        assert params["pass"] == "secret"

    def test_nested_json(self):
        freq = _make_freq(post_data='{"user":{"name":"alice"}}', method="POST")
        params = extract_params(freq)
        assert params["user.name"] == "alice"

    def test_empty_query(self):
        freq = _make_freq("")
        params = extract_params(freq)
        assert params == {}

    def test_mixed_query_and_body(self):
        freq = _make_freq("a=1", post_data="b=2")
        params = extract_params(freq)
        assert params["a"] == "1"
        assert params["b"] == "2"


# ── KB response limit ───────────────────────────────────────────────────


class TestKbResponseLimit:
    def test_max_responses_stored(self):
        kb = KnowledgeBase(max_responses=5)
        for i in range(10):
            kb.store_response(type("R", (), {"status_code": i})())
        assert len(kb.get_all_responses()) == 5

    def test_unlimited_when_zero(self):
        kb = KnowledgeBase(max_responses=0)
        for i in range(100):
            kb.store_response(type("R", (), {"status_code": i})())
        assert len(kb.get_all_responses()) == 100

    def test_findings不受max_responses影响(self):
        kb = KnowledgeBase(max_responses=0)
        for i in range(10):
            kb.append("loc", Finding(
                name=f"vuln-{i}",
                severity=Severity.LOW,
                description="test",
                url="https://example.com",
            ))
        assert len(kb) == 10


# ── Scope validation ────────────────────────────────────────────────────


class TestScopeValidation:
    def test_scan_config_scope_defaults(self):
        from xfweb.core.controllers.w3af_core import ScanConfig
        config = ScanConfig(target="https://example.com")
        assert config.scope == []
        assert config.exclude_scope == []

    def test_scan_config_scope_custom(self):
        from xfweb.core.controllers.w3af_core import ScanConfig
        config = ScanConfig(
            target="https://example.com",
            scope=["api.example.com", "dev.example.com"],
            exclude_scope=["staging.example.com"],
        )
        assert "api.example.com" in config.scope
        assert "staging.example.com" in config.exclude_scope


# ── Session management ──────────────────────────────────────────────────


class TestSessionManagement:
    def test_scan_config_auth_fields(self):
        from xfweb.core.controllers.w3af_core import ScanConfig
        config = ScanConfig(
            target="https://example.com",
            auth_token="test123",
            extra_cookies={"session": "abc"},
            extra_headers={"X-Custom": "val"},
            login_url="https://example.com/login",
            login_data={"user": "admin", "pass": "secret"},
        )
        assert config.auth_token == "test123"
        assert config.extra_cookies["session"] == "abc"
        assert config.extra_headers["X-Custom"] == "val"
        assert config.login_url == "https://example.com/login"
        assert config.login_data["user"] == "admin"


# ── Strategy scope validation ────────────────────────────────────────────


class TestStrategyScope:
    def _make_strategy(self, target: str, scope: list[str] | None = None, exclude: list[str] | None = None):
        from xfweb.core.controllers.w3af_core import XfwebCore, ScanConfig
        from xfweb.core.controllers.strategy import ScanStrategy

        config = ScanConfig(target=target, scope=scope or [], exclude_scope=exclude or [])
        core = XfwebCore(config)
        strategy = ScanStrategy(core)
        # Simulate what run() does to init scope
        from urllib.parse import urlparse
        parsed = urlparse(target)
        strategy._target_domain = parsed.hostname or ""
        parts = strategy._target_domain.split(".")
        for i in range(len(parts)):
            strategy._target_subdomains.add(".".join(parts[i:]))
        for s in config.scope:
            strategy._target_subdomains.add(s)
        for s in config.exclude_scope:
            strategy._excluded_domains.add(s)
            strategy._target_subdomains.discard(s)
        return strategy

    def test_in_scope_same_domain(self):
        s = self._make_strategy("https://example.com")
        assert s._is_in_scope("https://example.com/page")

    def test_in_scope_subdomain(self):
        s = self._make_strategy("https://example.com")
        assert s._is_in_scope("https://api.example.com/data")

    def test_out_of_scope(self):
        s = self._make_strategy("https://example.com")
        assert not s._is_in_scope("https://evil.com/steal")

    def test_out_of_scope_subdomain(self):
        s = self._make_strategy("https://example.com")
        assert not s._is_in_scope("https://notexample.com/page")

    def test_explicit_scope_adds_domain(self):
        s = self._make_strategy("https://example.com", scope=["api.other.com"])
        assert s._is_in_scope("https://api.other.com/v1")

    def test_exclude_scope_removes_domain(self):
        s = self._make_strategy("https://example.com", exclude=["staging.example.com"])
        assert not s._is_in_scope("https://staging.example.com")


# ── Finding body truncation ──────────────────────────────────────────────


class TestFindingTruncation:
    def test_truncates_long_evidence(self):
        kb = KnowledgeBase(max_responses=0)
        long_evidence = "x" * 5000
        finding = Finding(
            name="test",
            severity=Severity.LOW,
            description="test",
            url="https://example.com",
            evidence=long_evidence,
        )
        kb.append("loc", finding)
        d = kb.to_dicts()[0]
        assert len(d["evidence"]) <= 2048

    def test_truncates_long_body_excerpt(self):
        kb = KnowledgeBase(max_responses=0)
        finding = Finding(
            name="test",
            severity=Severity.LOW,
            description="test",
            url="https://example.com",
            http_response={"body_excerpt": "y" * 5000},
        )
        kb.append("loc", finding)
        d = kb.to_dicts()[0]
        body = d["http_response"]["body_excerpt"]
        assert len(body) <= 2048 + 20  # MAX_BODY_LEN + truncation suffix len

    def test_short_evidence_not_truncated(self):
        kb = KnowledgeBase(max_responses=0)
        finding = Finding(
            name="test",
            severity=Severity.LOW,
            description="test",
            url="https://example.com",
            evidence="short evidence",
        )
        kb.append("loc", finding)
        d = kb.to_dicts()[0]
        assert d["evidence"] == "short evidence"


# ── Max page size config ────────────────────────────────────────────────


class TestMaxPageSize:
    def test_default_is_zero(self):
        from xfweb.core.controllers.w3af_core import ScanConfig
        config = ScanConfig(target="https://example.com")
        assert config.max_page_size == 0

    def test_custom_max_page_size(self):
        from xfweb.core.controllers.w3af_core import ScanConfig
        config = ScanConfig(target="https://example.com", max_page_size=1048576)
        assert config.max_page_size == 1048576
