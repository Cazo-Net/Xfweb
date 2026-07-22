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
