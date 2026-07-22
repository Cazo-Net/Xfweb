"""Tests for Xfweb HTTP engine."""

import pytest
from xfweb.core.net.http_engine import HttpEngine, HttpResponse


def test_http_response_properties():
    resp = HttpResponse(
        status_code=200,
        headers={"content-type": "text/html"},
        body=b"<html>Hello</html>",
        text="<html>Hello</html>",
        url="https://example.com",
    )
    assert resp.status_code == 200
    assert resp.is_text is True
    assert "Hello" in resp.text


def test_http_response_json():
    import json

    data = {"key": "value"}
    resp = HttpResponse(
        status_code=200,
        headers={"content-type": "application/json"},
        body=json.dumps(data).encode(),
        text=json.dumps(data),
        url="https://example.com/api",
    )
    assert resp.json == data


def test_http_engine_init():
    engine = HttpEngine(user_agent="TestAgent/1.0")
    assert engine.user_agent == "TestAgent/1.0"
    assert engine.request_count == 0
    assert engine.error_count == 0
