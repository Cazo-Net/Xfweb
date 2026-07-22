"""Basic tests for Xfweb core modules."""

import pytest
from xfweb import __version__, __app_name__


def test_version():
    assert __version__ == "1.0.0"


def test_app_name():
    assert __app_name__ == "Xfweb"


def test_scan_config_defaults():
    from xfweb.core.controllers.w3af_core import ScanConfig

    config = ScanConfig(target="https://example.com")
    assert config.target == "https://example.com"
    assert config.max_threads == 30
    assert config.enable_ai is False
    assert config.rate_limit == 0.0


def test_scan_state():
    from xfweb.core.controllers.w3af_core import ScanState

    assert ScanState.STOPPED.value == "stopped"
    assert ScanState.RUNNING.value == "running"
    assert ScanState.COMPLETED.value == "completed"


def test_knowledge_base():
    from xfweb.core.data.kb.knowledge_base import KnowledgeBase, Finding, Severity

    kb = KnowledgeBase()
    assert len(kb) == 0

    finding = Finding(
        name="Test Vuln",
        severity=Severity.HIGH,
        description="A test vulnerability",
        url="https://example.com",
    )
    kb.append("https://example.com", finding)
    assert len(kb) == 1

    summary = kb.get_summary()
    assert summary["high"] == 1
    assert summary["total"] == 1


def test_fuzzable_request():
    from xfweb.core.data.url import parse_url
    from xfweb.core.data.url.fuzzable_request import FuzzableRequest

    url = parse_url("https://example.com/page?id=1")
    freq = FuzzableRequest.from_url(url)

    assert freq.method == "GET"
    assert freq.url.hostname == "example.com"
    assert freq.sent("needle") is False


def test_url_parsing():
    from xfweb.core.data.url import parse_url

    url = parse_url("https://example.com:8443/api/v1?key=value#section")
    assert url.scheme == "https"
    assert url.hostname == "example.com"
    assert url.port == 8443
    assert url.path == "/api/v1"
    assert url.query == "key=value"


def test_plugin_manager_discovery():
    from xfweb.core.controllers.plugin_manager import PluginManager

    manager = PluginManager()
    plugins = manager.discover_plugins()
    assert isinstance(plugins, dict)
    assert "sqli" in plugins
    assert "xss" in plugins
