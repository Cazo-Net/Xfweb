"""Comprehensive tests for Xfweb plugins — audit, crawl, grep, infrastructure, evasion."""

import pytest
from xfweb.core.controllers.plugin_manager import PluginManager
from xfweb.core.plugins.plugin_base import (
    Plugin, AuditPlugin, CrawlPlugin, GrepPlugin,
    InfrastructurePlugin, EvasionPlugin, OutputPlugin,
)


class TestPluginManager:
    def test_discover_plugins_returns_dict(self):
        mgr = PluginManager()
        plugins = mgr.discover_plugins()
        assert isinstance(plugins, dict)

    def test_all_categories_present(self):
        mgr = PluginManager()
        plugins = mgr.discover_plugins()
        expected = ["sqli", "xss", "csrf", "lfi", "rfi", "ssrf",
                    "web_spider", "robots_txt", "sitemap_xml",
                    "csp", "server_header"]
        for name in expected:
            assert name in plugins, f"Missing plugin: {name}"

    def test_plugin_instances_are_correct_type(self):
        mgr = PluginManager()
        plugins = mgr.discover_plugins()
        assert issubclass(plugins["sqli"], AuditPlugin)
        assert issubclass(plugins["web_spider"], CrawlPlugin)
        assert issubclass(plugins["csp"], GrepPlugin)
        assert issubclass(plugins["server_header"], InfrastructurePlugin)

    def test_plugins_have_options(self):
        mgr = PluginManager()
        plugins = mgr.discover_plugins()
        for name, plugin_cls in plugins.items():
            try:
                instance = plugin_cls()
                assert isinstance(instance.options, dict), f"{name} missing options"
            except TypeError:
                pass  # Skip abstract base classes

    def test_set_options(self):
        mgr = PluginManager()
        plugins = mgr.discover_plugins()
        instance = plugins["sqli"]()
        instance.set_options({"max_payloads": 50})
        assert instance.options["max_payloads"] == 50

    def test_category_counts(self):
        mgr = PluginManager()
        plugins = mgr.discover_plugins()
        categories = {}
        for p in plugins.values():
            categories[p.category] = categories.get(p.category, 0) + 1
        assert categories.get("audit", 0) >= 10
        assert categories.get("crawl", 0) >= 6
        assert categories.get("grep", 0) >= 8
        assert categories.get("infrastructure", 0) >= 3
        assert categories.get("evasion", 0) >= 3


class TestAuditPlugins:
    def _get_plugin(self, name):
        mgr = PluginManager()
        return mgr.discover_plugins()[name]

    def test_sqli_properties(self):
        p = self._get_plugin("sqli")
        assert p.plugin_name == "sqli"
        assert p.category == "audit"
        assert "sql" in p.brief_description.lower()

    def test_xss_properties(self):
        p = self._get_plugin("xss")
        assert p.plugin_name == "xss"
        assert p.category == "audit"

    def test_csrf_properties(self):
        p = self._get_plugin("csrf")
        assert p.plugin_name == "csrf"

    def test_lfi_properties(self):
        p = self._get_plugin("lfi")
        assert p.plugin_name == "lfi"
        assert "local file" in p.brief_description.lower()

    def test_ssrf_properties(self):
        p = self._get_plugin("ssrf")
        assert p.plugin_name == "ssrf"

    def test_xxe_properties(self):
        p = self._get_plugin("xxe")
        assert p.plugin_name == "xxe"

    def test_os_commanding_properties(self):
        p = self._get_plugin("os_commanding")
        assert p.plugin_name == "os_commanding"

    def test_eval_properties(self):
        p = self._get_plugin("eval")
        assert p.plugin_name == "eval"


class TestCrawlPlugins:
    def _get_plugin(self, name):
        mgr = PluginManager()
        return mgr.discover_plugins()[name]

    def test_web_spider_properties(self):
        p = self._get_plugin("web_spider")
        assert p.category == "crawl"
        assert "spider" in p.plugin_name

    def test_robots_txt(self):
        p = self._get_plugin("robots_txt")
        assert p.category == "crawl"

    def test_sitemap_xml(self):
        p = self._get_plugin("sitemap_xml")
        assert p.category == "crawl"


class TestGrepPlugins:
    def _get_plugin(self, name):
        mgr = PluginManager()
        return mgr.discover_plugins()[name]

    def test_csp(self):
        p = self._get_plugin("csp")
        assert p.category == "grep"
        assert "csp" in p.brief_description.lower()

    def test_credit_cards(self):
        p = self._get_plugin("credit_cards")
        assert p.category == "grep"

    def test_private_ip(self):
        p = self._get_plugin("private_ip")
        assert p.category == "grep"


class TestInfrastructurePlugins:
    def _get_plugin(self, name):
        mgr = PluginManager()
        return mgr.discover_plugins()[name]

    def test_server_header(self):
        p = self._get_plugin("server_header")
        assert p.category == "infrastructure"

    def test_fingerprint_os(self):
        p = self._get_plugin("fingerprint_os")
        assert p.category == "infrastructure"

    def test_fingerprint_waf(self):
        p = self._get_plugin("fingerprint_waf")
        assert p.category == "infrastructure"


class TestEvasionPlugins:
    def _get_plugin(self, name):
        mgr = PluginManager()
        return mgr.discover_plugins()[name]

    def test_rnd_case(self):
        p = self._get_plugin("rnd_case")
        assert p.category == "evasion"
        assert hasattr(p, "modify_request")

    def test_x_forwarded_for(self):
        p = self._get_plugin("x_forwarded_for")
        assert p.category == "evasion"


class TestOutputPlugins:
    def _get_plugin_class(self, name):
        mgr = PluginManager()
        return mgr.discover_plugins()[name]

    def test_sarif_output(self):
        cls = self._get_plugin_class("sarif_output")
        p = cls()
        assert p.category == "output"

    def test_json_output(self):
        cls = self._get_plugin_class("json_output")
        p = cls()
        assert p.category == "output"

    def test_html_output(self):
        cls = self._get_plugin_class("html_output")
        p = cls()
        assert p.category == "output"
