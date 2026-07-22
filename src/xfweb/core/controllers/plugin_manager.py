"""PluginManager — loads, configures, and manages all scanner plugins.

Supports the plugin categories inherited from w3af plus new categories:
- AI-powered plugins
- WebSocket fuzzing
- GraphQL testing
- gRPC testing
- API-specific security testing
"""

from __future__ import annotations

import importlib
import pkgutil
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from xfweb.core.plugins.plugin_base import Plugin
    from xfweb.core.data.kb.knowledge_base import KnowledgeBase

logger = structlog.get_logger()

PLUGIN_PACKAGES = [
    "xfweb.plugins.audit",
    "xfweb.plugins.crawl",
    "xfweb.plugins.grep",
    "xfweb.plugins.infrastructure",
    "xfweb.plugins.evasion",
    "xfweb.plugins.output",
    "xfweb.plugins.attack",
    "xfweb.plugins.bruteforce",
    "xfweb.plugins.auth",
    "xfweb.plugins.mangle",
    "xfweb.plugins.ai",
    "xfweb.plugins.websocket",
    "xfweb.plugins.graphql",
    "xfweb.plugins.grpc",
    "xfweb.plugins.api",
]


class PluginManager:
    """Manages plugin discovery, loading, and lifecycle."""

    def __init__(self) -> None:
        self._plugins: dict[str, Plugin] = {}
        self._plugin_classes: dict[str, type[Plugin]] = {}

    @property
    def loaded_count(self) -> int:
        return len(self._plugins)

    def discover_plugins(self) -> dict[str, type[Plugin]]:
        """Discover all available plugin classes."""
        for package_name in PLUGIN_PACKAGES:
            try:
                package = importlib.import_module(package_name)
                package_path = Path(package.__file__).parent  # type: ignore

                for importer, modname, ispkg in pkgutil.iter_modules([str(package_path)]):
                    if modname.startswith("_"):
                        continue
                    try:
                        module = importlib.import_module(f"{package_name}.{modname}")
                        for attr_name in dir(module):
                            attr = getattr(module, attr_name)
                            if (
                                isinstance(attr, type)
                                and hasattr(attr, "plugin_name")
                                and attr_name != "Plugin"
                                and attr_name != "AuditPlugin"
                                and attr_name != "CrawlPlugin"
                            ):
                                name = getattr(attr, "plugin_name", modname)
                                self._plugin_classes[name] = attr
                    except Exception as exc:
                        logger.warning(
                            "xfweb.plugins.load_failed",
                            module=f"{package_name}.{modname}",
                            error=str(exc),
                        )
            except Exception as exc:
                logger.warning("xfweb.plugins.package_failed", package=package_name, error=str(exc))

        logger.info("xfweb.plugins.discovered", count=len(self._plugin_classes))
        return self._plugin_classes

    def load_plugins(
        self,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
        enable_ai: bool = False,
        kb: KnowledgeBase | None = None,
    ) -> None:
        """Load specified plugins or all if none specified."""
        if not self._plugin_classes:
            self.discover_plugins()

        exclude = exclude or []
        to_load = include or list(self._plugin_classes.keys())

        for name in to_load:
            if name in exclude:
                continue
            if name not in self._plugin_classes:
                logger.warning("xfweb.plugins.not_found", name=name)
                continue

            try:
                plugin_cls = self._plugin_classes[name]
                instance = plugin_cls()
                if kb:
                    instance.set_kb(kb)
                self._plugins[name] = instance
                logger.info("xfweb.plugins.loaded", name=name, category=plugin_cls.category)
            except Exception as exc:
                logger.error("xfweb.plugins.init_failed", name=name, error=str(exc))

        logger.info("xfweb.plugins.loaded_total", count=len(self._plugins))

    def get_plugins_by_category(self, category: str) -> list[Plugin]:
        return [p for p in self._plugins.values() if p.category == category]

    def get_plugin(self, name: str) -> Plugin | None:
        return self._plugins.get(name)

    def get_all(self) -> dict[str, Plugin]:
        return dict(self._plugins)
