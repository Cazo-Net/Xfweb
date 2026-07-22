"""Plugin base classes for all Xfweb scanner plugins.

Hierarchy:
  Plugin
    ├── AuditPlugin       — active vulnerability detection
    ├── CrawlPlugin       — URL/endpoint discovery
    ├── GrepPlugin        — passive response analysis
    ├── InfrastructurePlugin — server fingerprinting
    ├── EvasionPlugin     — WAF/IDS bypass
    ├── AuthPlugin        — session/authentication management
    ├── BruteforcePlugin  — credential brute-forcing
    ├── AttackPlugin      — post-scan exploitation
    ├── OutputPlugin      — report generation
    ├── ManglePlugin      — request/response transformation
    ├── WebSocketPlugin   — WebSocket protocol testing
    ├── GraphQLPlugin     — GraphQL-specific testing
    ├── GrpcPlugin        — gRPC-specific testing
    ├── ApiPlugin         — REST/API-specific testing
    └── AiPlugin          — AI-powered detection
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from xfweb.core.net.http_engine import HttpEngine, HttpResponse
    from xfweb.core.data.url.fuzzable_request import FuzzableRequest
    from xfweb.core.data.kb.knowledge_base import KnowledgeBase, Finding

logger = structlog.get_logger()


class Plugin(ABC):
    """Base class for all Xfweb plugins."""

    plugin_name: str = "base"
    category: str = "unknown"
    brief_description: str = ""

    def __init__(self) -> None:
        self.options: dict[str, Any] = {}
        self.kb: KnowledgeBase | None = None

    @abstractmethod
    async def run(self, target: Any, http: HttpEngine) -> Any:
        """Execute the plugin's main logic."""

    def get_options(self) -> dict[str, Any]:
        return self.options

    def set_options(self, options: dict[str, Any]) -> None:
        self.options.update(options)

    def set_kb(self, kb: KnowledgeBase) -> None:
        self.kb = kb

    def report_finding(
        self,
        name: str,
        severity: str,
        url: str,
        description: str,
        parameter: str = "",
        evidence: str = "",
        http_request: dict[str, Any] | None = None,
        http_response: dict[str, Any] | None = None,
        remediation: str = "",
    ) -> None:
        """Report a finding to the knowledge base."""
        if not self.kb:
            return

        from xfweb.core.data.kb.knowledge_base import Finding, Severity

        severity_map = {
            "information": Severity.INFORMATION,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        sev = severity_map.get(severity.lower(), Severity.MEDIUM)

        finding = Finding(
            name=name,
            severity=sev,
            description=description,
            url=url,
            parameter=parameter,
            plugin_name=self.plugin_name,
            evidence=evidence,
            http_request=http_request or {},
            http_response=http_response or {},
            remediation=remediation,
        )

        location = f"{self.plugin_name}:{url}"
        added = self.kb.append_uniq(location, finding)
        if added:
            logger.warning(
                "xfweb.finding.new",
                plugin=self.plugin_name,
                name=name,
                severity=severity,
                url=url,
                param=parameter,
            )


class AuditPlugin(Plugin):
    """Active vulnerability detection plugin."""

    category = "audit"

    @abstractmethod
    async def audit(self, freq: FuzzableRequest, http: HttpEngine) -> None:
        """Test a single fuzzable request for vulnerabilities."""

    async def run(self, target: FuzzableRequest, http: HttpEngine) -> None:
        await self.audit(target, http)


class CrawlPlugin(Plugin):
    """URL/endpoint discovery plugin."""

    category = "crawl"

    @abstractmethod
    async def crawl(self, freq: FuzzableRequest, http: HttpEngine) -> list[FuzzableRequest]:
        """Discover new endpoints from a fuzzable request."""

    async def run(self, target: FuzzableRequest, http: HttpEngine) -> list[FuzzableRequest]:
        return await self.crawl(target, http)


class GrepPlugin(Plugin):
    """Passive response analysis plugin."""

    category = "grep"

    @abstractmethod
    async def grep(self, freq: FuzzableRequest, http: HttpEngine) -> None:
        """Analyze a response for patterns."""

    async def run(self, target: Any, http: HttpEngine) -> None:
        await self.grep(target, http)


class InfrastructurePlugin(Plugin):
    """Server fingerprinting and configuration analysis plugin."""

    category = "infrastructure"

    @abstractmethod
    async def discover(self, freq: FuzzableRequest, http: HttpEngine) -> None:
        """Fingerprint server infrastructure."""

    async def run(self, target: FuzzableRequest, http: HttpEngine) -> list:
        await self.discover(target, http)
        return []


class EvasionPlugin(Plugin):
    """WAF/IDS bypass technique plugin."""

    category = "evasion"

    @abstractmethod
    def modify_request(self, request: Any) -> Any:
        """Modify a request to evade detection."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return self.modify_request(target)


class AuthPlugin(Plugin):
    """Authentication session management plugin."""

    category = "auth"

    @abstractmethod
    async def login(self, http: HttpEngine) -> bool:
        """Attempt to log in and establish a session."""

    @abstractmethod
    async def logout(self, http: HttpEngine) -> None:
        """Log out and invalidate the session."""

    @abstractmethod
    async def has_active_session(self, http: HttpEngine) -> bool:
        """Check if we have an active authenticated session."""

    async def run(self, target: Any, http: HttpEngine) -> bool:
        return await self.login(http)


class BruteforcePlugin(Plugin):
    """Credential brute-forcing plugin."""

    category = "bruteforce"

    @abstractmethod
    async def audit(self, freq: FuzzableRequest, http: HttpEngine) -> None:
        """Brute-force credentials against an authentication endpoint."""

    async def run(self, target: FuzzableRequest, http: HttpEngine) -> None:
        await self.audit(target, http)


class AttackPlugin(Plugin):
    """Post-scan exploitation plugin."""

    category = "attack"

    @abstractmethod
    async def exploit(self, vuln: dict[str, Any], http: HttpEngine) -> dict[str, Any] | None:
        """Attempt to exploit a confirmed vulnerability."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return await self.exploit(target, http)


class OutputPlugin(Plugin):
    """Report generation plugin."""

    category = "output"

    @abstractmethod
    async def generate(self, findings: list[dict[str, Any]], output_dir: Any) -> Any:
        """Generate a report from scan findings."""

    async def run(self, target: Any, http: HttpEngine) -> None:
        pass


class ManglePlugin(Plugin):
    """Request/response transformation plugin."""

    category = "mangle"

    @abstractmethod
    def transform_request(self, request: Any) -> Any:
        """Transform a request before sending."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return self.transform_request(target)


class WebSocketPlugin(Plugin):
    """WebSocket protocol testing plugin."""

    category = "websocket"

    @abstractmethod
    async def test_websocket(self, url: str, http: HttpEngine) -> list[dict[str, Any]]:
        """Test a WebSocket endpoint for vulnerabilities."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return await self.test_websocket(target, http)


class GraphQLPlugin(Plugin):
    """GraphQL-specific security testing plugin."""

    category = "graphql"

    @abstractmethod
    async def test_graphql(self, url: str, http: HttpEngine) -> list[dict[str, Any]]:
        """Test a GraphQL endpoint for vulnerabilities."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return await self.test_graphql(target, http)


class GrpcPlugin(Plugin):
    """gRPC-specific security testing plugin."""

    category = "grpc"

    @abstractmethod
    async def test_grpc(self, target: str, http: HttpEngine) -> list[dict[str, Any]]:
        """Test a gRPC endpoint for vulnerabilities."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return await self.test_grpc(target, http)


class ApiPlugin(Plugin):
    """REST/API-specific security testing plugin."""

    category = "api"

    @abstractmethod
    async def test_api(self, endpoint: str, http: HttpEngine) -> list[dict[str, Any]]:
        """Test an API endpoint for vulnerabilities."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return await self.test_api(target, http)


class AiPlugin(Plugin):
    """AI-powered detection and payload generation plugin."""

    category = "ai"

    @abstractmethod
    async def analyze(self, context: dict[str, Any], http: HttpEngine) -> dict[str, Any]:
        """Use AI to analyze findings and generate insights."""

    async def run(self, target: Any, http: HttpEngine) -> Any:
        return await self.analyze(target, http)
