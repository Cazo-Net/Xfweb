"""GraphQL security plugin — introspection, query fuzzing, IDOR, batching attacks."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import GraphQLPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

INTROSPECTION_QUERY = """
query IntrospectionQuery {
    __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
            name
            kind
            fields {
                name
                type { name kind }
                args { name type { name } }
            }
        }
    }
}
"""


class GraphQLIntrospectionPlugin(GraphQLPlugin):
    """Test for GraphQL introspection exposure."""

    plugin_name = "graphql_introspection"
    brief_description = "Detect exposed GraphQL introspection and schema leakage"

    async def test_graphql(self, url: str, http: HttpEngine) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        resp = await http.post(
            url,
            json={"query": INTROSPECTION_QUERY},
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code == 200 and "__schema" in resp.text:
            findings.append({
                "name": "GraphQL Introspection Enabled",
                "severity": "medium",
                "description": "GraphQL introspection is enabled, exposing the full API schema to attackers.",
                "url": url,
                "remediation": "Disable introspection in production.",
            })

        return findings


class GraphQLBatchingPlugin(GraphQLPlugin):
    """Test for GraphQL query batching attacks."""

    plugin_name = "graphql_batching"
    brief_description = "Test for query batching and alias-based rate limit bypass"

    async def test_graphql(self, url: str, http: HttpEngine) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        batch = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]

        resp = await http.post(url, json=batch, headers={"Content-Type": "application/json"})

        if resp.status_code == 200:
            try:
                data = resp.json
                if isinstance(data, list) and len(data) == 3:
                    findings.append({
                        "name": "GraphQL Query Batching Allowed",
                        "severity": "medium",
                        "description": "The GraphQL endpoint accepts batched queries, which can be used to bypass rate limiting.",
                        "url": url,
                        "remediation": "Disable query batching or enforce per-query rate limits.",
                    })
            except Exception:
                pass

        return findings


class GraphQLDepthPlugin(GraphQLPlugin):
    """Test for GraphQL query depth attacks (DoS)."""

    plugin_name = "graphql_depth"
    brief_description = "Test for deep nested query DoS"

    async def test_graphql(self, url: str, http: HttpEngine) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        deep_query = "{ " + "a { " * 20 + "__typename" + " }" * 20 + " }"
        resp = await http.post(
            url,
            json={"query": deep_query},
            headers={"Content-Type": "application/json"},
        )

        if resp.status_code == 200 and "__typename" in resp.text:
            findings.append({
                "name": "GraphQL No Depth Limit",
                "severity": "medium",
                "description": "The GraphQL endpoint accepts deeply nested queries, enabling DoS attacks.",
                "url": url,
                "remediation": "Implement query depth limiting (recommended: max depth 10).",
            })

        return findings
