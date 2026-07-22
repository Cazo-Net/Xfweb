"""SQL Injection audit plugin — detects SQL injection vulnerabilities.

Detects error-based, boolean-based, and time-based SQL injection across
multiple database backends (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).

Inherited from w3af's sqli.py, modernized with async httpx and enhanced
payload sets.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine

logger = structlog.get_logger()

SQLI_PAYLOADS = {
    "error": [
        "'",
        "''",
        '"',
        "\\",  # noqa: W605
        "' OR '1'='1",
        "' OR '1'='1'--",
        "' OR '1'='1'/*",
        "1' OR '1'='1",
        "1; SELECT 1",
        "')) OR 1=1--",
        "1 AND 1=1",
        "1 AND 1=2",
        "' AND '1'='1",
        "' AND '1'='2",
        "1' AND '1'='2",
        "1' ORDER BY 100--",
        "' UNION SELECT NULL--",
        "1' UNION SELECT NULL--",
    ],
    "time": [
        "' OR SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR pg_sleep(5)--",
        "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "'; SELECT pg_sleep(5);--",
    ],
    "boolean_true": [
        "' OR 1=1--",
        "' OR 'a'='a",
        "1' OR 1=1#",
        "') OR (1=1",
    ],
    "boolean_false": [
        "' OR 1=2--",
        "' OR 'a'='b",
        "1' OR 1=2#",
        "') OR (1=2",
    ],
}

SQLI_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "ORA-01756",
    "Microsoft OLE DB",
    "ODBC SQL Server",
    "PostgreSQL",
    "pg_query",
    "SQLite/JDBCDriver",
    "SQLite::prepare",
    "Warning: mysql",
    "valid MySQL result",
    "Unclosed quotation mark",
    "unterminated quoted string",
    "SQLSTATE",
    "syntax error at or near",
    "near \".*?\".*?:.*syntax",
    "You have an error in your SQL",
    "The error occurred in",
    "Query failed",
    "Database error",
]


class SqliPlugin(AuditPlugin):
    """SQL Injection vulnerability detector."""

    plugin_name = "sqli"
    brief_description = "Detect SQL injection vulnerabilities"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        """Test for SQL injection in all parameters of a fuzzable request."""
        params = self._extract_params(freq)
        if not params:
            return

        tasks = []
        for param_name, param_value in params.items():
            tasks.append(self._test_param(freq, param_name, param_value, http))

        await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        """Extract injectable parameters from a fuzzable request."""
        params: dict[str, str] = {}

        if freq.post_data:
            if isinstance(freq.post_data, str):
                for pair in freq.post_data.split("&"):
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        params[k] = v

        if freq.url.query:
            for pair in freq.url.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    params[k] = v

        return params

    async def _test_param(
        self, freq: Any, param_name: str, param_value: str, http: HttpEngine
    ) -> None:
        """Test a single parameter for SQL injection."""
        logger.debug("xfweb.sqli.testing", param=param_name)

        baseline_resp = await http.get(freq.url.raw_url)
        baseline_len = len(baseline_resp.body)

        for payload_type, payloads in SQLI_PAYLOADS.items():
            for payload in payloads:
                modified_value = param_value + payload
                modified_url = freq.url.raw_url.replace(
                    f"{param_name}={param_value}",
                    f"{param_name}={modified_value}",
                )

                resp = await http.get(modified_url)

                if payload_type == "error":
                    if self._check_error_response(resp):
                        self._report_finding(freq, param_name, payload, "error-based", resp)
                        return

                elif payload_type == "time":
                    if resp.elapsed_ms >= 4500:
                        self._report_finding(freq, param_name, payload, "time-based", resp)
                        return

                elif payload_type == "boolean_true":
                    true_len = len(resp.body)

                elif payload_type == "boolean_false":
                    false_len = len(resp.body)
                    if abs(true_len - false_len) > 10 and true_len != baseline_len:
                        self._report_finding(freq, param_name, payload, "boolean-based", resp)
                        return

    def _check_error_response(self, resp: Any) -> bool:
        """Check if the response contains SQL error messages."""
        body_lower = resp.text.lower()
        return any(pattern.lower() in body_lower for pattern in SQLI_ERROR_PATTERNS)

    def _report_finding(
        self, freq: Any, param: str, payload: str, sqli_type: str, resp: Any
    ) -> None:
        logger.warning(
            "xfweb.sqli.vuln_found",
            url=freq.url.raw_url,
            param=param,
            type=sqli_type,
            payload=payload,
        )
