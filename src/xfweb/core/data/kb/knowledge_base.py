"""KnowledgeBase — central in-memory store for all scan findings.

Thread-safe, supports deduplication, and provides query/filter capabilities.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(Enum):
    INFORMATION = "information"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    name: str
    severity: Severity
    description: str
    url: str
    parameter: str = ""
    plugin_name: str = ""
    evidence: str = ""
    http_request: dict[str, Any] = field(default_factory=dict)
    http_response: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    MAX_BODY_LEN = 2048

    def to_dict(self) -> dict[str, Any]:
        resp = self.http_response.copy() if self.http_response else {}
        if "body_excerpt" in resp and len(resp["body_excerpt"]) > self.MAX_BODY_LEN:
            resp["body_excerpt"] = resp["body_excerpt"][: self.MAX_BODY_LEN] + "... [truncated]"
        return {
            "name": self.name,
            "severity": self.severity.value,
            "description": self.description,
            "url": self.url,
            "parameter": self.parameter,
            "plugin_name": self.plugin_name,
            "evidence": self.evidence[: self.MAX_BODY_LEN] if len(self.evidence) > self.MAX_BODY_LEN else self.evidence,
            "http_request": self.http_request,
            "http_response": resp,
            "remediation": self.remediation,
        }


class KnowledgeBase:
    """Central store for all scan findings."""

    def __init__(self, max_responses: int = 5000) -> None:
        self._lock = threading.RLock()
        self._findings: dict[str, list[Finding]] = {}
        self._responses: list[Any] = []
        self._fuzzable_requests: list[Any] = []
        self._max_responses = max_responses

    def __len__(self) -> int:
        with self._lock:
            return sum(len(v) for v in self._findings.values())

    def append(self, location: str, finding: Finding) -> None:
        with self._lock:
            if location not in self._findings:
                self._findings[location] = []
            self._findings[location].append(finding)

    def append_uniq(self, location: str, finding: Finding) -> bool:
        """Append only if no similar finding exists. Returns True if appended."""
        with self._lock:
            if location not in self._findings:
                self._findings[location] = []
            for existing in self._findings[location]:
                if existing.name == finding.name and existing.parameter == finding.parameter:
                    return False
            self._findings[location].append(finding)
            return True

    def store_response(self, response: Any) -> None:
        with self._lock:
            if self._max_responses > 0 and len(self._responses) >= self._max_responses:
                return
            self._responses.append(response)

    def store_fuzzable_request(self, freq: Any) -> None:
        with self._lock:
            self._fuzzable_requests.append(freq)

    def get_all_responses(self) -> list[Any]:
        with self._lock:
            return list(self._responses)

    def get_all_fuzzable_requests(self) -> list[Any]:
        with self._lock:
            return list(self._fuzzable_requests)

    def get_findings(self, location: str | None = None, severity: Severity | None = None) -> list[Finding]:
        with self._lock:
            if location:
                findings = self._findings.get(location, [])
            else:
                findings = [f for fs in self._findings.values() for f in fs]
            if severity:
                findings = [f for f in findings if f.severity == severity]
            return findings

    def to_dicts(self) -> list[dict[str, Any]]:
        with self._lock:
            return [f.to_dict() for fs in self._findings.values() for f in fs]

    def get_summary(self) -> dict[str, int]:
        with self._lock:
            summary = {s.value: 0 for s in Severity}
            for findings in self._findings.values():
                for f in findings:
                    summary[f.severity.value] += 1
            summary["total"] = sum(v for k, v in summary.items() if k != "total")
            return summary
