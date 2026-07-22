"""SARIF output plugin — generates SARIF reports for GitHub/GitLab Security tabs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import OutputPlugin
from xfweb import __version__

logger = structlog.get_logger()


class SarifOutputPlugin(OutputPlugin):
    """Generate SARIF (Static Analysis Results Interchange Format) reports."""

    plugin_name = "sarif_output"
    brief_description = "Generate SARIF reports compatible with GitHub/GitLab Security tabs"

    async def generate(self, findings: list[dict[str, Any]], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / "results.sarif"

        rules = {}
        results = []

        for f in findings:
            rule_id = f.get("name", "unknown").replace(" ", "_").lower()

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.get("name", "Unknown"),
                    "shortDescription": {"text": f.get("name", "Unknown")},
                    "fullDescription": {"text": f.get("description", "")},
                    "helpUri": f"https://xfweb.readthedocs.io/plugins/{rule_id}",
                    "defaultConfiguration": {
                        "level": self._severity_to_level(f.get("severity", "note"))
                    },
                    "properties": {"tags": ["security", f.get("plugin_name", "")]},
                }

            results.append({
                "ruleId": rule_id,
                "level": self._severity_to_level(f.get("severity", "note")),
                "message": {"text": f.get("description", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("url", "")},
                        "region": {"startLine": 1},
                    }
                }],
                "properties": {
                    "severity": f.get("severity", "note"),
                    "remediation": f.get("remediation", ""),
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Xfweb",
                        "version": __version__,
                        "informationUri": "https://github.com/xfweb/xfweb",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }],
        }

        with open(filepath, "w") as f:
            json.dump(sarif, f, indent=2)

        logger.info("xfweb.output.sarif_generated", path=str(filepath), findings=len(results))
        return filepath

    def _severity_to_level(self, severity: str) -> str:
        return {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "information": "note",
        }.get(severity, "note")
