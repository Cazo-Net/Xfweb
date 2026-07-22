"""CSV output plugin."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import OutputPlugin

logger = structlog.get_logger()


class CsvOutputPlugin(OutputPlugin):
    """Generate CSV report from scan findings."""

    plugin_name = "csv_output"
    brief_description = "Generate CSV report"

    async def generate(self, findings: list[dict[str, Any]], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / "results.csv"

        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=["severity", "name", "url", "parameter", "plugin_name", "description", "remediation"],
            )
            writer.writeheader()
            for finding in findings:
                writer.writerow({
                    "severity": finding.get("severity", ""),
                    "name": finding.get("name", ""),
                    "url": finding.get("url", ""),
                    "parameter": finding.get("parameter", ""),
                    "plugin_name": finding.get("plugin_name", ""),
                    "description": finding.get("description", ""),
                    "remediation": finding.get("remediation", ""),
                })

        logger.info("xfweb.output.csv_generated", path=str(filepath))
        return filepath
