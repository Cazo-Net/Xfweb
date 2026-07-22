"""JSON output plugin."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import OutputPlugin

logger = structlog.get_logger()


class JsonOutputPlugin(OutputPlugin):
    """Generate JSON report from scan findings."""

    plugin_name = "json_output"
    brief_description = "Generate JSON report"

    async def generate(self, findings: list[dict[str, Any]], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / "results.json"

        with open(filepath, "w") as f:
            json.dump({"findings": findings}, f, indent=2)

        logger.info("xfweb.output.json_generated", path=str(filepath), count=len(findings))
        return filepath
