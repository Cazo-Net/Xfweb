"""HTML report output plugin."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import OutputPlugin
from xfweb import __version__

logger = structlog.get_logger()

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>Xfweb Scan Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 40px; background: #0d1117; color: #c9d1d9; }}
        h1 {{ color: #ff4444; border-bottom: 2px solid #ff4444; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat {{ background: #161b22; padding: 15px 25px; border-radius: 8px; border: 1px solid #30363d; }}
        .stat h3 {{ margin: 0; font-size: 24px; }}
        .stat p {{ margin: 5px 0 0 0; color: #8b949e; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 10px 15px; text-align: left; border-bottom: 1px solid #30363d; }}
        th {{ background: #161b22; color: #ff4444; }}
        .critical {{ color: #ff4444; font-weight: bold; }}
        .high {{ color: #ff6b35; font-weight: bold; }}
        .medium {{ color: #f0ad4e; font-weight: bold; }}
        .low {{ color: #5cb85c; }}
        .info {{ color: #5bc0de; }}
        a {{ color: #58a6ff; }}
    </style>
</head>
<body>
    <h1>Xfweb Scan Report v{version}</h1>
    <div class="summary">
        <div class="stat"><h3>{total}</h3><p>Total Findings</p></div>
        <div class="stat"><h3 class="critical">{critical}</h3><p>Critical</p></div>
        <div class="stat"><h3 class="high">{high}</h3><p>High</p></div>
        <div class="stat"><h3 class="medium">{medium}</h3><p>Medium</p></div>
        <div class="stat"><h3 class="low">{low}</h3><p>Low</p></div>
    </div>
    <table>
        <tr><th>Severity</th><th>Finding</th><th>URL</th><th>Plugin</th><th>Description</th></tr>
        {rows}
    </table>
</body>
</html>"""


class HtmlOutputPlugin(OutputPlugin):
    """Generate HTML report from scan findings."""

    plugin_name = "html_output"
    brief_description = "Generate styled HTML report"

    async def generate(self, findings: list[dict[str, Any]], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / "report.html"

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "information": 0}
        rows = []

        for f in findings:
            sev = f.get("severity", "information")
            counts[sev] = counts.get(sev, 0) + 1

            rows.append(
                f'<tr><td class="{sev}">{sev.upper()}</td>'
                f'<td>{f.get("name", "Unknown")}</td>'
                f'<td><a href="{f.get("url", "#")}">{f.get("url", "N/A")}</a></td>'
                f'<td>{f.get("plugin_name", "N/A")}</td>'
                f'<td>{f.get("description", "")}</td></tr>'
            )

        html = HTML_TEMPLATE.format(
            version=__version__,
            total=len(findings),
            critical=counts.get("critical", 0),
            high=counts.get("high", 0),
            medium=counts.get("medium", 0),
            low=counts.get("low", 0),
            rows="\n".join(rows),
        )

        with open(filepath, "w") as f:
            f.write(html)

        logger.info("xfweb.output.html_generated", path=str(filepath))
        return filepath
