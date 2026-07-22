"""HTML report output plugin — professional pentest report format."""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from xfweb.core.plugins.plugin_base import OutputPlugin
from xfweb import __version__

logger = structlog.get_logger()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Xfweb Security Report</title>
    <style>
        :root {{
            --bg: #0d1117; --surface: #161b22; --border: #30363d;
            --text: #c9d1d9; --text-muted: #8b949e;
            --critical: #ff4444; --high: #ff6b35; --medium: #f0ad4e;
            --low: #5cb85c; --info: #5bc0de;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; background: var(--bg); color: var(--text); line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        header {{ border-bottom: 2px solid var(--critical); padding-bottom: 20px; margin-bottom: 30px; }}
        h1 {{ color: var(--critical); font-size: 28px; font-weight: 700; }}
        .meta {{ color: var(--text-muted); margin-top: 8px; font-size: 14px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin: 30px 0; }}
        .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
        .card .count {{ font-size: 36px; font-weight: 700; }}
        .card .label {{ color: var(--text-muted); font-size: 13px; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}
        .critical {{ color: var(--critical); }} .high {{ color: var(--high); }}
        .medium {{ color: var(--medium); }} .low {{ color: var(--low); }} .info {{ color: var(--info); }}
        .finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; margin: 16px 0; overflow: hidden; }}
        .finding-header {{ padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }}
        .finding-header h3 {{ font-size: 16px; flex: 1; }}
        .badge {{ padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
        .badge-critical {{ background: var(--critical); color: #fff; }}
        .badge-high {{ background: var(--high); color: #fff; }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); color: #000; }}
        .badge-info {{ background: var(--info); color: #000; }}
        .finding-body {{ padding: 20px; }}
        .finding-body p {{ margin: 8px 0; }}
        .detail-label {{ color: var(--text-muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
        .evidence {{ background: #0d1117; border: 1px solid var(--border); border-radius: 4px; padding: 12px; margin: 12px 0; font-family: 'Fira Code', monospace; font-size: 13px; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }}
        .remediation {{ border-left: 3px solid var(--low); padding-left: 12px; margin: 12px 0; color: var(--low); }}
        a {{ color: var(--info); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .stats-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        .stats-table th, .stats-table td {{ padding: 10px 16px; text-align: left; border-bottom: 1px solid var(--border); }}
        .stats-table th {{ background: var(--surface); color: var(--info); font-size: 12px; text-transform: uppercase; }}
        footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 12px; text-align: center; }}
        @media print {{
            body {{ background: #fff; color: #000; }}
            .card {{ border: 1px solid #ccc; }}
            .finding {{ border: 1px solid #ccc; }}
            .evidence {{ background: #f5f5f5; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>XFWEB SECURITY REPORT</h1>
            <div class="meta">
                Generated: {timestamp} | Target: {target} | Version: {version}
            </div>
        </header>

        <div class="summary">
            <div class="card"><div class="count">{total}</div><div class="label">Total</div></div>
            <div class="card"><div class="count critical">{critical}</div><div class="label">Critical</div></div>
            <div class="card"><div class="count high">{high}</div><div class="label">High</div></div>
            <div class="card"><div class="count medium">{medium}</div><div class="label">Medium</div></div>
            <div class="card"><div class="count low">{low}</div><div class="label">Low</div></div>
            <div class="card"><div class="count info">{info}</div><div class="label">Info</div></div>
        </div>

        <h2 style="color: var(--info); margin: 30px 0 16px;">Findings</h2>
        {findings_html}

        {stats_html}

        <footer>
            Xfweb v{version} — The Beast — Web Application Security Scanner
        </footer>
    </div>
</body>
</html>"""

FINDING_TEMPLATE = """
        <div class="finding">
            <div class="finding-header">
                <span class="badge badge-{severity}">{severity}</span>
                <h3>{name}</h3>
            </div>
            <div class="finding-body">
                <p><span class="detail-label">URL:</span> <a href="{url}">{url}</a></p>
                {parameter_html}
                <p><span class="detail-label">Plugin:</span> {plugin}</p>
                <p>{description}</p>
                {evidence_html}
                {remediation_html}
            </div>
        </div>"""


class HtmlOutputPlugin(OutputPlugin):
    """Generate professional pentest-style HTML report."""

    plugin_name = "html_output"
    brief_description = "Generate professional HTML security report"

    async def generate(self, findings: list[dict[str, Any]], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        filepath = output_dir / "report.html"

        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "information": 0}
        findings_html_parts: list[str] = []

        for f in findings:
            sev = f.get("severity", "information")
            counts[sev] = counts.get(sev, 0) + 1

            param_html = ""
            if f.get("parameter"):
                param_html = f'<p><span class="detail-label">Parameter:</span> <code>{html.escape(f["parameter"])}</code></p>'

            evidence_html = ""
            if f.get("evidence"):
                evidence_html = f'<p><span class="detail-label">Evidence:</span></p><div class="evidence">{html.escape(f["evidence"])}</div>'

            remediation_html = ""
            if f.get("remediation"):
                remediation_html = f'<div class="remediation"><strong>Remediation:</strong> {html.escape(f["remediation"])}</div>'

            findings_html_parts.append(FINDING_TEMPLATE.format(
                severity=sev,
                name=html.escape(f.get("name", "Unknown")),
                url=html.escape(f.get("url", "#")),
                parameter_html=param_html,
                plugin=html.escape(f.get("plugin_name", "N/A")),
                description=html.escape(f.get("description", "")),
                evidence_html=evidence_html,
                remediation_html=remediation_html,
            ))

        stats_html = ""
        if findings:
            stats_html = '<h2 style="color: var(--info); margin: 30px 0 16px;">Statistics</h2>'
            stats_html += '<table class="stats-table"><tr><th>Metric</th><th>Value</th></tr>'
            stats_html += f'<tr><td>Total Findings</td><td>{len(findings)}</td></tr>'
            stats_html += f'<tr><td>Critical</td><td class="critical">{counts["critical"]}</td></tr>'
            stats_html += f'<tr><td>High</td><td class="high">{counts["high"]}</td></tr>'
            stats_html += f'<tr><td>Medium</td><td class="medium">{counts["medium"]}</td></tr>'
            stats_html += f'<tr><td>Low</td><td class="low">{counts["low"]}</td></tr>'
            stats_html += '</table>'

        html_content = HTML_TEMPLATE.format(
            version=__version__,
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            target=findings[0].get("url", "N/A") if findings else "N/A",
            total=len(findings),
            critical=counts["critical"],
            high=counts["high"],
            medium=counts["medium"],
            low=counts["low"],
            info=counts["information"],
            findings_html="\n".join(findings_html_parts),
            stats_html=stats_html,
        )

        with open(filepath, "w") as f:
            f.write(html_content)

        logger.info("xfweb.output.html_generated", path=str(filepath), findings=len(findings))
        return filepath
