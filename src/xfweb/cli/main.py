"""Xfweb CLI — the main command-line interface.

Usage:
    xfweb scan --target https://example.com
    xfweb scan --target https://example.com --profile full_audit
    xfweb scan --target https://example.com --plugins sqli,xss
    xfweb serve --port 8080
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

import click
import structlog
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TimeElapsedColumn,
    MofNCompleteColumn,
)

from xfweb import __version__, __app_name__

console = Console()
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
)

# ── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║      ███████╗██╗  ██╗██╗   ██╗████████╗██████╗  ██████╗ ██╗   ██╗██╗███████╗║
║      ██╔════╝╚██╗██╔╝██║   ██║╚══██╔══╝██╔══██╗██╔═══██╗██║   ██║██║██╔════╝║
║      █████╗   ╚███╔╝ ██║   ██║   ██║   ██████╔╝██║   ██║██║   ██║██║███████╗║
║      ██╔══╝   ██╔██╗ ██║   ██║   ██║   ██╔══██╗██║   ██║╚██╗ ██╔╝██║╚════██║║
║      ███████╗██╔╝ ██╗╚██████╔╝   ██║   ██║  ██║╚██████╔╝ ╚████╔╝ ██║███████║║
║      ╚══════╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝ ╚═════╝   ╚═══╝  ╚═╝╚══════╝║
║                                                                              ║
║                          ██╗  ██╗ ██████╗ ███████╗ █████╗ ███╗   ██╗         ║
║                          ██║  ██║██╔═══██╗██╔════╝██╔══██╗████╗  ██║         ║
║                          ███████║██║   ██║███████╗███████║██╔██╗ ██║         ║
║                          ██╔══██║██║   ██║╚════██║██╔══██║██║╚██╗██║         ║
║                          ██║  ██║╚██████╔╝███████║██║  ██║██║ ╚████║         ║
║                          ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝         ║
║                                                                              ║
║                    [bold white]v{version}[/]  ─  The Beast[/]                            ║
║              [dim]Next-Gen Web Application Security Scanner[/]                    ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

SLIM_BANNER = r"""
[bold red]   ╔╦╗╔═╗╔╦╗╦═╗╦╔═╗  ╦═╗╔═╗╔╗ ╔═╗╦    ╔═╗╔═╗╔═╗╔╗╔[/]
[bold red]    ║ ║╣  ║ ╠╦╝║╠═╣  ╠╦╝║╣ ╠╩╗║ ║║    ║ ╦╠═╣╚═╗║║║[/]
[bold red]    ╩ ╚═╝ ╩ ╩╚═╩╩ ╩  ╩╚═╚═╝╚═╝╚═╝╩═╝  ╚═╝╩ ╩╚═╝╝╚╝[/]
[dim]       v{version} ─ The Beast ─ Web Security Scanner[/]
"""


def _print_banner() -> None:
    """Print the scanner banner."""
    version_str = __version__
    try:
        console.print(BANNER.format(version=version_str))
    except Exception:
        console.print(SLIM_BANNER.format(version=version_str))
    console.print()


def _print_target_info(target: str, profile: str | None, plugins: str | None, ai: bool) -> None:
    """Print target reconnaissance info like nmap does."""
    console.print(f"  [bold cyan]TARGET[/]    {target}")
    console.print(f"  [bold cyan]PROFILE[/]   {profile or 'default'}")
    console.print(f"  [bold cyan]PLUGINS[/]   {plugins or 'all'}")
    console.print(f"  [bold cyan]AI[/]        {'[bold green]ENABLED[/]' if ai else '[dim]disabled[/]'}")
    console.print()


# ── Scan progress ───────────────────────────────────────────────────────────

def _make_progress() -> Progress:
    """Create a professional progress bar."""
    return Progress(
        SpinnerColumn("dots", style="bold red"),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(
            bar_width=40,
            complete_style="bold green",
            finished_style="bold green",
            pulse_style="bold red",
        ),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    )


# ── Results ─────────────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "critical": ("bold white on red", "████"),
    "high":     ("bold red",         "▓▓▓▓"),
    "medium":   ("bold yellow",      "▒▒▒▒"),
    "low":      ("bold green",       "░░░░"),
    "information": ("bold cyan",     "····"),
}

SEVERITY_ICON = {
    "critical": "██",
    "high":     "▓▓",
    "medium":   "▒▒",
    "low":      "░░",
    "information": "··",
}


def _print_results(findings: list[dict[str, Any]], stats: dict[str, Any], output: str, fmt: str) -> None:
    """Print scan results with professional pentester formatting."""
    console.print()

    # ── Summary banner ──────────────────────────────────────────────────
    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "information")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    total = len(findings)

    console.print("[bold red]═══════════════════════════════════════════════════════════════════[/]")
    console.print("[bold white]                          SCAN COMPLETE                            [/]")
    console.print("[bold red]═══════════════════════════════════════════════════════════════════[/]")
    console.print()

    # ── Severity summary ────────────────────────────────────────────────
    sev_order = ["critical", "high", "medium", "low", "information"]
    summary_parts = []
    for sev in sev_order:
        count = severity_counts.get(sev, 0)
        style, icon = SEVERITY_STYLE[sev]
        summary_parts.append(f"  [{style}]{icon} {sev.upper():>12} {count:>4}[/]")

    console.print("[bold white]  ┌─────────────────────────────────────────────────────┐[/]")
    console.print("[bold white]  │              V U L N E R A B I L I T I E S          │[/]")
    console.print("[bold white]  ├─────────────────────────────────────────────────────┤[/]")
    for part in summary_parts:
        console.print(f"[bold white]  │[/] {part}  [bold white]│[/]")
    console.print("[bold white]  ├─────────────────────────────────────────────────────┤[/]")
    console.print(f"[bold white]  │[/]  [bold white]TOTAL{' ':>25}{total:>8}[/]  [bold white]│[/]")
    console.print("[bold white]  └─────────────────────────────────────────────────────┘[/]")
    console.print()

    # ── Findings table ──────────────────────────────────────────────────
    if findings:
        table = Table(
            title=None,
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            pad_edge=False,
            show_lines=True,
        )
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("SEVERITY", width=12, justify="center")
        table.add_column("PLUGIN", width=20, style="cyan")
        table.add_column("FINDING", min_width=30)
        table.add_column("URL", min_width=30, style="dim")

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "information")
            style, _ = SEVERITY_STYLE[sev]
            table.add_row(
                str(i),
                f"[{style}]{sev.upper()}[/]",
                f.get("plugin_name", "?"),
                f.get("name", "Unknown"),
                f.get("url", "")[:60],
            )

        console.print(table)
    else:
        console.print("[green]  ✓ No vulnerabilities found.[/]")

    console.print()

    # ── Stats ───────────────────────────────────────────────────────────
    if stats:
        stats_table = Table(title=None, show_header=True, header_style="bold blue", border_style="dim")
        stats_table.add_column("METRIC", style="bold")
        stats_table.add_column("VALUE", justify="right", style="green")
        for key, value in stats.items():
            stats_table.add_row(key.replace("_", " ").title(), str(value))
        console.print(stats_table)

    console.print()

    # ── Save output ─────────────────────────────────────────────────────
    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        outfile = output_dir / "results.json"
        with open(outfile, "w") as f:
            json.dump({"findings": findings, "stats": stats}, f, indent=2)
    elif fmt == "sarif":
        outfile = output_dir / "results.sarif"
        _write_sarif(findings, outfile)
    elif fmt == "html":
        outfile = output_dir / "report.html"
        _write_html_report(findings, stats, outfile)
    else:
        outfile = output_dir / f"results.{fmt}"
        with open(outfile, "w") as f:
            json.dump({"findings": findings, "stats": stats}, f, indent=2)

    # Always generate HTML alongside primary output
    if fmt != "html":
        html_path = output_dir / "report.html"
        _write_html_report(findings, stats, html_path)

    console.print(f"  [bold green]►[/] Results saved to [bold cyan]{outfile}[/]")
    if fmt != "html":
        console.print(f"  [bold green]►[/] HTML report at [bold cyan]{output_dir / 'report.html'}[/]")
    console.print()


def _write_sarif(findings: list[dict[str, Any]], path: Path) -> None:
    """Write results in SARIF format for GitHub Security tab."""
    runs = [{
        "tool": {
            "driver": {
                "name": "Xfweb",
                "version": __version__,
                "informationUri": "https://github.com/Cazo-Net/Xfweb",
            }
        },
        "results": [
            {
                "ruleId": f.get("name", "unknown").replace(" ", "_"),
                "level": {
                    "critical": "error",
                    "high": "error",
                    "medium": "warning",
                    "low": "note",
                    "information": "note",
                }.get(f.get("severity", "information"), "note"),
                "message": {"text": f.get("description", "")},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("url", "")},
                        "region": {"startLine": 1},
                    }
                }],
            }
            for f in findings
        ],
    }]

    sarif = {"version": "2.1.0", "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "runs": runs}
    with open(path, "w") as f:
        json.dump(sarif, f, indent=2)


def _write_html_report(findings: list[dict[str, Any]], stats: dict[str, Any], path: Path) -> None:
    """Write a professional pentest-style HTML report."""
    from xfweb.plugins.output.html_file import HTML_TEMPLATE, FINDING_TEMPLATE

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

    from datetime import datetime, timezone
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

    with open(path, "w") as f:
        f.write(html_content)


# ── CLI commands ────────────────────────────────────────────────────────────

@click.group()
@click.version_option(__version__, prog_name=__app_name__)
def cli() -> None:
    f"""{__app_name__} — The Beast: Next-gen web application security scanner."""
    pass


@cli.command()
@click.option("-t", "--target", required=True, help="Target URL to scan")
@click.option("-p", "--profile", help="Scan profile (full_audit, fast_scan, etc.)")
@click.option("-P", "--plugins", help="Comma-separated plugin names to enable")
@click.option("-x", "--exclude", help="Comma-separated plugin names to exclude")
@click.option("--max-threads", default=30, help="Maximum concurrent threads")
@click.option("--rate-limit", default=0.0, type=float, help="Requests per second (0=unlimited)")
@click.option("--proxy", help="HTTP proxy (http://host:port)")
@click.option("--output", "-o", default="xfweb_output", help="Output directory")
@click.option("--format", "-f", "output_format", default="json", help="Output format (json, sarif, html, csv)")
@click.option("--enable-ai", is_flag=True, help="Enable AI-powered detection")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose logging")
@click.option("--no-banner", is_flag=True, help="Suppress the ASCII banner")
@click.option("--auth-token", help="Bearer token for authenticated scanning")
@click.option("--cookie", multiple=True, help="Cookie to include (key=value, repeatable)")
@click.option("--header", multiple=True, help="Custom header (Key: Value, repeatable)")
@click.option("--max-scan-time", default=14400, type=int, help="Max scan time in seconds (0=unlimited)")
@click.option("--max-pages", default=500, type=int, help="Max pages to crawl")
@click.option("--scope", multiple=True, help="Domain scope (repeatable, e.g. --scope example.com)")
@click.option("--exclude-scope", multiple=True, help="Exclude domain from scope (repeatable)")
@click.option("--max-page-size", default=0, type=int, help="Max response body size in bytes (0=unlimited)")
def scan(
    target: str,
    profile: str | None,
    plugins: str | None,
    exclude: str | None,
    max_threads: int,
    rate_limit: float,
    proxy: str | None,
    output: str,
    output_format: str,
    enable_ai: bool,
    verbose: bool,
    no_banner: bool,
    auth_token: str | None,
    cookie: tuple[str, ...],
    header: tuple[str, ...],
    max_scan_time: int,
    max_pages: int,
    scope: tuple[str, ...],
    exclude_scope: tuple[str, ...],
    max_page_size: int,
) -> None:
    """Scan a web application for vulnerabilities."""
    from xfweb.core.controllers.w3af_core import XfwebCore, ScanConfig

    if not no_banner:
        _print_banner()

    if verbose:
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer(),
            ],
        )

    # Parse cookies
    extra_cookies: dict[str, str] = {}
    for c in cookie:
        if "=" in c:
            k, v = c.split("=", 1)
            extra_cookies[k.strip()] = v.strip()

    # Parse headers
    extra_headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    config = ScanConfig(
        target=target,
        profile=profile,
        plugins=plugins.split(",") if plugins else [],
        exclude_plugins=exclude.split(",") if exclude else [],
        max_threads=max_threads,
        rate_limit=rate_limit,
        proxy=proxy,
        output_dir=Path(output),
        enable_ai=enable_ai,
        auth_token=auth_token or "",
        extra_headers=extra_headers,
        extra_cookies=extra_cookies,
        max_scan_time=max_scan_time,
        scope=list(scope) if scope else [],
        exclude_scope=list(exclude_scope) if exclude_scope else [],
        max_page_size=max_page_size,
    )

    _print_target_info(target, profile, plugins, enable_ai)

    console.print("  [bold red]►[/] Initializing scan engine...")
    console.print(f"  [dim]  ├─ Threads: {max_threads}[/]")
    console.print(f"  [dim]  ├─ Rate limit: {'unlimited' if rate_limit == 0 else f'{rate_limit} req/s'}[/]")
    console.print(f"  [dim]  ├─ Auth: {'token' if auth_token else 'cookie' if extra_cookies else 'none'}[/]")
    console.print(f"  [dim]  ├─ Proxy: {proxy or 'direct'}[/]")
    console.print(f"  [dim]  ├─ Max scan time: {max_scan_time}s[/]")
    console.print(f"  [dim]  └─ Output: {output}/ ({output_format})[/]")
    console.print()

    start_time = time.monotonic()

    # Real-time progress tracking
    phase_status = {"phase": "init", "pages": 0, "tested": 0, "findings": 0, "total": 0}
    progress_task = None

    async def _on_event(event: str, data: dict[str, Any] | None = None) -> None:
        nonlocal progress_task
        if event == "progress" and data:
            phase_status["phase"] = data.get("phase", phase_status["phase"])
            if "pages_crawled" in data:
                phase_status["pages"] = data["pages_crawled"]
            if "tested" in data:
                phase_status["tested"] = data["tested"]
            if "total" in data:
                phase_status["total"] = data["total"]
            if "findings" in data:
                phase_status["findings"] = data["findings"]
        elif event == "phase" and data:
            phase_status["phase"] = data.get("phase", phase_status["phase"])

    async def _run_scan() -> None:
        core = XfwebCore(config)
        core.on_event(_on_event)

        # Start scan in background
        scan_task = asyncio.create_task(core.start())

        # Progress display
        last_phase = ""
        with _make_progress() as progress:
            task = progress.add_task("[bold red]SCANNING[/]", total=None)
            while not scan_task.done():
                await asyncio.sleep(0.5)
                phase = phase_status["phase"]
                if phase == "discovery":
                    desc = f"[bold cyan]CRAWL[/] {phase_status['pages']} pages"
                elif phase == "audit":
                    desc = f"[bold yellow]AUDIT[/] {phase_status['tested']}/{phase_status['total']} tested"
                elif phase == "grep":
                    desc = "[bold blue]GREP[/] Analyzing..."
                elif phase == "output":
                    desc = "[bold green]OUTPUT[/] Generating..."
                else:
                    desc = f"[bold red]{phase.upper()}[/]"
                if phase_status["findings"] > 0:
                    desc += f" | [bold red]{phase_status['findings']} findings[/]"
                progress.update(task, description=desc)
            await scan_task
            progress.update(task, description="[bold green]COMPLETE[/]")

        findings = core.get_findings()
        stats = core.get_stats()

        elapsed = time.monotonic() - start_time
        stats["scan_time"] = f"{elapsed:.1f}s"

        _print_results(findings, stats, output, output_format)

    asyncio.run(_run_scan())


# Suppress "Task exception was never retrieved" noise from Playwright/Node.js
import logging as __logging
__logging.getLogger("asyncio").setLevel(__logging.CRITICAL)


@cli.command()
@click.option("--host", default="0.0.0.0", help="API server host")
@click.option("--port", default=8080, type=int, help="API server port")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the Xfweb REST API server."""
    import uvicorn

    _print_banner()
    console.print(f"  [bold red]►[/] Starting API server on [bold cyan]{host}:{port}[/]")
    console.print(f"  [dim]  ├─ Dashboard: http://{host}:{port}/dashboard[/]")
    console.print(f"  [dim]  ├─ API docs:  http://{host}:{port}/docs[/]")
    console.print(f"  [dim]  └─ Health:    http://{host}:{port}/health[/]")
    console.print()

    uvicorn.run(
        "xfweb.core.ui.api.main:app",
        host=host,
        port=port,
        reload=reload,
    )


@cli.command()
@click.option("--target", "-t", required=True, help="Target URL")
@click.option("--output", "-o", default="xfweb_output", help="Output directory")
def crawl(target: str, output: str) -> None:
    """Crawl a web application and map its attack surface."""
    from xfweb.core.controllers.w3af_core import XfwebCore, ScanConfig

    _print_banner()
    console.print(f"  [bold cyan]TARGET[/]    {target}")
    console.print(f"  [bold red]►[/] Crawling target...")
    console.print()

    config = ScanConfig(
        target=target,
        plugins=["web_spider", "robots_txt", "sitemap_xml", "open_api"],
        output_dir=Path(output),
    )

    async def _crawl() -> None:
        core = XfwebCore(config)
        with _make_progress() as progress:
            task = progress.add_task("[bold red]CRAWLING[/]", total=None)
            await core.start()
            progress.update(task, description="[bold green]COMPLETE[/]")

        urls = [fr.url.raw_url for fr in core.kb.get_all_fuzzable_requests()]
        console.print()
        console.print(f"  [bold green]►[/] Discovered [bold cyan]{len(urls)}[/] URLs")
        console.print()
        for url in sorted(urls):
            console.print(f"    [dim]▸[/] {url}")

    asyncio.run(_crawl())


@cli.command()
def plugins() -> None:
    """List all available plugins."""
    _print_banner()

    from xfweb.core.controllers.plugin_manager import PluginManager

    manager = PluginManager()
    all_plugins = manager.discover_plugins()

    # Group by category
    categories: dict[str, list[tuple[str, Any]]] = {}
    for name, cls in sorted(all_plugins.items()):
        cat = cls.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append((name, cls))

    console.print(f"  [bold white]Total: [bold cyan]{len(all_plugins)}[/] plugins across [bold cyan]{len(categories)}[/] categories[/]")
    console.print()

    for cat, plugin_list in sorted(categories.items()):
        console.print(f"  [bold red]── {cat.upper()} {'─' * (50 - len(cat))}[/]")
        for name, cls in sorted(plugin_list):
            console.print(f"    [dim]▸[/] [cyan]{name:<30}[/] {cls.brief_description}")
        console.print()


if __name__ == "__main__":
    cli()
