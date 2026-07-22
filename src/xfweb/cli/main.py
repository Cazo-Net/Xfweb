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
from pathlib import Path
from typing import Any

import click
import structlog
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

from xfweb import __version__, __app_name__

console = Console()
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ],
)


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
) -> None:
    """Scan a web application for vulnerabilities."""
    from xfweb.core.controllers.w3af_core import XfwebCore, ScanConfig

    if verbose:
        structlog.configure(
            processors=[
                structlog.processors.TimeStamper(fmt="iso"),
                structlog.dev.ConsoleRenderer(),
            ],
        )

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
    )

    console.print(Panel(
        f"[bold red]{__app_name__}[/] v{__version__} — The Beast\n"
        f"Target: [cyan]{target}[/]\n"
        f"Plugins: [green]{plugins or 'all'}[/]\n"
        f"AI: [yellow]{'enabled' if enable_ai else 'disabled'}[/]",
        title="Starting Scan",
        border_style="red",
    ))

    async def _run_scan() -> None:
        core = XfwebCore(config)
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=None)
            await core.start()
            progress.update(task, description="Scan complete!")

        findings = core.get_findings()
        stats = core.get_stats()

        _print_results(findings, stats, output, output_format)

    asyncio.run(_run_scan())


def _print_results(findings: list[dict[str, Any]], stats: dict[str, Any], output: str, fmt: str) -> None:
    """Print scan results to console and save to file."""
    table = Table(title="Scan Results")
    table.add_column("Severity", style="bold")
    table.add_column("Count", justify="right")
    table.add_column("Finding", style="cyan")

    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
        "information": "blue",
    }

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "information")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        table.add_row(
            f"[{severity_colors.get(sev, 'white')}]{sev.upper()}[/]",
            "",
            f.get("name", "Unknown"),
        )

    console.print(table)

    stats_table = Table(title="Scan Statistics")
    stats_table.add_column("Metric", style="bold")
    stats_table.add_column("Value", justify="right")
    for key, value in stats.items():
        stats_table.add_row(key.replace("_", " ").title(), str(value))
    console.print(stats_table)

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        outfile = output_dir / "results.json"
        with open(outfile, "w") as f:
            json.dump({"findings": findings, "stats": stats}, f, indent=2)
    elif fmt == "sarif":
        outfile = output_dir / "results.sarif"
        _write_sarif(findings, outfile)
    else:
        outfile = output_dir / f"results.{fmt}"
        with open(outfile, "w") as f:
            json.dump({"findings": findings, "stats": stats}, f, indent=2)

    console.print(f"\n[green]Results saved to {outfile}[/]")


def _write_sarif(findings: list[dict[str, Any]], path: Path) -> None:
    """Write results in SARIF format for GitHub Security tab."""
    runs = [{
        "tool": {
            "driver": {
                "name": "Xfweb",
                "version": __version__,
                "informationUri": "https://github.com/xfweb/xfweb",
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


@cli.command()
@click.option("--host", default="0.0.0.0", help="API server host")
@click.option("--port", default=8080, type=int, help="API server port")
@click.option("--reload", is_flag=True, help="Enable auto-reload for development")
def serve(host: str, port: int, reload: bool) -> None:
    """Start the Xfweb REST API server."""
    import uvicorn

    console.print(Panel(
        f"[bold red]{__app_name__}[/] API Server\n"
        f"Host: [cyan]{host}:{port}[/]\n"
        f"Docs: [green]http://{host}:{port}/docs[/]",
        title="Starting Server",
        border_style="red",
    ))

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

    config = ScanConfig(
        target=target,
        plugins=["web_spider", "robots_txt", "sitemap_xml", "open_api"],
        output_dir=Path(output),
    )

    async def _crawl() -> None:
        core = XfwebCore(config)
        await core.start()
        urls = [fr.url.raw_url for fr in core.kb.get_all_fuzzable_requests()]
        console.print(f"\n[green]Discovered {len(urls)} URLs[/]")
        for url in sorted(urls):
            console.print(f"  {url}")

    asyncio.run(_crawl())


@cli.command()
def plugins() -> None:
    """List all available plugins."""
    from xfweb.core.controllers.plugin_manager import PluginManager

    manager = PluginManager()
    all_plugins = manager.discover_plugins()

    table = Table(title="Available Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Category", style="green")
    table.add_column("Description")

    for name, cls in sorted(all_plugins.items()):
        table.add_row(name, cls.category, cls.brief_description)

    console.print(table)


if __name__ == "__main__":
    cli()
