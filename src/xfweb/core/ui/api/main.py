"""FastAPI REST API server for Xfweb.

Provides endpoints for:
- Starting/stopping scans
- Monitoring scan progress (WebSocket)
- Retrieving findings
- Managing plugins and profiles
- Generating reports
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from xfweb import __version__, __app_name__

app = FastAPI(
    title=__app_name__,
    version=__version__,
    description="The Beast — Next-gen web application security scanner API",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str
    profile: str | None = None
    plugins: list[str] | None = None
    exclude_plugins: list[str] | None = None
    max_threads: int = 30
    rate_limit: float = 0.0
    proxy: str | None = None
    enable_ai: bool = False


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


_scan_sessions: dict[str, Any] = {}
_ws_connections: list[WebSocket] = []


@app.get("/")
async def root() -> dict[str, str]:
    return {
        "name": __app_name__,
        "version": __version__,
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "healthy"}


@app.post("/api/v1/scan", response_model=ScanResponse)
async def start_scan(request: ScanRequest) -> ScanResponse:
    """Start a new vulnerability scan."""
    import uuid
    from xfweb.core.controllers.w3af_core import XfwebCore, ScanConfig

    scan_id = str(uuid.uuid4())[:8]
    config = ScanConfig(
        target=request.target,
        plugins=request.plugins or [],
        exclude_plugins=request.exclude_plugins or [],
        max_threads=request.max_threads,
        rate_limit=request.rate_limit,
        proxy=request.proxy,
        enable_ai=request.enable_ai,
    )

    core = XfwebCore(config)

    async def _run() -> None:
        def on_event(event: str, data: dict[str, Any] | None = None) -> None:
            _scan_sessions[scan_id]["events"].append({"event": event, "data": data})

        core.on_event(on_event)
        await core.start()
        _scan_sessions[scan_id]["status"] = "completed"
        _scan_sessions[scan_id]["findings"] = core.get_findings()
        _scan_sessions[scan_id]["stats"] = core.get_stats()

    _scan_sessions[scan_id] = {
        "status": "running",
        "config": request.model_dump(),
        "events": [],
        "findings": [],
        "stats": {},
        "task": asyncio.create_task(_run()),
    }

    return ScanResponse(scan_id=scan_id, status="running", message="Scan started")


@app.get("/api/v1/scan/{scan_id}")
async def get_scan_status(scan_id: str) -> dict[str, Any]:
    """Get the status of a running or completed scan."""
    if scan_id not in _scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = _scan_sessions[scan_id]
    return {
        "scan_id": scan_id,
        "status": session["status"],
        "findings_count": len(session.get("findings", [])),
        "stats": session.get("stats", {}),
    }


@app.get("/api/v1/scan/{scan_id}/findings")
async def get_scan_findings(
    scan_id: str,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """Get findings from a completed scan."""
    if scan_id not in _scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = _scan_sessions[scan_id]
    findings = session.get("findings", [])

    if severity:
        findings = [f for f in findings if f.get("severity") == severity]

    return findings


@app.delete("/api/v1/scan/{scan_id}")
async def stop_scan(scan_id: str) -> dict[str, str]:
    """Stop a running scan."""
    if scan_id not in _scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = _scan_sessions[scan_id]
    if session["status"] == "running":
        session["task"].cancel()
        session["status"] = "stopped"

    return {"scan_id": scan_id, "status": "stopped"}


@app.get("/api/v1/plugins")
async def list_plugins() -> dict[str, list[str]]:
    """List all available plugins by category."""
    from xfweb.core.controllers.plugin_manager import PluginManager

    manager = PluginManager()
    all_plugins = manager.discover_plugins()

    by_category: dict[str, list[str]] = {}
    for name, cls in all_plugins.items():
        cat = cls.category
        if cat not in by_category:
            by_category[cat] = []
        by_category[cat].append(name)

    return by_category


@app.get("/api/v1/profiles")
async def list_profiles() -> list[str]:
    """List available scan profiles."""
    profiles_dir = Path("profiles")
    if not profiles_dir.exists():
        return []
    return [f.stem for f in profiles_dir.glob("*.yaml")]


@app.get("/api/v1/results/{scan_id}/export")
async def export_results(
    scan_id: str,
    format: str = "json",
) -> Any:
    """Export scan results in various formats (json, sarif, csv)."""
    if scan_id not in _scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = _scan_sessions[scan_id]
    findings = session.get("findings", [])

    if format == "json":
        return JSONResponse(content={"findings": findings, "stats": session.get("stats", {})})
    elif format == "sarif":
        return JSONResponse(content=_to_sarif(findings))
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket(websocket: WebSocket, scan_id: str) -> None:
    """WebSocket endpoint for real-time scan updates."""
    await websocket.accept()

    if scan_id not in _scan_sessions:
        await websocket.send_json({"error": "Scan not found"})
        await websocket.close()
        return

    session = _scan_sessions[scan_id]
    event_index = 0

    try:
        while session["status"] == "running":
            if event_index < len(session["events"]):
                event = session["events"][event_index]
                await websocket.send_json(event)
                event_index += 1
            else:
                await asyncio.sleep(0.5)

        await websocket.send_json({
            "event": "scan_complete",
            "data": {"status": session["status"], "stats": session.get("stats", {})},
        })
    except WebSocketDisconnect:
        pass


def _to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "Xfweb", "version": __version__}},
            "results": [
                {
                    "ruleId": f.get("name", "unknown").replace(" ", "_"),
                    "level": f.get("severity", "note"),
                    "message": {"text": f.get("description", "")},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.get("url", "")}}}],
                }
                for f in findings
            ],
        }],
    }


@app.get("/dashboard")
async def dashboard() -> FileResponse:
    """Serve the web dashboard."""
    dashboard_path = Path(__file__).parent.parent / "dashboard" / "index.html"
    return FileResponse(str(dashboard_path), media_type="text/html")


@app.get("/api/v1/scan/{scan_id}/export/{format}")
async def export_results_formatted(
    scan_id: str,
    format: str,
) -> Any:
    """Export scan results in the specified format."""
    if scan_id not in _scan_sessions:
        raise HTTPException(status_code=404, detail="Scan not found")

    session = _scan_sessions[scan_id]
    findings = session.get("findings", [])

    if format == "json":
        return JSONResponse(content={"findings": findings, "stats": session.get("stats", {})})
    elif format == "sarif":
        return JSONResponse(content=_to_sarif(findings))
    elif format == "csv":
        import csv, io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["severity", "name", "url", "plugin_name", "description"])
        writer.writeheader()
        for f in findings:
            writer.writerow({k: f.get(k, "") for k in ["severity", "name", "url", "plugin_name", "description"]})
        return JSONResponse(content={"csv": output.getvalue()})
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    """Entry point for the API server."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)
