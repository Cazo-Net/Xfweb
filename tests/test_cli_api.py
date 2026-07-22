"""Tests for Xfweb CLI and FastAPI endpoints."""

import pytest
from click.testing import CliRunner
import httpx


class TestCli:
    def test_version(self):
        from xfweb.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_plugins_list(self):
        from xfweb.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0
        assert "sqli" in result.output

    def test_plugins_categories(self):
        from xfweb.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["plugins"])
        assert result.exit_code == 0
        assert "audit" in result.output

    def test_scan_no_target(self):
        from xfweb.cli.main import cli
        runner = CliRunner()
        result = runner.invoke(cli, ["scan"])
        assert result.exit_code != 0


@pytest.mark.asyncio
class TestApi:
    async def test_health_endpoint(self):
        from xfweb.core.ui.api.main import app
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/health")
            assert response.status_code == 200
            assert response.json()["status"] == "healthy"

    async def test_root_endpoint(self):
        from xfweb.core.ui.api.main import app
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/")
            assert response.status_code == 200
            data = response.json()
            assert data["name"] == "Xfweb"
            assert data["version"] == "1.0.0"

    async def test_plugins_endpoint(self):
        from xfweb.core.ui.api.main import app
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/plugins")
            assert response.status_code == 200
            data = response.json()
            assert "audit" in data
            assert len(data["audit"]) > 0

    async def test_profiles_endpoint(self):
        from xfweb.core.ui.api.main import app
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://test"
        ) as client:
            response = await client.get("/api/v1/profiles")
            assert response.status_code == 200
            data = response.json()
            assert len(data) > 0
