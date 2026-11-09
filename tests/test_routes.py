"""Unit tests for modular HTTP routes."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from httpx import ASGITransport, AsyncClient
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette

from mcp_server.routes import register_routes
from mcp_server.session import RedisSessionStore


class MockRedis:
    def __init__(self) -> None:
        self.data: dict[str, str | bytes] = {}

    async def get(self, key: str) -> str | None:
        val = self.data.get(key)
        if isinstance(val, bytes):
            return val.decode("utf-8")
        return val

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.data[key] = value
        return True

    async def delete(self, key: str) -> int:
        return 1 if self.data.pop(key, None) is not None else 0


@pytest.fixture
def test_app():
    mcp = MCPServer("test-server")
    redis = MockRedis()
    store = RedisSessionStore(redis)  # type: ignore

    register_routes(
        mcp,
        redis_client=redis,  # type: ignore
        session_store=store,
        base_url="https://mcp.odoo.plus",
        oauth_client_id="gemini_mcp_client_id",
        oauth_client_secret="gemini_mcp_client_secret",
        oauth_audience="gemini_mcp_audience",
        http_oauth_issuer_url="https://authentik.odoo.plus/application/o/mcp-server-http/",
        http_oauth_client_id="http_oauth_client_id_123",
        http_oauth_client_secret="http_oauth_client_secret_456",
        http_oauth_audience="Ci48gU8Jt3cQH3pisFr6x1eegp2s2dqBf01ItInTz",
        google_client_id="test_google_client_id",
        google_client_secret="test_google_client_secret",
    )

    app = Starlette(routes=mcp._custom_starlette_routes)
    return app, redis, store


@pytest.mark.anyio
async def test_health_endpoint(test_app):
    app, _, _ = test_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok", "service": "mcp-server"}


@pytest.mark.anyio
async def test_protected_resource_endpoint(test_app):
    app, _, _ = test_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/.well-known/oauth-protected-resource")
        assert resp.status_code == 200
        data = resp.json()
        assert "resource" in data
        assert "authorization_servers" in data


@pytest.mark.anyio
async def test_artifacts_route(test_app):
    app, redis, _ = test_app
    redis.data["artifacts/catalog-widget"] = json.dumps({
        "content": "<h1>Catalog Widget</h1>",
        "mime_type": "text/html",
    })

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/artifacts/catalog-widget")
        assert resp.status_code == 200
        assert "<h1>Catalog Widget</h1>" in resp.text
        assert "text/html" in resp.headers["content-type"]

        resp_404 = await client.get("/artifacts/not-found")
        assert resp_404.status_code == 404


@pytest.mark.anyio
async def test_auth_login_uses_http_oauth_variables(test_app):
    app, _, _ = test_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        resp = await client.get("/auth/login")
        assert resp.status_code == 302
        redirect_url = resp.headers["location"]
        assert redirect_url.startswith("https://authentik.odoo.plus/application/o/authorize/?")
        parsed = urlparse(redirect_url)
        params = parse_qs(parsed.query)
        assert params["client_id"] == ["http_oauth_client_id_123"]
        assert params["redirect_uri"] == ["https://mcp.odoo.plus/auth/callback"]


@pytest.mark.anyio
async def test_auth_status_endpoint(test_app):
    app, _, store = test_app
    await store.create_or_update_session(sub="test-user")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get(
            "/auth/status",
            cookies={"mcp_sub": "test-user"},
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["authenticated"] is True
        assert data["sub"] == "test-user"
        assert data["session_key"] == "session/test-user"


@pytest.mark.anyio
async def test_auth_logout(test_app):
    app, _, _ = test_app
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", follow_redirects=False) as client:
        resp = await client.get("/auth/logout")
        assert resp.status_code == 302
        assert 'mcp_sub=""' in resp.headers.get("set-cookie", "")
