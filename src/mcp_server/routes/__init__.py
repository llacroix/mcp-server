"""HTTP Route registration for MCP server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp_server.routes.artifacts import register_artifact_routes
from mcp_server.routes.auth import register_auth_routes
from mcp_server.routes.health import register_health_routes

if TYPE_CHECKING:
    from mcp.server.auth.settings import AuthSettings
    from mcp.server.mcpserver import MCPServer
    from redis.asyncio import Redis

    from mcp_server.session import RedisSessionStore


def register_routes(
    mcp: MCPServer,
    *,
    auth: AuthSettings | None = None,
    redis_client: Redis | None = None,
    session_store: RedisSessionStore | None = None,
    base_url: str | None = None,
    oauth_client_id: str | None = None,
    oauth_client_secret: str | None = None,
    oauth_audience: str | None = None,
    http_oauth_issuer_url: str | None = None,
    http_oauth_client_id: str | None = None,
    http_oauth_client_secret: str | None = None,
    http_oauth_audience: str | None = None,
    google_client_id: str | None = None,
    google_client_secret: str | None = None,
    google_oauth_scopes: str | None = None,
) -> None:
    """Register all HTTP custom routes on the MCPServer."""
    register_health_routes(mcp, auth=auth, base_url=base_url)
    register_artifact_routes(mcp, redis_client=redis_client)
    register_auth_routes(
        mcp,
        auth=auth,
        session_store=session_store,
        redis_client=redis_client,
        base_url=base_url,
        oauth_client_id=oauth_client_id,
        oauth_client_secret=oauth_client_secret,
        oauth_audience=oauth_audience,
        http_oauth_issuer_url=http_oauth_issuer_url,
        http_oauth_client_id=http_oauth_client_id,
        http_oauth_client_secret=http_oauth_client_secret,
        http_oauth_audience=http_oauth_audience,
        google_client_id=google_client_id,
        google_client_secret=google_client_secret,
        google_oauth_scopes=google_oauth_scopes,
    )


__all__ = [
    "register_artifact_routes",
    "register_auth_routes",
    "register_health_routes",
    "register_routes",
]
