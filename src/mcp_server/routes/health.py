"""Health check and RFC 9728 discovery routes."""

from __future__ import annotations

from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


def register_health_routes(
    mcp: MCPServer,
    auth: AuthSettings | None = None,
    base_url: str | None = None,
) -> None:
    """Register /health and /.well-known/oauth-protected-resource routes."""

    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(_request: Request) -> Response:
        """Unauthenticated health check endpoint for reverse proxies (e.g. Traefik)."""
        return JSONResponse({"status": "ok", "service": "mcp-server"})

    @mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
    async def root_protected_resource(_request: Request) -> Response:
        """RFC 9728 route at root for clients querying without the /mcp subpath."""
        auth_servers = [str(auth.issuer_url)] if auth and auth.issuer_url else []
        if auth and auth.resource_server_url:
            res_url = str(auth.resource_server_url)
        elif base_url:
            res_url = base_url if base_url.endswith("/mcp") else f"{base_url.rstrip('/')}/mcp"
        else:
            res_url = "https://mcp.odoo.plus/mcp"

        return JSONResponse({
            "resource": res_url,
            "authorization_servers": auth_servers,
            "bearer_methods_supported": ["header"],
        })
