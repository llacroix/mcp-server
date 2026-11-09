"""General starter tools (add, echo, whoami, tools.refresh)."""

from __future__ import annotations

import logging
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import Context, MCPServer

logger = logging.getLogger(__name__)


def register_general_tools(mcp: MCPServer) -> None:
    """Register general starter tools on the given MCPServer instance."""

    @mcp.tool()
    def add(a: int, b: int) -> int:
        """Add two integers together."""
        return a + b

    @mcp.tool()
    async def echo(message: str, ctx: Context) -> str:
        """Echo back a message and log it via MCP context."""
        await ctx.info(f"Echoing message: {message}")
        return f"Echo: {message}"

    @mcp.tool()
    def whoami() -> dict[str, Any]:
        """Return the currently authenticated OAuth 2.0 principal information."""
        token = get_access_token()
        if token is None:
            return {"authenticated": False}
        return {
            "authenticated": True,
            "client_id": token.client_id,
            "subject": token.subject,
            "scopes": token.scopes,
            "resource": token.resource,
            "expires_at": token.expires_at,
        }

    @mcp.tool(name="tools.refresh")
    async def tools_refresh(ctx: Context) -> dict[str, Any]:
        """Force the connected client to reload its tools list by sending a list_changed notification."""
        try:
            # 1. Send notifications/tools/list_changed on the session connection
            await ctx.session.send_tool_list_changed()
        except Exception as exc:
            logger.warning("Could not send session tool_list_changed notification: %s", exc, exc_info=exc)

        try:
            # 2. Also publish to 2026+ subscriptions/listen event bus if subscribed
            await ctx.notify_tools_changed()
        except Exception as exc:
            logger.debug("Could not publish to subscriptions bus: %s", exc, exc_info=exc)

        logger.info("Sent tools list_changed notification to client")
        return {
            "success": True,
            "notification": "notifications/tools/list_changed",
            "message": "Sent tools list_changed notification. The client should refresh its available tools.",
        }
