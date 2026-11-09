"""Tools package for the MCP server."""

from __future__ import annotations

from mcp.server.mcpserver import MCPServer
from redis.asyncio import Redis

from mcp_server.session import RedisSessionStore
from mcp_server.tools.artifacts import register_artifact_tools
from mcp_server.tools.general import register_general_tools
from mcp_server.tools.help import register_help_tools
from mcp_server.tools.session import register_session_tools


def register_tools(
    mcp: MCPServer,
    redis_client: Redis | None = None,
    base_url: str | None = None,
    session_store: RedisSessionStore | None = None,
) -> None:
    """Register all tools with the MCPServer instance."""
    register_help_tools(mcp)
    register_general_tools(mcp)
    register_artifact_tools(mcp, redis_client, base_url)
    register_session_tools(mcp, session_store)


__all__ = [
    "register_artifact_tools",
    "register_general_tools",
    "register_help_tools",
    "register_session_tools",
    "register_tools",
]
