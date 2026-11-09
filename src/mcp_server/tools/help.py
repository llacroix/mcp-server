"""Help tool for discovering available MCP tools, resources, and prompts."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer


def register_help_tools(mcp: MCPServer) -> None:
    """Register the help tool on the given MCPServer instance."""

    @mcp.tool(name="help")
    async def help_tool(tool_name: str | None = None) -> dict[str, Any]:
        """List available tools, resources, and prompts, or show details for a specific tool.

        Args:
            tool_name: Optional name of a specific tool to inspect.
        """
        tools = await mcp.list_tools()

        if tool_name:
            for tool in tools:
                if tool.name == tool_name:
                    return {
                        "name": tool.name,
                        "title": tool.title,
                        "description": tool.description,
                        "input_schema": tool.input_schema,
                        "output_schema": tool.output_schema,
                    }
            return {
                "error": f"Unknown tool: {tool_name!r}",
                "available_tools": [t.name for t in tools],
            }

        resources = await mcp.list_resources()
        resource_templates = await mcp.list_resource_templates()
        prompts = await mcp.list_prompts()

        return {
            "server": {
                "name": mcp.name,
                "version": mcp.version,
                "instructions": mcp.instructions,
            },
            "tools": [
                {
                    "name": t.name,
                    "description": t.description,
                }
                for t in tools
            ],
            "resources": [
                {
                    "uri": str(r.uri),
                    "name": r.name,
                    "description": r.description,
                }
                for r in resources
            ],
            "resource_templates": [
                {
                    "uri_template": rt.uri_template,
                    "name": rt.name,
                    "description": rt.description,
                }
                for rt in resource_templates
            ],
            "prompts": [
                {
                    "name": p.name,
                    "description": p.description,
                }
                for p in prompts
            ],
        }
