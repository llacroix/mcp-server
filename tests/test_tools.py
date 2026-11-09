"""Unit tests for artifact and session MCP tools."""

from __future__ import annotations

import json
import pytest
from mcp.server.mcpserver import MCPServer

from mcp_server.session import RedisSessionStore, current_user_sub
from mcp_server.tools.artifacts import register_artifact_tools
from mcp_server.tools.session import register_session_tools


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


@pytest.mark.anyio
async def test_artifact_set_returns_markdown_message():
    mcp = MCPServer("test-server")
    redis = MockRedis()
    register_artifact_tools(mcp, redis_client=redis, base_url="https://mcp.odoo.plus")  # type: ignore

    # Call tool handler
    tool_func = mcp._tool_manager.get_tool("artifact.set")
    assert tool_func is not None

    result = await tool_func.fn(
        artifact_id="product-catalog-widget",
        value="<div>Product 1: Laptop</div>",
        mime_type="text/html",
    )

    assert result["artifact_id"] == "product-catalog-widget"
    assert result["url"] == "https://mcp.odoo.plus/artifacts/product-catalog-widget"
    assert "> ### 📦 Product Catalog Artifact" in result["message"]
    assert "Ready to inspect." in result["message"]
    assert "↳ [**▶ Open Product Catalog Artifact**](https://mcp.odoo.plus/artifacts/product-catalog-widget)" in result["message"]
    # Ensure raw HTML is not returned in result
    assert "<div>Product 1: Laptop</div>" not in result.values()

    # Verify Redis stored full HTML document
    stored = json.loads(redis.data["artifacts/product-catalog-widget"])
    assert "<!DOCTYPE html>" in stored["content"]
    assert "<div>Product 1: Laptop</div>" in stored["content"]
    assert stored["mime_type"] == "text/html"


@pytest.mark.anyio
async def test_session_tools():
    mcp = MCPServer("test-server")
    redis = MockRedis()
    store = RedisSessionStore(redis)  # type: ignore
    register_session_tools(mcp, session_store=store)

    session_get_tool = mcp._tool_manager.get_tool("session.get")
    session_set_tool = mcp._tool_manager.get_tool("session.set_context")
    google_token_tool = mcp._tool_manager.get_tool("google.get_token")

    # Set sub in contextvar
    current_user_sub.set("user-abc")

    # 1. session_set_context
    set_res = await session_set_tool.fn(key="preference", value="dark_mode")
    assert set_res["success"] is True
    assert set_res["sub"] == "user-abc"
    assert set_res["session_key"] == "session/user-abc"
    assert set_res["context"]["preference"] == "dark_mode"

    # 2. session_get
    get_res = await session_get_tool.fn()
    assert get_res["sub"] == "user-abc"
    assert get_res["session_key"] == "session/user-abc"
    assert get_res["context"]["preference"] == "dark_mode"
    assert get_res["google_account_linked"] is False

    # 3. google.get_token when not linked
    tok_res = await google_token_tool.fn()
    assert "error" in tok_res
    assert "No Google account is linked" in tok_res["error"]

    # 4. link google token and test google.get_token
    await store.store_google_tokens("user-abc", {
        "access_token": "ya29.sample_bearer_token",
        "expires_in": 3600,
    })
    tok_res2 = await google_token_tool.fn()
    assert tok_res2["access_token"] == "ya29.sample_bearer_token"
    assert tok_res2["token_type"] == "Bearer"
