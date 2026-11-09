"""Artifact retrieval routes."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from starlette.requests import Request
from starlette.responses import Response

if TYPE_CHECKING:
    from mcp.server.mcpserver import MCPServer
    from redis.asyncio import Redis

logger = logging.getLogger(__name__)


def register_artifact_routes(
    mcp: MCPServer,
    redis_client: Redis | None = None,
) -> None:
    """Register artifact routes on MCPServer.

    Exclusively registers /artifacts/{artifact_id:path} to inspect HTML/interactive artifacts.
    """

    @mcp.custom_route("/artifacts/{artifact_id:path}", methods=["GET"])
    async def get_artifact(request: Request) -> Response:
        """Retrieve an artifact by ID from Redis (artifacts/{artifact_id}) and return with proper MIME type."""
        artifact_id = request.path_params.get("artifact_id", "").strip()
        if not artifact_id:
            return Response("Artifact ID is required", status_code=400)

        if redis_client is None:
            return Response("Artifact store not configured (Redis unavailable)", status_code=503)

        redis_key = f"artifacts/{artifact_id}"
        try:
            raw_content = await redis_client.get(redis_key)
        except Exception as exc:
            logger.error("Error reading artifact %s from Redis: %s", redis_key, exc, exc_info=exc)
            return Response("Internal server error", status_code=500)

        if raw_content is None:
            return Response("Artifact not found", status_code=404)

        text_content = raw_content.decode("utf-8") if isinstance(raw_content, bytes) else str(raw_content)
        content_to_return = text_content
        media_type = "text/html"

        try:
            parsed = json.loads(text_content)
            if isinstance(parsed, dict) and "content" in parsed:
                content_to_return = parsed["content"]
                media_type = parsed.get("mime_type") or "text/html"
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

        return Response(content=content_to_return, media_type=media_type)
