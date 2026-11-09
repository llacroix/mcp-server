"""Artifact tools for storing content in Redis."""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib.parse import urlparse

from mcp.server.mcpserver import Context, MCPServer
from redis.asyncio import Redis

logger = logging.getLogger(__name__)


def _resolve_base_url(ctx: Context | None, base_url: str | None = None) -> str:
    """Determine the public base origin using base_url, incoming request headers, or environment."""
    if base_url and base_url.strip():
        parsed = urlparse(base_url.strip())
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return base_url.strip().rstrip("/")

    if ctx is not None:
        try:
            headers = ctx.headers
            if headers:
                host = headers.get("x-forwarded-host") or headers.get("host")
                proto = headers.get("x-forwarded-proto") or "https"
                if host:
                    return f"{proto}://{host}".rstrip("/")
        except Exception:
            pass

    env_url = os.environ.get("MCP_RESOURCE_SERVER_URL", "").strip()
    if env_url:
        parsed = urlparse(env_url)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
        return env_url.rstrip("/")

    domain = os.environ.get("MCP_DOMAIN", "").strip()
    if domain:
        return f"https://{domain}".rstrip("/")

    return ""


def _normalize_mime_type(mime_type: str | None) -> str:
    """Normalize common short MIME type aliases to standard MIME strings."""
    if not mime_type or not mime_type.strip():
        return "text/html"
    raw = mime_type.strip().lower()
    mapping = {
        "html": "text/html",
        "json": "application/json",
        "text": "text/plain",
        "txt": "text/plain",
        "csv": "text/csv",
        "svg": "image/svg+xml",
        "markdown": "text/markdown",
        "md": "text/markdown",
        "xml": "application/xml",
    }
    return mapping.get(raw, raw)


def _ensure_full_html_document(content: str, artifact_id: str) -> str:
    """Ensure HTML content is a full valid document with <!DOCTYPE html>."""
    stripped = content.strip()
    lower = stripped.lower()
    if lower.startswith("<!doctype html") or lower.startswith("<html"):
        return content

    clean = artifact_id.replace("-", " ").replace("_", " ").strip()
    words = clean.split()
    if words and words[-1].lower() in {"widget", "component", "app"}:
        base_words = words[:-1]
    else:
        base_words = words
    title = " ".join(base_words).title() if base_words else clean.title()

    return (
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "  <meta charset=\"UTF-8\">\n"
        "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        f"  <title>{title}</title>\n"
        "</head>\n"
        "<body>\n"
        f"{content}\n"
        "</body>\n"
        "</html>"
    )


def _format_markdown_message(artifact_id: str, url: str) -> str:
    """Format a markdown card message with a clickable link to open the artifact."""
    clean = artifact_id.replace("-", " ").replace("_", " ").strip()
    words = clean.split()
    if words and words[-1].lower() in {"widget", "component", "app"}:
        base_words = words[:-1]
    else:
        base_words = words
    title = " ".join(base_words).title() if base_words else clean.title()
    label = f"{title} Artifact" if not title.lower().endswith("artifact") else title
    return (
        f"> ### 📦 {label}\n"
        f"> Ready to inspect.\n"
        f">\n"
        f"> ↳ [**▶ Open {label}**]({url})"
    )


def register_artifact_tools(
    mcp: MCPServer,
    redis_client: Redis | None,
    base_url: str | None = None,
) -> None:
    """Register the artifact.set tool and artifact resource template on the MCPServer instance."""

    @mcp.tool(
        name="artifact.set",
        title="Store and Render Artifact",
        meta={
            "ui": {
                "type": "html",
                "resourceUri": "artifact://{artifact_id}",
                "action": "render",
            }
        },
    )
    async def artifact_set(
        artifact_id: str,
        value: str,
        mime_type: str = "text/html",
        ttl_seconds: int | None = None,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Store artifact content in Redis under artifacts/{artifact_id} with a specified MIME type.

        Args:
            artifact_id: Unique artifact identifier (e.g. report-123, product-catalog-widget, or data.json).
            value: HTML, JSON, SVG, or text content to store.
            mime_type: MIME type of the content (default: text/html). Common values: text/html, application/json, text/plain, image/svg+xml.
            ttl_seconds: Optional expiration time in seconds (e.g. 86400 for 24h).
        """
        if redis_client is None:
            return {
                "artifact_id": artifact_id,
                "url": "",
                "error": "Redis is not configured on this server (REDIS_URL unset).",
            }

        clean_id = artifact_id.strip()
        if not clean_id:
            return {
                "artifact_id": "",
                "url": "",
                "error": "artifact_id cannot be empty.",
            }

        clean_mime = _normalize_mime_type(mime_type)
        redis_key = f"artifacts/{clean_id}"
        path = f"/artifacts/{clean_id}"
        resolved_base = _resolve_base_url(ctx, base_url)
        full_url = f"{resolved_base}{path}" if resolved_base else path

        # Ensure text/html has a full <!DOCTYPE html> document structure so browsers render properly
        content_to_store = _ensure_full_html_document(value, clean_id) if clean_mime == "text/html" else value

        payload_to_store = json.dumps({
            "content": content_to_store,
            "mime_type": clean_mime,
        })

        try:
            if ttl_seconds and ttl_seconds > 0:
                await redis_client.set(redis_key, payload_to_store, ex=ttl_seconds)
            else:
                await redis_client.set(redis_key, payload_to_store)
            logger.info("Artifact stored: %s (size=%d bytes, mime=%s, ttl=%s)", redis_key, len(content_to_store), clean_mime, ttl_seconds)

            message = _format_markdown_message(clean_id, full_url)
            return {
                "artifact_id": clean_id,
                "url": full_url,
                "message": message,
            }
        except Exception as exc:
            logger.error("Failed to store artifact %s in Redis: %s", redis_key, exc, exc_info=exc)
            return {
                "artifact_id": clean_id,
                "url": full_url,
                "error": f"Failed to store artifact: {exc}",
            }

    @mcp.resource(
        "artifact://{artifact_id}",
        name="get_artifact",
        title="Artifact Content",
        description="Retrieve stored artifact content by its identifier.",
        mime_type="text/html",
    )
    async def get_artifact(artifact_id: str) -> str:
        """Fetch the stored artifact content from Redis."""
        if redis_client is None:
            return "Redis is not configured on this server."

        clean_id = artifact_id.strip()
        if not clean_id:
            return "artifact_id cannot be empty."

        try:
            raw = await redis_client.get(f"artifacts/{clean_id}")
            if raw is None:
                return f"Artifact '{clean_id}' not found."

            text = raw.decode("utf-8", errors="replace")
            try:
                data = json.loads(text)
                if isinstance(data, dict) and "content" in data:
                    return str(data["content"])
            except json.JSONDecodeError:
                pass
            return text
        except Exception as exc:
            logger.error("Failed to read artifact resource %s from Redis: %s", clean_id, exc, exc_info=exc)
            return f"Error reading artifact: {exc}"
