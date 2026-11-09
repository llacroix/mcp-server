"""MCP tools for inspecting and updating the user's Redis session and Google Bearer token."""

from __future__ import annotations

import logging
import os
from typing import Any

import jwt
from mcp.server.mcpserver import Context, MCPServer

from mcp_server.session import RedisSessionStore, current_user_sub

logger = logging.getLogger(__name__)


def resolve_current_sub(ctx: Context | None) -> str | None:
    """Resolve the authenticated user's 'sub' claim from ContextVar or request context."""
    sub = current_user_sub.get(None)
    if sub:
        return sub

    if ctx is not None:
        try:
            req = getattr(ctx.request_context, "request", None)
            if req is not None:
                user = getattr(req, "user", None)
                if user is not None and hasattr(user, "access_token"):
                    access_token = user.access_token
                    if hasattr(access_token, "subject") and access_token.subject:
                        return str(access_token.subject)
            headers = ctx.headers
            if headers:
                auth_header = headers.get("authorization", "")
                if auth_header.lower().startswith("bearer "):
                    token = auth_header.split()[1]
                    unverified = jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
                    if "sub" in unverified and unverified["sub"]:
                        return str(unverified["sub"])
        except Exception as exc:
            logger.debug("Error resolving sub from context: %s", exc, exc_info=exc)

    return None


def register_session_tools(
    mcp: MCPServer,
    session_store: RedisSessionStore | None,
) -> None:
    """Register session-related tools with the MCPServer instance."""

    google_client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip() or None
    google_client_secret = (
        os.environ.get("GOOGLE_CLIENT_SECRET_ID", "").strip()
        or os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
        or None
    )

    @mcp.tool(
        name="session.get",
        title="Get User Session Context",
        description="Retrieve the current authenticated user's session context and Google token status from Redis.",
    )
    async def session_get(ctx: Context | None = None) -> dict[str, Any]:
        """Fetch the current user's session from session/{sub}."""
        if session_store is None:
            return {"error": "Redis session store is not configured."}

        sub = resolve_current_sub(ctx)
        if not sub:
            return {
                "error": "No authenticated user sub found in the current request context.",
                "hint": "Ensure the request includes an Authorization Bearer token with a 'sub' claim.",
            }

        session = await session_store.get_session(sub)
        if not session:
            # Create initialized session if not present
            session = await session_store.create_or_update_session(sub=sub)

        gt = session.get("google_tokens") or {}
        has_google = bool(gt.get("access_token"))

        return {
            "sub": sub,
            "session_key": f"session/{sub}",
            "created_at": session.get("created_at"),
            "updated_at": session.get("updated_at"),
            "context": session.get("context", {}),
            "google_account_linked": has_google,
            "google_token_scope": gt.get("scope", ""),
            "google_token_expires_at": gt.get("expires_at"),
        }

    @mcp.tool(
        name="session.set_context",
        title="Set User Session Context",
        description="Store a key-value pair in the current user's session context in Redis.",
    )
    async def session_set_context(
        key: str,
        value: Any,
        ctx: Context | None = None,
    ) -> dict[str, Any]:
        """Store context data under session/{sub}['context'][key]."""
        if session_store is None:
            return {"error": "Redis session store is not configured."}

        clean_key = key.strip()
        if not clean_key:
            return {"error": "Key cannot be empty."}

        sub = resolve_current_sub(ctx)
        if not sub:
            return {"error": "No authenticated user sub found in the current request context."}

        try:
            updated = await session_store.set_context(sub=sub, key=clean_key, value=value)
            return {
                "success": True,
                "sub": sub,
                "session_key": f"session/{sub}",
                "updated_key": clean_key,
                "context": updated.get("context", {}),
            }
        except Exception as exc:
            logger.error("Failed to update session context for sub %s: %s", sub, exc, exc_info=exc)
            return {"error": f"Failed to update session context: {exc}"}

    @mcp.tool(
        name="google.get_token",
        title="Get Google Bearer Token",
        description="Retrieve a valid Google OAuth 2.0 Bearer token bound to the current user's session for Gemini APIs.",
    )
    async def google_get_token(ctx: Context | None = None) -> dict[str, Any]:
        """Fetch or refresh the Google Bearer token for the current user."""
        if session_store is None:
            return {"error": "Redis session store is not configured."}

        sub = resolve_current_sub(ctx)
        if not sub:
            return {"error": "No authenticated user sub found in the current request context."}

        session = await session_store.get_session(sub)
        if not session or not session.get("google_tokens"):
            return {
                "error": "No Google account is linked to this session.",
                "sub": sub,
                "hint": "Authenticate via /auth/google/login in your browser to bind your Google Bearer token.",
            }

        token = await session_store.get_valid_google_token(
            sub=sub,
            client_id=google_client_id,
            client_secret=google_client_secret,
        )

        if not token:
            return {
                "error": "Google token is expired and could not be refreshed.",
                "sub": sub,
                "hint": "Re-authenticate at /auth/google/login.",
            }

        gt = session.get("google_tokens", {})
        return {
            "token_type": "Bearer",
            "access_token": token,
            "expires_at": gt.get("expires_at"),
            "scope": gt.get("scope", ""),
            "sub": sub,
        }
