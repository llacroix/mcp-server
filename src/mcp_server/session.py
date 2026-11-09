"""Redis-backed session store for user context indexed by OAuth 'sub' claim."""

from __future__ import annotations

import json
import logging
import os
import time
from contextvars import ContextVar
from typing import Any

import httpx
from redis.asyncio import Redis

logger = logging.getLogger(__name__)

# Context variable tracking the current request's authenticated subject (sub)
current_user_sub: ContextVar[str | None] = ContextVar("current_user_sub", default=None)


class RedisSessionStore:
    """Manages user sessions in Redis indexed by the OAuth 'sub' claim."""

    def __init__(
        self,
        redis_client: Redis,
        key_prefix: str = "session/",
        session_ttl_seconds: int = 86400 * 30,  # 30 days
    ) -> None:
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.session_ttl = session_ttl_seconds

    def _session_key(self, sub: str) -> str:
        clean_sub = sub.strip()
        return f"{self.key_prefix}{clean_sub}"

    async def get_session(self, sub: str) -> dict[str, Any] | None:
        """Retrieve the session dict from Redis for a given sub."""
        clean_sub = sub.strip()
        if not clean_sub:
            return None

        key = self._session_key(clean_sub)
        try:
            raw = await self.redis.get(key)
            if not raw:
                return None
            text = raw.decode("utf-8") if isinstance(raw, bytes) else str(raw)
            return json.loads(text)
        except Exception as exc:
            logger.error("Failed to read session %s from Redis: %s", key, exc, exc_info=exc)
            return None

    async def create_or_update_session(
        self,
        sub: str,
        claims: dict[str, Any] | None = None,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create or update session for a given sub."""
        clean_sub = sub.strip()
        if not clean_sub:
            raise ValueError("sub cannot be empty")

        key = self._session_key(clean_sub)
        now = int(time.time())

        existing = await self.get_session(clean_sub)
        if existing is None:
            session_data: dict[str, Any] = {
                "sub": clean_sub,
                "created_at": now,
                "updated_at": now,
                "claims": claims or {},
                "context": context or {},
                "google_tokens": None,
            }
        else:
            session_data = existing
            session_data["updated_at"] = now
            if claims:
                session_data.setdefault("claims", {}).update(claims)
            if context:
                session_data.setdefault("context", {}).update(context)

        try:
            payload = json.dumps(session_data)
            await self.redis.set(key, payload, ex=self.session_ttl)
            logger.info("Session updated in Redis: key=%s (sub=%s)", key, clean_sub)
            return session_data
        except Exception as exc:
            logger.error("Failed to save session %s to Redis: %s", key, exc, exc_info=exc)
            raise

    async def set_context(self, sub: str, key: str, value: Any) -> dict[str, Any]:
        """Update a specific context key/value in the user's session."""
        session = await self.get_session(sub)
        if session is None:
            session = await self.create_or_update_session(sub=sub)

        session.setdefault("context", {})[key] = value
        session["updated_at"] = int(time.time())

        redis_key = self._session_key(sub)
        try:
            await self.redis.set(redis_key, json.dumps(session), ex=self.session_ttl)
            return session
        except Exception as exc:
            logger.error("Failed to update context on session %s: %s", redis_key, exc, exc_info=exc)
            raise

    async def store_google_tokens(
        self,
        sub: str,
        tokens: dict[str, Any],
    ) -> dict[str, Any]:
        """Store Google OAuth tokens in the session dictionary."""
        session = await self.get_session(sub)
        if session is None:
            session = await self.create_or_update_session(sub=sub)

        now = int(time.time())
        expires_in = int(tokens.get("expires_in", 3600))
        expires_at = now + expires_in

        existing_gt = session.get("google_tokens") or {}
        # Preserve existing refresh_token if new one was not returned in refresh flow
        refresh_token = tokens.get("refresh_token") or existing_gt.get("refresh_token")

        google_data = {
            "access_token": tokens.get("access_token"),
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": expires_in,
            "expires_at": expires_at,
            "refresh_token": refresh_token,
            "scope": tokens.get("scope", ""),
            "id_token": tokens.get("id_token"),
            "linked_at": now,
        }

        session["google_tokens"] = google_data
        session["updated_at"] = now

        redis_key = self._session_key(sub)
        try:
            await self.redis.set(redis_key, json.dumps(session), ex=self.session_ttl)
            logger.info("Stored Google tokens for sub=%s (expires_in=%ds)", sub, expires_in)
            return session
        except Exception as exc:
            logger.error("Failed to store Google tokens in Redis for sub %s: %s", sub, exc, exc_info=exc)
            raise

    async def get_valid_google_token(
        self,
        sub: str,
        client_id: str | None = None,
        client_secret: str | None = None,
    ) -> str | None:
        """Get a valid Google Bearer token, automatically refreshing if expired."""
        session = await self.get_session(sub)
        if not session or not session.get("google_tokens"):
            return None

        gt = session["google_tokens"]
        access_token = gt.get("access_token")
        expires_at = gt.get("expires_at", 0)
        refresh_token = gt.get("refresh_token")

        now = int(time.time())
        # If token is valid for more than 60 seconds, return it
        if access_token and expires_at > (now + 60):
            return str(access_token)

        cid = client_id or os.environ.get("GOOGLE_CLIENT_ID", "").strip() or None
        csec = (
            client_secret
            or os.environ.get("GOOGLE_CLIENT_SECRET_ID", "").strip()
            or os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
            or None
        )

        # Token is expired or expiring soon; try to refresh if refresh_token and client creds exist
        if refresh_token and cid and csec:
            logger.info("Google access token for sub=%s is expired, attempting refresh...", sub)
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    resp = await client.post(
                        "https://oauth2.googleapis.com/token",
                        data={
                            "client_id": cid,
                            "client_secret": csec,
                            "refresh_token": refresh_token,
                            "grant_type": "refresh_token",
                        },
                    )
                if resp.status_code == 200:
                    new_tokens = resp.json()
                    await self.store_google_tokens(sub, new_tokens)
                    return str(new_tokens.get("access_token"))
                else:
                    logger.error("Google token refresh failed: HTTP %d: %s", resp.status_code, resp.text)
            except Exception as exc:
                logger.error("Exception refreshing Google token for sub %s: %s", sub, exc, exc_info=exc)

        # Fallback to current access_token if refresh failed but token exists
        return str(access_token) if access_token else None
