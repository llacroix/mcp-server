"""Unit tests for RedisSessionStore."""

from __future__ import annotations

import json
import time
from unittest.mock import AsyncMock

import pytest
from mcp_server.session import RedisSessionStore, current_user_sub


class MockRedis:
    def __init__(self) -> None:
        self.data: dict[str, str | bytes] = {}
        self.ttls: dict[str, int] = {}

    async def get(self, key: str) -> str | None:
        val = self.data.get(key)
        if isinstance(val, bytes):
            return val.decode("utf-8")
        return val

    async def set(self, key: str, value: str, ex: int | None = None) -> bool:
        self.data[key] = value
        if ex is not None:
            self.ttls[key] = ex
        return True

    async def delete(self, key: str) -> int:
        return 1 if self.data.pop(key, None) is not None else 0


@pytest.mark.anyio
async def test_session_store_create_and_get():
    redis = MockRedis()
    store = RedisSessionStore(redis)  # type: ignore

    session = await store.create_or_update_session(sub="user-123", claims={"email": "user@example.com"})
    assert session["sub"] == "user-123"
    assert session["claims"]["email"] == "user@example.com"
    assert "session/user-123" in redis.data

    fetched = await store.get_session("user-123")
    assert fetched is not None
    assert fetched["sub"] == "user-123"
    assert fetched["claims"]["email"] == "user@example.com"


@pytest.mark.anyio
async def test_session_store_set_context():
    redis = MockRedis()
    store = RedisSessionStore(redis)  # type: ignore

    await store.create_or_update_session(sub="user-123")
    updated = await store.set_context("user-123", "theme", "dark")
    assert updated["context"]["theme"] == "dark"

    fetched = await store.get_session("user-123")
    assert fetched is not None
    assert fetched["context"]["theme"] == "dark"


@pytest.mark.anyio
async def test_session_store_google_tokens():
    redis = MockRedis()
    store = RedisSessionStore(redis)  # type: ignore

    await store.create_or_update_session(sub="user-123")
    tokens = {
        "access_token": "ya29.test_token",
        "refresh_token": "1//refresh_test",
        "expires_in": 3600,
        "scope": "https://www.googleapis.com/auth/generative-language.retriever",
    }
    updated = await store.store_google_tokens("user-123", tokens)
    gt = updated["google_tokens"]
    assert gt["access_token"] == "ya29.test_token"
    assert gt["refresh_token"] == "1//refresh_test"
    assert gt["expires_at"] > time.time()

    valid_token = await store.get_valid_google_token("user-123")
    assert valid_token == "ya29.test_token"
