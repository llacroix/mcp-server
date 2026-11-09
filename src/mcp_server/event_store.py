"""Redis Streams-backed EventStore for MCP Streamable HTTP session resumption."""

from __future__ import annotations

import logging
from typing import Any
import pydantic_core
from redis.asyncio import Redis
from mcp_types import JSONRPCMessage, jsonrpc_message_adapter
from mcp.server.streamable_http import EventCallback, EventId, EventMessage, EventStore, StreamId

logger = logging.getLogger(__name__)


class RedisEventStore(EventStore):
    """EventStore implementation backed by Redis Streams.

    Features:
    - Ordered event storage and replay via Redis Streams (XADD / XRANGE).
    - Monotonically increasing event IDs generated natively by Redis.
    - Automatic TTL expiration for inactive streams.
    - Capped stream length (MAXLEN) to bound memory consumption.
    """

    def __init__(
        self,
        redis_client: Redis,
        key_prefix: str = "mcp:events:",
        stream_ttl_seconds: int = 3600,
        max_stream_length: int = 1000,
    ) -> None:
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.stream_ttl = stream_ttl_seconds
        self.max_len = max_stream_length

    def _stream_key(self, stream_id: str) -> str:
        return f"{self.key_prefix}stream:{stream_id}"

    def _index_key(self, event_id: str) -> str:
        return f"{self.key_prefix}idx:{event_id}"

    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage | None) -> EventId:
        """Append an event to the stream in Redis."""
        stream_key = self._stream_key(stream_id)
        payload = pydantic_core.to_json(message).decode("utf-8") if message else ""

        event_id_raw = await self.redis.xadd(
            stream_key,
            {"msg": payload},
            maxlen=self.max_len,
            approximate=True,
        )
        event_id = event_id_raw.decode("utf-8") if isinstance(event_id_raw, bytes) else str(event_id_raw)

        pipe = self.redis.pipeline()
        pipe.expire(stream_key, self.stream_ttl)
        pipe.set(self._index_key(event_id), stream_id, ex=self.stream_ttl)
        await pipe.execute()

        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: EventCallback,
    ) -> StreamId | None:
        """Replay all stream events that occurred after last_event_id."""
        stream_id_raw = await self.redis.get(self._index_key(last_event_id))
        if not stream_id_raw:
            return None
        stream_id = stream_id_raw.decode("utf-8") if isinstance(stream_id_raw, bytes) else str(stream_id_raw)

        stream_key = self._stream_key(stream_id)
        events = await self.redis.xrange(
            stream_key,
            min=f"({last_event_id}",
            max="+",
        )

        for eid, fields in events:
            eid_str = eid.decode("utf-8") if isinstance(eid, bytes) else str(eid)
            raw_msg = fields.get(b"msg") if b"msg" in fields else fields.get("msg")
            msg_str = raw_msg.decode("utf-8") if isinstance(raw_msg, bytes) else (raw_msg or "")

            msg: JSONRPCMessage | None = None
            if msg_str:
                try:
                    msg = jsonrpc_message_adapter.validate_json(msg_str)
                except Exception as exc:
                    logger.warning("Failed to deserialize replayed JSON-RPC message: %s", exc)
                    continue

            await send_callback(EventMessage(message=msg, event_id=eid_str))

        return stream_id
