"""SSE (Server-Sent Events) router for real-time proof status notifications.

Replaces the previous Socket.IO implementation with a simpler, unidirectional
server→browser push mechanism that requires no client-side JS library.

Single-pod mode (REDIS_MODE=none):
    Uses in-process asyncio.Event signaling. Only one SSE subscriber per pid
    is supported (one auth session = one browser tab).

Multi-pod mode (REDIS_MODE=single/sentinel/cluster):
    Uses Redis pub/sub on channel `sse:{pid}`. The async Redis client is
    initialized at startup and stored via set_redis_client().

    Note: For Redis Cluster (mode=cluster), this implementation uses standard
    PUBLISH/SUBSCRIBE which broadcasts to all nodes. Requires Redis >= 6.x.
    For Redis 7.0+ clusters, consider sharded pub/sub (SSUBSCRIBE/SPUBLISH)
    for better performance at scale.

Sentinel failover: If a Sentinel failover occurs mid-session, the pub/sub
    connection drops and listen() raises ConnectionError. The browser's native
    EventSource auto-reconnects, starting a fresh generator that re-subscribes
    via Sentinel discovery. No explicit retry logic is needed in the generator.
"""

import asyncio
import json
from datetime import UTC, datetime
from typing import AsyncGenerator

import redis.asyncio as async_redis
import structlog
from fastapi import APIRouter, Depends, Header, Request
from pymongo.database import Database
from starlette.responses import StreamingResponse

from ..authSessions.crud import AuthSessionCRUD
from ..authSessions.models import AuthSessionPatch, AuthSessionState
from ..core.config import settings
from ..core.redis_utils import parse_host_port_pairs
from ..db.session import get_db

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

router = APIRouter()

TERMINAL_STATES = frozenset(
    {
        AuthSessionState.VERIFIED,
        AuthSessionState.FAILED,
        AuthSessionState.EXPIRED,
        AuthSessionState.ABANDONED,
    }
)

# Single-pod in-process signaling: pid -> asyncio.Event
# Note: supports only one SSE subscriber per pid (one browser tab per session).
_signals: dict[str, asyncio.Event] = {}
_latest: dict[str, str] = {}

# Multi-pod: async Redis client (initialized at app startup via set_redis_client)
_redis_client: async_redis.Redis | None = None


def set_redis_client(client: async_redis.Redis) -> None:
    """Store the async Redis client for multi-pod SSE pub/sub.

    Called from the FastAPI startup event in main.py.
    Must be called after the event loop is running (not at module import time).
    """
    global _redis_client
    _redis_client = client


async def build_async_redis_client() -> async_redis.Redis:
    """Build an async Redis client based on REDIS_MODE settings.

    For cluster mode, connects to the first node since PUBLISH broadcasts
    to all nodes in a Redis Cluster.
    """
    mode = settings.REDIS_MODE

    if mode == "single":
        hosts = parse_host_port_pairs(settings.REDIS_HOST)
        host, port = hosts[0]
        return async_redis.Redis(
            host=host,
            port=port,
            password=settings.REDIS_PASSWORD or None,
            db=settings.REDIS_DB,
        )

    elif mode == "sentinel":
        from redis.asyncio.sentinel import Sentinel

        sentinel_hosts = parse_host_port_pairs(settings.REDIS_HOST)
        sentinel_kwargs = {}
        if settings.REDIS_PASSWORD:
            sentinel_kwargs["password"] = settings.REDIS_PASSWORD
        sentinel = Sentinel(sentinel_hosts, sentinel_kwargs=sentinel_kwargs)
        return sentinel.master_for(
            settings.REDIS_SENTINEL_MASTER_NAME,
            password=settings.REDIS_PASSWORD or None,
        )

    elif mode == "cluster":
        # Connect to the first node; PUBLISH broadcasts to all cluster nodes
        hosts = parse_host_port_pairs(settings.REDIS_HOST)
        host, port = hosts[0]
        return async_redis.Redis(
            host=host,
            port=port,
            password=settings.REDIS_PASSWORD or None,
        )

    else:
        raise ValueError(f"Unsupported REDIS_MODE for async client: {mode}")


async def notify(pid: str, status: str) -> None:
    """Notify SSE subscribers of a status change.

    Single-pod mode: sets an in-process asyncio.Event.
    Multi-pod mode: publishes to Redis channel sse:{pid}.
    """
    if settings.REDIS_MODE == "none":
        # Only cache if a subscriber is currently connected; otherwise the initial
        # DB state emit on connect handles any status changes that fired before
        # the browser connected, so storing here would only leak memory.
        if pid in _signals:
            _latest[pid] = status
            _signals[pid].set()
    else:
        if _redis_client is not None:
            try:
                await _redis_client.publish(
                    f"sse:{pid}", json.dumps({"status": status})
                )
            except Exception as e:
                logger.error(
                    f"Failed to publish SSE notification to Redis: {e}",
                    pid=pid,
                    status=status,
                )
        else:
            logger.warning(
                "Redis client not available for SSE notification",
                pid=pid,
                status=status,
            )


def _format_event(data: dict, event: str = "status", id: str | None = None) -> str:
    """Format a server-sent event string."""
    parts = []
    if id is not None:
        parts.append(f"id: {id}")
    parts.append(f"event: {event}")
    parts.append(f"data: {json.dumps(data)}")
    parts.append("")
    parts.append("")
    return "\n".join(parts)


async def _get_initial_state(
    pid: str, db: Database
) -> tuple[str | None, bool, datetime | None]:
    """Fetch current proof_status from DB for the initial SSE event on connect.

    Returns (status, is_terminal, expired_timestamp). Returns (None, False, None)
    if session not found. Called on every (re)connect so the browser is immediately
    up-to-date even if the webhook fired before the browser connected.
    """
    try:
        auth_session = await AuthSessionCRUD(db).get(pid)
        return (
            auth_session.proof_status,
            auth_session.proof_status in TERMINAL_STATES,
            auth_session.expired_timestamp,
        )
    except Exception:
        return None, False, None


def _seconds_until_expiry(expired_timestamp: datetime | None) -> float:
    """Return seconds until expiry, clamped to [1.0, 30.0].

    Used to wake up the wait loop promptly when the deadline is near rather
    than always waiting the full 30s keepalive interval.
    """
    if expired_timestamp is None:
        return 30.0
    now = datetime.now(UTC) if expired_timestamp.tzinfo is not None else datetime.now()
    remaining = (expired_timestamp - now).total_seconds()
    return min(30.0, max(1.0, remaining))


async def _expire_if_needed(pid: str, db: Database) -> bool:
    """Transition a NOT_STARTED session to EXPIRED if its deadline has passed.

    Called on connect (one extra DB read after _get_initial_state — accepted
    trade-off to keep expiry logic in one place) and on every keepalive tick.
    Returns True if the session was just expired, False otherwise.
    """
    try:
        auth_session = await AuthSessionCRUD(db).get(pid)
        if auth_session.proof_status != AuthSessionState.NOT_STARTED:
            logger.debug(
                "SSE expiry check: status is not NOT_STARTED, skipping",
                pid=pid,
                proof_status=auth_session.proof_status,
            )
            return False
        expired_time = auth_session.expired_timestamp
        now = datetime.now(UTC) if expired_time.tzinfo is not None else datetime.now()
        logger.debug(
            "SSE expiry check",
            pid=pid,
            expired_time=str(expired_time),
            now=str(now),
            is_expired=expired_time < now,
        )
        if expired_time < now:
            auth_session.proof_status = AuthSessionState.EXPIRED
            await AuthSessionCRUD(db).patch(
                pid, AuthSessionPatch(**auth_session.model_dump())
            )
            logger.info("SSE detected expired session", pid=pid)
            return True
    except Exception:
        logger.exception("SSE expiry check failed", pid=pid)
    return False


async def _single_pod_stream(
    pid: str, request: Request, db: Database
) -> AsyncGenerator[str, None]:
    """Generate SSE events for single-pod mode using in-process asyncio.Event."""
    seq = 0

    status, is_terminal, expired_timestamp = await _get_initial_state(pid, db)
    if status is not None:
        yield _format_event({"status": status}, id=str(seq))
        seq += 1
        if is_terminal:
            return

    # Check expiry immediately on connect in case the deadline already passed.
    # Guard on NOT_STARTED: any other status means expiry can't apply, skip the DB read.
    if status == AuthSessionState.NOT_STARTED and await _expire_if_needed(pid, db):
        yield _format_event({"status": "expired"}, id=str(seq))
        seq += 1
        return

    event = asyncio.Event()
    _signals[pid] = event
    try:
        while not await request.is_disconnected():
            try:
                await asyncio.wait_for(
                    event.wait(), timeout=_seconds_until_expiry(expired_timestamp)
                )
            except asyncio.TimeoutError:
                # Timeout — send a keepalive comment and check expiry.
                yield ": keepalive\n\n"
                if await _expire_if_needed(pid, db):
                    yield _format_event({"status": "expired"}, id=str(seq))
                    seq += 1
                    return
                # Keep expired_timestamp as-is: _seconds_until_expiry clamps to 1s minimum
                # when past the deadline, so we retry every second until expiry succeeds.
                continue
            event.clear()
            status = _latest.get(pid)
            if status is None:
                continue
            yield _format_event({"status": status}, id=str(seq))
            seq += 1
            if status in TERMINAL_STATES:
                return
    finally:
        _signals.pop(pid, None)
        _latest.pop(pid, None)


async def _next_redis_message(pubsub) -> dict:
    """Consume pubsub.listen() until a data message arrives.

    Blocks efficiently at the Redis socket read — no spin loop.
    asyncio.wait_for raises TimeoutError after 30s, which allows the outer
    loop to send a keepalive comment and re-check for disconnect.

    Raises ConnectionError if the pubsub stream closes without delivering
    a message (e.g., on Sentinel failover), so the caller can handle it.
    """
    async for msg in pubsub.listen():
        if msg["type"] == "message":
            return json.loads(msg["data"])
    raise ConnectionError("Redis pubsub closed without delivering a message")


async def _multi_pod_stream(
    pid: str, request: Request, db: Database
) -> AsyncGenerator[str, None]:
    """Generate SSE events for multi-pod mode using Redis pub/sub.

    Subscribes BEFORE reading DB state to close the race window where a webhook
    fires between the DB check and the subscription setup. Any notification
    published in that window is queued and delivered when listen() starts.
    """
    pubsub = _redis_client.pubsub()
    await pubsub.subscribe(f"sse:{pid}")
    seq = 0
    try:
        # Emit current state from DB on (re)connect
        status, is_terminal, expired_timestamp = await _get_initial_state(pid, db)
        if status is not None:
            yield _format_event({"status": status}, id=str(seq))
            seq += 1
            if is_terminal:
                return

        # Check expiry immediately on connect in case the deadline already passed.
        # Guard on NOT_STARTED: any other status means expiry can't apply, skip the DB read.
        if status == AuthSessionState.NOT_STARTED and await _expire_if_needed(pid, db):
            yield _format_event({"status": "expired"}, id=str(seq))
            seq += 1
            return

        while not await request.is_disconnected():
            try:
                payload = await asyncio.wait_for(
                    _next_redis_message(pubsub),
                    timeout=_seconds_until_expiry(expired_timestamp),
                )
            except asyncio.TimeoutError:
                # Timeout — send a keepalive comment and check expiry.
                yield ": keepalive\n\n"
                if await _expire_if_needed(pid, db):
                    yield _format_event({"status": "expired"}, id=str(seq))
                    seq += 1
                    return
                # Keep expired_timestamp as-is: _seconds_until_expiry clamps to 1s minimum
                # when past the deadline, so we retry every second until expiry succeeds.
                continue
            yield _format_event(payload, id=str(seq))
            seq += 1
            if payload.get("status") in TERMINAL_STATES:
                return
    finally:
        await pubsub.unsubscribe(f"sse:{pid}")
        await pubsub.aclose()


@router.get("/sse/status/{pid}")
async def sse_status(
    pid: str,
    request: Request,
    db: Database = Depends(get_db),
    last_event_id: str | None = Header(default=None, alias="Last-Event-ID"),  # noqa: ARG001
):
    """SSE endpoint for real-time proof status updates.

    The browser's native EventSource automatically reconnects on disconnect
    and sends the Last-Event-ID header. We don't replay from that ID —
    instead we always emit the current DB state on (re)connect, which gives
    the client a consistent snapshot without needing an event log.

    The `pid` is a MongoDB ObjectId — not guessable, provides adequate
    authorization for this use case.
    """
    mode = settings.REDIS_MODE

    if mode != "none" and _redis_client is not None:
        stream = _multi_pod_stream(pid, request, db)
    else:
        if mode != "none":
            logger.warning(
                "Redis client not initialized, falling back to single-pod SSE",
                pid=pid,
                redis_mode=mode,
            )
        stream = _single_pod_stream(pid, request, db)

    return StreamingResponse(
        stream,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )
