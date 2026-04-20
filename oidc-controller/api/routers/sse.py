"""SSE (Server-Sent Events) router for real-time proof status notifications.

Replaces the previous Socket.IO implementation with a simpler, unidirectional
server -> browser push mechanism that requires no client-side JS library.

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
    connection drops and get_message() raises ConnectionError. The SSE generator
    catches this and returns cleanly. The browser's native EventSource
    auto-reconnects, starting a fresh generator that re-subscribes via Sentinel
    discovery. No explicit retry logic is needed in the generator.
"""

import asyncio
import json
from datetime import UTC, datetime
from typing import AsyncGenerator, Awaitable, Callable

import redis.asyncio as async_redis
import structlog
from fastapi import APIRouter, Depends, Request
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
    mode = settings.REDIS_MODE.lower()

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
) -> tuple[str | None, bool, datetime | None, object]:
    """Fetch current proof_status from DB for the initial SSE event on connect.

    Returns (status, is_terminal, expired_timestamp, auth_session). Returns
    (None, False, None, None) if session not found. Called on every (re)connect
    so the browser is immediately up-to-date even if the webhook fired before
    the browser connected. The auth_session is returned to avoid a second DB
    read in the connect-time expiry check.
    """
    try:
        auth_session = await AuthSessionCRUD(db).get(pid)
        return (
            auth_session.proof_status,
            auth_session.proof_status in TERMINAL_STATES,
            auth_session.expired_timestamp,
            auth_session,
        )
    except Exception:
        return None, False, None, None


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


async def _expire_if_needed(pid: str, db: Database, auth_session=None) -> bool:
    """Transition a NOT_STARTED session to EXPIRED if its deadline has passed.

    Called on connect (passing the auth_session from _get_initial_state to avoid
    a second DB read) and on every keepalive tick (auth_session=None, re-fetches).
    Returns True if the session was just expired, False otherwise.
    """
    try:
        if auth_session is None:
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


async def _sse_event_loop(
    pid: str,
    request: Request,
    db: Database,
    wait_fn: Callable[[float], Awaitable[dict | None]],
) -> AsyncGenerator[str, None]:
    """Core SSE event loop shared by single-pod and multi-pod implementations.

    Handles the common logic:
    - Emitting current DB state on (re)connect
    - Connect-time expiry check
    - Keepalive + expiry check on timeout
    - Event formatting and terminal state detection

    Args:
        pid: Proof session ID.
        request: FastAPI request used for disconnect detection.
        db: MongoDB database.
        wait_fn: Async callable that takes a timeout (seconds) and returns a
            payload dict when a notification arrives, or None on timeout.
            May raise ConnectionError if the underlying transport closes.
    """
    seq = 0

    status, is_terminal, expired_timestamp, auth_session = await _get_initial_state(
        pid, db
    )
    if status is not None:
        # Last-Event-ID presence signals browser reconnect. We don't use the
        # value (DB is source of truth), but logging it confirms the
        # mobile-backgrounding recovery path is working in production.
        if is_terminal:
            logger.info(
                "SSE initial-state emit is terminal",
                pid=pid,
                status=status,
                is_reconnect=request.headers.get("last-event-id") is not None,
            )
        yield _format_event({"status": status}, id=str(seq))
        seq += 1
        if is_terminal:
            return

    # Check expiry immediately on connect in case the deadline already passed.
    # Guard on NOT_STARTED: any other status means expiry can't apply, skip the DB read.
    if status == AuthSessionState.NOT_STARTED and await _expire_if_needed(
        pid, db, auth_session=auth_session
    ):
        yield _format_event({"status": "expired"}, id=str(seq))
        return

    while not await request.is_disconnected():
        try:
            payload = await wait_fn(_seconds_until_expiry(expired_timestamp))
        except ConnectionError:
            return
        if payload is None:
            # Timeout — send a keepalive comment and check expiry.
            yield ": keepalive\n\n"
            if await _expire_if_needed(pid, db):
                yield _format_event({"status": "expired"}, id=str(seq))
                return
            # _seconds_until_expiry clamps to 1s minimum when past the deadline,
            # so we retry every second until expiry succeeds.
            continue
        yield _format_event(payload, id=str(seq))
        seq += 1
        if payload.get("status") in TERMINAL_STATES:
            return


async def _single_pod_stream(
    pid: str, request: Request, db: Database
) -> AsyncGenerator[str, None]:
    """Generate SSE events for single-pod mode using in-process asyncio.Event."""
    event = asyncio.Event()
    if pid in _signals:
        logger.warning(
            "SSE single-pod: overwriting existing subscriber for pid "
            "(second tab or reconnect race — previous connection will stall)",
            pid=pid,
        )
    _signals[pid] = event

    async def wait_fn(timeout: float) -> dict | None:
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            return None
        event.clear()
        status = _latest.get(pid)
        return {"status": status} if status is not None else None

    try:
        async for chunk in _sse_event_loop(pid, request, db, wait_fn):
            yield chunk
    finally:
        # Only clear mappings if they still belong to this connection's event.
        if _signals.get(pid) is event:
            _signals.pop(pid, None)
            _latest.pop(pid, None)


async def _poll_redis_pubsub(pubsub) -> dict | None:
    """Non-blocking poll of a Redis pubsub channel. Cancel-safe.

    Returns parsed JSON payload if a data message is available, None otherwise.
    Raises ConnectionError if the pubsub connection has been closed (e.g., on
    Sentinel failover), so the caller can handle it.
    """
    msg = await pubsub.get_message(ignore_subscribe_messages=True, timeout=0)
    if msg is None:
        return None
    if msg.get("type") == "message":
        return json.loads(msg["data"])
    return None


async def _multi_pod_stream(
    pid: str, request: Request, db: Database
) -> AsyncGenerator[str, None]:
    """Generate SSE events for multi-pod mode using Redis pub/sub.

    Subscribes BEFORE reading DB state to close the race window where a webhook
    fires between the DB check and the subscription setup. Any notification
    published in that window is queued and delivered when get_message() polls.
    """
    pubsub = _redis_client.pubsub()
    await pubsub.subscribe(f"sse:{pid}")

    async def wait_fn(timeout: float) -> dict | None:
        elapsed = 0.0
        poll_step = 0.05
        while elapsed < timeout:
            try:
                payload = await _poll_redis_pubsub(pubsub)
            except ConnectionError:
                logger.warning(
                    "Redis pubsub closed (Sentinel failover?), ending SSE stream",
                    pid=pid,
                )
                raise
            if payload is not None:
                return payload
            await asyncio.sleep(poll_step)
            elapsed += poll_step
        return None

    try:
        async for chunk in _sse_event_loop(pid, request, db, wait_fn):
            yield chunk
    finally:
        await pubsub.unsubscribe(f"sse:{pid}")
        await pubsub.aclose()


@router.get("/sse/status/{pid}")
async def sse_status(
    pid: str,
    request: Request,
    db: Database = Depends(get_db),
):
    """SSE endpoint for real-time proof status updates.

    The browser's native EventSource automatically reconnects on disconnect
    and sends the Last-Event-ID header. We intentionally ignore that ID —
    instead we always emit the current DB state on (re)connect, which gives
    the client a consistent snapshot without needing an event log.

    The `pid` is a MongoDB ObjectId that identifies the proof session in
    the database.
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
