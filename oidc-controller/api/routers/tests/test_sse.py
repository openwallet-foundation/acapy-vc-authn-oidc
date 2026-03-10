"""Tests for SSE (Server-Sent Events) status endpoint."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch, AsyncMock

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.authSessions.models import AuthSession, AuthSessionState
from api.core.models import PyObjectId
from api.routers import sse as sse_module
from api.routers.sse import (
    TERMINAL_STATES,
    _format_event,
    _get_initial_state,
    _latest,
    _next_redis_message,
    _signals,
    build_async_redis_client,
    notify,
    router,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_app() -> FastAPI:
    """Create a minimal FastAPI app with the SSE router for testing."""
    app = FastAPI()
    app.include_router(router)
    return app


def _make_auth_session(
    status: AuthSessionState = AuthSessionState.NOT_STARTED,
) -> AuthSession:
    """Create a minimal AuthSession for mocking."""
    return AuthSession(
        _id=PyObjectId("507f1f77bcf86cd799439011"),
        ver_config_id="test-config",
        request_parameters={},
        pyop_auth_code="test-code",
        response_url="http://test.com/callback",
        proof_status=status,
    )


# ---------------------------------------------------------------------------
# Unit tests: _format_event
# ---------------------------------------------------------------------------


class TestFormatEvent:
    def test_basic_event(self):
        result = _format_event({"status": "verified"})
        assert "event: status" in result
        assert 'data: {"status": "verified"}' in result
        assert result.endswith("\n\n")

    def test_event_with_id(self):
        result = _format_event({"status": "pending"}, id="3")
        assert "id: 3\n" in result

    def test_event_without_id(self):
        result = _format_event({"status": "pending"})
        assert "id:" not in result


# ---------------------------------------------------------------------------
# Unit tests: notify() — single-pod mode
# ---------------------------------------------------------------------------


class TestNotifySinglePod:
    def setup_method(self):
        # Ensure single-pod mode and clean state
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    @pytest.mark.asyncio
    async def test_notify_sets_latest_only_when_subscriber_present(self):
        with patch.object(sse_module.settings, "REDIS_MODE", "none"):
            event = asyncio.Event()
            _signals["pid1"] = event
            await notify("pid1", "verified")
            assert _latest["pid1"] == "verified"

    @pytest.mark.asyncio
    async def test_notify_sets_event_for_registered_pid(self):
        with patch.object(sse_module.settings, "REDIS_MODE", "none"):
            event = asyncio.Event()
            _signals["pid1"] = event
            assert not event.is_set()
            await notify("pid1", "pending")
            assert event.is_set()

    @pytest.mark.asyncio
    async def test_notify_no_latest_for_unknown_pid(self):
        with patch.object(sse_module.settings, "REDIS_MODE", "none"):
            # No subscriber → notify() is a no-op in single-pod mode.
            # DB state emit on (re)connect handles the "fired before connect" case.
            await notify("unknown-pid", "failed")
            assert "unknown-pid" not in _latest

    def teardown_method(self):
        _signals.clear()
        _latest.clear()


# ---------------------------------------------------------------------------
# Unit tests: notify() — multi-pod mode
# ---------------------------------------------------------------------------


class TestNotifyMultiPod:
    def setup_method(self):
        _signals.clear()
        _latest.clear()

    @pytest.mark.asyncio
    async def test_notify_publishes_to_redis(self):
        mock_redis = AsyncMock()
        sse_module._redis_client = mock_redis
        try:
            with patch.object(sse_module.settings, "REDIS_MODE", "single"):
                await notify("pid1", "verified")
                mock_redis.publish.assert_awaited_once_with(
                    "sse:pid1", json.dumps({"status": "verified"})
                )
        finally:
            sse_module._redis_client = None

    @pytest.mark.asyncio
    async def test_notify_logs_warning_when_no_redis_client(self, caplog):
        sse_module._redis_client = None
        with patch.object(sse_module.settings, "REDIS_MODE", "single"):
            await notify("pid1", "verified")
            # Should not raise; redis_client is None so it logs a warning
            assert _latest.get("pid1") is None  # not stored in single-pod dict

    def teardown_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None


# ---------------------------------------------------------------------------
# Integration tests: SSE endpoint
# ---------------------------------------------------------------------------


class TestSseEndpoint:
    """Integration tests for GET /sse/status/{pid}."""

    def setup_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def teardown_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def test_sse_returns_event_stream_content_type(self):
        """SSE endpoint must return text/event-stream content type.

        Uses VERIFIED (terminal) so the generator closes immediately.
        """
        app = _make_app()
        auth_session = _make_auth_session(AuthSessionState.VERIFIED)
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=auth_session)

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/sse/status/507f1f77bcf86cd799439011")
                assert resp.status_code == 200
                assert "text/event-stream" in resp.headers["content-type"]

    def test_sse_emits_current_db_state_on_connect(self):
        """On connect, endpoint should immediately emit the current DB proof_status."""
        app = _make_app()
        auth_session = _make_auth_session(AuthSessionState.VERIFIED)
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=auth_session)

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/sse/status/507f1f77bcf86cd799439011")
                assert resp.status_code == 200
                assert b"verified" in resp.content

    def test_sse_closes_stream_on_terminal_status_in_db(self):
        """When DB state is already terminal, stream should end after first event."""
        app = _make_app()
        for terminal_status in TERMINAL_STATES:
            auth_session = _make_auth_session(terminal_status)
            mock_crud = MagicMock()
            mock_crud.get = AsyncMock(return_value=auth_session)

            with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
                with patch("api.routers.sse.settings") as mock_settings:
                    mock_settings.REDIS_MODE = "none"
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.get("/sse/status/507f1f77bcf86cd799439011")
                    assert resp.status_code == 200
                    assert terminal_status.value.encode() in resp.content


# ---------------------------------------------------------------------------
# Unit tests: terminal state set
# ---------------------------------------------------------------------------


class TestTerminalStates:
    def test_terminal_states_are_correct(self):
        assert AuthSessionState.VERIFIED in TERMINAL_STATES
        assert AuthSessionState.FAILED in TERMINAL_STATES
        assert AuthSessionState.EXPIRED in TERMINAL_STATES
        assert AuthSessionState.ABANDONED in TERMINAL_STATES
        assert AuthSessionState.NOT_STARTED not in TERMINAL_STATES
        assert AuthSessionState.PENDING not in TERMINAL_STATES


# ---------------------------------------------------------------------------
# Unit tests: set_redis_client
# ---------------------------------------------------------------------------


class TestSetRedisClient:
    def teardown_method(self):
        sse_module._redis_client = None

    def test_set_redis_client_stores_client(self):
        mock_client = MagicMock()
        sse_module.set_redis_client(mock_client)
        assert sse_module._redis_client is mock_client

    def test_set_redis_client_replaces_existing(self):
        first = MagicMock()
        second = MagicMock()
        sse_module.set_redis_client(first)
        sse_module.set_redis_client(second)
        assert sse_module._redis_client is second


# ---------------------------------------------------------------------------
# Unit tests: notify() — Redis publish failure
# ---------------------------------------------------------------------------


class TestNotifyRedisFailure:
    def setup_method(self):
        _signals.clear()
        _latest.clear()

    def teardown_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    @pytest.mark.asyncio
    async def test_notify_logs_error_on_redis_publish_exception(self, caplog):
        """Redis publish failure should be caught and logged, not propagated."""
        mock_redis = AsyncMock()
        mock_redis.publish.side_effect = ConnectionError("Redis unavailable")
        sse_module._redis_client = mock_redis

        with patch.object(sse_module.settings, "REDIS_MODE", "single"):
            # Should not raise
            await notify("pid1", "verified")
            mock_redis.publish.assert_awaited_once()


# ---------------------------------------------------------------------------
# Unit tests: _get_initial_state
# ---------------------------------------------------------------------------


class TestGetInitialState:
    @pytest.mark.asyncio
    async def test_returns_status_and_terminal_flag_for_known_session(self):
        mock_db = MagicMock()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(
            return_value=_make_auth_session(AuthSessionState.VERIFIED)
        )
        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            status, is_terminal = await _get_initial_state("any-pid", mock_db)
        assert status == AuthSessionState.VERIFIED
        assert is_terminal is True

    @pytest.mark.asyncio
    async def test_returns_none_false_when_session_not_found(self):
        """DB lookup failure (session doesn't exist yet) should not raise."""
        mock_db = MagicMock()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(side_effect=Exception("not found"))
        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            status, is_terminal = await _get_initial_state("missing-pid", mock_db)
        assert status is None
        assert is_terminal is False

    @pytest.mark.asyncio
    async def test_non_terminal_status_returns_false(self):
        mock_db = MagicMock()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(
            return_value=_make_auth_session(AuthSessionState.PENDING)
        )
        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            status, is_terminal = await _get_initial_state("pid1", mock_db)
        assert status == AuthSessionState.PENDING
        assert is_terminal is False


# ---------------------------------------------------------------------------
# Unit tests: _single_pod_stream — live update loop
# ---------------------------------------------------------------------------


class TestSinglePodStream:
    def setup_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def teardown_method(self):
        _signals.clear()
        _latest.clear()

    @pytest.mark.asyncio
    async def test_stream_delivers_pending_then_terminal(self):
        """Non-terminal update followed by terminal update yields both events then closes."""
        mock_db = MagicMock()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(
            return_value=_make_auth_session(AuthSessionState.NOT_STARTED)
        )

        mock_request = MagicMock()
        mock_request.is_disconnected = AsyncMock(return_value=False)

        collected = []

        async def consume():
            with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
                with patch.object(sse_module.settings, "REDIS_MODE", "none"):
                    async for chunk in sse_module._single_pod_stream(
                        "live-pid", mock_request, mock_db
                    ):
                        collected.append(chunk)

        async def produce():
            await asyncio.sleep(0.05)
            # Directly trigger the in-process signal (same event loop as consume)
            event = _signals.get("live-pid")
            if event:
                _latest["live-pid"] = "pending"
                event.set()
            await asyncio.sleep(0.02)
            event = _signals.get("live-pid")
            if event:
                _latest["live-pid"] = "verified"
                event.set()

        await asyncio.gather(consume(), produce())

        content = "".join(collected)
        assert "not_started" in content
        assert "pending" in content
        assert "verified" in content

    def test_stream_yields_no_initial_event_when_session_not_found(self):
        """If session missing from DB, stream opens and waits (returns on disconnect)."""
        app = _make_app()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(side_effect=Exception("not found"))

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"

                # Immediately fire a terminal status so the stream closes
                import threading, time

                def _fire():
                    time.sleep(0.05)
                    pid = "507f1f77bcf86cd799439011"
                    event = _signals.get(pid)
                    if event:
                        _latest[pid] = "verified"
                        event.set()

                t = threading.Thread(target=_fire, daemon=True)
                t.start()
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/sse/status/507f1f77bcf86cd799439011")
                t.join(timeout=5)

        assert b"not_started" not in resp.content
        assert b"verified" in resp.content


# ---------------------------------------------------------------------------
# Unit tests: _next_redis_message
# ---------------------------------------------------------------------------


class TestNextRedisMessage:
    @pytest.mark.asyncio
    async def test_returns_parsed_json_from_message(self):
        async def fake_listen():
            yield {"type": "subscribe", "data": 1}  # skipped
            yield {"type": "message", "data": json.dumps({"status": "verified"})}

        mock_pubsub = MagicMock()
        mock_pubsub.listen = fake_listen
        result = await _next_redis_message(mock_pubsub)
        assert result == {"status": "verified"}

    @pytest.mark.asyncio
    async def test_raises_connection_error_when_stream_closes(self):
        """Pubsub closing without a message should raise ConnectionError."""

        async def fake_listen():
            return
            yield  # make it an async generator

        mock_pubsub = MagicMock()
        mock_pubsub.listen = fake_listen
        with pytest.raises(ConnectionError):
            await _next_redis_message(mock_pubsub)

    @pytest.mark.asyncio
    async def test_skips_non_message_events(self):
        """subscribe/psubscribe/pong frames should be skipped."""

        async def fake_listen():
            yield {"type": "subscribe", "data": 1}
            yield {"type": "pong", "data": None}
            yield {"type": "message", "data": json.dumps({"status": "failed"})}

        mock_pubsub = MagicMock()
        mock_pubsub.listen = fake_listen
        result = await _next_redis_message(mock_pubsub)
        assert result == {"status": "failed"}


# ---------------------------------------------------------------------------
# Unit tests: build_async_redis_client
# ---------------------------------------------------------------------------


class TestBuildAsyncRedisClient:
    @pytest.mark.asyncio
    async def test_single_mode_returns_redis_client(self):
        with (
            patch.object(sse_module.settings, "REDIS_MODE", "single"),
            patch.object(sse_module.settings, "REDIS_HOST", "redis:6379"),
            patch.object(sse_module.settings, "REDIS_PASSWORD", ""),
            patch.object(sse_module.settings, "REDIS_DB", 0),
            patch("api.routers.sse.async_redis.Redis") as mock_cls,
        ):
            await build_async_redis_client()
            mock_cls.assert_called_once_with(
                host="redis", port=6379, password=None, db=0
            )

    @pytest.mark.asyncio
    async def test_cluster_mode_returns_redis_client(self):
        with (
            patch.object(sse_module.settings, "REDIS_MODE", "cluster"),
            patch.object(sse_module.settings, "REDIS_HOST", "node1:6379,node2:6380"),
            patch.object(sse_module.settings, "REDIS_PASSWORD", ""),
            patch("api.routers.sse.async_redis.Redis") as mock_cls,
        ):
            await build_async_redis_client()
            # Cluster mode connects to the first node only
            mock_cls.assert_called_once_with(
                host="node1", port=6379, password=None
            )

    @pytest.mark.asyncio
    async def test_unsupported_mode_raises(self):
        with patch.object(sse_module.settings, "REDIS_MODE", "bogus"):
            with pytest.raises(ValueError, match="Unsupported REDIS_MODE"):
                await build_async_redis_client()

    @pytest.mark.asyncio
    async def test_sentinel_mode_calls_sentinel(self):
        mock_sentinel_cls = MagicMock()
        mock_sentinel_instance = MagicMock()
        mock_sentinel_cls.return_value = mock_sentinel_instance
        mock_sentinel_instance.master_for.return_value = MagicMock()

        with (
            patch.object(sse_module.settings, "REDIS_MODE", "sentinel"),
            patch.object(sse_module.settings, "REDIS_HOST", "sentinel1:26379"),
            patch.object(sse_module.settings, "REDIS_PASSWORD", ""),
            patch.object(
                sse_module.settings, "REDIS_SENTINEL_MASTER_NAME", "mymaster"
            ),
            patch("api.routers.sse.async_redis.sentinel.Sentinel", mock_sentinel_cls),
        ):
            await build_async_redis_client()
            mock_sentinel_instance.master_for.assert_called_once_with(
                "mymaster", password=None
            )


# ---------------------------------------------------------------------------
# Integration tests: SSE endpoint routing
# ---------------------------------------------------------------------------


class TestSseEndpointRouting:
    def setup_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def teardown_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def test_uses_multi_pod_stream_when_redis_client_set(self):
        """When _redis_client is set and REDIS_MODE != none, multi-pod path is used."""
        app = _make_app()
        auth_session = _make_auth_session(AuthSessionState.VERIFIED)
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=auth_session)

        # pubsub() is a synchronous method on the Redis client — use MagicMock so
        # calling it returns mock_pubsub directly (not a coroutine).
        mock_redis = MagicMock()
        mock_pubsub = MagicMock()
        mock_redis.pubsub.return_value = mock_pubsub
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.aclose = AsyncMock()

        # Terminal state from DB causes return before entering the Redis listen loop.
        async def empty_listen():
            return
            yield

        mock_pubsub.listen = empty_listen
        sse_module._redis_client = mock_redis

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "single"
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/sse/status/507f1f77bcf86cd799439011")

        assert resp.status_code == 200
        assert b"verified" in resp.content
        # subscribe was called — confirms multi-pod path was taken
        mock_pubsub.subscribe.assert_awaited_once_with("sse:507f1f77bcf86cd799439011")

    def test_falls_back_to_single_pod_when_redis_client_none(self):
        """When REDIS_MODE != none but _redis_client is None, fall back with warning."""
        app = _make_app()
        auth_session = _make_auth_session(AuthSessionState.VERIFIED)
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=auth_session)

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "single"
                # _redis_client is None (not initialized)
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/sse/status/507f1f77bcf86cd799439011")

        assert resp.status_code == 200
        assert b"verified" in resp.content
