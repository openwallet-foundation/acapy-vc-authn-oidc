"""Tests for SSE (Server-Sent Events) status endpoint."""

import asyncio
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.authSessions.models import AuthSession, AuthSessionState
from api.core.models import PyObjectId
from api.routers import sse as sse_module
from api.routers.sse import (
    TERMINAL_STATES,
    _expire_if_needed,
    _format_event,
    _get_initial_state,
    _latest,
    _poll_redis_pubsub,
    _seconds_until_expiry,
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
            status, is_terminal, _, auth_session = await _get_initial_state(
                "any-pid", mock_db
            )
        assert status == AuthSessionState.VERIFIED
        assert is_terminal is True
        assert auth_session is not None

    @pytest.mark.asyncio
    async def test_returns_none_false_when_session_not_found(self):
        """DB lookup failure (session doesn't exist yet) should not raise."""
        mock_db = MagicMock()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(side_effect=Exception("not found"))
        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            status, is_terminal, _, auth_session = await _get_initial_state(
                "missing-pid", mock_db
            )
        assert status is None
        assert is_terminal is False
        assert auth_session is None

    @pytest.mark.asyncio
    async def test_non_terminal_status_returns_false(self):
        mock_db = MagicMock()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(
            return_value=_make_auth_session(AuthSessionState.PENDING)
        )
        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            status, is_terminal, _, _ = await _get_initial_state("pid1", mock_db)
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
                import threading
                import time

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
# Unit tests: _poll_redis_pubsub
# ---------------------------------------------------------------------------


class TestPollRedisPubsub:
    @pytest.mark.asyncio
    async def test_returns_parsed_json_on_message(self):
        mock_pubsub = AsyncMock()
        mock_pubsub.get_message = AsyncMock(
            return_value={"type": "message", "data": json.dumps({"status": "verified"})}
        )
        result = await _poll_redis_pubsub(mock_pubsub)
        assert result == {"status": "verified"}
        mock_pubsub.get_message.assert_awaited_once_with(
            ignore_subscribe_messages=True, timeout=0
        )

    @pytest.mark.asyncio
    async def test_returns_none_when_no_message(self):
        """get_message returns None when no message is queued."""
        mock_pubsub = AsyncMock()
        mock_pubsub.get_message = AsyncMock(return_value=None)
        result = await _poll_redis_pubsub(mock_pubsub)
        assert result is None

    @pytest.mark.asyncio
    async def test_connection_error_propagates(self):
        """ConnectionError from get_message propagates to the caller."""
        mock_pubsub = AsyncMock()
        mock_pubsub.get_message = AsyncMock(
            side_effect=ConnectionError("pubsub closed")
        )
        with pytest.raises(ConnectionError):
            await _poll_redis_pubsub(mock_pubsub)

    @pytest.mark.asyncio
    async def test_returns_none_for_non_message_type(self):
        """Non-message frames (pong, subscribe ack) return None."""
        mock_pubsub = AsyncMock()
        mock_pubsub.get_message = AsyncMock(return_value={"type": "pong", "data": None})
        result = await _poll_redis_pubsub(mock_pubsub)
        assert result is None


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
            mock_cls.assert_called_once_with(host="node1", port=6379, password=None)

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
            patch.object(sse_module.settings, "REDIS_SENTINEL_MASTER_NAME", "mymaster"),
            patch("api.routers.sse.async_redis.sentinel.Sentinel", mock_sentinel_cls),
        ):
            await build_async_redis_client()
            mock_sentinel_instance.master_for.assert_called_once_with(
                "mymaster", password=None
            )

    @pytest.mark.asyncio
    async def test_sentinel_mode_passes_password(self):
        mock_sentinel_cls = MagicMock()
        mock_sentinel_instance = MagicMock()
        mock_sentinel_cls.return_value = mock_sentinel_instance
        mock_sentinel_instance.master_for.return_value = MagicMock()

        with (
            patch.object(sse_module.settings, "REDIS_MODE", "sentinel"),
            patch.object(sse_module.settings, "REDIS_HOST", "sentinel1:26379"),
            patch.object(sse_module.settings, "REDIS_PASSWORD", "secret"),
            patch.object(sse_module.settings, "REDIS_SENTINEL_MASTER_NAME", "mymaster"),
            patch("api.routers.sse.async_redis.sentinel.Sentinel", mock_sentinel_cls),
        ):
            await build_async_redis_client()
            # Password goes into sentinel_kwargs, not directly to master_for
            _, kwargs = mock_sentinel_cls.call_args
            assert kwargs["sentinel_kwargs"]["password"] == "secret"


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


# ---------------------------------------------------------------------------
# Unit tests: _seconds_until_expiry
# ---------------------------------------------------------------------------


class TestSecondsUntilExpiry:
    def test_returns_30_when_timestamp_is_none(self):
        assert _seconds_until_expiry(None) == 30.0

    def test_returns_remaining_seconds_when_future(self):
        future = datetime.now(UTC) + timedelta(seconds=15)
        result = _seconds_until_expiry(future)
        assert 13.0 < result <= 15.0

    def test_clamps_to_minimum_1_when_nearly_expired(self):
        nearly_expired = datetime.now(UTC) + timedelta(milliseconds=100)
        assert _seconds_until_expiry(nearly_expired) == 1.0

    def test_clamps_to_minimum_1_when_already_past(self):
        past = datetime.now(UTC) - timedelta(seconds=5)
        assert _seconds_until_expiry(past) == 1.0

    def test_clamps_to_maximum_30_when_far_future(self):
        far_future = datetime.now(UTC) + timedelta(seconds=300)
        assert _seconds_until_expiry(far_future) == 30.0

    def test_handles_naive_datetime(self):
        future = datetime.now() + timedelta(seconds=15)
        result = _seconds_until_expiry(future)
        assert 13.0 < result <= 15.0


# ---------------------------------------------------------------------------
# Unit tests: _expire_if_needed
# ---------------------------------------------------------------------------


class TestExpireIfNeeded:
    @pytest.mark.asyncio
    async def test_returns_true_and_patches_db_when_expired(self):
        mock_db = MagicMock()
        mock_crud = MagicMock()
        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) - timedelta(seconds=30)
        mock_crud.get = AsyncMock(return_value=session)
        mock_crud.patch = AsyncMock()

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            result = await _expire_if_needed(str(session.id), mock_db)

        assert result is True
        mock_crud.patch.assert_awaited_once()
        call_args = mock_crud.patch.call_args
        assert call_args[0][1].proof_status == AuthSessionState.EXPIRED

    @pytest.mark.asyncio
    async def test_returns_false_when_not_yet_expired(self):
        mock_db = MagicMock()
        mock_crud = MagicMock()
        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) + timedelta(seconds=300)
        mock_crud.get = AsyncMock(return_value=session)
        mock_crud.patch = AsyncMock()

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            result = await _expire_if_needed(str(session.id), mock_db)

        assert result is False
        mock_crud.patch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_returns_false_for_non_not_started_status(self):
        mock_db = MagicMock()
        mock_crud = MagicMock()
        for status in [
            AuthSessionState.PENDING,
            AuthSessionState.VERIFIED,
            AuthSessionState.FAILED,
            AuthSessionState.EXPIRED,
        ]:
            session = _make_auth_session(status)
            session.expired_timestamp = datetime.now(UTC) - timedelta(seconds=30)
            mock_crud.get = AsyncMock(return_value=session)
            mock_crud.patch = AsyncMock()

            with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
                result = await _expire_if_needed(str(session.id), mock_db)

            assert result is False, f"Expected False for status={status}"
            mock_crud.patch.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_returns_false_and_logs_on_db_error(self):
        mock_db = MagicMock()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(side_effect=Exception("DB unavailable"))

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            result = await _expire_if_needed("any-pid", mock_db)

        assert result is False


# ---------------------------------------------------------------------------
# Integration tests: expiry-on-connect in _single_pod_stream
# ---------------------------------------------------------------------------


class TestSinglePodStreamExpiry:
    def setup_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def teardown_method(self):
        _signals.clear()
        _latest.clear()

    def test_stream_emits_expired_immediately_when_session_already_expired(self):
        """If the session deadline has already passed on connect, emit expired and close."""
        app = _make_app()
        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) - timedelta(seconds=30)

        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=session)
        mock_crud.patch = AsyncMock()

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/sse/status/507f1f77bcf86cd799439011")

        assert resp.status_code == 200
        assert b"expired" in resp.content
        # Should have patched the DB to record the expiry
        mock_crud.patch.assert_awaited()

    @pytest.mark.asyncio
    async def test_stream_emits_expired_on_keepalive_timeout(self):
        """Timeout fires → _expire_if_needed returns True → expired event emitted."""
        mock_db = MagicMock()
        mock_request = MagicMock()
        mock_request.is_disconnected = AsyncMock(return_value=False)

        # Session not yet expired on connect (so connect-time check passes)
        # then expired when the timeout handler calls _expire_if_needed.
        future_session = _make_auth_session(AuthSessionState.NOT_STARTED)
        future_session.expired_timestamp = datetime.now(UTC) + timedelta(seconds=300)
        expired_session = _make_auth_session(AuthSessionState.NOT_STARTED)
        expired_session.expired_timestamp = datetime.now(UTC) - timedelta(seconds=1)

        mock_crud = MagicMock()
        # _get_initial_state, connect-time _expire_if_needed, then loop _expire_if_needed
        mock_crud.get = AsyncMock(
            side_effect=[future_session, future_session, expired_session]
        )
        mock_crud.patch = AsyncMock()

        call_count = 0
        original_wait_for = asyncio.wait_for

        async def mock_wait_for(coro, timeout):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                coro.close()
                raise asyncio.TimeoutError()
            return await original_wait_for(coro, timeout)

        collected = []
        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.asyncio.wait_for", mock_wait_for):
                async for chunk in sse_module._single_pod_stream(
                    "test-pid", mock_request, mock_db
                ):
                    collected.append(chunk)

        content = "".join(collected)
        assert ": keepalive" in content
        assert "expired" in content

    @pytest.mark.asyncio
    async def test_stream_continues_when_event_fires_with_no_status(self):
        """Event fires but _latest has no entry → continue without yielding."""
        mock_db = MagicMock()
        mock_request = MagicMock()

        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) + timedelta(seconds=300)
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=session)

        # First call: disconnected=False (enter loop), second call: disconnected=True (exit)
        mock_request.is_disconnected = AsyncMock(side_effect=[False, True])

        collected = []

        async def consume():
            with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
                async for chunk in sse_module._single_pod_stream(
                    "pid-no-status", mock_request, mock_db
                ):
                    collected.append(chunk)

        async def produce():
            await asyncio.sleep(0.02)
            # Fire the event without putting anything in _latest
            event = _signals.get("pid-no-status")
            if event:
                event.set()

        await asyncio.gather(consume(), produce())
        # Stream should not have emitted any status update (only the initial NOT_STARTED)
        content = "".join(collected)
        assert content.count("not_started") == 1


# ---------------------------------------------------------------------------
# Integration tests: expiry in _multi_pod_stream
# ---------------------------------------------------------------------------


class TestMultiPodStreamExpiry:
    def setup_method(self):
        _signals.clear()
        _latest.clear()

    def teardown_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def test_multi_pod_stream_emits_expired_on_connect(self):
        """Multi-pod: already-expired session on connect → emit expired and close."""
        app = _make_app()
        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) - timedelta(seconds=30)

        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=session)
        mock_crud.patch = AsyncMock()

        mock_redis = MagicMock()
        mock_pubsub = MagicMock()
        mock_redis.pubsub.return_value = mock_pubsub
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.aclose = AsyncMock()

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
        assert b"expired" in resp.content
        mock_crud.patch.assert_awaited()


# ---------------------------------------------------------------------------
# Unit tests: double-subscribe warning in _single_pod_stream
# ---------------------------------------------------------------------------


class TestSinglePodDoubleSubscribeWarning:
    def setup_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def teardown_method(self):
        _signals.clear()
        _latest.clear()

    @pytest.mark.asyncio
    async def test_warns_when_pid_already_subscribed(self):
        """If _signals already has an entry for pid, a warning is logged."""
        mock_db = MagicMock()
        mock_request = MagicMock()
        # is_disconnected=True causes the while loop to exit immediately after setup
        mock_request.is_disconnected = AsyncMock(return_value=True)

        # Use NOT_STARTED with a future timestamp so the stream reaches the
        # _signals assignment (VERIFIED would return early as terminal).
        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) + timedelta(seconds=300)
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=session)

        # Pre-populate _signals to simulate an existing subscriber
        existing_event = asyncio.Event()
        _signals["dup-pid"] = existing_event

        logged_warnings = []

        def capture_warning(*args, **kwargs):
            logged_warnings.append(kwargs.get("pid") or args)

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch.object(
                sse_module.logger, "warning", side_effect=capture_warning
            ):
                async for _ in sse_module._single_pod_stream(
                    "dup-pid", mock_request, mock_db
                ):
                    pass

        assert any("dup-pid" in str(w) for w in logged_warnings)


# ---------------------------------------------------------------------------
# Unit tests: SSE-only expiry (no polling needed)
# ---------------------------------------------------------------------------


class TestSseOnlyExpiry:
    """Verify that _expire_if_needed both patches DB and triggers the expired SSE
    event — confirming the polling timer in the frontend is not needed."""

    def setup_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def teardown_method(self):
        _signals.clear()
        _latest.clear()

    @pytest.mark.asyncio
    async def test_expire_if_needed_patches_db_and_returns_true(self):
        """_expire_if_needed marks the session EXPIRED in DB and signals expiry."""
        mock_db = MagicMock()
        mock_crud = MagicMock()
        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) - timedelta(seconds=60)
        mock_crud.get = AsyncMock(return_value=session)
        mock_crud.patch = AsyncMock()

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            result = await _expire_if_needed(str(session.id), mock_db)

        assert result is True
        mock_crud.patch.assert_awaited_once()
        patched = mock_crud.patch.call_args[0][1]
        assert patched.proof_status == AuthSessionState.EXPIRED

    def test_sse_stream_emits_expired_event_without_polling(self):
        """The SSE stream emits an 'expired' event server-side; no client polling needed."""
        app = _make_app()
        session = _make_auth_session(AuthSessionState.NOT_STARTED)
        session.expired_timestamp = datetime.now(UTC) - timedelta(seconds=60)

        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(return_value=session)
        mock_crud.patch = AsyncMock()

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"
                client = TestClient(app, raise_server_exceptions=False)
                resp = client.get("/sse/status/507f1f77bcf86cd799439011")

        assert resp.status_code == 200
        assert b"expired" in resp.content
        # DB was patched — expiry was handled server-side via SSE, not polling
        mock_crud.patch.assert_awaited()


# ---------------------------------------------------------------------------
# Integration tests: reconnect-after-terminal-status (mobile backgrounding)
# ---------------------------------------------------------------------------


class TestReconnectAfterStatusChange:
    """Simulates the mobile backgrounding flow:

    1. Client opens SSE stream in NOT_STARTED.
    2. Tab backgrounds → SSE connection drops (server-side it just ends).
    3. ACA-Py webhook arrives while no subscriber is live; DB flips to
       terminal status and notify() publishes (delivered to no one).
    4. Tab returns → native EventSource (or visibilitychange handler)
       reconnects, sending the Last-Event-ID header.
    5. Server reads current DB state, emits the terminal status, closes.
    """

    def setup_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def teardown_method(self):
        _signals.clear()
        _latest.clear()
        sse_module._redis_client = None

    def test_reconnect_single_pod_receives_terminal_status_after_missed_notify(self):
        app = _make_app()
        not_started = _make_auth_session(AuthSessionState.NOT_STARTED)
        not_started.expired_timestamp = datetime.now(UTC) + timedelta(seconds=300)
        verified = _make_auth_session(AuthSessionState.VERIFIED)

        mock_crud = MagicMock()
        # Connect #1 reads NOT_STARTED; in between the DB flips; Connect #2
        # reads VERIFIED.
        mock_crud.get = AsyncMock(side_effect=[not_started, not_started, verified])
        mock_crud.patch = AsyncMock()

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"
                client = TestClient(app, raise_server_exceptions=False)

                # Connect #1 — client sees the initial NOT_STARTED state and
                # closes (simulating tab backgrounding). The client does NOT
                # fully consume the stream because the while loop would block
                # on the wait_fn; closing the TestClient context ends it.
                with client.stream(
                    "GET", "/sse/status/507f1f77bcf86cd799439011"
                ) as resp1:
                    assert resp1.status_code == 200
                    # Read just enough to confirm initial state arrived.
                    chunks = []
                    for chunk in resp1.iter_bytes():
                        chunks.append(chunk)
                        if b"not_started" in b"".join(chunks):
                            break
                    assert b"not_started" in b"".join(chunks)

                # Simulate a missed notify() while backgrounded — nothing is
                # listening, so _latest/_signals stays empty. This is exactly
                # what happens in the real flow.
                #
                # Connect #2 — browser reconnects with Last-Event-ID header.
                # Server reads DB (now VERIFIED), emits verified, closes.
                resp2 = client.get(
                    "/sse/status/507f1f77bcf86cd799439011",
                    headers={"Last-Event-ID": "0"},
                )
                assert resp2.status_code == 200
                assert b"verified" in resp2.content

    def test_terminal_on_connect_logs_is_reconnect_from_last_event_id_header(self):
        """When Last-Event-ID is present and the initial state is terminal, the
        structured log records is_reconnect=True so production traffic can be
        audited for the mobile backgrounding recovery path."""
        app = _make_app()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(
            return_value=_make_auth_session(AuthSessionState.VERIFIED)
        )

        log_calls = []

        def capture_info(msg, **kwargs):
            log_calls.append((msg, kwargs))

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"
                with patch.object(sse_module.logger, "info", side_effect=capture_info):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.get(
                        "/sse/status/507f1f77bcf86cd799439011",
                        headers={"Last-Event-ID": "42"},
                    )

        assert resp.status_code == 200
        terminal_logs = [
            kwargs
            for msg, kwargs in log_calls
            if "SSE initial-state emit is terminal" in msg
        ]
        assert len(terminal_logs) == 1
        assert terminal_logs[0]["is_reconnect"] is True
        assert terminal_logs[0]["status"] == AuthSessionState.VERIFIED

    def test_terminal_on_connect_logs_is_reconnect_false_without_header(self):
        """First-time connect (no Last-Event-ID) logs is_reconnect=False."""
        app = _make_app()
        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(
            return_value=_make_auth_session(AuthSessionState.VERIFIED)
        )

        log_calls = []

        def capture_info(msg, **kwargs):
            log_calls.append((msg, kwargs))

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "none"
                with patch.object(sse_module.logger, "info", side_effect=capture_info):
                    client = TestClient(app, raise_server_exceptions=False)
                    resp = client.get("/sse/status/507f1f77bcf86cd799439011")

        assert resp.status_code == 200
        terminal_logs = [
            kwargs
            for msg, kwargs in log_calls
            if "SSE initial-state emit is terminal" in msg
        ]
        assert len(terminal_logs) == 1
        assert terminal_logs[0]["is_reconnect"] is False

    def test_reconnect_multi_pod_receives_terminal_status_after_missed_notify(self):
        """Multi-pod variant: Redis pub/sub publish during disconnect is lost,
        but reconnect reads DB and delivers terminal status."""
        app = _make_app()
        not_started = _make_auth_session(AuthSessionState.NOT_STARTED)
        not_started.expired_timestamp = datetime.now(UTC) + timedelta(seconds=300)
        verified = _make_auth_session(AuthSessionState.VERIFIED)

        mock_crud = MagicMock()
        mock_crud.get = AsyncMock(side_effect=[not_started, not_started, verified])
        mock_crud.patch = AsyncMock()

        mock_redis = MagicMock()
        mock_pubsub = MagicMock()
        mock_redis.pubsub.return_value = mock_pubsub
        mock_pubsub.subscribe = AsyncMock()
        mock_pubsub.unsubscribe = AsyncMock()
        mock_pubsub.aclose = AsyncMock()
        mock_pubsub.get_message = AsyncMock(return_value=None)
        sse_module._redis_client = mock_redis

        with patch("api.routers.sse.AuthSessionCRUD", return_value=mock_crud):
            with patch("api.routers.sse.settings") as mock_settings:
                mock_settings.REDIS_MODE = "single"
                client = TestClient(app, raise_server_exceptions=False)

                with client.stream(
                    "GET", "/sse/status/507f1f77bcf86cd799439011"
                ) as resp1:
                    assert resp1.status_code == 200
                    chunks = []
                    for chunk in resp1.iter_bytes():
                        chunks.append(chunk)
                        if b"not_started" in b"".join(chunks):
                            break
                    assert b"not_started" in b"".join(chunks)

                resp2 = client.get(
                    "/sse/status/507f1f77bcf86cd799439011",
                    headers={"Last-Event-ID": "0"},
                )
                assert resp2.status_code == 200
                assert b"verified" in resp2.content
