"""Tests for SSE (Server-Sent Events) status endpoint."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.authSessions.models import AuthSession, AuthSessionState
from api.core.models import PyObjectId
from api.routers import sse as sse_module
from api.routers.sse import (
    TERMINAL_STATES,
    _format_event,
    _latest,
    _signals,
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
