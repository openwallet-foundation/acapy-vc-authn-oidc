#!/usr/bin/env python3
"""
Test Redis fallback behavior to ensure graceful degradation.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import time

from api.routers.socketio import (
    safe_emit,
    create_socket_manager,
    _should_use_redis_adapter,
    validate_redis_connection,
    sio,
)


class TestSafeEmit:
    """Test the safe_emit wrapper function."""

    @pytest.mark.asyncio
    async def test_safe_emit_success(self):
        """Test safe_emit works when Socket.IO is functioning."""
        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.return_value = True

            result = await safe_emit("test_event", {"data": "test"}, to="test_room")

            mock_emit.assert_called_once_with(
                "test_event", {"data": "test"}, to="test_room"
            )

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_safe_emit_graceful_failure(self, mock_settings):
        """Test safe_emit continues gracefully when Redis fails and REDIS_REQUIRED=false."""
        mock_settings.REDIS_REQUIRED = False

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Redis connection failed")

            # Should not raise exception
            await safe_emit("test_event", {"data": "test"}, to="test_room")

            mock_emit.assert_called_once_with(
                "test_event", {"data": "test"}, to="test_room"
            )

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_safe_emit_crash_on_required_failure(self, mock_settings):
        """Test safe_emit crashes when Redis fails and REDIS_REQUIRED=true."""
        mock_settings.REDIS_REQUIRED = True

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Redis connection failed")

            with patch("sys.exit") as mock_exit:
                await safe_emit("test_event", {"data": "test"}, to="test_room")
                mock_exit.assert_called_once_with(1)

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_safe_emit_handles_various_kwargs(self, mock_settings):
        """Test safe_emit handles various Socket.IO parameters correctly."""
        mock_settings.REDIS_REQUIRED = False

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.return_value = True

            await safe_emit(
                "status",
                {"status": "verified"},
                to="test_sid",
                namespace="/test",
                callback=lambda: None,
            )

            mock_emit.assert_called_once_with(
                "status",
                {"status": "verified"},
                to="test_sid",
                namespace="/test",
                callback=mock_emit.call_args[1]["callback"],
            )


class TestRedisValidation:
    """Test Redis connection validation."""

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_validate_redis_skipped_when_not_required(self, mock_settings):
        """Test validation is skipped when REDIS_REQUIRED=false."""
        mock_settings.REDIS_REQUIRED = False

        # Should complete without error
        await validate_redis_connection()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_validate_redis_success(self, mock_settings):
        """Test validation succeeds when Redis is available."""
        mock_settings.REDIS_REQUIRED = True
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_DB = 0

        with patch("redis.asyncio.from_url") as mock_redis:
            mock_client = AsyncMock()
            mock_redis.return_value = mock_client
            mock_client.ping = AsyncMock()
            mock_client.close = AsyncMock()

            await validate_redis_connection()

            mock_client.ping.assert_called_once()
            mock_client.close.assert_called_once()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_validate_redis_failure_crashes(self, mock_settings):
        """Test validation crashes when Redis is required but unavailable."""
        mock_settings.REDIS_REQUIRED = True
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_HOST = "nonexistent-redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_DB = 0

        with patch("redis.asyncio.from_url") as mock_redis:
            mock_redis.side_effect = Exception("Connection failed")

            with patch("sys.exit") as mock_exit:
                await validate_redis_connection()
                mock_exit.assert_called_once_with(1)


class TestRedisConfiguration:
    """Test Redis configuration and fallback logic."""

    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_disabled(self, mock_settings):
        """Test Redis adapter is disabled when USE_REDIS_ADAPTER is False."""
        mock_settings.USE_REDIS_ADAPTER = False
        mock_settings.REDIS_HOST = "redis"

        result = _should_use_redis_adapter()
        assert not result

    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_no_host(self, mock_settings):
        """Test Redis adapter falls back when no REDIS_HOST provided."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = ""

        result = _should_use_redis_adapter()
        assert not result

    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_enabled(self, mock_settings):
        """Test Redis adapter is enabled when properly configured."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"

        result = _should_use_redis_adapter()
        assert result

    @patch("api.routers.socketio.settings")
    def test_create_socket_manager_disabled(self, mock_settings):
        """Test socket manager creation when Redis is disabled."""
        mock_settings.USE_REDIS_ADAPTER = False
        mock_settings.REDIS_HOST = "redis"

        manager = create_socket_manager()
        assert manager is None

    @patch("api.routers.socketio.settings")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_redis_enabled(
        self, mock_redis_manager, mock_settings
    ):
        """Test socket manager creates Redis manager when enabled."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_DB = 0
        mock_settings.REDIS_REQUIRED = False

        mock_instance = Mock()
        mock_redis_manager.return_value = mock_instance

        manager = create_socket_manager()

        assert manager is mock_instance
        mock_redis_manager.assert_called_once_with("redis://redis:6379/0")

    @patch("api.routers.socketio.settings")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_redis_failure_graceful(
        self, mock_redis_manager, mock_settings
    ):
        """Test socket manager graceful fallback when Redis fails to initialize."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_DB = 0
        mock_settings.REDIS_REQUIRED = False

        mock_redis_manager.side_effect = Exception("Redis connection failed")

        manager = create_socket_manager()
        assert manager is None

    @patch("api.routers.socketio.settings")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_redis_failure_crash(
        self, mock_redis_manager, mock_settings
    ):
        """Test socket manager crashes when Redis required but fails to initialize."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_DB = 0
        mock_settings.REDIS_REQUIRED = True

        mock_redis_manager.side_effect = Exception("Redis connection failed")

        with patch("sys.exit") as mock_exit:
            manager = create_socket_manager()
            mock_exit.assert_called_once_with(1)


class TestIntegrationScenarios:
    """Integration tests for various Redis deployment scenarios."""

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_issue_854_no_infinite_loops(self, mock_settings):
        """Test that Redis failures don't cause infinite loops (Issue #854)."""
        mock_settings.REDIS_REQUIRED = False

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Redis publish failed")

            # Perform multiple operations that would trigger Redis failures
            start_time = time.time()
            for i in range(10):
                await safe_emit(f"test_{i}", {"data": i}, to=f"room_{i}")

            elapsed_time = time.time() - start_time

            # Should complete quickly without getting stuck in retry loops
            assert elapsed_time < 1.0  # Should complete almost immediately
            assert mock_emit.call_count == 10  # All calls should have been attempted

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_graceful_degradation_scenario(self, mock_settings):
        """Test graceful degradation when Redis becomes unavailable during runtime."""
        mock_settings.REDIS_REQUIRED = False

        call_count = 0

        async def mock_emit_with_failure(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count > 3:
                raise Exception("Redis connection lost")
            return True

        with patch.object(sio, "emit", side_effect=mock_emit_with_failure):
            # First few calls succeed
            await safe_emit("status", {"status": "pending"})
            await safe_emit("status", {"status": "verified"})
            await safe_emit("status", {"status": "completed"})

            # Subsequent calls fail but are handled gracefully
            await safe_emit("status", {"status": "expired"})
            await safe_emit("status", {"status": "failed"})

            assert call_count == 5  # All attempts were made

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_strict_mode_scenario(self, mock_settings):
        """Test strict mode crashes immediately on Redis failure."""
        mock_settings.REDIS_REQUIRED = True

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Critical Redis failure")

            with patch("sys.exit") as mock_exit:
                await safe_emit("status", {"status": "verified"})
                mock_exit.assert_called_once_with(1)
                # Only one call should be made before crashing
                assert mock_emit.call_count == 1
