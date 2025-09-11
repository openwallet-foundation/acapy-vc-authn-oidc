#!/usr/bin/env python3
"""
Test Redis fallback behavior to ensure proper handling when USE_REDIS_ADAPTER is enabled/disabled.
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
import time

from api.routers.socketio import (
    safe_emit,
    create_socket_manager,
    _should_use_redis_adapter,
    _validate_redis_before_manager_creation,
    _patch_redis_manager_for_crash_on_failure,
    validate_redis_connection,
    sio,
    RedisCriticalError,
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
    async def test_safe_emit_graceful_failure_adapter_disabled(self, mock_settings):
        """Test safe_emit continues gracefully when Redis fails and USE_REDIS_ADAPTER=false."""
        mock_settings.USE_REDIS_ADAPTER = False

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Redis connection failed")

            # Should not raise exception
            await safe_emit("test_event", {"data": "test"}, to="test_room")

            mock_emit.assert_called_once_with(
                "test_event", {"data": "test"}, to="test_room"
            )

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_safe_emit_crash_on_adapter_enabled_failure(self, mock_settings):
        """Test safe_emit crashes when Redis fails and USE_REDIS_ADAPTER=true."""
        mock_settings.USE_REDIS_ADAPTER = True

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Redis connection failed")

            with pytest.raises(RedisCriticalError, match="Redis Socket.IO emit failed"):
                await safe_emit("test_event", {"data": "test"}, to="test_room")

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_safe_emit_handles_various_kwargs(self, mock_settings):
        """Test safe_emit handles various Socket.IO parameters correctly."""
        mock_settings.USE_REDIS_ADAPTER = False

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
    async def test_validate_redis_skipped_when_adapter_disabled(self, mock_settings):
        """Test validation is skipped when USE_REDIS_ADAPTER=false."""
        mock_settings.USE_REDIS_ADAPTER = False

        # Should complete without error
        await validate_redis_connection()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_validate_redis_success(self, mock_settings):
        """Test validation succeeds when Redis is available."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_DB = 0

        with patch("api.routers.socketio.async_redis.from_url") as mock_redis:
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
        """Test validation crashes when Redis adapter is enabled but Redis is unavailable."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_HOST = "nonexistent-redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_DB = 0

        with patch("api.routers.socketio.async_redis.from_url") as mock_redis:
            mock_redis.side_effect = Exception("Connection failed")

            with pytest.raises(
                RedisCriticalError, match="Redis connection validation failed"
            ):
                await validate_redis_connection()


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
    @patch("api.routers.socketio._validate_redis_before_manager_creation")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_redis_enabled(
        self, mock_redis_manager, mock_validate_redis, mock_settings
    ):
        """Test socket manager creates Redis manager when enabled."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_DB = 0

        # Mock successful validation
        mock_validate_redis.return_value = None

        mock_instance = Mock()
        mock_redis_manager.return_value = mock_instance

        manager = create_socket_manager()

        assert manager is mock_instance
        mock_validate_redis.assert_called_once_with("redis://redis:6379/0")
        mock_redis_manager.assert_called_once_with("redis://redis:6379/0")

    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio._validate_redis_before_manager_creation")
    def test_create_socket_manager_redis_failure_crash(
        self, mock_validate_redis, mock_settings
    ):
        """Test socket manager crashes when Redis validation fails before manager creation."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_DB = 0

        # Simulate Redis validation failure
        mock_validate_redis.side_effect = RedisCriticalError(
            "Redis validation failed before manager creation: Connection refused"
        )

        with pytest.raises(
            RedisCriticalError, match="Redis validation failed before manager creation"
        ):
            manager = create_socket_manager()

    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.routers.socketio._validate_redis_before_manager_creation")
    @patch("api.routers.socketio.socketio.AsyncRedisManager")
    def test_create_socket_manager_unexpected_exception(
        self, mock_manager, mock_validate, mock_should_use, mock_settings
    ):
        """Test socket manager handles unexpected exceptions during creation."""
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = ""
        mock_settings.REDIS_DB = 0

        # Setup
        mock_should_use.return_value = True
        mock_validate.return_value = None  # Validation passes
        mock_manager.side_effect = RuntimeError("Unexpected socket.io error")

        # Execute and verify
        with pytest.raises(
            RedisCriticalError, match="Redis adapter initialization failed"
        ):
            create_socket_manager()


class TestInternalRedisFunctions:
    """Test internal Redis validation and patching functions."""

    @patch("api.routers.socketio.redis.from_url")
    def test_validate_redis_before_manager_creation_success(self, mock_redis):
        """Test successful Redis validation before manager creation."""
        # Setup
        mock_client = Mock()
        mock_redis.return_value = mock_client
        mock_client.ping.return_value = True

        # Execute - should not raise exception
        _validate_redis_before_manager_creation("redis://localhost:6379/0")

        # Verify
        mock_redis.assert_called_once_with("redis://localhost:6379/0")
        mock_client.ping.assert_called_once()
        mock_client.close.assert_called_once()

    @patch("api.routers.socketio.redis.from_url")
    def test_validate_redis_before_manager_creation_failure(self, mock_redis):
        """Test Redis validation failure before manager creation."""
        # Setup
        mock_redis.side_effect = Exception("Connection refused")

        # Execute and verify - the function calls sys.exit when _handle_redis_error raises
        with pytest.raises(SystemExit):
            _validate_redis_before_manager_creation("redis://localhost:6379/0")

    @patch("api.routers.socketio._handle_redis_error")
    @patch("api.routers.socketio.redis.from_url")
    @patch("sys.exit")
    def test_validate_redis_before_manager_creation_handle_error_failure(
        self, mock_exit, mock_redis, mock_handle_error
    ):
        """Test sys.exit fallback when error handling itself fails."""
        # Setup
        mock_redis.side_effect = Exception("Connection refused")
        mock_handle_error.side_effect = Exception("Error handler failed")

        # Execute
        _validate_redis_before_manager_creation("redis://localhost:6379/0")

        # Verify fallback to sys.exit
        mock_exit.assert_called_once_with(1)

    def test_patch_redis_manager_for_crash_on_failure_none_manager(self):
        """Test patching function with None manager."""
        # Execute - should not raise exception
        result = _patch_redis_manager_for_crash_on_failure(None)

        # Verify
        assert result is None

    @patch("api.routers.socketio.logger")
    def test_patch_redis_manager_for_crash_on_failure_with_manager(self, mock_logger):
        """Test patching function with actual manager."""
        # Setup
        mock_manager = Mock()
        original_thread = AsyncMock()
        mock_manager._thread = original_thread

        # Execute
        _patch_redis_manager_for_crash_on_failure(mock_manager)

        # Verify the manager's _thread method was replaced
        assert mock_manager._thread != original_thread

    @patch("api.routers.socketio.logger")
    @patch("sys.exit")
    @pytest.mark.asyncio
    async def test_patched_manager_background_thread_failure(
        self, mock_exit, mock_logger
    ):
        """Test that patched manager background thread crashes on failure."""
        # Setup
        mock_manager = Mock()
        original_thread = AsyncMock()
        original_thread.side_effect = Exception("Background thread failed")
        mock_manager._thread = original_thread

        # Execute patching
        _patch_redis_manager_for_crash_on_failure(mock_manager)

        # Execute the patched thread function
        await mock_manager._thread()

        # Verify sys.exit was called
        mock_exit.assert_called_once_with(1)


class TestIntegrationScenarios:
    """Integration tests for various Redis deployment scenarios."""

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_graceful_degradation_when_adapter_disabled(self, mock_settings):
        """Test graceful degradation when USE_REDIS_ADAPTER=false and Redis fails."""
        mock_settings.USE_REDIS_ADAPTER = False

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
    async def test_graceful_degradation_scenario_adapter_disabled(self, mock_settings):
        """Test graceful degradation when Redis becomes unavailable during runtime and adapter is disabled."""
        mock_settings.USE_REDIS_ADAPTER = False

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
    async def test_strict_mode_scenario_adapter_enabled(self, mock_settings):
        """Test strict mode crashes immediately on Redis failure when adapter is enabled."""
        mock_settings.USE_REDIS_ADAPTER = True

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Critical Redis failure")

            with pytest.raises(RedisCriticalError, match="Redis Socket.IO emit failed"):
                await safe_emit("status", {"status": "verified"})
            # Only one call should be made before crashing
            assert mock_emit.call_count == 1
