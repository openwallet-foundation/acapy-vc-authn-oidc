#!/usr/bin/env python3
"""
Test Redis fallback behavior to ensure proper handling when USE_REDIS_ADAPTER is enabled/disabled.
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import time

from api.routers.socketio import (
    safe_emit,
    create_socket_manager,
    _should_use_redis_adapter,
    can_we_reach_redis,
    _patch_redis_manager_for_graceful_failure,
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
    async def test_safe_emit_graceful_failure_adapter_enabled(self, mock_settings):
        """Test safe_emit continues gracefully when Redis fails and USE_REDIS_ADAPTER=true."""
        mock_settings.USE_REDIS_ADAPTER = True

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Redis connection failed")

            # Should not raise exception - should handle gracefully
            await safe_emit("test_event", {"data": "test"}, to="test_room")

            mock_emit.assert_called_once_with(
                "test_event", {"data": "test"}, to="test_room"
            )

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


class TestRedisConfiguration:
    """Test Redis configuration and fallback logic."""

    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_mode_none(self, mock_settings):
        """Test Redis adapter is disabled when REDIS_MODE is none."""
        mock_settings.REDIS_MODE = "none"
        mock_settings.REDIS_HOST = "redis"

        result = _should_use_redis_adapter()
        assert not result

    @patch("api.routers.socketio.validate_redis_config")
    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_no_host(self, mock_settings, mock_validate):
        """Test Redis adapter falls back when no REDIS_HOST provided."""
        mock_settings.REDIS_MODE = "single"
        mock_validate.side_effect = ValueError("REDIS_HOST required")

        result = _should_use_redis_adapter()
        assert not result

    @patch("api.routers.socketio.validate_redis_config")
    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_single_mode(self, mock_settings, mock_validate):
        """Test Redis adapter is enabled when REDIS_MODE is single."""
        mock_settings.REDIS_MODE = "single"
        mock_validate.return_value = None  # Validation passes

        result = _should_use_redis_adapter()
        assert result

    @patch("api.routers.socketio.settings")
    def test_create_socket_manager_disabled(self, mock_settings):
        """Test socket manager creation when Redis is disabled."""
        mock_settings.REDIS_MODE = "none"
        mock_settings.REDIS_HOST = "redis"

        manager = create_socket_manager()
        assert manager is None

    @patch("api.core.redis_utils.settings")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_redis")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_single_mode_enabled(
        self, mock_redis_manager, mock_can_reach_redis, mock_settings, mock_utils_settings
    ):
        """Test socket manager creates Redis manager when single mode enabled."""
        for s in (mock_settings, mock_utils_settings):
            s.REDIS_MODE = "single"
            s.REDIS_HOST = "redis:6379"
            s.REDIS_PASSWORD = ""
            s.REDIS_DB = 0

        # Mock successful validation
        mock_can_reach_redis.return_value = True

        mock_instance = Mock()
        mock_redis_manager.return_value = mock_instance

        manager = create_socket_manager()

        assert manager is mock_instance
        mock_can_reach_redis.assert_called_once_with("redis://redis:6379/0")
        mock_redis_manager.assert_called_once_with("redis://redis:6379/0")

    @patch("api.core.redis_utils.settings")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_redis")
    def test_create_socket_manager_redis_failure_fallback(
        self, mock_can_reach_redis, mock_settings, mock_utils_settings
    ):
        """Test socket manager returns None when Redis validation fails before manager creation."""
        for s in (mock_settings, mock_utils_settings):
            s.REDIS_MODE = "single"
            s.REDIS_HOST = "redis:6379"
            s.REDIS_PASSWORD = ""
            s.REDIS_DB = 0

        # Simulate Redis validation failure
        mock_can_reach_redis.return_value = False

        manager = create_socket_manager()
        assert manager is None

    @patch("api.core.redis_utils.settings")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.routers.socketio.can_we_reach_redis")
    @patch("api.routers.socketio.socketio.AsyncRedisManager")
    def test_create_socket_manager_unexpected_exception(
        self, mock_manager, mock_can_reach_redis, mock_should_use, mock_settings, mock_utils_settings
    ):
        """Test socket manager handles unexpected exceptions during creation."""
        for s in (mock_settings, mock_utils_settings):
            s.REDIS_MODE = "single"
            s.REDIS_HOST = "redis:6379"
            s.REDIS_PASSWORD = ""
            s.REDIS_DB = 0

        # Setup
        mock_should_use.return_value = True
        mock_can_reach_redis.return_value = True  # Validation passes
        mock_manager.side_effect = RuntimeError("Unexpected socket.io error")

        # Execute and verify - should return None on error
        manager = create_socket_manager()
        assert manager is None


class TestInternalRedisFunctions:
    """Test internal Redis validation and patching functions."""

    @patch("api.routers.socketio.redis.from_url")
    def test_can_we_reach_redis_success(self, mock_redis):
        """Test successful Redis connectivity check before manager creation."""
        # Setup
        mock_client = Mock()
        mock_redis.return_value = mock_client
        mock_client.ping.return_value = True

        # Execute - should not raise exception
        can_we_reach_redis("redis://localhost:6379/0")

        # Verify
        mock_redis.assert_called_once_with("redis://localhost:6379/0")
        mock_client.ping.assert_called_once()
        mock_client.close.assert_called_once()

    @patch("api.routers.socketio.redis.from_url")
    def test_can_we_reach_redis_failure(self, mock_redis):
        """Test Redis connectivity check failure before manager creation."""
        # Setup
        mock_redis.side_effect = Exception("Connection refused")

        # Execute and verify - should return False on failure
        result = can_we_reach_redis("redis://localhost:6379/0")
        assert result is False

    def test_patch_redis_manager_for_graceful_failure_none_manager(self):
        """Test patching function with None manager."""
        # Execute - should not raise exception
        result = _patch_redis_manager_for_graceful_failure(None)

        # Verify
        assert result is None

    @patch("api.routers.socketio.logger")
    def test_patch_redis_manager_for_graceful_failure_with_manager(self, mock_logger):
        """Test patching function with actual manager."""
        # Setup
        mock_manager = Mock()
        original_thread = AsyncMock()
        mock_manager._thread = original_thread

        # Execute
        _patch_redis_manager_for_graceful_failure(mock_manager)

        # Verify the manager's _thread method was replaced
        assert mock_manager._thread != original_thread

    @patch("api.routers.socketio.logger")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.asyncio.sleep", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_patched_manager_background_thread_failure_with_retries(
        self, mock_sleep, mock_settings, mock_logger
    ):
        """Test that patched manager background thread handles failures with retry logic."""
        # Setup settings
        mock_settings.REDIS_THREAD_MAX_RETRIES = 3
        mock_settings.REDIS_RETRY_BASE_DELAY = 1
        mock_settings.REDIS_RETRY_MAX_DELAY = 60

        # Setup mock manager
        mock_manager = Mock()
        original_thread = AsyncMock()
        original_thread.side_effect = Exception("Background thread failed")
        mock_manager._thread = original_thread

        # Execute patching
        _patch_redis_manager_for_graceful_failure(mock_manager)

        # Execute the patched thread function - should not raise
        await mock_manager._thread()

        # Verify retry logic
        assert original_thread.call_count == 3  # Should retry 3 times
        assert (
            mock_sleep.call_count == 2
        )  # Should sleep 2 times (after first 2 failures)
        assert (
            mock_logger.warning.call_count >= 2
        )  # Should log warnings for retries (includes _handle_redis_failure warnings)
        assert (
            mock_logger.error.call_count >= 1
        )  # Should log final error (includes _handle_redis_failure errors)


class TestIntegrationScenarios:
    """Integration tests for various Redis deployment scenarios."""

    @pytest.mark.asyncio
    @patch("api.routers.socketio.settings")
    async def test_graceful_degradation_when_mode_none(self, mock_settings):
        """Test graceful degradation when REDIS_MODE=none and Redis fails."""
        mock_settings.REDIS_MODE = "none"
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
    async def test_graceful_degradation_scenario_mode_none(self, mock_settings):
        """Test graceful degradation when Redis becomes unavailable during runtime and mode is none."""
        mock_settings.REDIS_MODE = "none"
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
    async def test_graceful_degradation_scenario_single_mode(self, mock_settings):
        """Test graceful degradation continues on Redis failure when single mode enabled."""
        mock_settings.REDIS_MODE = "single"
        mock_settings.USE_REDIS_ADAPTER = True

        with patch.object(sio, "emit", new_callable=AsyncMock) as mock_emit:
            mock_emit.side_effect = Exception("Critical Redis failure")

            # Should not raise exception - should handle gracefully
            await safe_emit("status", {"status": "verified"})
            # Call should be attempted
            assert mock_emit.call_count == 1
