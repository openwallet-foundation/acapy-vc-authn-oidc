"""Tests that verify cleanup uses native async I/O and doesn't block the event loop."""

import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from api.services.cleanup import perform_cleanup


async def _batch_gen(batches):
    """Async generator helper for mocking get_connections_batched."""
    for batch in batches:
        yield batch


class TestCleanupNonBlocking:
    """Tests that cleanup is natively async and doesn't block the event loop."""

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_perform_cleanup_is_awaitable(self, mock_acapy_class):
        """Verify that perform_cleanup is a proper coroutine that can be awaited."""

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(return_value=[])
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))

        # perform_cleanup must be awaitable
        result = await perform_cleanup(MagicMock())

        assert result is not None
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_concurrent_cleanup_calls_complete_without_conflict(
        self, mock_acapy_class
    ):
        """Verify two concurrent cleanup calls both complete without interfering."""

        old_time = datetime.now(UTC) - timedelta(hours=25)
        mock_records = [
            {
                "pres_ex_id": "record-1",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            }
        ]

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(
            return_value=mock_records
        )
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))
        mock_instance.delete_presentation_record_and_connection = AsyncMock(
            return_value=(True, None, [])
        )

        # Run two concurrent cleanup calls
        result1, result2 = await asyncio.gather(
            perform_cleanup(MagicMock()),
            perform_cleanup(MagicMock()),
        )

        # Both should complete successfully
        assert result1["total_presentation_records"] == 1
        assert result2["total_presentation_records"] == 1
        assert result1["cleaned_presentation_records"] == 1
        assert result2["cleaned_presentation_records"] == 1
        assert result1["failed_cleanups"] == 0
        assert result2["failed_cleanups"] == 0

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_event_loop_responsive_during_cleanup(self, mock_acapy_class):
        """Verify that async tasks can interleave while cleanup awaits I/O."""

        async def slow_get_records():
            """Simulate slow async I/O — suspends the coroutine, freeing the loop."""
            await asyncio.sleep(0.15)
            return []

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = slow_get_records
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))

        health_check_times = []
        cleanup_done = asyncio.Event()

        async def simulated_health_check():
            """Simulated health check: should complete quickly because the loop is free."""
            checks = 0
            while not cleanup_done.is_set() and checks < 10:
                start = asyncio.get_event_loop().time()
                await asyncio.sleep(0.02)
                elapsed = asyncio.get_event_loop().time() - start
                health_check_times.append(elapsed)
                checks += 1

        async def run_cleanup():
            try:
                await perform_cleanup(MagicMock())
            finally:
                cleanup_done.set()

        await asyncio.gather(run_cleanup(), simulated_health_check())

        # Health checks should have run — the loop was not blocked
        assert len(health_check_times) > 0, "No health checks completed"

        # Each 20ms sleep should complete in under 100ms if the loop is free
        for elapsed in health_check_times:
            assert elapsed < 0.1, (
                f"Health check took {elapsed:.3f}s — event loop may have been blocked. "
                "Expected < 0.1s for a 20ms sleep."
            )

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_multiple_concurrent_tasks_during_cleanup(self, mock_acapy_class):
        """Verify multiple async tasks can run concurrently during cleanup."""

        async def slow_get_records():
            await asyncio.sleep(0.1)
            return []

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = slow_get_records
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))

        task_execution_times = []

        async def background_task(task_id):
            """A simple async task that should complete quickly during cleanup."""
            start = asyncio.get_event_loop().time()
            await asyncio.sleep(0.01)
            elapsed = asyncio.get_event_loop().time() - start
            task_execution_times.append((task_id, elapsed))

        # Run cleanup with multiple concurrent background tasks
        await asyncio.gather(
            perform_cleanup(MagicMock()),
            background_task(1),
            background_task(2),
            background_task(3),
        )

        # All background tasks should complete quickly
        assert len(task_execution_times) == 3, "Not all background tasks completed"
        for task_id, elapsed in task_execution_times:
            assert elapsed < 0.1, (
                f"Task {task_id} took {elapsed:.3f}s — event loop was blocked!"
            )
