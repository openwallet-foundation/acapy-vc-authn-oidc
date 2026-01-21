"""Tests that verify cleanup doesn't block the event loop."""

import asyncio
import threading
import time
from datetime import datetime, timedelta, UTC
from unittest.mock import patch, Mock

import pytest

from api.services.cleanup import perform_cleanup


class TestCleanupNonBlocking:
    """Tests that cleanup runs in a thread pool and doesn't block the event loop."""

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_event_loop_remains_responsive_during_cleanup(
        self, mock_delete, mock_get
    ):
        """Verify that async tasks can run while cleanup is executing."""

        # Track which thread the HTTP calls run in
        cleanup_thread_ids = []
        main_thread_id = threading.current_thread().ident

        def slow_get(*args, **kwargs):
            """Simulate slow HTTP call and record thread ID."""
            cleanup_thread_ids.append(threading.current_thread().ident)
            time.sleep(0.3)  # Simulate network latency
            response = Mock()
            response.status_code = 200
            response.content = b'{"results": []}'
            return response

        def slow_delete(*args, **kwargs):
            """Simulate slow HTTP delete."""
            cleanup_thread_ids.append(threading.current_thread().ident)
            time.sleep(0.1)
            response = Mock()
            response.status_code = 200
            return response

        mock_get.side_effect = slow_get
        mock_delete.side_effect = slow_delete

        # Track health check response times
        health_check_times = []
        cleanup_done = asyncio.Event()

        async def simulated_health_check():
            """Simulate health checks during cleanup."""
            checks_completed = 0
            while not cleanup_done.is_set() and checks_completed < 10:
                start = asyncio.get_event_loop().time()
                # This simulates what the health endpoint does - just an async sleep
                # If the event loop were blocked, this would take much longer
                await asyncio.sleep(0.05)
                elapsed = asyncio.get_event_loop().time() - start
                health_check_times.append(elapsed)
                checks_completed += 1

        async def run_cleanup():
            """Run cleanup and signal when done."""
            try:
                await perform_cleanup()
            finally:
                cleanup_done.set()

        # Run cleanup and health checks concurrently
        await asyncio.gather(
            run_cleanup(),
            simulated_health_check(),
        )

        # Assertions

        # 1. HTTP calls should happen in worker threads, not the main thread
        assert len(cleanup_thread_ids) > 0, "No HTTP calls were made"
        for thread_id in cleanup_thread_ids:
            assert thread_id != main_thread_id, (
                f"HTTP call ran in main thread {main_thread_id} - "
                "asyncio.to_thread() is not working!"
            )

        # 2. Health checks should complete quickly (not blocked by cleanup)
        # If event loop was blocked, sleep(0.05) would take much longer
        assert len(health_check_times) > 0, "No health checks completed"
        for elapsed in health_check_times:
            assert elapsed < 0.2, (
                f"Health check took {elapsed:.3f}s - event loop was blocked! "
                "Expected < 0.2s for a 0.05s sleep"
            )

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_cleanup_runs_in_thread_pool(self, mock_delete, mock_get):
        """Verify cleanup functions execute in a thread pool, not the main thread."""

        execution_thread_ids = set()
        main_thread_id = threading.current_thread().ident

        def tracking_get(*args, **kwargs):
            execution_thread_ids.add(threading.current_thread().ident)
            response = Mock()
            response.status_code = 200
            response.content = b'{"results": []}'
            return response

        def tracking_delete(*args, **kwargs):
            execution_thread_ids.add(threading.current_thread().ident)
            response = Mock()
            response.status_code = 200
            return response

        mock_get.side_effect = tracking_get
        mock_delete.side_effect = tracking_delete

        # Run cleanup
        await perform_cleanup()

        # Verify HTTP calls happened in worker threads
        assert len(execution_thread_ids) > 0, "No HTTP calls were recorded"
        assert main_thread_id not in execution_thread_ids, (
            "Cleanup ran in main thread - would block event loop! "
            "asyncio.to_thread() should offload to thread pool."
        )

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_multiple_concurrent_tasks_during_cleanup(
        self, mock_delete, mock_get
    ):
        """Verify multiple async tasks can run concurrently during cleanup."""

        def slow_get(*args, **kwargs):
            time.sleep(0.2)
            response = Mock()
            response.status_code = 200
            response.content = b'{"results": []}'
            return response

        mock_get.side_effect = slow_get
        mock_delete.return_value = Mock(status_code=200)

        task_execution_times = []

        async def background_task(task_id):
            """A simple async task that should run during cleanup."""
            start = asyncio.get_event_loop().time()
            await asyncio.sleep(0.01)
            elapsed = asyncio.get_event_loop().time() - start
            task_execution_times.append((task_id, elapsed))

        # Run cleanup with multiple concurrent background tasks
        await asyncio.gather(
            perform_cleanup(),
            background_task(1),
            background_task(2),
            background_task(3),
        )

        # All background tasks should complete quickly
        assert len(task_execution_times) == 3, "Not all background tasks completed"
        for task_id, elapsed in task_execution_times:
            assert elapsed < 0.1, (
                f"Task {task_id} took {elapsed:.3f}s - event loop was blocked!"
            )
