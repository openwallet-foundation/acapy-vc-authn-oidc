"""Tests for PresentationCleanupService."""

import asyncio
from datetime import datetime, timedelta, UTC
from unittest.mock import Mock, patch, AsyncMock
import pytest

from api.services.cleanup import (
    PresentationCleanupService,
    cleanup_old_presentation_records,
)


class TestPresentationCleanupService:
    """Test PresentationCleanupService functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        with patch("api.services.cleanup.settings") as mock_settings:
            mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
            mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 60
            mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
            mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
            mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10
            mock_settings.REDIS_HOST = "localhost"
            mock_settings.REDIS_PORT = 6379
            mock_settings.REDIS_PASSWORD = None
            mock_settings.REDIS_DB = 0
            with patch(
                "api.services.cleanup.PresentationCleanupService._create_scheduler"
            ) as mock_scheduler:
                mock_scheduler.return_value = Mock()
                self.service = PresentationCleanupService()

    @patch("api.services.cleanup.settings")
    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_success(
        self, mock_client_class, mock_settings
    ):
        """Test successful cleanup of old presentation records."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create test records - one old, one recent
        old_time = datetime.now(UTC) - timedelta(hours=25)
        recent_time = datetime.now(UTC) - timedelta(hours=1)

        mock_records = [
            {
                "pres_ex_id": "old-record-1",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "old-record-2",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "recent-record",
                "created_at": recent_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = iter(
            []
        )  # No connections to clean
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            None,
            [],
        )

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 3
        assert (
            result["cleaned_presentation_records"] == 2
        )  # Only old records should be cleaned
        assert result["total_connections"] == 0
        assert result["cleaned_connections"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

        # Verify delete was called for old records only
        assert mock_client.delete_presentation_record_and_connection.call_count == 2
        mock_client.delete_presentation_record_and_connection.assert_any_call(
            "old-record-1", None
        )
        mock_client.delete_presentation_record_and_connection.assert_any_call(
            "old-record-2", None
        )

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_no_records(self, mock_client_class):
        """Test cleanup when no records exist."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        mock_client.get_all_presentation_records.return_value = []
        mock_client.get_connections_batched.return_value = iter(
            []
        )  # No connections to clean

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

        mock_client.delete_presentation_record_and_connection.assert_not_called()

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_deletion_failures(
        self, mock_client_class
    ):
        """Test cleanup with some deletion failures."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        old_time = datetime.now(UTC) - timedelta(hours=25)
        mock_records = [
            {
                "pres_ex_id": "record-1",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "record-2",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = iter(
            []
        )  # No connections to clean
        # First delete succeeds, second fails
        mock_client.delete_presentation_record_and_connection.side_effect = [
            (True, None, []),  # First record succeeds
            (
                False,
                None,
                ["Failed to delete presentation record record-2"],
            ),  # Second record fails
        ]

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 2
        assert result["cleaned_presentation_records"] == 1
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Failed to delete presentation record record-2" in result["errors"][0]
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_invalid_timestamp(
        self, mock_client_class
    ):
        """Test cleanup with records having invalid timestamps."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        mock_records = [
            {
                "pres_ex_id": "record-no-timestamp",
                "state": "done",
                # Missing created_at
            },
            {
                "pres_ex_id": "record-invalid-timestamp",
                "created_at": "invalid-date-format",
                "state": "done",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = iter(
            []
        )  # No connections to clean

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 2
        assert result["cleaned_presentation_records"] == 0
        assert result["failed_cleanups"] == 1  # The first record fails processing
        assert len(result["errors"]) == 1  # One error for the record with no timestamp
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

        # No deletion should be attempted for invalid records
        mock_client.delete_presentation_record_and_connection.assert_not_called()

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_api_exception(
        self, mock_client_class
    ):
        """Test cleanup when get_all_presentation_records throws exception."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        mock_client.get_all_presentation_records.side_effect = Exception("API error")

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 1
        assert "Background cleanup failed: API error" in result["errors"][0]
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_record_processing_exception(
        self, mock_client_class
    ):
        """Test cleanup when individual record processing throws exception."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        old_time = datetime.now(UTC) - timedelta(hours=25)
        mock_records = [
            {
                "pres_ex_id": "good-record",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "bad-record",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = iter(
            []
        )  # No connections to clean
        # First delete succeeds, second throws exception
        mock_client.delete_presentation_record_and_connection.side_effect = [
            (True, None, []),  # First record succeeds
            Exception("Delete error"),  # Second record throws exception
        ]

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 2
        assert result["cleaned_presentation_records"] == 1
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Error processing record bad-record" in result["errors"][0]
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

    def test_cleanup_timestamp_parsing_variations(self):
        """Test different timestamp format parsing."""
        # Test various ISO format variations that ACA-Py might return
        test_cases = [
            "2024-01-01T12:00:00Z",  # UTC with Z
            "2024-01-01T12:00:00+00:00",  # UTC with offset
            "2024-01-01T12:00:00.123456Z",  # With microseconds and Z
            "2024-01-01T12:00:00.123456+00:00",  # With microseconds and offset
        ]

        for timestamp_str in test_cases:
            # Test that our parsing logic handles these formats
            if timestamp_str.endswith("Z"):
                processed = timestamp_str[:-1] + "+00:00"
            else:
                processed = timestamp_str

            try:
                parsed_time = datetime.fromisoformat(processed)
                if parsed_time.tzinfo is None:
                    parsed_time = parsed_time.replace(tzinfo=UTC)
                assert parsed_time.tzinfo is not None
            except ValueError:
                pytest.fail(f"Failed to parse timestamp: {timestamp_str}")

    @patch("apscheduler.schedulers.asyncio.AsyncIOScheduler")
    @pytest.mark.asyncio
    async def test_start_scheduler_success(self, mock_scheduler_class):
        """Test APScheduler startup."""
        # Arrange
        mock_scheduler = Mock()
        mock_scheduler_class.return_value = mock_scheduler
        self.service.scheduler = mock_scheduler

        # Act
        await self.service.start_scheduler()

        # Assert
        mock_scheduler.add_job.assert_called_once()
        mock_scheduler.start.assert_called_once()

        # Verify job configuration
        call_args = mock_scheduler.add_job.call_args
        assert call_args[1]["id"] == "presentation_cleanup"
        assert call_args[1]["max_instances"] == 1
        assert call_args[1]["replace_existing"] == True

    @patch("apscheduler.schedulers.asyncio.AsyncIOScheduler")
    @pytest.mark.asyncio
    async def test_start_scheduler_with_exception(self, mock_scheduler_class):
        """Test APScheduler startup handles exceptions."""
        # Arrange
        mock_scheduler = Mock()
        mock_scheduler.start.side_effect = Exception("Scheduler error")
        mock_scheduler_class.return_value = mock_scheduler
        self.service.scheduler = mock_scheduler

        # Act & Assert
        with pytest.raises(Exception, match="Scheduler error"):
            await self.service.start_scheduler()

    @patch("apscheduler.schedulers.asyncio.AsyncIOScheduler")
    @pytest.mark.asyncio
    async def test_stop_scheduler_success(self, mock_scheduler_class):
        """Test APScheduler shutdown."""
        # Arrange
        mock_scheduler = Mock()
        mock_scheduler.running = True
        mock_scheduler_class.return_value = mock_scheduler
        self.service.scheduler = mock_scheduler

        # Act
        await self.service.stop_scheduler()

        # Assert
        mock_scheduler.shutdown.assert_called_once_with(wait=True)

    @patch("apscheduler.schedulers.asyncio.AsyncIOScheduler")
    @pytest.mark.asyncio
    async def test_stop_scheduler_not_running(self, mock_scheduler_class):
        """Test APScheduler shutdown when not running."""
        # Arrange
        mock_scheduler = Mock()
        mock_scheduler.running = False
        mock_scheduler_class.return_value = mock_scheduler
        self.service.scheduler = mock_scheduler

        # Act
        await self.service.stop_scheduler()

        # Assert
        mock_scheduler.shutdown.assert_not_called()

    @patch("api.services.cleanup.settings")
    def test_cleanup_service_configuration(self, mock_settings):
        """Test that cleanup service uses configuration correctly."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 30
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10
        mock_settings.REDIS_HOST = "localhost"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = None
        mock_settings.REDIS_DB = 0

        with patch(
            "api.services.cleanup.PresentationCleanupService._create_scheduler"
        ) as mock_scheduler:
            mock_scheduler.return_value = Mock()
            # Act
            service = PresentationCleanupService()

            # Assert
            assert service.schedule_minutes == 30

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_resource_limits(self, mock_client_class):
        """Test that resource limits prevent excessive processing."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create more records than the limit
        old_time = datetime.now(UTC) - timedelta(hours=25)
        mock_records = []
        for i in range(1200):  # More than MAX_PRESENTATION_RECORDS_PER_CLEANUP (1000)
            mock_records.append(
                {
                    "pres_ex_id": f"record-{i}",
                    "created_at": old_time.isoformat().replace("+00:00", "Z"),
                    "state": "done",
                }
            )

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = iter([])  # No connections
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            None,
            [],
        )

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 1200
        assert result["cleaned_presentation_records"] == 1000  # Limited to MAX
        assert result["hit_presentation_limit"] == True
        assert result["hit_connection_limit"] == False

        # Verify only 1000 deletes were attempted
        assert mock_client.delete_presentation_record_and_connection.call_count == 1000

    def test_setup_cleanup_job(self):
        """Test APScheduler job setup."""
        # Arrange
        mock_scheduler = Mock()
        self.service.scheduler = mock_scheduler

        # Act
        self.service.setup_cleanup_job()

        # Assert
        mock_scheduler.add_job.assert_called_once()
        call_args = mock_scheduler.add_job.call_args

        # Verify job parameters
        assert call_args[1]["func"] == cleanup_old_presentation_records
        assert call_args[1]["id"] == "presentation_cleanup"
        assert call_args[1]["max_instances"] == 1
        assert call_args[1]["replace_existing"] == True
        assert call_args[1]["misfire_grace_time"] == 300

    @patch("api.services.cleanup.settings")
    def test_build_redis_url_with_password(self, mock_settings):
        """Test Redis URL building with password."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 60
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10
        mock_settings.REDIS_HOST = "redis-host"
        mock_settings.REDIS_PORT = 6380
        mock_settings.REDIS_PASSWORD = "secret"
        mock_settings.REDIS_DB = 2

        with patch(
            "api.services.cleanup.PresentationCleanupService._create_scheduler"
        ) as mock_scheduler:
            mock_scheduler.return_value = Mock()
            service = PresentationCleanupService()

            # Act
            url = service._build_redis_url()

            # Assert - password should be masked
            assert url == "redis://***@redis-host:6380/3"

    @patch("api.services.cleanup.settings")
    def test_build_redis_url_without_password(self, mock_settings):
        """Test Redis URL building without password."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 60
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10
        mock_settings.REDIS_HOST = "redis-host"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = None
        mock_settings.REDIS_DB = 0

        with patch(
            "api.services.cleanup.PresentationCleanupService._create_scheduler"
        ) as mock_scheduler:
            mock_scheduler.return_value = Mock()
            service = PresentationCleanupService()

            # Act
            url = service._build_redis_url()

            # Assert
            assert url == "redis://redis-host:6379/1"
