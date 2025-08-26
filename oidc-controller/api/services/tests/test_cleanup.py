"""Tests for PresentationCleanupService."""

import asyncio
from datetime import datetime, timedelta, UTC
from unittest.mock import Mock, patch, AsyncMock
import pytest

from api.services.cleanup import PresentationCleanupService


class TestPresentationCleanupService:
    """Test PresentationCleanupService functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        with patch("api.services.cleanup.settings") as mock_settings:
            mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
            mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 60
            self.service = PresentationCleanupService()

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_success(self, mock_client_class):
        """Test successful cleanup of old presentation records."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        self.service.client = mock_client

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
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            None,
            [],
        )

        # Act
        result = await self.service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 3
        assert result["cleaned_records"] == 2  # Only old records should be cleaned
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0

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
        self.service.client = mock_client

        mock_client.get_all_presentation_records.return_value = []

        # Act
        result = await self.service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 0
        assert result["cleaned_records"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0

        mock_client.delete_presentation_record.assert_not_called()

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_deletion_failures(
        self, mock_client_class
    ):
        """Test cleanup with some deletion failures."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        self.service.client = mock_client

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
        # First delete succeeds, second fails
        mock_client.delete_presentation_record_and_connection.side_effect = [
            (True, None, []),  # First record succeeds
            (False, None, []),  # Second record fails
        ]

        # Act
        result = await self.service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 2
        assert result["cleaned_records"] == 1
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Failed to delete presentation record record-2" in result["errors"][0]

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_invalid_timestamp(
        self, mock_client_class
    ):
        """Test cleanup with records having invalid timestamps."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        self.service.client = mock_client

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

        # Act
        result = await self.service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 2
        assert result["cleaned_records"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0

        # No deletion should be attempted for invalid records
        mock_client.delete_presentation_record.assert_not_called()

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_api_exception(
        self, mock_client_class
    ):
        """Test cleanup when get_all_presentation_records throws exception."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        self.service.client = mock_client

        mock_client.get_all_presentation_records.side_effect = Exception("API error")

        # Act
        result = await self.service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 0
        assert result["cleaned_records"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 1
        assert "Background cleanup failed: API error" in result["errors"][0]

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_cleanup_old_presentation_records_record_processing_exception(
        self, mock_client_class
    ):
        """Test cleanup when individual record processing throws exception."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        self.service.client = mock_client

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
        # First delete succeeds, second throws exception
        mock_client.delete_presentation_record_and_connection.side_effect = [
            (True, None, []),  # First record succeeds
            Exception("Delete error"),  # Second record throws exception
        ]

        # Act
        result = await self.service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 2
        assert result["cleaned_records"] == 1
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Error processing record bad-record" in result["errors"][0]

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

    @patch("api.services.cleanup.asyncio.sleep")
    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_start_background_cleanup_task_success(
        self, mock_client_class, mock_sleep
    ):
        """Test background cleanup task execution."""
        # Arrange
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        self.service.client = mock_client

        mock_client.get_all_presentation_records.return_value = []

        # Mock sleep to prevent infinite loop in test
        mock_sleep.side_effect = [None, asyncio.CancelledError()]

        # Act & Assert
        with pytest.raises(asyncio.CancelledError):
            await self.service.start_background_cleanup_task()

        # Verify cleanup was called
        mock_client.get_all_presentation_records.assert_called()

        # Verify sleep was called with correct interval (60 minutes * 60 seconds)
        mock_sleep.assert_called_with(3600)

    @patch("api.services.cleanup.asyncio.sleep")
    @patch.object(PresentationCleanupService, "cleanup_old_presentation_records")
    @pytest.mark.asyncio
    async def test_start_background_cleanup_task_with_exception(
        self, mock_cleanup_method, mock_sleep
    ):
        """Test background cleanup task handles exceptions."""
        # Arrange
        # First call throws exception, second succeeds, then cancel
        mock_cleanup_method.side_effect = [
            Exception("Temporary error"),
            None,
            asyncio.CancelledError(),
        ]

        mock_sleep.side_effect = [None, None, asyncio.CancelledError()]

        # Act & Assert
        with pytest.raises(asyncio.CancelledError):
            await self.service.start_background_cleanup_task()

        # Verify cleanup was attempted multiple times
        assert mock_cleanup_method.call_count >= 2

        # Verify error recovery sleep (5 minutes = 300 seconds) was called
        mock_sleep.assert_any_call(300)

    @patch("api.services.cleanup.settings")
    def test_cleanup_service_configuration(self, mock_settings):
        """Test that cleanup service uses configuration correctly."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 48
        mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 30

        # Act
        service = PresentationCleanupService()

        # Assert
        assert service.retention_hours == 48
        assert service.schedule_minutes == 30
