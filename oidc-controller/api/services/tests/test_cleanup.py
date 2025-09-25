"""Tests for cleanup functions."""

import asyncio
from datetime import datetime, timedelta, UTC
from unittest.mock import Mock, patch, AsyncMock
import pytest

from api.services.cleanup import (
    perform_cleanup,
)


class TestPerformCleanup:
    """Test standalone perform_cleanup function."""

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_success(self, mock_settings, mock_client_class):
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
        expired_connection_time = datetime.now(UTC) - timedelta(seconds=30)
        recent_connection_time = datetime.now(UTC) - timedelta(seconds=5)

        mock_records = [
            {
                "pres_ex_id": "old-record-1",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "recent-record",
                "created_at": recent_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
        ]

        mock_connections = [
            {
                "connection_id": "expired-conn-1",
                "created_at": expired_connection_time.isoformat().replace(
                    "+00:00", "Z"
                ),
                "invitation_key": "key1",
                "state": "invitation",
            },
            {
                "connection_id": "recent-conn",
                "created_at": recent_connection_time.isoformat().replace("+00:00", "Z"),
                "invitation_key": "key2",
                "state": "invitation",
            },
        ]

        # Mock ACA-Py responses
        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = [mock_connections]
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            False,
            [],
        )
        mock_client.delete_connection.return_value = True

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 2
        assert result["cleaned_presentation_records"] == 1  # Only old record
        assert result["total_connections"] == 2
        assert result["cleaned_connections"] == 1  # Only expired connection
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0

        # Verify the old record was deleted, recent record was not
        mock_client.delete_presentation_record_and_connection.assert_called_once_with(
            "old-record-1", None
        )
        mock_client.delete_connection.assert_called_once_with("expired-conn-1")

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_no_records(self, mock_settings, mock_client_class):
        """Test cleanup when no records exist."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_all_presentation_records.return_value = []
        mock_client.get_connections_batched.return_value = []

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert result["total_connections"] == 0
        assert result["cleaned_connections"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_deletion_failures(
        self, mock_settings, mock_client_class
    ):
        """Test handling of deletion failures."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        old_time = datetime.now(UTC) - timedelta(hours=25)
        mock_records = [
            {
                "pres_ex_id": "old-record-1",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            }
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = []

        # Mock deletion failure
        mock_client.delete_presentation_record_and_connection.side_effect = Exception(
            "Deletion failed"
        )

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 1
        assert result["cleaned_presentation_records"] == 0  # Failed to clean
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Deletion failed" in result["errors"][0]

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_invalid_timestamp(
        self, mock_settings, mock_client_class
    ):
        """Test handling of records with invalid timestamps."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        mock_records = [
            {
                "pres_ex_id": "invalid-record",
                "created_at": "invalid-timestamp",
                "state": "done",
            }
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = []

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 1
        assert result["cleaned_presentation_records"] == 0
        assert (
            result["failed_cleanups"] == 0
        )  # Invalid timestamps are handled gracefully, not counted as failures
        assert (
            len(result["errors"]) == 0
        )  # No errors added to the error list for invalid timestamps

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_api_exception(
        self, mock_settings, mock_client_class
    ):
        """Test handling of API exceptions during record retrieval."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_all_presentation_records.side_effect = Exception("API Error")

        # Act
        result = await perform_cleanup()

        # Assert - function should handle exception gracefully and return error stats
        assert result["failed_cleanups"] == 0  # No records were processed
        assert len(result["errors"]) == 1
        assert (
            "API Error" in result["errors"][0]
            or "Cleanup operation failed" in result["errors"][0]
        )

    def test_cleanup_timestamp_parsing_variations(self):
        """Test different timestamp format parsing."""
        # Test various ISO format variations that ACA-Py might return
        test_cases = [
            "2024-01-01T12:00:00Z",  # UTC with Z
            "2024-01-01T12:00:00+00:00",  # UTC with offset
            "2024-01-01T12:00:00.123456Z",  # With microseconds and Z
            "2024-01-01T12:00:00.123456+00:00",  # With microseconds and offset
        ]

        from api.services.cleanup import _parse_record_timestamp

        for timestamp_str in test_cases:
            # Test that our parsing logic handles these formats
            try:
                result = _parse_record_timestamp(timestamp_str, "test-record-id")
                assert isinstance(result, datetime)
                # All test cases should represent the same moment in time
                expected = datetime(2024, 1, 1, 12, 0, 0, tzinfo=UTC)
                # Allow for microsecond differences
                assert abs((result - expected).total_seconds()) < 1
            except Exception as e:
                pytest.fail(f"Failed to parse timestamp '{timestamp_str}': {e}")
