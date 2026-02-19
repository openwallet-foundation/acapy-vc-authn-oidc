"""Tests for cleanup functions."""

import unittest.mock
from datetime import datetime, timedelta, UTC
from unittest.mock import Mock, patch
import pytest

from api.services.cleanup import (
    perform_cleanup,
)


class TestConstants:
    """Constants for cleanup tests."""

    # Default settings
    DEFAULT_RETENTION_HOURS = 24
    DEFAULT_MAX_PRESENTATION_RECORDS = 1000
    DEFAULT_MAX_CONNECTIONS = 2000
    DEFAULT_EXPIRE_TIME = 600

    # Time offsets for test data
    OLD_RECORD_AGE_HOURS = 25
    RECENT_RECORD_AGE_HOURS = 1
    EXPIRED_CONNECTION_AGE_SECONDS = 700
    RECENT_CONNECTION_AGE_SECONDS = 300


class BaseCleanupTest:
    """Base class for cleanup tests with shared fixtures and utilities."""

    def configure_default_settings(self, mock_settings):
        """Configure mock settings with default values."""
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = (
            TestConstants.DEFAULT_RETENTION_HOURS
        )
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = (
            TestConstants.DEFAULT_MAX_PRESENTATION_RECORDS
        )
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = (
            TestConstants.DEFAULT_MAX_CONNECTIONS
        )
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = (
            TestConstants.DEFAULT_EXPIRE_TIME
        )
        return mock_settings

    def configure_mock_client(self, mock_client_class):
        """Create and configure a mock ACA-Py client."""
        mock_client = Mock()
        mock_client_class.return_value = mock_client
        return mock_client

    def create_test_timestamps(self):
        """Create standard test timestamps."""
        return {
            "old_time": datetime.now(UTC)
            - timedelta(hours=TestConstants.OLD_RECORD_AGE_HOURS),
            "recent_time": datetime.now(UTC)
            - timedelta(hours=TestConstants.RECENT_RECORD_AGE_HOURS),
            "expired_connection_time": datetime.now(UTC)
            - timedelta(seconds=TestConstants.EXPIRED_CONNECTION_AGE_SECONDS),
            "recent_connection_time": datetime.now(UTC)
            - timedelta(seconds=TestConstants.RECENT_CONNECTION_AGE_SECONDS),
        }

    def create_presentation_record(
        self, pres_ex_id: str, created_at: datetime, state: str = "done"
    ):
        """Create a test presentation record."""
        return {
            "pres_ex_id": pres_ex_id,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "state": state,
        }

    def create_connection(
        self,
        connection_id: str,
        created_at: datetime,
        invitation_key: str = None,
        state: str = "invitation",
    ):
        """Create a test connection."""
        return {
            "connection_id": connection_id,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "invitation_key": invitation_key or f"key-{connection_id}",
            "state": state,
        }

    def create_cleanup_stats(self, **overrides):
        """Create cleanup statistics with optional overrides."""
        default_stats = {
            "total_presentation_records": 0,
            "cleaned_presentation_records": 0,
            "total_connections": 0,
            "cleaned_connections": 0,
            "failed_cleanups": 0,
            "errors": [],
            "hit_presentation_limit": False,
            "hit_connection_limit": False,
        }
        default_stats.update(overrides)
        return default_stats

    def assert_cleanup_stats(
        self,
        result,
        expected_total_presentations=None,
        expected_cleaned_presentations=None,
        expected_total_connections=None,
        expected_cleaned_connections=None,
        expected_failed_cleanups=None,
        expected_error_count=None,
        expected_hit_presentation_limit=None,
        expected_hit_connection_limit=None,
    ):
        """Helper to assert cleanup statistics."""
        if expected_total_presentations is not None:
            assert result["total_presentation_records"] == expected_total_presentations
        if expected_cleaned_presentations is not None:
            assert (
                result["cleaned_presentation_records"] == expected_cleaned_presentations
            )
        if expected_total_connections is not None:
            assert result["total_connections"] == expected_total_connections
        if expected_cleaned_connections is not None:
            assert result["cleaned_connections"] == expected_cleaned_connections
        if expected_failed_cleanups is not None:
            assert result["failed_cleanups"] == expected_failed_cleanups
        if expected_error_count is not None:
            assert len(result["errors"]) == expected_error_count
        if expected_hit_presentation_limit is not None:
            assert result["hit_presentation_limit"] == expected_hit_presentation_limit
        if expected_hit_connection_limit is not None:
            assert result["hit_connection_limit"] == expected_hit_connection_limit


class TestPerformCleanup(BaseCleanupTest):
    """Test standalone perform_cleanup function."""

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_success(self, mock_settings, mock_client_class):
        """Test successful cleanup of old presentation records."""
        # Configure default settings and override expire time for this specific test
        self.configure_default_settings(mock_settings)
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        # Configure mock client
        mock_client = self.configure_mock_client(mock_client_class)

        # Create test timestamps and data using utilities
        timestamps = self.create_test_timestamps()
        # Override connection times for this specific test
        expired_connection_time = datetime.now(UTC) - timedelta(seconds=30)
        recent_connection_time = datetime.now(UTC) - timedelta(seconds=5)

        mock_records = [
            self.create_presentation_record(
                "old-record-1", timestamps["old_time"], "done"
            ),
            self.create_presentation_record(
                "recent-record", timestamps["recent_time"], "done"
            ),
        ]

        mock_connections = [
            self.create_connection(
                "expired-conn-1", expired_connection_time, "key1", "invitation"
            ),
            self.create_connection(
                "recent-conn", recent_connection_time, "key2", "invitation"
            ),
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

        # Assert using utility
        self.assert_cleanup_stats(
            result,
            expected_total_presentations=2,
            expected_cleaned_presentations=1,
            expected_total_connections=2,
            expected_cleaned_connections=1,
            expected_failed_cleanups=0,
            expected_error_count=0,
        )

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
        # Configure default settings and override expire time for this specific test
        self.configure_default_settings(mock_settings)
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        # Configure mock client
        mock_client = self.configure_mock_client(mock_client_class)

        mock_client.get_all_presentation_records.return_value = []
        mock_client.get_connections_batched.return_value = []

        # Act
        result = await perform_cleanup()

        # Assert using utility
        self.assert_cleanup_stats(
            result,
            expected_total_presentations=0,
            expected_cleaned_presentations=0,
            expected_total_connections=0,
            expected_cleaned_connections=0,
            expected_failed_cleanups=0,
            expected_error_count=0,
        )

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_deletion_failures(
        self, mock_settings, mock_client_class
    ):
        """Test handling of deletion failures."""
        # Configure default settings and override expire time for this specific test
        self.configure_default_settings(mock_settings)
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        # Configure mock client
        mock_client = self.configure_mock_client(mock_client_class)

        # Create test data using utilities
        timestamps = self.create_test_timestamps()
        mock_records = [
            self.create_presentation_record(
                "old-record-1", timestamps["old_time"], "done"
            )
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = []

        # Mock deletion failure
        mock_client.delete_presentation_record_and_connection.side_effect = Exception(
            "Deletion failed"
        )

        # Act
        result = await perform_cleanup()

        # Assert using utility
        self.assert_cleanup_stats(
            result,
            expected_total_presentations=1,
            expected_cleaned_presentations=0,
            expected_failed_cleanups=1,
            expected_error_count=1,
        )
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


class TestCleanupConfigurationValidation:
    """Test cleanup configuration validation."""

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_success(self, mock_settings):
        """Test successful configuration validation with valid settings."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange - set all valid settings
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        # Act & Assert - should not raise any exception
        validate_cleanup_configuration()

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_negative_retention_hours(
        self, mock_settings
    ):
        """Test validation failure with negative retention hours."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = -1
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert (
            "CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS must be positive"
            in error_msg
        )
        assert "got -1" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_zero_retention_hours(self, mock_settings):
        """Test validation failure with zero retention hours."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 0
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert (
            "CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS must be positive"
            in error_msg
        )
        assert "got 0" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_invalid_max_presentation_records_too_low(
        self, mock_settings
    ):
        """Test validation failure with max presentation records too low."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 0
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert (
            "CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS must be between 1 and 10000"
            in error_msg
        )
        assert "got 0" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_invalid_max_presentation_records_too_high(
        self, mock_settings
    ):
        """Test validation failure with max presentation records too high."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 15000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert (
            "CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS must be between 1 and 10000"
            in error_msg
        )
        assert "got 15000" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_invalid_max_connections_too_low(
        self, mock_settings
    ):
        """Test validation failure with max connections too low."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 0
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert (
            "CONTROLLER_CLEANUP_MAX_CONNECTIONS must be between 1 and 20000"
            in error_msg
        )
        assert "got 0" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_invalid_max_connections_too_high(
        self, mock_settings
    ):
        """Test validation failure with max connections too high."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 25000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert (
            "CONTROLLER_CLEANUP_MAX_CONNECTIONS must be between 1 and 20000"
            in error_msg
        )
        assert "got 25000" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_negative_expire_time(self, mock_settings):
        """Test validation failure with negative expire time."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = -10

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert "CONTROLLER_PRESENTATION_EXPIRE_TIME must be positive" in error_msg
        assert "got -10" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_zero_expire_time(self, mock_settings):
        """Test validation failure with zero expire time."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 0

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        assert "CONTROLLER_PRESENTATION_EXPIRE_TIME must be positive" in error_msg
        assert "got 0" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_multiple_errors(self, mock_settings):
        """Test validation failure with multiple configuration errors."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange - set multiple invalid values
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = -5
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 15000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 0
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = -100

        # Act & Assert
        with pytest.raises(ValueError) as exc_info:
            validate_cleanup_configuration()

        error_msg = str(exc_info.value)
        # All error messages should be present
        assert (
            "CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS must be positive"
            in error_msg
        )
        assert (
            "CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS must be between 1 and 10000"
            in error_msg
        )
        assert (
            "CONTROLLER_CLEANUP_MAX_CONNECTIONS must be between 1 and 20000"
            in error_msg
        )
        assert "CONTROLLER_PRESENTATION_EXPIRE_TIME must be positive" in error_msg

    @patch("api.services.cleanup.settings")
    def test_validate_cleanup_configuration_boundary_values(self, mock_settings):
        """Test validation with boundary values that should be valid."""
        from api.services.cleanup import validate_cleanup_configuration

        # Test minimum valid values
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 1
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 1
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 1

        # Should not raise exception
        validate_cleanup_configuration()

        # Test maximum valid values
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = (
            999999  # No upper limit defined
        )
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 10000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 20000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = (
            999999  # No upper limit defined
        )

        # Should not raise exception
        validate_cleanup_configuration()


class TestCleanupResourceLimits:
    """Test cleanup function behavior with resource limits."""

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_hits_presentation_limit(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup behavior when hitting presentation record limit."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = (
            2  # Low limit to trigger
        )
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create 5 old records, but limit should stop at 2
        old_time = datetime.now(UTC) - timedelta(hours=25)
        mock_records = []
        for i in range(5):
            mock_records.append(
                {
                    "pres_ex_id": f"old-record-{i}",
                    "created_at": old_time.isoformat().replace("+00:00", "Z"),
                    "state": "done",
                }
            )

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = []
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            False,
            [],
        )

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 5
        assert result["cleaned_presentation_records"] == 2  # Hit the limit
        assert result["hit_presentation_limit"] is True
        assert result["hit_connection_limit"] is False
        assert result["failed_cleanups"] == 0

        # Verify only 2 deletions were called
        assert mock_client.delete_presentation_record_and_connection.call_count == 2

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_hits_connection_limit(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup behavior when hitting connection limit."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2  # Low limit to trigger
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create 5 expired connections, but limit should stop at 2
        expired_time = datetime.now(UTC) - timedelta(seconds=30)
        mock_connections = []
        for i in range(5):
            mock_connections.append(
                {
                    "connection_id": f"expired-conn-{i}",
                    "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                    "invitation_key": f"key{i}",
                    "state": "invitation",
                }
            )

        mock_client.get_all_presentation_records.return_value = []
        mock_client.get_connections_batched.return_value = [mock_connections]
        mock_client.delete_connection.return_value = True

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_connections"] == 5
        assert result["cleaned_connections"] == 2  # Hit the limit
        assert result["hit_presentation_limit"] is False
        assert result["hit_connection_limit"] is True
        assert result["failed_cleanups"] == 0

        # Verify only 2 deletions were called
        assert mock_client.delete_connection.call_count == 2

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_dry_run_mode(self, mock_settings, mock_client_class):
        """Test cleanup function with dry-run parameter (currently not implemented)."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        old_time = datetime.now(UTC) - timedelta(hours=25)
        expired_connection_time = datetime.now(UTC) - timedelta(seconds=30)

        mock_records = [
            {
                "pres_ex_id": "old-record-1",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            }
        ]

        mock_connections = [
            {
                "connection_id": "expired-conn-1",
                "created_at": expired_connection_time.isoformat().replace(
                    "+00:00", "Z"
                ),
                "invitation_key": "key1",
                "state": "invitation",
            }
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = [mock_connections]
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            False,
            [],
        )
        mock_client.delete_connection.return_value = True

        # Act - dry run mode (currently not implemented, so deletions still occur)
        result = await perform_cleanup(dry_run=True)

        # Assert - Currently behaves the same as regular cleanup since dry-run is not implemented
        assert result["total_presentation_records"] == 1
        assert result["cleaned_presentation_records"] == 1
        assert result["total_connections"] == 1
        assert result["cleaned_connections"] == 1
        assert result["failed_cleanups"] == 0

        # Verify deletions were called (because dry-run mode is not yet implemented)
        mock_client.delete_presentation_record_and_connection.assert_called_once()
        mock_client.delete_connection.assert_called_once()

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_with_custom_limits(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup function with custom resource limits (currently not implemented)."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000  # Default
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000  # Default
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create 5 old records and 5 expired connections
        old_time = datetime.now(UTC) - timedelta(hours=25)
        expired_time = datetime.now(UTC) - timedelta(seconds=30)

        mock_records = []
        for i in range(5):
            mock_records.append(
                {
                    "pres_ex_id": f"old-record-{i}",
                    "created_at": old_time.isoformat().replace("+00:00", "Z"),
                    "state": "done",
                }
            )

        mock_connections = []
        for i in range(5):
            mock_connections.append(
                {
                    "connection_id": f"expired-conn-{i}",
                    "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                    "invitation_key": f"key{i}",
                    "state": "invitation",
                }
            )

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = [mock_connections]
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            False,
            [],
        )
        mock_client.delete_connection.return_value = True

        # Act - with custom limits (currently not implemented, so uses defaults)
        result = await perform_cleanup(max_presentation_records=3, max_connections=2)

        # Assert - Currently ignores custom limits and cleans all eligible records
        assert result["total_presentation_records"] == 5
        assert (
            result["cleaned_presentation_records"] == 5
        )  # Custom limits not implemented
        assert result["total_connections"] == 5
        assert result["cleaned_connections"] == 5  # Custom limits not implemented
        assert result["hit_presentation_limit"] is False
        assert result["hit_connection_limit"] is False

        # Verify all deletions were called (custom limits not implemented)
        assert mock_client.delete_presentation_record_and_connection.call_count == 5
        assert mock_client.delete_connection.call_count == 5


class TestCleanupServiceErrorScenarios:
    """Test cleanup service error handling and edge cases."""

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_connection_deletion_failures(
        self, mock_settings, mock_client_class
    ):
        """Test handling of connection deletion failures."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Setup expired connections
        expired_time = datetime.now(UTC) - timedelta(seconds=30)
        mock_connections = [
            {
                "connection_id": "expired-conn-1",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                "invitation_key": "key1",
                "state": "invitation",
            }
        ]

        mock_client.get_all_presentation_records.return_value = []
        mock_client.get_connections_batched.return_value = [mock_connections]

        # Mock connection deletion failure
        mock_client.delete_connection.side_effect = Exception(
            "Connection deletion failed"
        )

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_connections"] == 1
        assert result["cleaned_connections"] == 0  # Failed to clean
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Connection deletion failed" in result["errors"][0]

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_mixed_success_and_failures(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup with some successes and some failures."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Setup old presentation records
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

        # Setup expired connections
        expired_time = datetime.now(UTC) - timedelta(seconds=30)
        mock_connections = [
            {
                "connection_id": "conn-1",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                "invitation_key": "key1",
                "state": "invitation",
            },
            {
                "connection_id": "conn-2",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                "invitation_key": "key2",
                "state": "invitation",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = [mock_connections]

        # Mock mixed success/failure for presentations
        def presentation_side_effect(pres_ex_id, connection_id):
            if pres_ex_id == "record-1":
                return (True, False, [])  # Success
            else:
                raise Exception(f"Failed to delete {pres_ex_id}")

        mock_client.delete_presentation_record_and_connection.side_effect = (
            presentation_side_effect
        )

        # Mock mixed success/failure for connections
        def connection_side_effect(connection_id):
            if connection_id == "conn-1":
                return True  # Success
            else:
                raise Exception(f"Failed to delete {connection_id}")

        mock_client.delete_connection.side_effect = connection_side_effect

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 2
        assert result["cleaned_presentation_records"] == 1  # One success
        assert result["total_connections"] == 2
        assert result["cleaned_connections"] == 1  # One success
        assert result["failed_cleanups"] == 2  # Two failures total
        assert len(result["errors"]) == 2
        assert "Failed to delete record-2" in result["errors"][0]
        assert "Failed to delete conn-2" in result["errors"][1]

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_empty_results_edge_cases(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup behavior with various empty result scenarios."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Test with empty lists returned
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
        assert result["hit_presentation_limit"] is False
        assert result["hit_connection_limit"] is False

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_partial_deletion_results(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup when ACA-Py returns partial deletion results."""
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

        # Mock partial deletion success (presentation deleted, but with errors)
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,  # presentation_deleted: True
            False,  # connection_deleted: False
            [
                "Warning: Connection was already deleted",
                "Minor cleanup issue",
            ],  # errors
        )

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 1
        assert result["cleaned_presentation_records"] == 1  # Presentation was deleted
        assert (
            result["failed_cleanups"] == 0
        )  # No failures since presentation was deleted
        assert (
            len(result["errors"]) == 2
        )  # Partial success errors are included in errors list

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_malformed_timestamps_various_formats(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup with various malformed timestamp formats."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Various malformed timestamp scenarios
        mock_records = [
            {
                "pres_ex_id": "record-invalid-1",
                "created_at": "not-a-timestamp",
                "state": "done",
            },
            {
                "pres_ex_id": "record-invalid-2",
                "created_at": "",
                "state": "done",
            },
            {
                "pres_ex_id": "record-no-timestamp",
                "state": "done",
                # missing created_at field
            },
            {
                "pres_ex_id": "record-null-timestamp",
                "created_at": None,
                "state": "done",
            },
        ]

        mock_connections = [
            {
                "connection_id": "conn-invalid-1",
                "created_at": "malformed-date",
                "invitation_key": "key1",
                "state": "invitation",
            },
            {
                "connection_id": "conn-invalid-2",
                "created_at": "2024-13-45T99:99:99Z",  # Invalid date values
                "invitation_key": "key2",
                "state": "invitation",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = [mock_connections]

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 4
        assert result["cleaned_presentation_records"] == 0  # All timestamps invalid
        assert result["total_connections"] == 2
        assert result["cleaned_connections"] == 0  # All timestamps invalid
        assert (
            result["failed_cleanups"] == 3
        )  # Missing timestamps count as failed cleanups (3 presentation records with missing/null/empty created_at)
        assert (
            len(result["errors"]) == 3
        )  # Missing timestamp errors are included in errors list

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_acapy_client_instantiation_failure(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup when ACA-Py client instantiation fails."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        # Mock client instantiation failure
        mock_client_class.side_effect = Exception("Failed to connect to ACA-Py agent")

        # Act & Assert - Client instantiation failure should raise exception
        with pytest.raises(Exception) as exc_info:
            await perform_cleanup()

        assert "Failed to connect to ACA-Py agent" in str(exc_info.value)

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_concurrent_modification_scenarios(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup when records are modified during cleanup."""
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
                "pres_ex_id": "concurrent-record",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            }
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = []

        # Mock concurrent modification error (record not found during deletion)
        mock_client.delete_presentation_record_and_connection.side_effect = Exception(
            "Presentation record not found - may have been deleted by another process"
        )

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 1
        assert result["cleaned_presentation_records"] == 0
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert (
            "not found" in result["errors"][0]
            or "another process" in result["errors"][0]
        )

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_perform_cleanup_large_error_list_handling(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup behavior when many errors occur."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create multiple records that will all fail
        old_time = datetime.now(UTC) - timedelta(hours=25)
        mock_records = []
        for i in range(10):
            mock_records.append(
                {
                    "pres_ex_id": f"record-{i}",
                    "created_at": old_time.isoformat().replace("+00:00", "Z"),
                    "state": "done",
                }
            )

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = []

        # Mock all deletions to fail
        def deletion_side_effect(pres_ex_id, connection_id):
            raise Exception(f"Deletion failed for {pres_ex_id}")

        mock_client.delete_presentation_record_and_connection.side_effect = (
            deletion_side_effect
        )

        # Act
        result = await perform_cleanup()

        # Assert
        assert result["total_presentation_records"] == 10
        assert result["cleaned_presentation_records"] == 0
        assert result["failed_cleanups"] == 10  # All failed
        assert len(result["errors"]) == 10  # All errors captured
        # Verify each error contains the relevant record ID
        for i, error in enumerate(result["errors"]):
            assert f"record-{i}" in error


class TestCleanupBackgroundIntegration:
    """Integration tests for background cleanup operations."""

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_cleanup_integration_full_workflow(
        self, mock_settings, mock_client_class
    ):
        """Test complete cleanup workflow with realistic data patterns."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create realistic test data with mixed old/recent records
        old_time = datetime.now(UTC) - timedelta(hours=25)
        recent_time = datetime.now(UTC) - timedelta(hours=1)
        expired_connection_time = datetime.now(UTC) - timedelta(seconds=700)
        recent_connection_time = datetime.now(UTC) - timedelta(seconds=300)

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
                "connection_id": "expired-conn-2",
                "created_at": expired_connection_time.isoformat().replace(
                    "+00:00", "Z"
                ),
                "invitation_key": "key2",
                "state": "invitation",
            },
            {
                "connection_id": "recent-conn",
                "created_at": recent_connection_time.isoformat().replace("+00:00", "Z"),
                "invitation_key": "key3",
                "state": "invitation",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = [mock_connections]
        mock_client.delete_presentation_record_and_connection.return_value = (
            True,
            False,
            [],
        )
        mock_client.delete_connection.return_value = True

        # Act - Test the core cleanup service
        result = await perform_cleanup()

        # Assert - Verify expected cleanup behavior
        assert result["total_presentation_records"] == 3
        assert result["cleaned_presentation_records"] == 2  # Only old records
        assert result["total_connections"] == 3
        assert result["cleaned_connections"] == 2  # Only expired connections
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert result["hit_presentation_limit"] is False
        assert result["hit_connection_limit"] is False

        # Verify correct ACA-Py calls were made
        assert mock_client.delete_presentation_record_and_connection.call_count == 2
        assert mock_client.delete_connection.call_count == 2

        expected_presentation_calls = [
            unittest.mock.call("old-record-1", None),
            unittest.mock.call("old-record-2", None),
        ]
        mock_client.delete_presentation_record_and_connection.assert_has_calls(
            expected_presentation_calls, any_order=True
        )

        expected_connection_calls = [
            unittest.mock.call("expired-conn-1"),
            unittest.mock.call("expired-conn-2"),
        ]
        mock_client.delete_connection.assert_has_calls(
            expected_connection_calls, any_order=True
        )

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_cleanup_integration_with_resource_limits(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup integration when hitting resource limits."""

        # Arrange with low limits to trigger
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1  # Low limit
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 1  # Low limit
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # Create multiple old records and expired connections
        old_time = datetime.now(UTC) - timedelta(hours=25)
        expired_time = datetime.now(UTC) - timedelta(seconds=700)

        mock_records = []
        for i in range(3):
            mock_records.append(
                {
                    "pres_ex_id": f"old-record-{i}",
                    "created_at": old_time.isoformat().replace("+00:00", "Z"),
                    "state": "done",
                }
            )

        mock_connections = []
        for i in range(3):
            mock_connections.append(
                {
                    "connection_id": f"expired-conn-{i}",
                    "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                    "invitation_key": f"key{i}",
                    "state": "invitation",
                }
            )

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

        # Assert - Limits should be respected
        assert result["total_presentation_records"] == 3
        assert result["cleaned_presentation_records"] == 1  # Hit limit
        assert result["total_connections"] == 3
        assert result["cleaned_connections"] == 1  # Hit limit
        assert result["hit_presentation_limit"] is True
        assert result["hit_connection_limit"] is True
        assert result["failed_cleanups"] == 0

        # Verify limited number of calls
        assert mock_client.delete_presentation_record_and_connection.call_count == 1
        assert mock_client.delete_connection.call_count == 1

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_cleanup_integration_error_recovery(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup integration with error recovery behavior."""

        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        old_time = datetime.now(UTC) - timedelta(hours=25)
        expired_time = datetime.now(UTC) - timedelta(seconds=700)

        # Mix of successful and failing records
        mock_records = [
            {
                "pres_ex_id": "success-record",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "fail-record",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
        ]

        mock_connections = [
            {
                "connection_id": "success-conn",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                "invitation_key": "key1",
                "state": "invitation",
            },
            {
                "connection_id": "fail-conn",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
                "invitation_key": "key2",
                "state": "invitation",
            },
        ]

        mock_client.get_all_presentation_records.return_value = mock_records
        mock_client.get_connections_batched.return_value = [mock_connections]

        # Mock mixed success/failure
        def presentation_side_effect(pres_ex_id, connection_id):
            if pres_ex_id == "success-record":
                return (True, False, [])
            else:
                raise Exception(f"Failed to delete {pres_ex_id}")

        def connection_side_effect(connection_id):
            if connection_id == "success-conn":
                return True
            else:
                raise Exception(f"Failed to delete {connection_id}")

        mock_client.delete_presentation_record_and_connection.side_effect = (
            presentation_side_effect
        )
        mock_client.delete_connection.side_effect = connection_side_effect

        # Act
        result = await perform_cleanup()

        # Assert - Should continue processing despite errors
        assert result["total_presentation_records"] == 2
        assert result["cleaned_presentation_records"] == 1  # One success
        assert result["total_connections"] == 2
        assert result["cleaned_connections"] == 1  # One success
        assert result["failed_cleanups"] == 2  # Two failures
        assert len(result["errors"]) == 2

        # Verify all deletion attempts were made
        assert mock_client.delete_presentation_record_and_connection.call_count == 2
        assert mock_client.delete_connection.call_count == 2

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_cleanup_integration_with_configuration_validation(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup integration with configuration validation."""
        from api.services.cleanup import validate_cleanup_configuration

        # Arrange with valid configuration
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 48
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 500
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 1000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 300

        # Validate configuration works
        validate_cleanup_configuration()  # Should not raise

        mock_client = Mock()
        mock_client_class.return_value = mock_client
        mock_client.get_all_presentation_records.return_value = []
        mock_client.get_connections_batched.return_value = []

        # Act
        result = await perform_cleanup()

        # Assert - Should complete successfully with valid config
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert result["total_connections"] == 0
        assert result["cleaned_connections"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0

    @patch("api.services.cleanup.AcapyClient")
    @patch("api.services.cleanup.settings")
    @pytest.mark.asyncio
    async def test_cleanup_integration_empty_data_scenario(
        self, mock_settings, mock_client_class
    ):
        """Test cleanup integration with empty data scenario."""
        # Arrange
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 600

        mock_client = Mock()
        mock_client_class.return_value = mock_client

        # No data scenario
        mock_client.get_all_presentation_records.return_value = []
        mock_client.get_connections_batched.return_value = []

        # Act
        result = await perform_cleanup()

        # Assert - Should complete successfully with no data
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert result["total_connections"] == 0
        assert result["cleaned_connections"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert result["hit_presentation_limit"] is False
        assert result["hit_connection_limit"] is False

        # Verify methods were called
        mock_client.get_all_presentation_records.assert_called_once()
        mock_client.get_connections_batched.assert_called_once()
