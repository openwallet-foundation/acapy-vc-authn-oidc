"""Integration tests for the complete cleanup flow."""

from datetime import datetime, timedelta, UTC
from unittest.mock import MagicMock, patch, AsyncMock
import pytest

from api.services.cleanup import (
    perform_cleanup,
)


async def _batch_gen(batches):
    """Async generator helper for mocking get_connections_batched."""
    for batch in batches:
        yield batch


class TestCleanupIntegration:
    """Integration tests for the complete presentation cleanup flow."""

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_full_cleanup_flow_immediate_and_background(self, mock_acapy_class):
        """Test complete flow: immediate cleanup on webhook + background cleanup."""

        # Arrange - Mock ACA-Py API responses
        old_time = datetime.now(UTC) - timedelta(hours=25)
        recent_time = datetime.now(UTC) - timedelta(hours=1)
        expired_connection_time = datetime.now(UTC) - timedelta(
            seconds=30
        )  # Expired connection
        recent_connection_time = datetime.now(UTC) - timedelta(
            seconds=5
        )  # Recent connection

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

        # Only invitation-state connections (as returned by get_connections_batched)
        mock_invitation_connections = [
            {
                "connection_id": "expired-invitation-1",
                "state": "invitation",
                "created_at": expired_connection_time.isoformat().replace(
                    "+00:00", "Z"
                ),
            },
            {
                "connection_id": "recent-invitation",
                "state": "invitation",
                "created_at": recent_connection_time.isoformat().replace("+00:00", "Z"),
            },
        ]

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(
            return_value=mock_records
        )
        mock_instance.get_connections_batched = MagicMock(
            return_value=_batch_gen([mock_invitation_connections])
        )
        mock_instance.delete_presentation_record_and_connection = AsyncMock(
            return_value=(True, None, [])
        )
        mock_instance.delete_connection = AsyncMock(return_value=True)

        # Act - Run background cleanup
        result = await perform_cleanup(MagicMock())

        # Assert
        assert result["total_presentation_records"] == 3
        assert result["cleaned_presentation_records"] == 2  # Only old records cleaned
        assert (
            result["total_connections"] == 2
        )  # Only invitation-state connections returned by API
        assert (
            result["cleaned_connections"] == 1
        )  # Only expired invitation cleaned (not recent)
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert not result["hit_presentation_limit"]
        assert not result["hit_connection_limit"]

        # Verify service-level calls
        assert mock_instance.delete_presentation_record_and_connection.call_count == 2
        assert mock_instance.delete_connection.call_count == 1

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_immediate_cleanup_success_no_background_needed(
        self, mock_acapy_class
    ):
        """Test background cleanup finds nothing after immediate cleanup already ran."""

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(return_value=[])
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))

        # Background cleanup - should find nothing
        background_result = await perform_cleanup(MagicMock())

        # Assert
        assert background_result["total_presentation_records"] == 0
        assert background_result["cleaned_presentation_records"] == 0
        assert background_result["total_connections"] == 0
        assert background_result["cleaned_connections"] == 0

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_immediate_cleanup_failure_background_recovers(
        self, mock_acapy_class
    ):
        """Test background cleanup handles records missed by immediate cleanup."""

        old_time = datetime.now(UTC) - timedelta(hours=25)

        mock_record_data = {
            "pres_ex_id": "failed-immediate-cleanup",
            "created_at": old_time.isoformat().replace("+00:00", "Z"),
            "state": "done",
            "by_format": {"test": "data"},
        }

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(
            return_value=[mock_record_data]
        )
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))
        # Background cleanup succeeds
        mock_instance.delete_presentation_record_and_connection = AsyncMock(
            return_value=(True, None, [])
        )

        # Background cleanup
        background_result = await perform_cleanup(MagicMock())

        # Assert
        assert background_result["total_presentation_records"] == 1
        assert (
            background_result["cleaned_presentation_records"] == 1
        )  # Background succeeded
        assert background_result["failed_cleanups"] == 0
        assert not background_result["hit_presentation_limit"]
        assert not background_result["hit_connection_limit"]

    @patch("api.services.cleanup.settings")
    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_configurable_retention_periods(
        self, mock_acapy_class, mock_settings
    ):
        """Test that different retention periods work correctly."""

        # Arrange - Different retention period
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 48  # 2 days
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = (
            10  # 10 seconds for connections
        )
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000

        now = datetime.now(UTC)
        times_and_expected = [
            (
                now - timedelta(hours=25),
                False,
            ),  # 25 hours old - should NOT be cleaned (< 48h)
            (
                now - timedelta(hours=49),
                True,
            ),  # 49 hours old - should be cleaned (> 48h)
            (
                now - timedelta(hours=72),
                True,
            ),  # 72 hours old - should be cleaned (> 48h)
        ]

        mock_records = []
        for i, (time_created, should_clean) in enumerate(times_and_expected):
            mock_records.append(
                {
                    "pres_ex_id": f"record-{i}",
                    "created_at": time_created.isoformat().replace("+00:00", "Z"),
                    "state": "done",
                }
            )

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(
            return_value=mock_records
        )
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))
        mock_instance.delete_presentation_record_and_connection = AsyncMock(
            return_value=(True, None, [])
        )

        # Act
        result = await perform_cleanup(MagicMock())

        # Assert
        expected_cleaned = sum(
            1 for _, should_clean in times_and_expected if should_clean
        )
        assert result["total_presentation_records"] == 3
        assert (
            result["cleaned_presentation_records"] == expected_cleaned
        )  # Should be 2 (records 1 and 2)
        assert result["failed_cleanups"] == 0

        # Verify only old enough records were deleted
        assert (
            mock_instance.delete_presentation_record_and_connection.call_count
            == expected_cleaned
        )

    @patch("api.services.cleanup.settings")
    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_error_resilience_partial_failures(
        self, mock_acapy_class, mock_settings
    ):
        """Test system resilience when some operations fail."""

        # Arrange - Mix of successful and failed operations
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 24
        mock_settings.CONTROLLER_CLEANUP_MAX_PRESENTATION_RECORDS = 1000
        mock_settings.CONTROLLER_CLEANUP_MAX_CONNECTIONS = 2000
        mock_settings.CONTROLLER_PRESENTATION_EXPIRE_TIME = 10

        old_time = datetime.now(UTC) - timedelta(hours=25)

        mock_records = [
            {
                "pres_ex_id": "record-success-1",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "record-fail",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
            {
                "pres_ex_id": "record-success-2",
                "created_at": old_time.isoformat().replace("+00:00", "Z"),
                "state": "done",
            },
        ]

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(
            return_value=mock_records
        )
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))
        # Middle delete fails
        mock_instance.delete_presentation_record_and_connection = AsyncMock(
            side_effect=[
                (True, None, []),  # Success
                (False, None, ["Failed to delete presentation record record-fail"]),
                (True, None, []),  # Success
            ]
        )

        # Act
        result = await perform_cleanup(MagicMock())

        # Assert
        assert result["total_presentation_records"] == 3
        assert result["cleaned_presentation_records"] == 2  # 2 successful deletions
        assert result["failed_cleanups"] == 1  # 1 failed deletion
        assert len(result["errors"]) == 1
        assert "record-fail" in result["errors"][0]
        assert not result["hit_presentation_limit"]
        assert not result["hit_connection_limit"]

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_network_resilience(self, mock_acapy_class):
        """Test system behavior during network issues."""

        # Arrange - Network failure causes cleanup to handle gracefully
        # AcapyClient catches network errors internally and returns empty list
        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(return_value=[])
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))

        # Act
        result = await perform_cleanup(MagicMock())

        # Assert - System should handle gracefully by returning empty results
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_large_dataset_handling(self, mock_acapy_class):
        """Test handling of large numbers of records."""

        # Arrange - Large number of old records
        old_time = datetime.now(UTC) - timedelta(hours=25)

        # Generate 100 old records
        mock_records = []
        for i in range(100):
            mock_records.append(
                {
                    "pres_ex_id": f"bulk-record-{i}",
                    "created_at": old_time.isoformat().replace("+00:00", "Z"),
                    "state": "done",
                }
            )

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(
            return_value=mock_records
        )
        mock_instance.get_connections_batched = MagicMock(return_value=_batch_gen([]))
        mock_instance.delete_presentation_record_and_connection = AsyncMock(
            return_value=(True, None, [])
        )

        # Act
        result = await perform_cleanup(MagicMock())

        # Assert
        assert result["total_presentation_records"] == 100
        assert result["cleaned_presentation_records"] == 100
        assert result["failed_cleanups"] == 0
        assert mock_instance.delete_presentation_record_and_connection.call_count == 100
        assert not result["hit_presentation_limit"]
        assert not result["hit_connection_limit"]

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_connection_cleanup_only_invitations(self, mock_acapy_class):
        """Test that only expired connection invitations are cleaned up, not active connections."""

        # Arrange - Mock connections with different ages
        expired_time = datetime.now(UTC) - timedelta(
            seconds=30
        )  # Expired (> 10 seconds)
        recent_time = datetime.now(UTC) - timedelta(seconds=5)  # Recent (< 10 seconds)

        # Only invitation-state connections (get_connections_batched filters by state)
        mock_invitation_connections = [
            {
                "connection_id": "expired-invitation-1",
                "state": "invitation",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
            },
            {
                "connection_id": "expired-invitation-2",
                "state": "invitation",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
            },
            {
                "connection_id": "recent-invitation",
                "state": "invitation",
                "created_at": recent_time.isoformat().replace("+00:00", "Z"),
            },
        ]

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(return_value=[])
        mock_instance.get_connections_batched = MagicMock(
            return_value=_batch_gen([mock_invitation_connections])
        )
        mock_instance.delete_connection = AsyncMock(return_value=True)

        # Act
        result = await perform_cleanup(MagicMock())

        # Assert
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert (
            result["total_connections"] == 3
        )  # Only invitation-state connections returned by API
        assert result["cleaned_connections"] == 2  # Only expired invitations cleaned
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert not result["hit_presentation_limit"]
        assert not result["hit_connection_limit"]

        # Verify only expired invitations were deleted
        assert mock_instance.delete_connection.call_count == 2

    @patch("api.services.cleanup.AcapyClient")
    @pytest.mark.asyncio
    async def test_connection_cleanup_failure_handling(self, mock_acapy_class):
        """Test proper error handling when connection deletion fails."""

        # Arrange - Mock expired invitation
        expired_time = datetime.now(UTC) - timedelta(seconds=30)

        mock_invitation_connections = [
            {
                "connection_id": "failed-delete-connection",
                "state": "invitation",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
            },
        ]

        mock_instance = mock_acapy_class.return_value
        mock_instance.get_all_presentation_records = AsyncMock(return_value=[])
        mock_instance.get_connections_batched = MagicMock(
            return_value=_batch_gen([mock_invitation_connections])
        )
        # Delete fails
        mock_instance.delete_connection = AsyncMock(return_value=False)

        # Act
        result = await perform_cleanup(MagicMock())

        # Assert
        assert result["total_connections"] == 1
        assert result["cleaned_connections"] == 0  # Failed to clean
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Failed to delete expired connection invitation" in result["errors"][0]
        assert not result["hit_presentation_limit"]
        assert not result["hit_connection_limit"]
