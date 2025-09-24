"""Integration tests for the complete cleanup flow."""

import asyncio
import json
from datetime import datetime, timedelta, UTC
from unittest.mock import Mock, patch, AsyncMock
import pytest

from api.services.cleanup import (
    PresentationCleanupService,
    cleanup_old_presentation_records,
)
from api.core.acapy.client import AcapyClient


class TestCleanupIntegration:
    """Integration tests for the complete presentation cleanup flow."""

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_full_cleanup_flow_immediate_and_background(
        self, mock_delete, mock_get
    ):
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

        # Mock get_all_presentation_records response
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

        # Mock get_all_connections response
        mock_connections = [
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
            {
                "connection_id": "active-connection",
                "state": "active",
                "created_at": expired_connection_time.isoformat().replace(
                    "+00:00", "Z"
                ),
            },
        ]

        # Configure mock responses based on URL
        def mock_get_side_effect(url, **kwargs):
            mock_response = Mock()
            mock_response.status_code = 200
            if "/present-proof-2.0/records" in url:
                mock_response.content = json.dumps({"results": mock_records}).encode()
            elif "/connections" in url:
                # Filter connections by state parameter if provided
                params = kwargs.get("params", {})
                filtered_connections = mock_connections
                if "state" in params:
                    filtered_connections = [
                        conn
                        for conn in mock_connections
                        if conn["state"] == params["state"]
                    ]
                mock_response.content = json.dumps(
                    {"results": filtered_connections}
                ).encode()
            return mock_response

        mock_get.side_effect = mock_get_side_effect

        # Mock delete responses - all successful
        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_delete.return_value = mock_delete_response

        # Act - Run background cleanup
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 3
        assert result["cleaned_presentation_records"] == 2  # Only old records cleaned
        assert (
            result["total_connections"] == 2
        )  # Only invitation-state connections returned by API
        assert (
            result["cleaned_connections"] == 1
        )  # Only expired invitation cleaned (not active connection)
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

        # Verify API calls
        assert (
            mock_get.call_count == 2
        )  # Called for both presentation records and connections
        assert (
            mock_delete.call_count == 3
        )  # 2 old presentation records + 1 expired connection

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_immediate_cleanup_success_no_background_needed(
        self, mock_delete, mock_get
    ):
        """Test immediate cleanup success means background finds nothing to clean."""

        # Arrange - Simulate immediate cleanup scenario
        client = AcapyClient()

        # Mock get_presentation_request for immediate cleanup
        mock_get_individual = Mock()
        mock_get_individual.status_code = 200
        mock_get_individual.content = b'{"by_format": {"test": "data"}}'

        # Mock successful immediate delete
        mock_delete_success = Mock()
        mock_delete_success.status_code = 200

        # For background cleanup - no records remain
        mock_get_all = Mock()
        mock_get_all.status_code = 200
        mock_get_all.content = b'{"results": []}'

        # Configure mocks based on URL patterns
        def mock_get_side_effect(*args, **kwargs):
            url = args[0]
            if "/records/" in url and not url.endswith("/records"):
                return mock_get_individual
            else:
                return mock_get_all

        mock_get.side_effect = mock_get_side_effect
        mock_delete.return_value = mock_delete_success

        # Act - Immediate cleanup
        presentation_data = client.get_presentation_request("test-pres-ex-id")
        immediate_cleanup_success = client.delete_presentation_record("test-pres-ex-id")

        # Background cleanup
        background_result = await cleanup_old_presentation_records()

        # Assert
        assert presentation_data is not None
        assert immediate_cleanup_success is True
        assert background_result["total_presentation_records"] == 0
        assert background_result["cleaned_presentation_records"] == 0

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_immediate_cleanup_failure_background_recovers(
        self, mock_delete, mock_get
    ):
        """Test background cleanup handles records missed by immediate cleanup."""

        # Arrange - Mock immediate cleanup failure, background success
        old_time = datetime.now(UTC) - timedelta(hours=25)

        mock_record_data = {
            "pres_ex_id": "failed-immediate-cleanup",
            "created_at": old_time.isoformat().replace("+00:00", "Z"),
            "state": "done",
            "by_format": {"test": "data"},
        }

        # Mock get_presentation_request (for immediate)
        mock_get_individual = Mock()
        mock_get_individual.status_code = 200
        mock_get_individual.content = json.dumps(mock_record_data).encode()

        # Mock get_all_presentation_records (for background)
        mock_get_all = Mock()
        mock_get_all.status_code = 200
        mock_get_all.content = json.dumps({"results": [mock_record_data]}).encode()

        # Configure mock responses based on URL
        def mock_get_side_effect(url, **kwargs):
            if "/records/" in url and not url.endswith("/records"):
                return mock_get_individual
            elif "/present-proof-2.0/records" in url:
                return mock_get_all
            elif "/connections" in url:
                # No connections to clean in this test
                mock_response = Mock()
                mock_response.status_code = 200
                mock_response.content = json.dumps({"results": []}).encode()
                return mock_response
            else:
                return mock_get_all

        mock_get.side_effect = mock_get_side_effect

        # Setup delete to fail first time (immediate), succeed second time (background)
        delete_responses = [
            Mock(status_code=500),  # Immediate cleanup fails
            Mock(status_code=200),  # Background cleanup succeeds
        ]
        mock_delete.side_effect = delete_responses

        # Act
        client = AcapyClient()

        # Immediate cleanup
        presentation_data = client.get_presentation_request("failed-immediate-cleanup")
        immediate_cleanup_success = client.delete_presentation_record(
            "failed-immediate-cleanup"
        )

        # Background cleanup
        background_result = await cleanup_old_presentation_records()

        # Assert
        assert presentation_data is not None
        assert immediate_cleanup_success is False  # Immediate cleanup failed
        assert background_result["total_presentation_records"] == 1
        assert (
            background_result["cleaned_presentation_records"] == 1
        )  # Background succeeded
        assert background_result["failed_cleanups"] == 0
        assert background_result["hit_presentation_limit"] == False
        assert background_result["hit_connection_limit"] == False

    @patch("api.services.cleanup.settings")
    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_configurable_retention_periods(
        self, mock_delete, mock_get, mock_settings
    ):
        """Test that different retention periods work correctly."""

        # Arrange - Different retention period
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 48  # 2 days
        mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 60
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

        # Configure mock responses based on URL
        def mock_get_side_effect(url, **kwargs):
            mock_response = Mock()
            mock_response.status_code = 200
            if "/present-proof-2.0/records" in url:
                mock_response.content = json.dumps({"results": mock_records}).encode()
            elif "/connections" in url:
                # No connections to clean in this test
                mock_response.content = json.dumps({"results": []}).encode()
            return mock_response

        mock_get.side_effect = mock_get_side_effect

        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_delete.return_value = mock_delete_response

        # Act
        result = await cleanup_old_presentation_records()

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
        assert mock_delete.call_count == expected_cleaned

    @patch("api.services.cleanup.settings")
    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_error_resilience_partial_failures(
        self, mock_delete, mock_get, mock_settings
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

        # Configure mock responses based on URL
        def mock_get_side_effect(url, **kwargs):
            mock_response = Mock()
            mock_response.status_code = 200
            if "/present-proof-2.0/records" in url:
                mock_response.content = json.dumps({"results": mock_records}).encode()
            elif "/connections" in url:
                # No connections to clean in this test
                mock_response.content = json.dumps({"results": []}).encode()
            return mock_response

        mock_get.side_effect = mock_get_side_effect

        # Mock delete responses - middle one fails
        delete_responses = [
            Mock(status_code=200),  # Success
            Mock(status_code=404),  # Failure
            Mock(status_code=200),  # Success
        ]
        mock_delete.side_effect = delete_responses

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 3
        assert result["cleaned_presentation_records"] == 2  # 2 successful deletions
        assert result["failed_cleanups"] == 1  # 1 failed deletion
        assert len(result["errors"]) == 1
        assert "record-fail" in result["errors"][0]
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

    @patch("api.core.acapy.client.requests.get")
    @pytest.mark.asyncio
    async def test_network_resilience(self, mock_get):
        """Test system behavior during network issues."""

        # Arrange - Network failure causes cleanup to handle gracefully
        mock_get.side_effect = Exception("Network timeout")

        # Act
        result = await cleanup_old_presentation_records()

        # Assert - System should handle gracefully by returning empty results
        # The AcapyClient catches network errors and returns empty list,
        # so the cleanup function processes 0 records successfully
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert result["failed_cleanups"] == 0
        assert (
            len(result["errors"]) == 0
        )  # No errors because client handles them gracefully

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_large_dataset_handling(self, mock_delete, mock_get):
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

        # Configure mock responses based on URL
        def mock_get_side_effect(url, **kwargs):
            mock_response = Mock()
            mock_response.status_code = 200
            if "/present-proof-2.0/records" in url:
                mock_response.content = json.dumps({"results": mock_records}).encode()
            elif "/connections" in url:
                # No connections to clean in this test
                mock_response.content = json.dumps({"results": []}).encode()
            return mock_response

        mock_get.side_effect = mock_get_side_effect

        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_delete.return_value = mock_delete_response

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 100
        assert result["cleaned_presentation_records"] == 100
        assert result["failed_cleanups"] == 0
        assert mock_delete.call_count == 100
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_connection_cleanup_only_invitations(self, mock_delete, mock_get):
        """Test that only expired connection invitations are cleaned up, not active connections."""

        # Arrange - Mock connections with different states and ages
        expired_time = datetime.now(UTC) - timedelta(
            seconds=30
        )  # Expired (> 10 seconds)
        recent_time = datetime.now(UTC) - timedelta(seconds=5)  # Recent (< 10 seconds)

        mock_connections = [
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
            {
                "connection_id": "expired-but-active",
                "state": "active",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
            },
        ]

        # Configure mock responses
        def mock_get_side_effect(url, **kwargs):
            mock_response = Mock()
            mock_response.status_code = 200
            if "/present-proof-2.0/records" in url:
                # No presentation records to clean
                mock_response.content = json.dumps({"results": []}).encode()
            elif "/connections" in url:
                # Filter connections by state parameter if provided
                params = kwargs.get("params", {})
                filtered_connections = mock_connections
                if "state" in params:
                    filtered_connections = [
                        conn
                        for conn in mock_connections
                        if conn["state"] == params["state"]
                    ]
                mock_response.content = json.dumps(
                    {"results": filtered_connections}
                ).encode()
            return mock_response

        mock_get.side_effect = mock_get_side_effect

        # Mock successful delete responses
        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_delete.return_value = mock_delete_response

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_presentation_records"] == 0
        assert result["cleaned_presentation_records"] == 0
        assert (
            result["total_connections"] == 3
        )  # Only invitation-state connections returned by API
        assert result["cleaned_connections"] == 2  # Only expired invitations cleaned
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False

        # Verify API calls
        assert (
            mock_get.call_count == 2
        )  # Called for both presentation records and connections
        assert mock_delete.call_count == 2  # Only expired invitations deleted

    @patch("api.core.acapy.client.requests.get")
    @patch("api.core.acapy.client.requests.delete")
    @pytest.mark.asyncio
    async def test_connection_cleanup_failure_handling(self, mock_delete, mock_get):
        """Test proper error handling when connection deletion fails."""

        # Arrange - Mock expired invitation
        expired_time = datetime.now(UTC) - timedelta(seconds=30)

        mock_connections = [
            {
                "connection_id": "failed-delete-connection",
                "state": "invitation",
                "created_at": expired_time.isoformat().replace("+00:00", "Z"),
            },
        ]

        # Configure mock responses
        def mock_get_side_effect(url, **kwargs):
            mock_response = Mock()
            mock_response.status_code = 200
            if "/present-proof-2.0/records" in url:
                mock_response.content = json.dumps({"results": []}).encode()
            elif "/connections" in url:
                mock_response.content = json.dumps(
                    {"results": mock_connections}
                ).encode()
            return mock_response

        mock_get.side_effect = mock_get_side_effect

        # Mock failed delete response
        mock_delete_response = Mock()
        mock_delete_response.status_code = 500
        mock_delete.return_value = mock_delete_response

        # Act
        result = await cleanup_old_presentation_records()

        # Assert
        assert result["total_connections"] == 1
        assert result["cleaned_connections"] == 0  # Failed to clean
        assert result["failed_cleanups"] == 1
        assert len(result["errors"]) == 1
        assert "Failed to delete expired connection invitation" in result["errors"][0]
        assert result["hit_presentation_limit"] == False
        assert result["hit_connection_limit"] == False
