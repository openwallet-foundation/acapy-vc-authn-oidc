"""Integration tests for the complete cleanup flow."""

import asyncio
import json
from datetime import datetime, timedelta, UTC
from unittest.mock import Mock, patch, AsyncMock
import pytest

from api.services.cleanup import PresentationCleanupService
from api.core.acapy.client import AcapyClient


class TestCleanupIntegration:
    """Integration tests for the complete presentation cleanup flow."""

    @patch('api.core.acapy.client.requests.get')
    @patch('api.core.acapy.client.requests.delete')
    @pytest.mark.asyncio
    async def test_full_cleanup_flow_immediate_and_background(self, mock_delete, mock_get):
        """Test complete flow: immediate cleanup on webhook + background cleanup."""
        
        # Arrange - Mock ACA-Py API responses
        old_time = datetime.now(UTC) - timedelta(hours=25)
        recent_time = datetime.now(UTC) - timedelta(hours=1)
        
        # Mock get_all_presentation_records response
        mock_records = [
            {
                "pres_ex_id": "old-record-1",
                "created_at": old_time.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            },
            {
                "pres_ex_id": "old-record-2",
                "created_at": old_time.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            },
            {
                "pres_ex_id": "recent-record",
                "created_at": recent_time.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            }
        ]
        
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.content = json.dumps({"results": mock_records}).encode()
        mock_get.return_value = mock_get_response
        
        # Mock delete responses - all successful
        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_delete.return_value = mock_delete_response

        # Act - Run background cleanup
        cleanup_service = PresentationCleanupService()
        result = await cleanup_service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 3
        assert result["cleaned_records"] == 2  # Only old records cleaned
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 0
        
        # Verify API calls
        mock_get.assert_called_once()
        assert mock_delete.call_count == 2  # Only old records deleted

    @patch('api.core.acapy.client.requests.get')
    @patch('api.core.acapy.client.requests.delete')
    @pytest.mark.asyncio
    async def test_immediate_cleanup_success_no_background_needed(self, mock_delete, mock_get):
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
        cleanup_service = PresentationCleanupService()
        background_result = await cleanup_service.cleanup_old_presentation_records()

        # Assert
        assert presentation_data is not None
        assert immediate_cleanup_success is True
        assert background_result["total_records"] == 0
        assert background_result["cleaned_records"] == 0

    @patch('api.core.acapy.client.requests.get')
    @patch('api.core.acapy.client.requests.delete')
    @pytest.mark.asyncio
    async def test_immediate_cleanup_failure_background_recovers(self, mock_delete, mock_get):
        """Test background cleanup handles records missed by immediate cleanup."""
        
        # Arrange - Mock immediate cleanup failure, background success
        old_time = datetime.now(UTC) - timedelta(hours=25)
        
        mock_record_data = {
            "pres_ex_id": "failed-immediate-cleanup",
            "created_at": old_time.isoformat().replace('+00:00', 'Z'),
            "state": "done",
            "by_format": {"test": "data"}
        }
        
        # Mock get_presentation_request (for immediate)
        mock_get_individual = Mock()
        mock_get_individual.status_code = 200
        mock_get_individual.content = json.dumps(mock_record_data).encode()
        
        # Mock get_all_presentation_records (for background)
        mock_get_all = Mock()
        mock_get_all.status_code = 200
        mock_get_all.content = json.dumps({"results": [mock_record_data]}).encode()
        
        # Setup URL-based routing for different API endpoints
        mock_get.side_effect = lambda url, **kwargs: (
            mock_get_individual if "/records/" in url and not url.endswith("/records") 
            else mock_get_all
        )
        
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
        immediate_cleanup_success = client.delete_presentation_record("failed-immediate-cleanup")
        
        # Background cleanup
        cleanup_service = PresentationCleanupService()
        background_result = await cleanup_service.cleanup_old_presentation_records()

        # Assert
        assert presentation_data is not None
        assert immediate_cleanup_success is False  # Immediate cleanup failed
        assert background_result["total_records"] == 1
        assert background_result["cleaned_records"] == 1  # Background succeeded
        assert background_result["failed_cleanups"] == 0

    @patch('api.services.cleanup.settings')
    @patch('api.core.acapy.client.requests.get')
    @patch('api.core.acapy.client.requests.delete')
    @pytest.mark.asyncio
    async def test_configurable_retention_periods(self, mock_delete, mock_get, mock_settings):
        """Test that different retention periods work correctly."""
        
        # Arrange - Different retention period
        mock_settings.CONTROLLER_PRESENTATION_RECORD_RETENTION_HOURS = 48  # 2 days
        mock_settings.CONTROLLER_PRESENTATION_CLEANUP_SCHEDULE_MINUTES = 60
        
        now = datetime.now(UTC)
        times_and_expected = [
            (now - timedelta(hours=25), False),  # 25 hours old - should NOT be cleaned (< 48h)
            (now - timedelta(hours=49), True),   # 49 hours old - should be cleaned (> 48h)
            (now - timedelta(hours=72), True),   # 72 hours old - should be cleaned (> 48h)
        ]
        
        mock_records = []
        for i, (time_created, should_clean) in enumerate(times_and_expected):
            mock_records.append({
                "pres_ex_id": f"record-{i}",
                "created_at": time_created.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            })
        
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.content = json.dumps({"results": mock_records}).encode()
        mock_get.return_value = mock_get_response
        
        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_delete.return_value = mock_delete_response

        # Act
        cleanup_service = PresentationCleanupService()
        result = await cleanup_service.cleanup_old_presentation_records()

        # Assert
        expected_cleaned = sum(1 for _, should_clean in times_and_expected if should_clean)
        assert result["total_records"] == 3
        assert result["cleaned_records"] == expected_cleaned  # Should be 2 (records 1 and 2)
        assert result["failed_cleanups"] == 0
        
        # Verify only old enough records were deleted
        assert mock_delete.call_count == expected_cleaned

    @patch('api.core.acapy.client.requests.get')
    @patch('api.core.acapy.client.requests.delete')
    @pytest.mark.asyncio
    async def test_error_resilience_partial_failures(self, mock_delete, mock_get):
        """Test system resilience when some operations fail."""
        
        # Arrange - Mix of successful and failed operations
        old_time = datetime.now(UTC) - timedelta(hours=25)
        
        mock_records = [
            {
                "pres_ex_id": "record-success-1",
                "created_at": old_time.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            },
            {
                "pres_ex_id": "record-fail",
                "created_at": old_time.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            },
            {
                "pres_ex_id": "record-success-2",
                "created_at": old_time.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            }
        ]
        
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.content = json.dumps({"results": mock_records}).encode()
        mock_get.return_value = mock_get_response
        
        # Mock delete responses - middle one fails
        delete_responses = [
            Mock(status_code=200),  # Success
            Mock(status_code=404),  # Failure
            Mock(status_code=200),  # Success
        ]
        mock_delete.side_effect = delete_responses

        # Act
        cleanup_service = PresentationCleanupService()
        result = await cleanup_service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 3
        assert result["cleaned_records"] == 2    # 2 successful deletions
        assert result["failed_cleanups"] == 1    # 1 failed deletion
        assert len(result["errors"]) == 1
        assert "record-fail" in result["errors"][0]

    @patch.object(PresentationCleanupService, "cleanup_old_presentation_records")
    @pytest.mark.asyncio
    async def test_network_resilience(self, mock_cleanup):
        """Test system behavior during network issues."""
        
        # Arrange - Network failure causes cleanup to fail
        mock_cleanup.return_value = {
            "total_records": 0,
            "cleaned_records": 0,
            "failed_cleanups": 0,
            "errors": ["Background cleanup failed: Network timeout"],
        }

        # Act
        cleanup_service = PresentationCleanupService()
        result = await cleanup_service.cleanup_old_presentation_records()

        # Assert - System should handle gracefully
        assert result["total_records"] == 0
        assert result["cleaned_records"] == 0
        assert result["failed_cleanups"] == 0
        assert len(result["errors"]) == 1
        assert "Background cleanup failed: Network timeout" in result["errors"][0]

    @patch('api.core.acapy.client.requests.get')
    @patch('api.core.acapy.client.requests.delete')  
    @pytest.mark.asyncio
    async def test_large_dataset_handling(self, mock_delete, mock_get):
        """Test handling of large numbers of records."""
        
        # Arrange - Large number of old records
        old_time = datetime.now(UTC) - timedelta(hours=25)
        
        # Generate 100 old records
        mock_records = []
        for i in range(100):
            mock_records.append({
                "pres_ex_id": f"bulk-record-{i}",
                "created_at": old_time.isoformat().replace('+00:00', 'Z'),
                "state": "done"
            })
        
        mock_get_response = Mock()
        mock_get_response.status_code = 200
        mock_get_response.content = json.dumps({"results": mock_records}).encode()
        mock_get.return_value = mock_get_response
        
        mock_delete_response = Mock()
        mock_delete_response.status_code = 200
        mock_delete.return_value = mock_delete_response

        # Act
        cleanup_service = PresentationCleanupService()
        result = await cleanup_service.cleanup_old_presentation_records()

        # Assert
        assert result["total_records"] == 100
        assert result["cleaned_records"] == 100
        assert result["failed_cleanups"] == 0
        assert mock_delete.call_count == 100