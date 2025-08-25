"""Tests for AcapyClient cleanup-related methods."""

import json
from unittest.mock import Mock, patch
import pytest
import requests
from uuid import UUID

from api.core.acapy.client import AcapyClient


class TestAcapyClientCleanup:
    """Test cleanup-related methods in AcapyClient."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = AcapyClient()

    @patch("api.core.acapy.client.requests.delete")
    def test_delete_presentation_record_success(self, mock_delete):
        """Test successful deletion of presentation record."""
        # Arrange
        pres_ex_id = "test-pres-ex-id"
        mock_response = Mock()
        mock_response.status_code = 200
        mock_delete.return_value = mock_response

        # Act
        result = self.client.delete_presentation_record(pres_ex_id)

        # Assert
        assert result is True
        mock_delete.assert_called_once()
        call_args = mock_delete.call_args
        assert f"/present-proof-2.0/records/{pres_ex_id}" in call_args[0][0]

    @patch("api.core.acapy.client.requests.delete")
    def test_delete_presentation_record_failure(self, mock_delete):
        """Test failed deletion of presentation record."""
        # Arrange
        pres_ex_id = "test-pres-ex-id"
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.content = b"Record not found"
        mock_delete.return_value = mock_response

        # Act
        result = self.client.delete_presentation_record(pres_ex_id)

        # Assert
        assert result is False
        mock_delete.assert_called_once()

    @patch("api.core.acapy.client.requests.delete")
    def test_delete_presentation_record_exception(self, mock_delete):
        """Test deletion with network exception."""
        # Arrange
        pres_ex_id = "test-pres-ex-id"
        mock_delete.side_effect = requests.RequestException("Network error")

        # Act
        result = self.client.delete_presentation_record(pres_ex_id)

        # Assert
        assert result is False
        mock_delete.assert_called_once()

    @patch("api.core.acapy.client.requests.delete")
    def test_delete_presentation_record_with_uuid(self, mock_delete):
        """Test deletion with UUID parameter."""
        # Arrange
        pres_ex_id = UUID("12345678-1234-5678-1234-567812345678")
        mock_response = Mock()
        mock_response.status_code = 200
        mock_delete.return_value = mock_response

        # Act
        result = self.client.delete_presentation_record(pres_ex_id)

        # Assert
        assert result is True
        mock_delete.assert_called_once()
        call_args = mock_delete.call_args
        assert str(pres_ex_id) in call_args[0][0]

    @patch("api.core.acapy.client.requests.get")
    def test_get_all_presentation_records_success(self, mock_get):
        """Test successful retrieval of all presentation records."""
        # Arrange
        mock_records = [
            {
                "pres_ex_id": "record-1",
                "created_at": "2024-01-01T12:00:00Z",
                "state": "done",
            },
            {
                "pres_ex_id": "record-2",
                "created_at": "2024-01-02T12:00:00Z",
                "state": "done",
            },
        ]
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"results": mock_records}).encode()
        mock_get.return_value = mock_response

        # Act
        result = self.client.get_all_presentation_records()

        # Assert
        assert len(result) == 2
        assert result[0]["pres_ex_id"] == "record-1"
        assert result[1]["pres_ex_id"] == "record-2"
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert "/present-proof-2.0/records" in call_args[0][0]

    @patch("api.core.acapy.client.requests.get")
    def test_get_all_presentation_records_empty_results(self, mock_get):
        """Test retrieval when no records exist."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"results": []}).encode()
        mock_get.return_value = mock_response

        # Act
        result = self.client.get_all_presentation_records()

        # Assert
        assert result == []
        mock_get.assert_called_once()

    @patch("api.core.acapy.client.requests.get")
    def test_get_all_presentation_records_missing_results_key(self, mock_get):
        """Test retrieval when response doesn't have results key."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = json.dumps({"data": []}).encode()
        mock_get.return_value = mock_response

        # Act
        result = self.client.get_all_presentation_records()

        # Assert
        assert result == []
        mock_get.assert_called_once()

    @patch("api.core.acapy.client.requests.get")
    def test_get_all_presentation_records_http_error(self, mock_get):
        """Test retrieval with HTTP error response."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 500
        mock_response.content = b"Internal server error"
        mock_get.return_value = mock_response

        # Act
        result = self.client.get_all_presentation_records()

        # Assert
        assert result == []
        mock_get.assert_called_once()

    @patch("api.core.acapy.client.requests.get")
    def test_get_all_presentation_records_network_exception(self, mock_get):
        """Test retrieval with network exception."""
        # Arrange
        mock_get.side_effect = requests.RequestException("Network error")

        # Act
        result = self.client.get_all_presentation_records()

        # Assert
        assert result == []
        mock_get.assert_called_once()

    @patch("api.core.acapy.client.requests.get")
    def test_get_all_presentation_records_invalid_json(self, mock_get):
        """Test retrieval with invalid JSON response."""
        # Arrange
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"invalid json"
        mock_get.return_value = mock_response

        # Act
        result = self.client.get_all_presentation_records()

        # Assert
        assert result == []
        mock_get.assert_called_once()
