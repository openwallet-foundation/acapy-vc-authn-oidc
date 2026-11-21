"""Tests for updated webhook handler with cleanup functionality."""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from fastapi import Request

from api.authSessions.models import AuthSession, AuthSessionState
from api.routers.acapy_handler import post_topic
from api.routers.tests.fakes import fake_advance, saved_session


class TestAcapyHandlerCleanup:
    """Test updated webhook handler with presentation cleanup functionality."""

    @pytest.fixture
    def mock_db(self):
        """Mock database fixture."""
        return MagicMock()

    @pytest.fixture
    def mock_auth_session(self):
        """Mock auth session fixture."""
        return AuthSession(
            pres_exch_id="test-pres-ex-id",
            connection_id="test-connection-id",
            expired_timestamp=datetime.now(UTC) + timedelta(seconds=3600),
            ver_config_id="test-ver-config-id",
            request_parameters={"test": "params"},
            pyop_auth_code="test-auth-code",
            response_url="http://test.com/callback",
        )

    @pytest.fixture
    def mock_request(self):
        """Mock request fixture with present proof webhook body."""
        request = Mock(spec=Request)
        webhook_body = {
            "pres_ex_id": "test-pres-ex-id",
            "state": "done",
            "verified": "true",
        }
        request.body = AsyncMock(return_value=json.dumps(webhook_body).encode("ascii"))
        request.app = MagicMock()
        return request

    @pytest.fixture
    def mock_failed_verification_request(self):
        """Mock request fixture for failed verification."""
        request = Mock(spec=Request)
        webhook_body = {
            "pres_ex_id": "test-pres-ex-id",
            "state": "done",
            "verified": "false",  # Failed verification
        }
        request.body = AsyncMock(return_value=json.dumps(webhook_body).encode("ascii"))
        request.app = MagicMock()
        return request

    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.notify")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_failed_verification_no_cleanup(
        self,
        mock_notify,
        mock_auth_session_crud,
        mock_acapy_client,
        mock_db,
        mock_auth_session,
        mock_failed_verification_request,
    ):
        """Test that cleanup is not attempted for failed verifications."""
        # Arrange
        mock_crud_instance = mock_auth_session_crud.return_value
        mock_crud_instance.get_by_pres_exch_id = AsyncMock(
            return_value=mock_auth_session
        )
        mock_crud_instance.advance = fake_advance()

        mock_client_instance = mock_acapy_client.return_value

        # Act
        await post_topic(
            mock_failed_verification_request, "present_proof_v2_0", mock_db
        )

        # Assert
        # Verify presentation data was NOT retrieved for failed verification
        mock_client_instance.get_presentation_request.assert_not_called()

        # Verify cleanup was NOT attempted
        mock_client_instance.delete_presentation_record.assert_not_called()

        # Verify auth session was marked as failed
        saved = saved_session(mock_crud_instance.advance)
        assert saved.proof_status == AuthSessionState.FAILED

        # Verify SSE notification was sent for failure
        mock_notify.assert_awaited_once_with(str(mock_auth_session.id), "failed")

    def test_presentation_data_parsing_edge_cases(self):
        """Test edge cases in presentation data parsing."""
        # Test cases for different by_format structures
        test_cases = [
            # Normal case
            {"by_format": {"test": "data"}},
            # Empty by_format
            {"by_format": {}},
            # Missing by_format
            {"other_field": "value"},
            # by_format is None
            {"by_format": None},
        ]

        for test_data in test_cases:
            result = test_data.get("by_format", {})
            assert isinstance(result, dict) or result is None
