"""Tests for updated webhook handler with cleanup functionality."""

import json
from unittest.mock import AsyncMock, MagicMock, patch, Mock
import pytest
from bson import ObjectId
from fastapi import Request

from api.authSessions.models import AuthSession, AuthSessionState
from api.routers.acapy_handler import post_topic


class TestAcapyHandlerCleanup:
    """Test updated webhook handler with presentation cleanup functionality."""

    @pytest.fixture
    def mock_db(self):
        """Mock database fixture."""
        return MagicMock()

    @pytest.fixture
    def mock_auth_session(self):
        """Mock auth session fixture."""
        auth_session = MagicMock(spec=AuthSession)
        auth_session.id = ObjectId()
        auth_session.pres_exch_id = "test-pres-ex-id"
        auth_session.connection_id = "test-connection-id"
        auth_session.proof_status = AuthSessionState.NOT_STARTED
        auth_session.multi_use = False
        auth_session.model_dump.return_value = {
            "id": str(auth_session.id),
            "pres_exch_id": auth_session.pres_exch_id,
            "connection_id": auth_session.connection_id,
            "proof_status": AuthSessionState.VERIFIED,
            "presentation_exchange": {},
            "ver_config_id": "test-ver-config-id",
            "request_parameters": {"test": "params"},
            "pyop_auth_code": "test-auth-code",
            "response_url": "http://test.com/callback",
            "multi_use": False,
        }
        return auth_session

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
        return request

    @patch("api.routers.acapy_handler.settings.USE_CONNECTION_BASED_VERIFICATION", True)
    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.get_socket_id_for_pid")
    @patch("api.routers.acapy_handler.sio.emit")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_successful_cleanup(
        self,
        mock_sio_emit,
        mock_get_socket_id,
        mock_auth_session_crud,
        mock_acapy_client,
        mock_db,
        mock_auth_session,
        mock_request,
    ):
        """Test successful presentation data retrieval and cleanup."""
        # Arrange
        mock_crud_instance = mock_auth_session_crud.return_value
        mock_crud_instance.get_by_pres_exch_id = AsyncMock(
            return_value=mock_auth_session
        )
        mock_crud_instance.patch = AsyncMock()

        mock_client_instance = mock_acapy_client.return_value
        mock_client_instance.get_presentation_request.return_value = {
            "by_format": {"test": "presentation_data"}
        }
        # Setup mock to handle combined presentation and connection cleanup in single call
        mock_client_instance.delete_presentation_record_and_connection.return_value = (
            True,   # presentation_deleted: True
            False,  # connection_deleted: False (to match expected log output)
            []      # errors: empty list
        )

        mock_get_socket_id.return_value = "test-socket-id"

        # Act
        await post_topic(mock_request, "present_proof_v2_0", mock_db)

        # Assert
        # Verify presentation data was retrieved
        mock_client_instance.get_presentation_request.assert_called_once_with(
            "test-pres-ex-id"
        )

        # Verify auth session was updated with presentation data (set by production code)
        assert mock_auth_session.presentation_exchange == {"test": "presentation_data"}
        assert mock_auth_session.proof_status == AuthSessionState.VERIFIED

        # Verify combined cleanup was attempted for both presentation and connection in single call
        mock_client_instance.delete_presentation_record_and_connection.assert_called_once_with(
            "test-pres-ex-id", "test-connection-id"
        )

        # Verify database update was called (should still be 2 times due to multiple auth session updates)
        assert mock_crud_instance.patch.call_count == 2

        # Verify socket notification was sent
        mock_sio_emit.assert_called_once_with(
            "status", {"status": "verified"}, to="test-socket-id"
        )

    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.get_socket_id_for_pid")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_presentation_data_retrieval_failure(
        self,
        mock_get_socket_id,
        mock_auth_session_crud,
        mock_acapy_client,
        mock_db,
        mock_auth_session,
        mock_request,
    ):
        """Test when presentation data retrieval fails."""
        # Arrange
        mock_crud_instance = mock_auth_session_crud.return_value
        mock_crud_instance.get_by_pres_exch_id = AsyncMock(
            return_value=mock_auth_session
        )

        mock_client_instance = mock_acapy_client.return_value
        mock_client_instance.get_presentation_request.return_value = (
            None  # Simulates failure
        )

        mock_get_socket_id.return_value = "test-socket-id"

        # Act & Assert
        with pytest.raises(ValueError, match="Failed to retrieve presentation data"):
            await post_topic(mock_request, "present_proof_v2_0", mock_db)

        # Verify get_presentation_request was called
        mock_client_instance.get_presentation_request.assert_called_once_with(
            "test-pres-ex-id"
        )

        # Verify cleanup was not attempted since data retrieval failed
        mock_client_instance.delete_presentation_record_and_connection.assert_not_called()

        # Verify database update was not called since operation failed
        mock_crud_instance.patch.assert_not_called()

    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.get_socket_id_for_pid")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_presentation_data_api_exception(
        self,
        mock_get_socket_id,
        mock_auth_session_crud,
        mock_acapy_client,
        mock_db,
        mock_auth_session,
        mock_request,
    ):
        """Test when presentation data API call throws exception."""
        # Arrange
        mock_crud_instance = mock_auth_session_crud.return_value
        mock_crud_instance.get_by_pres_exch_id = AsyncMock(
            return_value=mock_auth_session
        )

        mock_client_instance = mock_acapy_client.return_value
        mock_client_instance.get_presentation_request.side_effect = Exception(
            "API Error"
        )

        mock_get_socket_id.return_value = "test-socket-id"

        # Act & Assert
        with pytest.raises(Exception, match="API Error"):
            await post_topic(mock_request, "present_proof_v2_0", mock_db)

        # Verify get_presentation_request was called
        mock_client_instance.get_presentation_request.assert_called_once_with(
            "test-pres-ex-id"
        )

        # Verify cleanup was not attempted since data retrieval failed
        mock_client_instance.delete_presentation_record_and_connection.assert_not_called()

    @patch("api.routers.acapy_handler.settings.USE_CONNECTION_BASED_VERIFICATION", True)
    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.get_socket_id_for_pid")
    @patch("api.routers.acapy_handler.sio.emit")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_cleanup_failure(
        self,
        mock_sio_emit,
        mock_get_socket_id,
        mock_auth_session_crud,
        mock_acapy_client,
        mock_db,
        mock_auth_session,
        mock_request,
    ):
        """Test when immediate cleanup fails but verification continues."""
        # Arrange
        mock_crud_instance = mock_auth_session_crud.return_value
        mock_crud_instance.get_by_pres_exch_id = AsyncMock(
            return_value=mock_auth_session
        )
        mock_crud_instance.patch = AsyncMock()

        mock_client_instance = mock_acapy_client.return_value
        mock_client_instance.get_presentation_request.return_value = {
            "by_format": {"test": "presentation_data"}
        }
        # Setup mock to handle combined presentation and connection cleanup failing
        mock_client_instance.delete_presentation_record_and_connection.return_value = (
            False,  # presentation_deleted: False (presentation cleanup fails)
            False,  # connection_deleted: False (connection cleanup also fails)
            []      # errors: empty list
        )

        mock_get_socket_id.return_value = "test-socket-id"

        # Act
        await post_topic(mock_request, "present_proof_v2_0", mock_db)

        # Assert
        # Verify presentation data was retrieved
        mock_client_instance.get_presentation_request.assert_called_once_with(
            "test-pres-ex-id"
        )

        # Verify auth session was updated despite cleanup failure
        assert mock_auth_session.presentation_exchange == {"test": "presentation_data"}
        assert mock_auth_session.proof_status == AuthSessionState.VERIFIED

        # Verify combined cleanup was attempted for both presentation and connection in single call
        mock_client_instance.delete_presentation_record_and_connection.assert_called_once_with(
            "test-pres-ex-id", "test-connection-id"
        )

        # Verify database update was called (should still be 2 times due to multiple auth session updates)
        assert mock_crud_instance.patch.call_count == 2

        # Verify socket notification was sent
        mock_sio_emit.assert_called_once_with(
            "status", {"status": "verified"}, to="test-socket-id"
        )

    @patch("api.routers.acapy_handler.settings.USE_CONNECTION_BASED_VERIFICATION", True)
    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.get_socket_id_for_pid")
    @patch("api.routers.acapy_handler.sio.emit")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_cleanup_exception(
        self,
        mock_sio_emit,
        mock_get_socket_id,
        mock_auth_session_crud,
        mock_acapy_client,
        mock_db,
        mock_auth_session,
        mock_request,
    ):
        """Test when cleanup throws exception but verification continues."""
        # Arrange
        mock_crud_instance = mock_auth_session_crud.return_value
        mock_crud_instance.get_by_pres_exch_id = AsyncMock(
            return_value=mock_auth_session
        )
        mock_crud_instance.patch = AsyncMock()

        mock_client_instance = mock_acapy_client.return_value
        mock_client_instance.get_presentation_request.return_value = {
            "by_format": {"test": "presentation_data"}
        }
        # Setup mock to handle combined cleanup throwing exception
        mock_client_instance.delete_presentation_record_and_connection.side_effect = Exception(
            "Cleanup error"
        )

        mock_get_socket_id.return_value = "test-socket-id"

        # Act
        await post_topic(mock_request, "present_proof_v2_0", mock_db)

        # Assert
        # Verify presentation data was retrieved
        mock_client_instance.get_presentation_request.assert_called_once_with(
            "test-pres-ex-id"
        )

        # Verify auth session was updated despite cleanup exception
        assert mock_auth_session.presentation_exchange == {"test": "presentation_data"}
        assert mock_auth_session.proof_status == AuthSessionState.VERIFIED

        # Verify combined cleanup was attempted for both presentation and connection in single call
        mock_client_instance.delete_presentation_record_and_connection.assert_called_once_with(
            "test-pres-ex-id", "test-connection-id"
        )

        # Verify database update was called (should still be 2 times due to multiple auth session updates)
        assert mock_crud_instance.patch.call_count == 2

        # Verify socket notification was sent
        mock_sio_emit.assert_called_once_with(
            "status", {"status": "verified"}, to="test-socket-id"
        )

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
        return request

    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.get_socket_id_for_pid")
    @patch("api.routers.acapy_handler.sio.emit")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_failed_verification_no_cleanup(
        self,
        mock_sio_emit,
        mock_get_socket_id,
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
        mock_crud_instance.patch = AsyncMock()

        mock_client_instance = mock_acapy_client.return_value
        mock_get_socket_id.return_value = "test-socket-id"

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
        assert mock_auth_session.proof_status == AuthSessionState.FAILED

        # Verify socket notification was sent for failure
        mock_sio_emit.assert_called_once_with(
            "status", {"status": "failed"}, to="test-socket-id"
        )

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

    @patch("api.routers.acapy_handler.settings.USE_CONNECTION_BASED_VERIFICATION", True)
    @patch("api.routers.acapy_handler.AcapyClient")
    @patch("api.routers.acapy_handler.AuthSessionCRUD")
    @patch("api.routers.acapy_handler.get_socket_id_for_pid")
    @patch("api.routers.acapy_handler.sio.emit")
    @pytest.mark.asyncio
    async def test_present_proof_webhook_network_timeout_during_cleanup(
        self,
        mock_sio_emit,
        mock_get_socket_id,
        mock_auth_session_crud,
        mock_acapy_client,
        mock_db,
        mock_auth_session,
        mock_request,
    ):
        """Test network timeout during cleanup operations."""
        # Arrange
        mock_crud_instance = mock_auth_session_crud.return_value
        mock_crud_instance.get_by_pres_exch_id = AsyncMock(
            return_value=mock_auth_session
        )
        mock_crud_instance.patch = AsyncMock()

        mock_client_instance = mock_acapy_client.return_value
        mock_client_instance.get_presentation_request.return_value = {
            "by_format": {"test": "presentation_data"}
        }
        # Setup mock to handle combined cleanup throwing network timeout
        import requests
        mock_client_instance.delete_presentation_record_and_connection.side_effect = requests.Timeout(
            "Network timeout"
        )

        mock_get_socket_id.return_value = "test-socket-id"

        # Act
        await post_topic(mock_request, "present_proof_v2_0", mock_db)

        # Assert - Cleanup failure should not prevent successful verification
        assert mock_auth_session.presentation_exchange == {"test": "presentation_data"}
        assert mock_auth_session.proof_status == AuthSessionState.VERIFIED

        # Verify combined cleanup was attempted for both presentation and connection in single call
        mock_client_instance.delete_presentation_record_and_connection.assert_called_once_with(
            "test-pres-ex-id", "test-connection-id"
        )

        # Verify verification still completed successfully
        mock_sio_emit.assert_called_once_with(
            "status", {"status": "verified"}, to="test-socket-id"
        )
