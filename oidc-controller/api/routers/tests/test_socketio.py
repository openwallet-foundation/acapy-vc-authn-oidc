"""Tests for socketio functionality."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from bson import ObjectId

from api.routers.socketio import get_socket_id_for_pid
from api.authSessions.models import AuthSession, AuthSessionState


@pytest.fixture
def sample_auth_session():
    """Create sample auth session for testing."""
    return AuthSession(
        id=ObjectId("507f1f77bcf86cd799439011"),
        pres_exch_id="test-pres-ex-id",
        connection_id="test-connection-id",
        ver_config_id="test-ver-config-id",
        request_parameters={"test": "params"},
        pyop_auth_code="test-auth-code",
        response_url="http://test.com/callback",
        presentation_exchange={},
        proof_status=AuthSessionState.NOT_STARTED,
        socket_id="test-socket-id",
    )


@pytest.fixture
def sample_auth_session_without_socket():
    """Create sample auth session without socket_id for testing."""
    return AuthSession(
        id=ObjectId("507f1f77bcf86cd799439012"),
        pres_exch_id="test-pres-ex-id-2",
        connection_id="test-connection-id-2",
        ver_config_id="test-ver-config-id",
        request_parameters={"test": "params"},
        pyop_auth_code="test-auth-code-2",
        response_url="http://test.com/callback",
        presentation_exchange={},
        proof_status=AuthSessionState.NOT_STARTED,
        socket_id=None,
    )


@pytest.fixture
def mock_database():
    """Create a mock database instance."""
    return MagicMock()


class TestGetSocketIdForPid:
    """Test cases for get_socket_id_for_pid function."""

    @pytest.mark.asyncio
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_get_socket_id_for_pid_success(
        self, mock_auth_session_crud_class, mock_database, sample_auth_session
    ):
        """Test successful retrieval of socket ID for presentation ID."""
        # Setup mocks
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(return_value=sample_auth_session)

        # Execute
        result = await get_socket_id_for_pid("507f1f77bcf86cd799439011", mock_database)

        # Verify
        assert result == "test-socket-id"
        mock_auth_session_crud_class.assert_called_once_with(mock_database)
        mock_crud_instance.get.assert_called_once_with("507f1f77bcf86cd799439011")

    @pytest.mark.asyncio
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_get_socket_id_for_pid_no_socket_id(
        self,
        mock_auth_session_crud_class,
        mock_database,
        sample_auth_session_without_socket,
    ):
        """Test retrieval when auth session has no socket_id."""
        # Setup mocks
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(
            return_value=sample_auth_session_without_socket
        )

        # Execute
        result = await get_socket_id_for_pid("507f1f77bcf86cd799439012", mock_database)

        # Verify
        assert result is None
        mock_auth_session_crud_class.assert_called_once_with(mock_database)
        mock_crud_instance.get.assert_called_once_with("507f1f77bcf86cd799439012")

    @pytest.mark.asyncio
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_get_socket_id_for_pid_auth_session_not_found(
        self, mock_auth_session_crud_class, mock_database
    ):
        """Test retrieval when auth session not found."""
        # Setup mocks
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(
            side_effect=Exception("Auth session not found")
        )

        # Execute
        result = await get_socket_id_for_pid("non-existent-id", mock_database)

        # Verify
        assert result is None
        mock_auth_session_crud_class.assert_called_once_with(mock_database)
        mock_crud_instance.get.assert_called_once_with("non-existent-id")

    @pytest.mark.asyncio
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_get_socket_id_for_pid_exception_handling(
        self, mock_auth_session_crud_class, mock_database
    ):
        """Test exception handling in get_socket_id_for_pid."""
        # Setup mocks
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(side_effect=Exception("Database error"))

        # Execute
        result = await get_socket_id_for_pid("test-pid", mock_database)

        # Verify
        assert result is None
        mock_auth_session_crud_class.assert_called_once_with(mock_database)
        mock_crud_instance.get.assert_called_once_with("test-pid")
