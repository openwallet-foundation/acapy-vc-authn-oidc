"""Tests for socketio functionality."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from bson import ObjectId

from api.routers.socketio import get_socket_id_for_pid, connect, initialize, disconnect
from api.authSessions.models import AuthSession, AuthSessionState, AuthSessionPatch


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


class TestSocketIOEventHandlers:
    """Test cases for Socket.IO event handlers."""

    @pytest.mark.asyncio
    async def test_connect_event(self):
        """Test the connect event handler."""
        # Test data
        sid = "test-socket-id"
        socket = MagicMock()

        # Execute - should not raise any exceptions
        await connect(sid, socket)

        # Verify - function should complete without error
        # (This is mainly for code coverage as connect just logs)

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_success(
        self, mock_auth_session_crud_class, mock_get_db, sample_auth_session
    ):
        """Test successful initialize event."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(return_value=sample_auth_session)
        mock_crud_instance.patch = AsyncMock()

        # Test data
        sid = "new-socket-id"
        data = {"pid": "507f1f77bcf86cd799439011"}

        # Execute
        await initialize(sid, data)

        # Verify
        mock_get_db.assert_called_once()
        mock_auth_session_crud_class.assert_called_with(mock_db)
        mock_crud_instance.get.assert_called_once_with("507f1f77bcf86cd799439011")
        mock_crud_instance.patch.assert_called_once()

        # Verify the patch was called with correct data
        patch_call_args = mock_crud_instance.patch.call_args
        assert patch_call_args[0][0] == "507f1f77bcf86cd799439011"
        patch_obj = patch_call_args[0][1]
        assert isinstance(patch_obj, AuthSessionPatch)

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_no_pid(
        self, mock_auth_session_crud_class, mock_get_db
    ):
        """Test initialize event with no pid in data."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        # Test data
        sid = "test-socket-id"
        data = {}  # No pid

        # Execute
        await initialize(sid, data)

        # Verify - should call get_db but not AuthSessionCRUD
        mock_get_db.assert_called_once()
        mock_auth_session_crud_class.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_empty_pid(
        self, mock_auth_session_crud_class, mock_get_db
    ):
        """Test initialize event with empty pid."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db

        # Test data
        sid = "test-socket-id"
        data = {"pid": ""}  # Empty pid

        # Execute
        await initialize(sid, data)

        # Verify - should call get_db but not AuthSessionCRUD due to empty pid
        mock_get_db.assert_called_once()
        mock_auth_session_crud_class.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_auth_session_not_found(
        self, mock_auth_session_crud_class, mock_get_db
    ):
        """Test initialize event when auth session is not found."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(
            side_effect=Exception("Auth session not found")
        )

        # Test data
        sid = "test-socket-id"
        data = {"pid": "non-existent-pid"}

        # Execute - should not raise exception
        await initialize(sid, data)

        # Verify
        mock_get_db.assert_called_once()
        mock_crud_instance.get.assert_called_once_with("non-existent-pid")
        mock_crud_instance.patch.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_patch_failure(
        self, mock_auth_session_crud_class, mock_get_db, sample_auth_session
    ):
        """Test initialize event when patch operation fails."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(return_value=sample_auth_session)
        mock_crud_instance.patch = AsyncMock(side_effect=Exception("Database error"))

        # Test data
        sid = "test-socket-id"
        data = {"pid": "507f1f77bcf86cd799439011"}

        # Execute - should not raise exception
        await initialize(sid, data)

        # Verify
        mock_crud_instance.get.assert_called_once_with("507f1f77bcf86cd799439011")
        mock_crud_instance.patch.assert_called_once()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_success(
        self, mock_auth_session_crud_class, mock_get_db, sample_auth_session
    ):
        """Test successful disconnect event."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(
            return_value=sample_auth_session
        )
        mock_crud_instance.patch = AsyncMock()

        # Test data
        sid = "test-socket-id"

        # Execute
        await disconnect(sid)

        # Verify
        mock_get_db.assert_called_once()
        mock_auth_session_crud_class.assert_called_with(mock_db)
        mock_crud_instance.get_by_socket_id.assert_called_once_with("test-socket-id")
        mock_crud_instance.patch.assert_called_once()

        # Verify the patch was called with correct data (socket_id set to None)
        patch_call_args = mock_crud_instance.patch.call_args
        assert patch_call_args[0][0] == str(sample_auth_session.id)
        patch_obj = patch_call_args[0][1]
        assert isinstance(patch_obj, AuthSessionPatch)

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_no_auth_session_found(
        self, mock_auth_session_crud_class, mock_get_db
    ):
        """Test disconnect event when no auth session is found."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(return_value=None)

        # Test data
        sid = "non-existent-socket-id"

        # Execute
        await disconnect(sid)

        # Verify
        mock_get_db.assert_called_once()
        mock_crud_instance.get_by_socket_id.assert_called_once_with(
            "non-existent-socket-id"
        )
        mock_crud_instance.patch.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_get_by_socket_id_exception(
        self, mock_auth_session_crud_class, mock_get_db
    ):
        """Test disconnect event when get_by_socket_id raises exception."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(
            side_effect=Exception("Database error")
        )

        # Test data
        sid = "test-socket-id"

        # Execute - should not raise exception
        await disconnect(sid)

        # Verify
        mock_get_db.assert_called_once()
        mock_crud_instance.get_by_socket_id.assert_called_once_with("test-socket-id")
        mock_crud_instance.patch.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_patch_failure(
        self, mock_auth_session_crud_class, mock_get_db, sample_auth_session
    ):
        """Test disconnect event when patch operation fails."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(
            return_value=sample_auth_session
        )
        mock_crud_instance.patch = AsyncMock(side_effect=Exception("Database error"))

        # Test data
        sid = "test-socket-id"

        # Execute - should not raise exception
        await disconnect(sid)

        # Verify
        mock_crud_instance.get_by_socket_id.assert_called_once_with("test-socket-id")
        mock_crud_instance.patch.assert_called_once()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_multiple_crud_calls(
        self, mock_auth_session_crud_class, mock_get_db, sample_auth_session
    ):
        """Test that initialize creates separate CRUD instances for get and patch."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get = AsyncMock(return_value=sample_auth_session)
        mock_crud_instance.patch = AsyncMock()

        # Test data
        sid = "test-socket-id"
        data = {"pid": "507f1f77bcf86cd799439011"}

        # Execute
        await initialize(sid, data)

        # Verify that AuthSessionCRUD was called twice (once for get, once for patch)
        assert mock_auth_session_crud_class.call_count == 2
        mock_crud_instance.get.assert_called_once()
        mock_crud_instance.patch.assert_called_once()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_multiple_crud_calls(
        self, mock_auth_session_crud_class, mock_get_db, sample_auth_session
    ):
        """Test that disconnect creates separate CRUD instances for get_by_socket_id and patch."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(
            return_value=sample_auth_session
        )
        mock_crud_instance.patch = AsyncMock()

        # Test data
        sid = "test-socket-id"

        # Execute
        await disconnect(sid)

        # Verify that AuthSessionCRUD was called twice
        assert mock_auth_session_crud_class.call_count == 2
        mock_crud_instance.get_by_socket_id.assert_called_once()
        mock_crud_instance.patch.assert_called_once()
