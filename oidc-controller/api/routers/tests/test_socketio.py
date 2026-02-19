"""Tests for socketio functionality."""

import pytest
from unittest.mock import AsyncMock, MagicMock, Mock, patch
from bson import ObjectId

from api.routers.socketio import (
    get_socket_id_for_pid,
    connect,
    initialize,
    disconnect,
    get_db_for_socketio,
)
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


class TestSocketIOEventHandlers:
    """Test cases for Socket.IO event handlers."""

    def test_get_db_for_socketio(self):
        """Test the get_db_for_socketio function."""
        # Execute
        result = get_db_for_socketio()

        # Verify
        assert result is not None
        # The function should return a database instance
        # We don't mock this since it's a simple synchronous function

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
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_success(
        self,
        mock_auth_session_crud_class,
        mock_get_db_for_socketio,
        sample_auth_session,
    ):
        """Test successful initialize event."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.update_socket_id = AsyncMock(return_value=True)

        # Test data
        sid = "new-socket-id"
        data = {"pid": "507f1f77bcf86cd799439011"}

        # Execute
        await initialize(sid, data)

        # Verify
        mock_get_db_for_socketio.assert_called_once()
        mock_auth_session_crud_class.assert_called_once_with(mock_db)
        mock_crud_instance.update_socket_id.assert_called_once_with(
            "507f1f77bcf86cd799439011", "new-socket-id"
        )

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_no_pid(
        self, mock_auth_session_crud_class, mock_get_db_for_socketio
    ):
        """Test initialize event with no pid in data."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db

        # Test data
        sid = "test-socket-id"
        data = {}  # No pid

        # Execute
        await initialize(sid, data)

        # Verify - should call get_db_for_socketio but not AuthSessionCRUD
        mock_get_db_for_socketio.assert_called_once()
        mock_auth_session_crud_class.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_empty_pid(
        self, mock_auth_session_crud_class, mock_get_db_for_socketio
    ):
        """Test initialize event with empty pid."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db

        # Test data
        sid = "test-socket-id"
        data = {"pid": ""}  # Empty pid

        # Execute
        await initialize(sid, data)

        # Verify - should call get_db_for_socketio but not AuthSessionCRUD due to empty pid
        mock_get_db_for_socketio.assert_called_once()
        mock_auth_session_crud_class.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_auth_session_not_found(
        self, mock_auth_session_crud_class, mock_get_db_for_socketio
    ):
        """Test initialize event when auth session is not found."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.update_socket_id = AsyncMock(
            side_effect=Exception("Auth session not found")
        )

        # Test data
        sid = "test-socket-id"
        data = {"pid": "non-existent-pid"}

        # Execute - should not raise exception
        await initialize(sid, data)

        # Verify
        mock_get_db_for_socketio.assert_called_once()
        mock_auth_session_crud_class.assert_called_once_with(mock_db)
        mock_crud_instance.update_socket_id.assert_called_once_with(
            "non-existent-pid", "test-socket-id"
        )

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_patch_failure(
        self,
        mock_auth_session_crud_class,
        mock_get_db_for_socketio,
        sample_auth_session,
    ):
        """Test initialize event when patch operation fails."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.update_socket_id = AsyncMock(
            side_effect=Exception("Database error")
        )

        # Test data
        sid = "test-socket-id"
        data = {"pid": "507f1f77bcf86cd799439011"}

        # Execute - should not raise exception
        await initialize(sid, data)

        # Verify
        mock_get_db_for_socketio.assert_called_once()
        mock_auth_session_crud_class.assert_called_once_with(mock_db)
        mock_crud_instance.update_socket_id.assert_called_once_with(
            "507f1f77bcf86cd799439011", "test-socket-id"
        )

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_success(
        self,
        mock_auth_session_crud_class,
        mock_get_db_for_socketio,
        sample_auth_session,
    ):
        """Test successful disconnect event."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(
            return_value=sample_auth_session
        )
        mock_crud_instance.update_socket_id = AsyncMock(return_value=True)

        # Test data
        sid = "test-socket-id"

        # Execute
        await disconnect(sid)

        # Verify
        mock_get_db_for_socketio.assert_called_once()
        mock_auth_session_crud_class.assert_called_with(mock_db)
        mock_crud_instance.get_by_socket_id.assert_called_once_with("test-socket-id")
        mock_crud_instance.update_socket_id.assert_called_once()

        # Verify update_socket_id was called with correct arguments
        update_call_args = mock_crud_instance.update_socket_id.call_args
        assert update_call_args[0][0] == str(sample_auth_session.id)
        assert update_call_args[0][1] is None

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_no_auth_session_found(
        self, mock_auth_session_crud_class, mock_get_db_for_socketio
    ):
        """Test disconnect event when no auth session is found."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(return_value=None)

        # Test data
        sid = "non-existent-socket-id"

        # Execute
        await disconnect(sid)

        # Verify
        mock_get_db_for_socketio.assert_called_once()
        mock_crud_instance.get_by_socket_id.assert_called_once_with(
            "non-existent-socket-id"
        )
        mock_crud_instance.update_socket_id.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_get_by_socket_id_exception(
        self, mock_auth_session_crud_class, mock_get_db_for_socketio
    ):
        """Test disconnect event when get_by_socket_id raises exception."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
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
        mock_get_db_for_socketio.assert_called_once()
        mock_crud_instance.get_by_socket_id.assert_called_once_with("test-socket-id")
        mock_crud_instance.update_socket_id.assert_not_called()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_patch_failure(
        self,
        mock_auth_session_crud_class,
        mock_get_db_for_socketio,
        sample_auth_session,
    ):
        """Test disconnect event when patch operation fails."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(
            return_value=sample_auth_session
        )
        mock_crud_instance.update_socket_id = AsyncMock(
            side_effect=Exception("Database error")
        )

        # Test data
        sid = "test-socket-id"

        # Execute - should not raise exception
        await disconnect(sid)

        # Verify
        mock_crud_instance.get_by_socket_id.assert_called_once_with("test-socket-id")
        mock_crud_instance.update_socket_id.assert_called_once()

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_initialize_event_multiple_crud_calls(
        self,
        mock_auth_session_crud_class,
        mock_get_db_for_socketio,
        sample_auth_session,
    ):
        """Test that initialize creates a single CRUD instance for update operation."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.update_socket_id = AsyncMock(return_value=True)

        # Test data
        sid = "test-socket-id"
        data = {"pid": "507f1f77bcf86cd799439011"}

        # Execute
        await initialize(sid, data)

        # Verify that AuthSessionCRUD was called once (only for update)
        assert mock_auth_session_crud_class.call_count == 1
        mock_auth_session_crud_class.assert_called_once_with(mock_db)
        mock_crud_instance.update_socket_id.assert_called_once_with(
            "507f1f77bcf86cd799439011", "test-socket-id"
        )

    @pytest.mark.asyncio
    @patch("api.routers.socketio.get_db_for_socketio")
    @patch("api.routers.socketio.AuthSessionCRUD")
    async def test_disconnect_event_multiple_crud_calls(
        self,
        mock_auth_session_crud_class,
        mock_get_db_for_socketio,
        sample_auth_session,
    ):
        """Test that disconnect creates separate CRUD instances for get_by_socket_id and patch."""
        # Setup mocks
        mock_db = MagicMock()
        mock_get_db_for_socketio.return_value = mock_db
        mock_crud_instance = MagicMock()
        mock_auth_session_crud_class.return_value = mock_crud_instance
        mock_crud_instance.get_by_socket_id = AsyncMock(
            return_value=sample_auth_session
        )
        mock_crud_instance.update_socket_id = AsyncMock(return_value=True)

        # Test data
        sid = "test-socket-id"

        # Execute
        await disconnect(sid)

        # Verify that AuthSessionCRUD was called twice
        assert mock_auth_session_crud_class.call_count == 2
        mock_crud_instance.get_by_socket_id.assert_called_once()
        mock_crud_instance.update_socket_id.assert_called_once()


class TestShouldUseRedisAdapter:
    """Test _should_use_redis_adapter function for consolidated Redis configuration checks."""

    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_mode_none(self, mock_settings):
        """Test _should_use_redis_adapter when REDIS_MODE is none."""
        from api.routers.socketio import _should_use_redis_adapter

        # Setup
        mock_settings.REDIS_MODE = "none"

        # Execute
        result = _should_use_redis_adapter()

        # Verify
        assert result is False

    @patch("api.routers.socketio.validate_redis_config")
    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_no_host(self, mock_settings, mock_validate):
        """Test _should_use_redis_adapter when REDIS_HOST is not configured."""
        from api.routers.socketio import _should_use_redis_adapter

        # Setup
        mock_settings.REDIS_MODE = "single"
        mock_validate.side_effect = ValueError("REDIS_HOST required")

        # Execute
        result = _should_use_redis_adapter()

        # Verify
        assert result is False

    @patch("api.routers.socketio.validate_redis_config")
    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_single_mode(self, mock_settings, mock_validate):
        """Test _should_use_redis_adapter when REDIS_MODE is single."""
        from api.routers.socketio import _should_use_redis_adapter

        # Setup
        mock_settings.REDIS_MODE = "single"
        mock_validate.return_value = None  # Validation passes

        # Execute
        result = _should_use_redis_adapter()

        # Verify
        assert result is True

    @patch("api.routers.socketio.validate_redis_config")
    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_sentinel_mode(self, mock_settings, mock_validate):
        """Test _should_use_redis_adapter when REDIS_MODE is sentinel."""
        from api.routers.socketio import _should_use_redis_adapter

        # Setup
        mock_settings.REDIS_MODE = "sentinel"
        mock_validate.return_value = None  # Validation passes

        # Execute
        result = _should_use_redis_adapter()

        # Verify
        assert result is True

    @patch("api.routers.socketio.validate_redis_config")
    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_cluster_mode(self, mock_settings, mock_validate):
        """Test _should_use_redis_adapter when REDIS_MODE is cluster."""
        from api.routers.socketio import _should_use_redis_adapter

        # Setup
        mock_settings.REDIS_MODE = "cluster"
        mock_validate.return_value = None  # Validation passes

        # Execute
        result = _should_use_redis_adapter()

        # Verify
        assert result is True

    @patch("api.routers.socketio.validate_redis_config")
    @patch("api.routers.socketio.settings")
    def test_should_use_redis_adapter_invalid_mode(self, mock_settings, mock_validate):
        """Test _should_use_redis_adapter when REDIS_MODE is invalid."""
        from api.routers.socketio import _should_use_redis_adapter

        # Setup
        mock_settings.REDIS_MODE = "invalid_mode"
        mock_validate.side_effect = ValueError("Invalid REDIS_MODE")

        # Execute
        result = _should_use_redis_adapter()

        # Verify
        assert result is False


class TestCreateSocketManager:
    """Test create_socket_manager function for Redis adapter configuration."""

    @patch("api.routers.socketio._should_use_redis_adapter")
    def test_create_socket_manager_should_not_use_redis(self, mock_should_use):
        """Test create_socket_manager when _should_use_redis_adapter returns False."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = False

        # Execute
        result = create_socket_manager()

        # Verify
        assert result is None
        mock_should_use.assert_called_once()

    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.core.redis_utils.settings")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_redis")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_single_mode_with_password(
        self,
        mock_redis_manager,
        mock_can_reach_redis,
        mock_settings,
        mock_utils_settings,
        mock_should_use,
    ):
        """Test successful Redis manager creation in single mode with password."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = True
        for s in (mock_settings, mock_utils_settings):
            s.REDIS_MODE = "single"
            s.REDIS_HOST = "localhost:6379"
            s.REDIS_PASSWORD = "secret"
            s.REDIS_DB = 0
        mock_can_reach_redis.return_value = True

        mock_instance = Mock()
        mock_redis_manager.return_value = mock_instance

        # Execute
        result = create_socket_manager()

        # Verify
        mock_should_use.assert_called_once()
        assert result is mock_instance
        expected_url = "redis://:secret@localhost:6379/0"
        mock_can_reach_redis.assert_called_once_with(expected_url)
        mock_redis_manager.assert_called_once_with(expected_url)

    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.core.redis_utils.settings")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_redis")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_single_mode_without_password(
        self,
        mock_redis_manager,
        mock_can_reach_redis,
        mock_settings,
        mock_utils_settings,
        mock_should_use,
    ):
        """Test successful Redis manager creation in single mode without password."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = True
        for s in (mock_settings, mock_utils_settings):
            s.REDIS_MODE = "single"
            s.REDIS_HOST = "localhost:6379"
            s.REDIS_PASSWORD = None
            s.REDIS_DB = 0
        mock_can_reach_redis.return_value = True

        mock_instance = Mock()
        mock_redis_manager.return_value = mock_instance

        # Execute
        result = create_socket_manager()

        # Verify
        mock_should_use.assert_called_once()
        assert result is mock_instance
        expected_url = "redis://localhost:6379/0"
        mock_can_reach_redis.assert_called_once_with(expected_url)
        mock_redis_manager.assert_called_once_with(expected_url)

    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.core.redis_utils.settings")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_sentinel")
    @patch("socketio.AsyncRedisManager")
    def test_create_socket_manager_sentinel_mode(
        self,
        mock_redis_manager,
        mock_can_reach_sentinel,
        mock_settings,
        mock_utils_settings,
        mock_should_use,
    ):
        """Test successful Redis manager creation in sentinel mode."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = True
        for s in (mock_settings, mock_utils_settings):
            s.REDIS_MODE = "sentinel"
            s.REDIS_HOST = "sentinel1:26379,sentinel2:26379"
            s.REDIS_PASSWORD = "secret"
            s.REDIS_DB = 0
            s.REDIS_SENTINEL_MASTER_NAME = "mymaster"
        mock_can_reach_sentinel.return_value = True

        mock_instance = Mock()
        mock_redis_manager.return_value = mock_instance

        # Execute
        result = create_socket_manager()

        # Verify
        mock_should_use.assert_called_once()
        assert result is mock_instance
        # Sentinel connectivity check is called with parsed hosts and master name
        mock_can_reach_sentinel.assert_called_once_with(
            [("sentinel1", 26379), ("sentinel2", 26379)], "mymaster"
        )
        # AsyncRedisManager is created with sentinel URL (db/service_name order per python-socketio)
        expected_url = (
            "redis+sentinel://:secret@sentinel1:26379,sentinel2:26379/0/mymaster"
        )
        mock_redis_manager.assert_called_once_with(expected_url)

    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_cluster")
    @patch("api.routers.socketio.AsyncRedisClusterManager")
    def test_create_socket_manager_cluster_mode(
        self,
        mock_cluster_manager,
        mock_can_reach_cluster,
        mock_settings,
        mock_should_use,
    ):
        """Test successful Redis manager creation in cluster mode."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = True
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "node1:6379,node2:6379,node3:6379"
        mock_settings.REDIS_PASSWORD = "secret"
        mock_can_reach_cluster.return_value = True

        mock_instance = Mock()
        mock_cluster_manager.return_value = mock_instance

        # Execute
        result = create_socket_manager()

        # Verify
        mock_should_use.assert_called_once()
        assert result is mock_instance
        mock_can_reach_cluster.assert_called_once_with(
            [("node1", 6379), ("node2", 6379), ("node3", 6379)]
        )
        mock_cluster_manager.assert_called_once_with(
            startup_nodes=[("node1", 6379), ("node2", 6379), ("node3", 6379)],
            password="secret",
        )

    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.core.redis_utils.settings")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_redis")
    def test_create_socket_manager_single_mode_connection_fails(
        self, mock_can_reach_redis, mock_settings, mock_utils_settings, mock_should_use
    ):
        """Test create_socket_manager returns None when Redis validation fails in single mode."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = True
        for s in (mock_settings, mock_utils_settings):
            s.REDIS_MODE = "single"
            s.REDIS_HOST = "localhost:6379"
            s.REDIS_PASSWORD = ""
            s.REDIS_DB = 0
        mock_can_reach_redis.return_value = False  # Validation fails

        # Execute and verify graceful fallback
        result = create_socket_manager()
        assert result is None  # Should return None on failure instead of crashing

        # Verify
        mock_should_use.assert_called_once()

    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.routers.socketio.settings")
    @patch("api.routers.socketio.can_we_reach_cluster")
    def test_create_socket_manager_cluster_mode_connection_fails(
        self, mock_can_reach_cluster, mock_settings, mock_should_use
    ):
        """Test create_socket_manager returns None when cluster validation fails."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = True
        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "node1:6379,node2:6379"
        mock_settings.REDIS_PASSWORD = None
        mock_can_reach_cluster.return_value = False  # Validation fails

        # Execute and verify graceful fallback
        result = create_socket_manager()
        assert result is None

        # Verify
        mock_should_use.assert_called_once()

    @patch("api.routers.socketio._should_use_redis_adapter")
    @patch("api.routers.socketio.settings")
    def test_create_socket_manager_invalid_mode(self, mock_settings, mock_should_use):
        """Test create_socket_manager returns None for invalid mode."""
        from api.routers.socketio import create_socket_manager

        # Setup
        mock_should_use.return_value = True
        mock_settings.REDIS_MODE = "invalid"

        # Execute
        result = create_socket_manager()

        # Verify
        assert result is None


class TestBuildRedisUrl:
    """Test _build_redis_url function for different Redis modes."""

    @patch("api.core.redis_utils.settings")
    def test_build_redis_url_single_mode_with_password(self, mock_settings):
        """Test URL building for single mode with password."""
        from api.core.redis_utils import build_redis_url as _build_redis_url

        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host:6379"
        mock_settings.REDIS_PASSWORD = "secret"
        mock_settings.REDIS_DB = 1

        result = _build_redis_url()

        assert result == "redis://:secret@redis-host:6379/1"

    @patch("api.core.redis_utils.settings")
    def test_build_redis_url_single_mode_without_password(self, mock_settings):
        """Test URL building for single mode without password."""
        from api.core.redis_utils import build_redis_url as _build_redis_url

        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis-host:6380"
        mock_settings.REDIS_PASSWORD = None
        mock_settings.REDIS_DB = 0

        result = _build_redis_url()

        assert result == "redis://redis-host:6380/0"

    @patch("api.core.redis_utils.settings")
    def test_build_redis_url_sentinel_mode_with_password(self, mock_settings):
        """Test URL building for sentinel mode with password."""
        from api.core.redis_utils import build_redis_url as _build_redis_url

        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "sentinel1:26379,sentinel2:26379,sentinel3:26379"
        mock_settings.REDIS_PASSWORD = "secret"
        mock_settings.REDIS_DB = 2
        mock_settings.REDIS_SENTINEL_MASTER_NAME = "mymaster"

        result = _build_redis_url()

        # python-socketio parse_redis_sentinel_url expects /db/service_name order
        assert (
            result
            == "redis+sentinel://:secret@sentinel1:26379,sentinel2:26379,sentinel3:26379/2/mymaster"
        )

    @patch("api.core.redis_utils.settings")
    def test_build_redis_url_sentinel_mode_without_password(self, mock_settings):
        """Test URL building for sentinel mode without password."""
        from api.core.redis_utils import build_redis_url as _build_redis_url

        mock_settings.REDIS_MODE = "sentinel"
        mock_settings.REDIS_HOST = "sentinel1:26379,sentinel2:26379"
        mock_settings.REDIS_PASSWORD = None
        mock_settings.REDIS_DB = 0
        mock_settings.REDIS_SENTINEL_MASTER_NAME = "redis-master"

        result = _build_redis_url()

        # python-socketio parse_redis_sentinel_url expects /db/service_name order
        assert (
            result == "redis+sentinel://sentinel1:26379,sentinel2:26379/0/redis-master"
        )

    @patch("api.core.redis_utils.settings")
    def test_build_redis_url_cluster_mode_returns_none(self, mock_settings):
        """Test URL building for cluster mode returns None (uses startup_nodes)."""
        from api.core.redis_utils import build_redis_url as _build_redis_url

        mock_settings.REDIS_MODE = "cluster"
        mock_settings.REDIS_HOST = "node1:6379,node2:6379"

        result = _build_redis_url()

        assert result is None


class TestParseHostPortPairs:
    """Test _parse_host_port_pairs function for parsing node strings."""

    def test_parse_single_node(self):
        """Test parsing a single node."""
        from api.core.redis_utils import parse_host_port_pairs as _parse_host_port_pairs

        result = _parse_host_port_pairs("redis-node:6379")

        assert result == [("redis-node", 6379)]

    def test_parse_multiple_nodes(self):
        """Test parsing multiple nodes."""
        from api.core.redis_utils import parse_host_port_pairs as _parse_host_port_pairs

        result = _parse_host_port_pairs("node1:6379,node2:6380,node3:6381")

        assert result == [("node1", 6379), ("node2", 6380), ("node3", 6381)]

    def test_parse_with_spaces(self):
        """Test parsing nodes with spaces around commas."""
        from api.core.redis_utils import parse_host_port_pairs as _parse_host_port_pairs

        result = _parse_host_port_pairs("node1:6379, node2:6380 , node3:6381")

        assert result == [("node1", 6379), ("node2", 6380), ("node3", 6381)]

    def test_parse_sentinel_nodes(self):
        """Test parsing sentinel nodes with default sentinel port."""
        from api.core.redis_utils import parse_host_port_pairs as _parse_host_port_pairs

        result = _parse_host_port_pairs(
            "sentinel1:26379,sentinel2:26379,sentinel3:26379"
        )

        assert result == [
            ("sentinel1", 26379),
            ("sentinel2", 26379),
            ("sentinel3", 26379),
        ]

    def test_parse_with_ipv4_addresses(self):
        """Test parsing nodes with IPv4 addresses."""
        from api.core.redis_utils import parse_host_port_pairs as _parse_host_port_pairs

        result = _parse_host_port_pairs("192.168.1.10:6379,192.168.1.11:6379")

        assert result == [("192.168.1.10", 6379), ("192.168.1.11", 6379)]


class TestCanWeReachCluster:
    """Test can_we_reach_cluster function for cluster connectivity testing."""

    @patch("api.routers.socketio.RedisCluster")
    @patch("api.routers.socketio.settings")
    def test_can_we_reach_cluster_success(self, mock_settings, mock_redis_cluster):
        """Test successful cluster connectivity check."""
        from api.routers.socketio import can_we_reach_cluster

        mock_settings.REDIS_PASSWORD = "secret"
        mock_client = Mock()
        mock_redis_cluster.return_value = mock_client

        result = can_we_reach_cluster([("node1", 6379), ("node2", 6379)])

        assert result is True
        mock_client.ping.assert_called_once()
        mock_client.close.assert_called_once()

    @patch("api.routers.socketio.RedisCluster")
    @patch("api.routers.socketio.settings")
    def test_can_we_reach_cluster_failure(self, mock_settings, mock_redis_cluster):
        """Test cluster connectivity check failure."""
        from api.routers.socketio import can_we_reach_cluster

        mock_settings.REDIS_PASSWORD = None
        mock_redis_cluster.side_effect = Exception("Cluster unreachable")

        result = can_we_reach_cluster([("node1", 6379)])

        assert result is False
