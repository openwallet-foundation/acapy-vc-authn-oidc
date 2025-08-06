"""Tests for AuthSession CRUD operations."""

import pytest
from unittest.mock import MagicMock, patch
from bson import ObjectId
from fastapi import HTTPException
from fastapi import status as http_status
from pymongo import ReturnDocument
from pymongo.database import Database

from api.authSessions.crud import AuthSessionCRUD
from api.authSessions.models import (
    AuthSession,
    AuthSessionCreate,
    AuthSessionPatch,
    AuthSessionState,
)
from api.core.models import PyObjectId
from api.db.session import COLLECTION_NAMES


@pytest.fixture
def mock_database():
    """Create a mock database instance."""
    db = MagicMock(spec=Database)
    return db


@pytest.fixture
def mock_collection():
    """Create a mock collection instance."""
    collection = MagicMock()
    return collection


@pytest.fixture
def auth_session_crud(mock_database):
    """Create an AuthSessionCRUD instance with mock database."""
    return AuthSessionCRUD(mock_database)


@pytest.fixture
def sample_auth_session_data():
    """Create sample auth session data for testing."""
    return {
        "_id": ObjectId("507f1f77bcf86cd799439011"),
        "pres_exch_id": "test-pres-ex-id",
        "connection_id": "test-connection-id",
        "ver_config_id": "test-ver-config-id",
        "request_parameters": {"test": "params"},
        "pyop_auth_code": "test-auth-code",
        "response_url": "http://test.com/callback",
        "presentation_exchange": {},
        "proof_status": AuthSessionState.NOT_STARTED,
        "proof_request": {"test": "proof_request"},
        "multi_use": False,
    }


@pytest.fixture
def sample_auth_session_create():
    """Create sample AuthSessionCreate object for testing."""
    return AuthSessionCreate(
        pres_exch_id="test-pres-ex-id",
        connection_id="test-connection-id",
        ver_config_id="test-ver-config-id",
        request_parameters={"test": "params"},
        pyop_auth_code="test-auth-code",
        response_url="http://test.com/callback",
        proof_request={"test": "proof_request"},
        multi_use=False,
    )


@pytest.fixture
def sample_auth_session_patch():
    """Create sample AuthSessionPatch object for testing."""
    return AuthSessionPatch(
        pres_exch_id="updated-pres-ex-id",
        proof_status=AuthSessionState.VERIFIED,
        presentation_exchange={"test": "updated"},
        ver_config_id="test-ver-config-id",
        request_parameters={"test": "params"},
        pyop_auth_code="test-auth-code",
        response_url="http://test.com/callback",
        multi_use=False,
    )


class TestAuthSessionCRUD:
    """Test cases for AuthSessionCRUD class."""

    def test_init(self, mock_database):
        """Test AuthSessionCRUD initialization."""
        crud = AuthSessionCRUD(mock_database)
        assert crud._db == mock_database

    @pytest.mark.asyncio
    async def test_create_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_create,
        sample_auth_session_data,
    ):
        """Test successful creation of auth session."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.insert_one.return_value = MagicMock(
            inserted_id=sample_auth_session_data["_id"]
        )
        mock_collection.find_one.return_value = sample_auth_session_data

        # Execute
        result = await auth_session_crud.create(sample_auth_session_create)

        # Verify
        assert isinstance(result, AuthSession)
        assert result.pres_exch_id == "test-pres-ex-id"
        assert result.connection_id == "test-connection-id"
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.insert_one.assert_called_once()
        mock_collection.find_one.assert_called_once_with(
            {"_id": sample_auth_session_data["_id"]}
        )

    @pytest.mark.asyncio
    async def test_get_by_connection_id_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_data,
    ):
        """Test successful retrieval of auth session by connection ID."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = sample_auth_session_data

        # Execute
        result = await auth_session_crud.get_by_connection_id("test-connection-id")

        # Verify
        assert isinstance(result, AuthSession)
        assert result.connection_id == "test-connection-id"
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one.assert_called_once_with(
            {"connection_id": "test-connection-id"}
        )

    @pytest.mark.asyncio
    async def test_get_by_connection_id_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test retrieval of auth session by connection ID when not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = None

        # Execute
        result = await auth_session_crud.get_by_connection_id("non-existent-connection")

        # Verify
        assert result is None
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one.assert_called_once_with(
            {"connection_id": "non-existent-connection"}
        )

    @pytest.mark.asyncio
    async def test_get_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_data,
    ):
        """Test successful retrieval of auth session by ID."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = sample_auth_session_data

        # Execute
        result = await auth_session_crud.get("507f1f77bcf86cd799439011")

        # Verify
        assert isinstance(result, AuthSession)
        assert result.pres_exch_id == "test-pres-ex-id"
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")}
        )

    @pytest.mark.asyncio
    async def test_get_invalid_id(self, auth_session_crud):
        """Test retrieval with invalid ObjectId format."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.get("invalid-id")

        assert exc_info.value.status_code == http_status.HTTP_400_BAD_REQUEST
        assert "Invalid id: invalid-id" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_get_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test retrieval of auth session when not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = None

        # Execute & Verify
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.get("507f1f77bcf86cd799439011")

        assert exc_info.value.status_code == http_status.HTTP_404_NOT_FOUND
        assert "The auth_session hasn't been found!" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_patch_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_patch,
        sample_auth_session_data,
    ):
        """Test successful patching of auth session."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        updated_data = sample_auth_session_data.copy()
        updated_data["pres_exch_id"] = "updated-pres-ex-id"
        mock_collection.find_one_and_update.return_value = updated_data

        # Execute
        result = await auth_session_crud.patch(
            "507f1f77bcf86cd799439011", sample_auth_session_patch
        )

        # Verify
        assert result == updated_data
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one_and_update.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")},
            {"$set": sample_auth_session_patch.model_dump(exclude_unset=True)},
            return_document=ReturnDocument.AFTER,
        )

    @pytest.mark.asyncio
    async def test_patch_invalid_id(self, auth_session_crud, sample_auth_session_patch):
        """Test patching with invalid ObjectId format."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.patch("invalid-id", sample_auth_session_patch)

        assert exc_info.value.status_code == http_status.HTTP_400_BAD_REQUEST
        assert "Invalid id: invalid-id" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_patch_with_pyobjectid(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_patch,
        sample_auth_session_data,
    ):
        """Test patching with PyObjectId instead of string."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        updated_data = sample_auth_session_data.copy()
        mock_collection.find_one_and_update.return_value = updated_data

        object_id = PyObjectId("507f1f77bcf86cd799439011")

        # Execute
        result = await auth_session_crud.patch(object_id, sample_auth_session_patch)

        # Verify
        assert result == updated_data
        mock_collection.find_one_and_update.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")},
            {"$set": sample_auth_session_patch.model_dump(exclude_unset=True)},
            return_document=ReturnDocument.AFTER,
        )

    @pytest.mark.asyncio
    async def test_delete_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_data,
    ):
        """Test successful deletion of auth session."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one_and_delete.return_value = sample_auth_session_data

        # Execute
        result = await auth_session_crud.delete("507f1f77bcf86cd799439011")

        # Verify
        assert result is True
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one_and_delete.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")}
        )

    @pytest.mark.asyncio
    async def test_delete_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test deletion when auth session not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one_and_delete.return_value = None

        # Execute
        result = await auth_session_crud.delete("507f1f77bcf86cd799439011")

        # Verify
        assert result is False
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one_and_delete.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")}
        )

    @pytest.mark.asyncio
    async def test_delete_invalid_id(self, auth_session_crud):
        """Test deletion with invalid ObjectId format."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.delete("invalid-id")

        assert exc_info.value.status_code == http_status.HTTP_400_BAD_REQUEST
        assert "Invalid id: invalid-id" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_get_by_pres_exch_id_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_data,
    ):
        """Test successful retrieval of auth session by presentation exchange ID."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = sample_auth_session_data

        # Execute
        result = await auth_session_crud.get_by_pres_exch_id("test-pres-ex-id")

        # Verify
        assert isinstance(result, AuthSession)
        assert result.pres_exch_id == "test-pres-ex-id"
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one.assert_called_once_with(
            {"pres_exch_id": "test-pres-ex-id"}
        )

    @pytest.mark.asyncio
    async def test_get_by_pres_exch_id_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test retrieval by presentation exchange ID when not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = None

        # Execute & Verify
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.get_by_pres_exch_id("non-existent-pres-ex-id")

        assert exc_info.value.status_code == http_status.HTTP_404_NOT_FOUND
        assert "The auth_session hasn't been found with that pres_exch_id!" in str(
            exc_info.value.detail
        )

    @pytest.mark.asyncio
    async def test_get_by_pyop_auth_code_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_data,
    ):
        """Test successful retrieval of auth session by PyOP auth code."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = sample_auth_session_data

        # Execute
        result = await auth_session_crud.get_by_pyop_auth_code("test-auth-code")

        # Verify
        assert isinstance(result, AuthSession)
        assert result.pyop_auth_code == "test-auth-code"
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one.assert_called_once_with(
            {"pyop_auth_code": "test-auth-code"}
        )

    @pytest.mark.asyncio
    async def test_get_by_pyop_auth_code_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test retrieval by PyOP auth code when not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = None

        # Execute & Verify
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.get_by_pyop_auth_code("non-existent-auth-code")

        assert exc_info.value.status_code == http_status.HTTP_404_NOT_FOUND
        assert "The auth_session hasn't been found with that pyop_auth_code!" in str(
            exc_info.value.detail
        )

    @pytest.mark.asyncio
    async def test_get_by_socket_id_success(
        self,
        auth_session_crud,
        mock_database,
        mock_collection,
        sample_auth_session_data,
    ):
        """Test successful retrieval of auth session by socket ID."""
        # Setup mocks - add socket_id to sample data
        sample_auth_session_data["socket_id"] = "test-socket-id"
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = sample_auth_session_data

        # Execute
        result = await auth_session_crud.get_by_socket_id("test-socket-id")

        # Verify
        assert isinstance(result, AuthSession)
        assert result.socket_id == "test-socket-id"
        assert result.pres_exch_id == "test-pres-ex-id"
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one.assert_called_once_with(
            {"socket_id": "test-socket-id"}
        )

    @pytest.mark.asyncio
    async def test_get_by_socket_id_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test retrieval by socket ID when not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.find_one.return_value = None

        # Execute
        result = await auth_session_crud.get_by_socket_id("non-existent-socket-id")

        # Verify
        assert result is None
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.find_one.assert_called_once_with(
            {"socket_id": "non-existent-socket-id"}
        )

    @pytest.mark.asyncio
    async def test_update_socket_id_success(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test successful socket ID update."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.update_one.return_value = MagicMock(modified_count=1)

        # Execute
        result = await auth_session_crud.update_socket_id(
            "507f1f77bcf86cd799439011", "new-socket-id"
        )

        # Verify
        assert result is True
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.update_one.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")},
            {"$set": {"socket_id": "new-socket-id"}},
        )

    @pytest.mark.asyncio
    async def test_update_socket_id_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test socket ID update when document not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.update_one.return_value = MagicMock(modified_count=0)

        # Execute
        result = await auth_session_crud.update_socket_id(
            "507f1f77bcf86cd799439011", "new-socket-id"
        )

        # Verify
        assert result is False
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.update_one.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")},
            {"$set": {"socket_id": "new-socket-id"}},
        )

    @pytest.mark.asyncio
    async def test_update_socket_id_clear(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test clearing socket ID (set to None)."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.update_one.return_value = MagicMock(modified_count=1)

        # Execute
        result = await auth_session_crud.update_socket_id(
            "507f1f77bcf86cd799439011", None
        )

        # Verify
        assert result is True
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.update_one.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")},
            {"$set": {"socket_id": None}},
        )

    @pytest.mark.asyncio
    async def test_update_socket_id_invalid_id(self, auth_session_crud):
        """Test socket ID update with invalid ObjectId format."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.update_socket_id("invalid-id", "new-socket-id")

        assert exc_info.value.status_code == http_status.HTTP_400_BAD_REQUEST
        assert "Invalid id: invalid-id" in str(exc_info.value.detail)

    @pytest.mark.asyncio
    async def test_update_pyop_auth_code_success(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test successful pyop_auth_code update."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.update_one.return_value = MagicMock(modified_count=1)

        # Execute
        result = await auth_session_crud.update_pyop_auth_code(
            "507f1f77bcf86cd799439011", "new-auth-code"
        )

        # Verify
        assert result is True
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.update_one.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")},
            {"$set": {"pyop_auth_code": "new-auth-code"}},
        )

    @pytest.mark.asyncio
    async def test_update_pyop_auth_code_not_found(
        self, auth_session_crud, mock_database, mock_collection
    ):
        """Test pyop_auth_code update when document not found."""
        # Setup mocks
        mock_database.get_collection.return_value = mock_collection
        mock_collection.update_one.return_value = MagicMock(modified_count=0)

        # Execute
        result = await auth_session_crud.update_pyop_auth_code(
            "507f1f77bcf86cd799439011", "new-auth-code"
        )

        # Verify
        assert result is False
        mock_database.get_collection.assert_called_once_with(
            COLLECTION_NAMES.AUTH_SESSION
        )
        mock_collection.update_one.assert_called_once_with(
            {"_id": PyObjectId("507f1f77bcf86cd799439011")},
            {"$set": {"pyop_auth_code": "new-auth-code"}},
        )

    @pytest.mark.asyncio
    async def test_update_pyop_auth_code_invalid_id(self, auth_session_crud):
        """Test pyop_auth_code update with invalid ObjectId format."""
        with pytest.raises(HTTPException) as exc_info:
            await auth_session_crud.update_pyop_auth_code("invalid-id", "new-auth-code")

        assert exc_info.value.status_code == http_status.HTTP_400_BAD_REQUEST
        assert "Invalid id: invalid-id" in str(exc_info.value.detail)
