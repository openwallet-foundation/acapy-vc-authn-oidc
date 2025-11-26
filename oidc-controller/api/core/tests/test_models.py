"""Tests for core models."""

from unittest.mock import Mock

import pytest
from api.core.models import (
    GenericErrorMessage,
    HealthCheck,
    PyObjectId,
    StatusMessage,
    UUIDModel,
    VCUserinfo,
)
from bson import ObjectId


class TestPyObjectId:
    """Test PyObjectId custom type."""

    def test_validate_with_valid_objectid(self):
        """Test that validate accepts valid ObjectId."""
        valid_id = "507f1f77bcf86cd799439011"
        result = PyObjectId.validate(valid_id, None)
        assert isinstance(result, ObjectId)
        assert str(result) == valid_id

    def test_validate_with_invalid_objectid_raises_error(self):
        """Test that validate raises ValueError for invalid ObjectId."""
        invalid_id = "not_a_valid_objectid"
        with pytest.raises(ValueError, match="Invalid objectid"):
            PyObjectId.validate(invalid_id, None)

    def test_get_pydantic_json_schema(self):
        """Test that __get_pydantic_json_schema__ updates field schema."""
        field_schema = {}
        PyObjectId.__get_pydantic_json_schema__(field_schema)
        assert field_schema["type"] == "string"


class TestUUIDModel:
    """Test UUIDModel base class."""

    def test_serialize_id_returns_string(self):
        """Test that serialize_id converts PyObjectId to string."""
        model = UUIDModel()
        serialized = model.serialize_id(model.id)
        assert isinstance(serialized, str)
        assert len(serialized) == 24  # ObjectId string length

    def test_uuid_model_serialization(self):
        """Test that UUIDModel properly serializes id field."""
        model = UUIDModel()
        data = model.model_dump()
        assert "id" in data
        assert isinstance(data["id"], str)


class TestHealthCheck:
    """Test HealthCheck model."""

    def test_health_check_creation(self):
        """Test creating a HealthCheck model."""
        health = HealthCheck(
            name="test-service", version="1.0.0", description="Test service"
        )
        assert health.name == "test-service"
        assert health.version == "1.0.0"
        assert health.description == "Test service"


class TestStatusMessage:
    """Test StatusMessage model."""

    def test_status_message_creation(self):
        """Test creating a StatusMessage model."""
        status = StatusMessage(status=True, message="Operation successful")
        assert status.status is True
        assert status.message == "Operation successful"


class TestGenericErrorMessage:
    """Test GenericErrorMessage model."""

    def test_generic_error_message_creation(self):
        """Test creating a GenericErrorMessage model."""
        error = GenericErrorMessage(detail="An error occurred")
        assert error.detail == "An error occurred"


class TestVCUserinfo:
    """Test VCUserinfo class with both dict and Redis-like storage."""

    @pytest.fixture
    def dict_storage(self):
        """Create in-memory dict storage (single-pod mode)."""
        return {}

    @pytest.fixture
    def mock_redis_storage(self):
        """Create mock Redis storage (multi-pod mode)."""
        storage = {}
        mock = Mock()
        # RedisWrapper only supports [] access, not .get()
        mock.__setitem__ = lambda self, key, value: storage.__setitem__(key, value)
        mock.__getitem__ = lambda self, key: storage[key]
        mock.keys = lambda: storage.keys()
        return mock

    def test_set_and_get_claims_for_user(self, dict_storage):
        """Test storing and retrieving claims for a user."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        user_id = "test_user_id"
        claims = {
            "pres_req_conf_id": "test_config",
            "vc_presented_attributes": '{"email": "test@example.com"}',
            "acr": "vc_authn",
        }

        # Store claims
        userinfo.set_claims_for_user(user_id, claims)

        # Retrieve claims
        result = userinfo.get_claims_for(user_id, {}, None)
        assert result == claims
        assert result["pres_req_conf_id"] == "test_config"

    def test_get_claims_for_nonexistent_user_returns_empty_dict(self, dict_storage):
        """Test that get_claims_for returns empty dict for unknown user."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        result = userinfo.get_claims_for("nonexistent_user", {}, None)
        assert result == {}

    def test_getitem_returns_stored_claims(self, dict_storage):
        """Test that __getitem__ returns stored claims."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        user_id = "test_user"
        claims = {"test_claim": "test_value"}

        userinfo.set_claims_for_user(user_id, claims)
        result = userinfo[user_id]
        assert result == claims

    def test_getitem_returns_empty_dict_for_unknown_user(self, dict_storage):
        """Test that __getitem__ returns empty dict for unknown user."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        result = userinfo["unknown_user"]
        assert result == {}

    def test_set_claims_for_user_with_none_user_id_raises_error(self, dict_storage):
        """Test set_claims_for_user raises ValueError for None user_id."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        with pytest.raises(ValueError, match="user_id cannot be None"):
            userinfo.set_claims_for_user(None, {"claim": "value"})

    def test_get_claims_for_with_none_user_id_raises_error(self, dict_storage):
        """Test that get_claims_for raises ValueError for None user_id."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        with pytest.raises(ValueError, match="user_id cannot be None"):
            userinfo.get_claims_for(None, {}, None)

    def test_getitem_with_none_user_id_raises_error(self, dict_storage):
        """Test that __getitem__ raises ValueError for None user_id."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        match_msg = "user_id \\(item\\) cannot be None"
        with pytest.raises(ValueError, match=match_msg):
            _ = userinfo[None]

    def test_multiple_users_with_different_claims(self, dict_storage):
        """Test storing claims for multiple users with different data."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)

        user1_claims = {
            "pres_req_conf_id": "config1",
            "email": "user1@test.com",
        }
        user2_claims = {
            "pres_req_conf_id": "config2",
            "email": "user2@test.com",
        }

        userinfo.set_claims_for_user("user1", user1_claims)
        userinfo.set_claims_for_user("user2", user2_claims)

        assert userinfo.get_claims_for("user1", {}, None) == user1_claims
        assert userinfo.get_claims_for("user2", {}, None) == user2_claims

    def test_overwriting_claims_for_same_user(self, dict_storage):
        """Test that setting claims again overwrites previous claims."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        user_id = "test_user"

        original_claims = {"claim1": "value1"}
        new_claims = {"claim2": "value2"}

        userinfo.set_claims_for_user(user_id, original_claims)
        userinfo.set_claims_for_user(user_id, new_claims)

        result = userinfo.get_claims_for(user_id, {}, None)
        assert result == new_claims
        assert "claim1" not in result

    def test_claims_include_custom_fields(self, dict_storage):
        """Test that custom VC claims are properly stored and retrieved."""
        userinfo = VCUserinfo({}, claims_storage=dict_storage)
        user_id = "hash_from_vc"
        claims = {
            "pres_req_conf_id": "showcase-person",
            "vc_presented_attributes": (
                '{"given_names": "John", "family_name": "Doe"}'
            ),
            "acr": "vc_authn",
            "nonce": "test_nonce",
        }

        userinfo.set_claims_for_user(user_id, claims)
        result = userinfo.get_claims_for(user_id, {}, None)

        # Verify all custom claims are present
        assert result["pres_req_conf_id"] == "showcase-person"
        assert "vc_presented_attributes" in result
        assert result["acr"] == "vc_authn"
        assert result["nonce"] == "test_nonce"

    def test_with_redis_like_storage(self, mock_redis_storage):
        """Test VCUserinfo works with Redis-like storage backend."""
        userinfo = VCUserinfo({}, claims_storage=mock_redis_storage)
        user_id = "test_user"
        claims = {
            "pres_req_conf_id": "test_config",
            "email": "test@example.com",
        }

        # Store and retrieve claims through Redis-like storage
        userinfo.set_claims_for_user(user_id, claims)
        result = userinfo.get_claims_for(user_id, {}, None)

        assert result == claims
        assert result["pres_req_conf_id"] == "test_config"

    def test_defaults_to_dict_storage_when_none(self):
        """Test that VCUserinfo defaults to dict storage if none provided."""
        userinfo = VCUserinfo({})
        user_id = "test_user"
        claims = {"test": "value"}

        userinfo.set_claims_for_user(user_id, claims)
        result = userinfo.get_claims_for(user_id, {}, None)

        assert result == claims

    def test_set_claims_for_user_storage_exception_handling(self):
        """Test that set_claims_for_user handles storage exceptions."""
        # Create a mock storage that raises an exception on write
        mock_storage = Mock()
        mock_storage.__setitem__ = Mock(
            side_effect=RuntimeError("Storage write failed")
        )

        userinfo = VCUserinfo({}, claims_storage=mock_storage)

        with pytest.raises(RuntimeError, match="Storage write failed"):
            userinfo.set_claims_for_user("user_id", {"claim": "value"})

    def test_getitem_storage_exception_handling(self):
        """Test that __getitem__ handles storage exceptions properly."""
        # Create a mock storage that raises an unexpected exception
        mock_storage = Mock()
        mock_storage.__getitem__ = Mock(side_effect=RuntimeError("Storage read failed"))

        userinfo = VCUserinfo({}, claims_storage=mock_storage)

        with pytest.raises(RuntimeError, match="Storage read failed"):
            _ = userinfo["user_id"]

    def test_get_claims_for_storage_exception_handling(self):
        """Test that get_claims_for handles storage exceptions properly."""
        # Create a mock storage that raises an unexpected exception
        mock_storage = Mock()
        mock_storage.__getitem__ = Mock(side_effect=RuntimeError("Storage read failed"))

        userinfo = VCUserinfo({}, claims_storage=mock_storage)

        with pytest.raises(RuntimeError, match="Storage read failed"):
            userinfo.get_claims_for("user_id", {}, None)
