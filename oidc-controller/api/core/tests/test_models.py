"""Tests for core models."""

import pytest
from bson import ObjectId
from pydantic import ValidationError

from api.core.models import (
    PyObjectId,
    HealthCheck,
    StatusMessage,
    UUIDModel,
    VCUserinfo,
    GenericErrorMessage,
)


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
    """Test VCUserinfo class."""

    def test_getitem_returns_empty_dict(self):
        """Test that __getitem__ always returns empty dictionary."""
        userinfo = VCUserinfo({})
        result = userinfo["any_user_id"]
        assert result == {}
        assert isinstance(result, dict)

    def test_get_claims_for_returns_empty_dict(self):
        """Test that get_claims_for always returns empty dictionary."""
        userinfo = VCUserinfo({})
        result = userinfo.get_claims_for(
            user_id="test_user",
            requested_claims={"name": None, "email": None},
            userinfo=None,
        )
        assert result == {}
        assert isinstance(result, dict)

    def test_vcuserinfo_with_different_users(self):
        """Test VCUserinfo returns empty dict for any user."""
        userinfo = VCUserinfo({})
        assert userinfo["user1"] == {}
        assert userinfo["user2"] == {}
        assert userinfo["any_random_user_id"] == {}
