"""Tests for AuthSession models."""

from datetime import UTC, datetime

from api.authSessions.models import (
    AuthSession,
    AuthSessionCreate,
    AuthSessionPatch,
    AuthSessionState,
)
from api.core.models import PyObjectId


class TestAuthSessionState:
    """Test AuthSessionState enum."""

    def test_enum_values(self):
        """Test that all expected states are defined."""
        assert AuthSessionState.NOT_STARTED == "not_started"
        assert AuthSessionState.PENDING == "pending"
        assert AuthSessionState.EXPIRED == "expired"
        assert AuthSessionState.VERIFIED == "verified"
        assert AuthSessionState.FAILED == "failed"
        assert AuthSessionState.ABANDONED == "abandoned"


class TestAuthSessionCreate:
    """Test AuthSessionCreate model."""

    def test_create_with_proof_status_default(self):
        """Test that proof_status defaults to NOT_STARTED."""
        auth_session = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        )

        # Verify proof_status is set to NOT_STARTED by default
        assert auth_session.proof_status == AuthSessionState.NOT_STARTED

    def test_create_proof_status_in_model_dump(self):
        """Test that proof_status is included when dumping the model."""
        auth_session = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        )

        dumped = auth_session.model_dump()

        # Critical: proof_status MUST be in dumped dict for MongoDB
        assert "proof_status" in dumped
        assert dumped["proof_status"] == AuthSessionState.NOT_STARTED

    def test_create_with_explicit_proof_status(self):
        """Test that explicit proof_status is honored."""
        auth_session = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
            proof_status=AuthSessionState.PENDING,
        )

        assert auth_session.proof_status == AuthSessionState.PENDING

    def test_create_with_optional_fields(self):
        """Test creation with optional fields."""
        auth_session = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
            pres_exch_id="test-pres-ex-id",
            connection_id="test-connection-id",
            socket_id="test-socket-id",
            proof_request={"test": "proof"},
            multi_use=True,
        )

        assert auth_session.pres_exch_id == "test-pres-ex-id"
        assert auth_session.connection_id == "test-connection-id"
        assert auth_session.socket_id == "test-socket-id"
        assert auth_session.proof_request == {"test": "proof"}
        assert auth_session.multi_use is True
        # Still has the default proof_status
        assert auth_session.proof_status == AuthSessionState.NOT_STARTED

    def test_create_timestamps_generated(self):
        """Test that timestamps are generated automatically."""
        before = datetime.now(UTC)
        auth_session = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        )
        after = datetime.now(UTC)

        assert before <= auth_session.created_at <= after
        assert before <= auth_session.expired_timestamp


class TestAuthSessionPatch:
    """Test AuthSessionPatch model."""

    def test_patch_proof_status_default(self):
        """Test that proof_status defaults to PENDING for patches."""
        patch = AuthSessionPatch(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        )

        # Patch should default to PENDING (different from Create)
        assert patch.proof_status == AuthSessionState.PENDING

    def test_patch_with_different_status(self):
        """Test patching with different status values."""
        for state in [
            AuthSessionState.VERIFIED,
            AuthSessionState.FAILED,
            AuthSessionState.EXPIRED,
            AuthSessionState.ABANDONED,
        ]:
            patch = AuthSessionPatch(
                ver_config_id="test-config",
                request_parameters={"test": "params"},
                pyop_auth_code="test-code",
                response_url="http://test.com/callback",
                proof_status=state,
            )
            assert patch.proof_status == state

    def test_patch_with_presentation_exchange(self):
        """Test patching with presentation exchange data."""
        patch = AuthSessionPatch(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
            presentation_exchange={"verified": "data"},
        )

        assert patch.presentation_exchange == {"verified": "data"}

    def test_patch_model_dump_excludes_unset(self):
        """Test model_dump(exclude_unset=True) only includes set."""
        patch = AuthSessionPatch(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
            proof_status=AuthSessionState.VERIFIED,
        )

        # This is how the CRUD patch operation uses it
        dumped = patch.model_dump(exclude_unset=True)

        # Should only include explicitly set fields
        assert "proof_status" in dumped
        assert dumped["proof_status"] == AuthSessionState.VERIFIED


class TestAuthSession:
    """Test AuthSession (full DB model) model."""

    def test_session_with_all_fields(self):
        """Test creating full AuthSession with all fields."""
        session = AuthSession(
            _id=PyObjectId(),
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
            proof_status=AuthSessionState.VERIFIED,
            presentation_exchange={"data": "here"},
            pres_exch_id="test-pres-ex-id",
        )

        assert session.proof_status == AuthSessionState.VERIFIED
        assert session.presentation_exchange == {"data": "here"}
        assert session.pres_exch_id == "test-pres-ex-id"

    def test_session_inherits_from_create_structure(self):
        """Test that AuthSession has all the same fields as Create."""
        # Create a dict like what MongoDB would return
        create_data = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        ).model_dump()

        # Add the _id that MongoDB adds
        create_data["_id"] = PyObjectId()

        # Should be able to create AuthSession from Create data + _id
        session = AuthSession(**create_data)
        assert session.proof_status == AuthSessionState.NOT_STARTED


class TestProofStatusForTTLIndex:
    """
    Critical tests to ensure proof_status field is always present
    for TTL index to work correctly.
    """

    def test_create_always_has_proof_status_field(self):
        """
        CRITICAL: Verify that AuthSessionCreate.model_dump() always
        includes proof_status field, even when not explicitly set.

        This is essential for the MongoDB TTL index partial filter
        expression to match documents for cleanup.
        """
        auth_session = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        )

        dumped = auth_session.model_dump()

        # This is the critical assertion - proof_status MUST exist
        assert (
            "proof_status" in dumped
        ), "proof_status field missing - documents won't be indexed by TTL!"

        # And it must have the correct default value
        assert (
            dumped["proof_status"] == AuthSessionState.NOT_STARTED
        ), "proof_status has wrong default value"

    def test_create_serializes_proof_status_correctly(self):
        """Test proof_status serializes to string for MongoDB."""
        auth_session = AuthSessionCreate(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        )

        dumped = auth_session.model_dump()

        # Should be the string enum value, not the enum object
        assert dumped["proof_status"] == "not_started"
        assert isinstance(dumped["proof_status"], str)

    def test_patch_always_has_proof_status_field(self):
        """Verify that AuthSessionPatch also has proof_status in dumps."""
        patch = AuthSessionPatch(
            ver_config_id="test-config",
            request_parameters={"test": "params"},
            pyop_auth_code="test-code",
            response_url="http://test.com/callback",
        )

        dumped = patch.model_dump()
        assert "proof_status" in dumped
        assert dumped["proof_status"] == AuthSessionState.PENDING

    def test_all_expirable_states_are_strings(self):
        """
        Test that all states that should trigger TTL cleanup
        serialize correctly as strings for MongoDB queries.
        """
        expirable_states = [
            AuthSessionState.VERIFIED,
            AuthSessionState.FAILED,
            AuthSessionState.EXPIRED,
            AuthSessionState.ABANDONED,
        ]

        for state in expirable_states:
            auth_session = AuthSessionCreate(
                ver_config_id="test-config",
                request_parameters={"test": "params"},
                pyop_auth_code="test-code",
                response_url="http://test.com/callback",
                proof_status=state,
            )

            dumped = auth_session.model_dump()
            assert "proof_status" in dumped
            assert isinstance(dumped["proof_status"], str)
            # StrEnum.auto() converts to lowercase with underscores
            assert dumped["proof_status"] in [
                "verified",
                "failed",
                "expired",
                "abandoned",
            ]
