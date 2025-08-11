"""Tests for database session management."""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open
from pymongo import ASCENDING
from pymongo.collection import Collection
from pymongo.errors import OperationFailure

from api.db.session import (
    apply_expiration_times,
    create_ttl_indexes,
    init_db,
    get_db,
    get_async_session,
    client,
)
from api.db.collections import COLLECTION_NAMES
from api.authSessions.models import AuthSessionState


@pytest.fixture
def mock_collection():
    """Create a mock collection instance."""
    return MagicMock(spec=Collection)


@pytest.fixture
def mock_database():
    """Create a mock database instance."""
    db = MagicMock()
    return db


@pytest.fixture
def sample_expiration_times():
    """Sample expiration times for testing."""
    return ["verified", "failed", "expired"]


@pytest.fixture
def valid_config_file_content():
    """Valid JSON config file content."""
    return ["verified", "failed", "expired"]


@pytest.fixture
def invalid_config_file_content():
    """Invalid JSON config file content."""
    return ["invalid_state", "another_invalid"]


class TestApplyExpirationTimes:
    """Test apply_expiration_times function."""

    def test_apply_expiration_times_success(
        self, mock_collection, sample_expiration_times
    ):
        """Test successful application of expiration times."""
        with patch(
            "api.db.session.settings.CONTROLLER_PRESENTATION_CLEANUP_TIME", 3600
        ):
            apply_expiration_times(mock_collection, sample_expiration_times)

            mock_collection.create_index.assert_called_once_with(
                [("created_at", ASCENDING)],
                expireAfterSeconds=3600,
                name="auth_session_ttl",
                partialFilterExpression={
                    "$or": [
                        {"proof_status": {"$eq": state}}
                        for state in sample_expiration_times
                    ]
                },
            )

    def test_apply_expiration_times_operation_failure(
        self, mock_collection, sample_expiration_times
    ):
        """Test handling of OperationFailure when index already exists."""
        mock_collection.create_index.side_effect = OperationFailure(
            "Index already exists"
        )

        with patch("api.db.session.logger") as mock_logger:
            with patch(
                "api.db.session.settings.CONTROLLER_PRESENTATION_CLEANUP_TIME", 3600
            ):
                apply_expiration_times(mock_collection, sample_expiration_times)

                mock_logger.warning.assert_called_once_with(
                    "The index auth_session_ttl already exists. It must manually be deleted to "
                    + "update the timeout or matched AuthSessionState's"
                )


class TestCreateTtlIndexes:
    """Test create_ttl_indexes function."""

    def test_create_ttl_indexes_valid_config(
        self, mock_collection, valid_config_file_content
    ):
        """Test TTL index creation with valid configuration file."""
        config_file = "/tmp/test_config.json"

        with patch(
            "builtins.open", mock_open(read_data=json.dumps(valid_config_file_content))
        ):
            with patch("api.db.session.apply_expiration_times") as mock_apply:
                create_ttl_indexes(mock_collection, config_file)

                mock_apply.assert_called_once_with(
                    mock_collection, valid_config_file_content
                )

    def test_create_ttl_indexes_file_not_found(self, mock_collection):
        """Test TTL index creation when config file is not found."""
        config_file = "/tmp/nonexistent_config.json"

        with patch("builtins.open", side_effect=FileNotFoundError()):
            with patch("api.db.session.logger") as mock_logger:
                create_ttl_indexes(mock_collection, config_file)

                mock_logger.warning.assert_called_once_with(
                    "The file "
                    + config_file
                    + " does not exist or could not be opened "
                    + "because of this no auth session timeouts will be applied."
                )

    def test_create_ttl_indexes_json_decode_error(self, mock_collection):
        """Test TTL index creation with invalid JSON."""
        config_file = "/tmp/invalid_config.json"

        with patch("builtins.open", mock_open(read_data="invalid json")):
            with patch("api.db.session.logger") as mock_logger:
                create_ttl_indexes(mock_collection, config_file)

                mock_logger.warning.assert_called_once()
                call_args = mock_logger.warning.call_args[0][0]
                assert (
                    "Failed to decode the auth session timeouts timeout config file"
                    in call_args
                )
                assert config_file in call_args

    def test_create_ttl_indexes_invalid_auth_session_states(
        self, mock_collection, invalid_config_file_content
    ):
        """Test TTL index creation with invalid auth session states."""
        config_file = "/tmp/invalid_states_config.json"

        with patch(
            "builtins.open",
            mock_open(read_data=json.dumps(invalid_config_file_content)),
        ):
            with patch("api.db.session.logger") as mock_logger:
                create_ttl_indexes(mock_collection, config_file)

                mock_logger.error.assert_called_once()
                call_args = mock_logger.error.call_args[0][0]
                assert "There is at least one invalid entry in the file" in call_args
                assert config_file in call_args
                assert "valid auth session strings are" in call_args

    def test_create_ttl_indexes_mixed_valid_invalid_states(self, mock_collection):
        """Test TTL index creation with mixed valid and invalid states."""
        config_file = "/tmp/mixed_config.json"
        mixed_content = ["verified", "invalid_state", "failed"]

        with patch("builtins.open", mock_open(read_data=json.dumps(mixed_content))):
            with patch("api.db.session.logger") as mock_logger:
                create_ttl_indexes(mock_collection, config_file)

                mock_logger.error.assert_called_once()

    def test_create_ttl_indexes_non_string_states(self, mock_collection):
        """Test TTL index creation with non-string states."""
        config_file = "/tmp/non_string_config.json"
        non_string_content = ["verified", 123, "failed"]

        with patch(
            "builtins.open", mock_open(read_data=json.dumps(non_string_content))
        ):
            with patch("api.db.session.logger") as mock_logger:
                create_ttl_indexes(mock_collection, config_file)

                mock_logger.error.assert_called_once()


class TestInitDb:
    """Test init_db function."""

    @pytest.mark.asyncio
    async def test_init_db_success_with_config_file(self, mock_database):
        """Test successful database initialization with config file."""
        mock_ver_configs = MagicMock()
        mock_client_configs = MagicMock()
        mock_auth_session = MagicMock()

        mock_database.get_collection.side_effect = [
            mock_ver_configs,
            mock_client_configs,
            mock_auth_session,
        ]

        with patch("api.db.session.client") as mock_client:
            with patch("api.db.session.settings") as mock_settings:
                with patch("api.db.session.create_ttl_indexes") as mock_create_ttl:
                    mock_client.__getitem__.return_value = mock_database
                    mock_settings.DB_NAME = "test_db"
                    mock_settings.CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE = (
                        "/tmp/config.json"
                    )

                    await init_db()

                    # Verify database access
                    mock_client.__getitem__.assert_called_once_with("test_db")

                    # Verify collection access
                    assert mock_database.get_collection.call_count == 3
                    mock_database.get_collection.assert_any_call(
                        COLLECTION_NAMES.VER_CONFIGS
                    )
                    mock_database.get_collection.assert_any_call(
                        COLLECTION_NAMES.CLIENT_CONFIGURATIONS
                    )
                    mock_database.get_collection.assert_any_call(
                        COLLECTION_NAMES.AUTH_SESSION
                    )

                    # Verify index creation
                    mock_ver_configs.create_index.assert_called_once_with(
                        [("ver_config_id", ASCENDING)], unique=True
                    )
                    mock_client_configs.create_index.assert_called_once_with(
                        [("client_id", ASCENDING)], unique=True
                    )
                    mock_auth_session.create_index.assert_any_call(
                        [("pres_exch_id", ASCENDING)], unique=True
                    )
                    mock_auth_session.create_index.assert_any_call(
                        [("pyop_auth_code", ASCENDING)], unique=True
                    )

                    # Verify TTL indexes creation
                    mock_create_ttl.assert_called_once_with(
                        mock_auth_session, "/tmp/config.json"
                    )

    @pytest.mark.asyncio
    async def test_init_db_success_without_config_file(self, mock_database):
        """Test successful database initialization without config file."""
        mock_ver_configs = MagicMock()
        mock_client_configs = MagicMock()
        mock_auth_session = MagicMock()

        mock_database.get_collection.side_effect = [
            mock_ver_configs,
            mock_client_configs,
            mock_auth_session,
        ]

        with patch("api.db.session.client") as mock_client:
            with patch("api.db.session.settings") as mock_settings:
                with patch("api.db.session.logger") as mock_logger:
                    mock_client.__getitem__.return_value = mock_database
                    mock_settings.DB_NAME = "test_db"
                    mock_settings.CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE = None

                    await init_db()

                    # Verify warning is logged
                    mock_logger.warn.assert_called_once_with(
                        "No configuration file was set for CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE"
                        + " No expiration times will be applied."
                    )

    @pytest.mark.asyncio
    async def test_init_db_index_creation_order(self, mock_database):
        """Test that indexes are created in the correct order."""
        mock_ver_configs = MagicMock()
        mock_client_configs = MagicMock()
        mock_auth_session = MagicMock()

        mock_database.get_collection.side_effect = [
            mock_ver_configs,
            mock_client_configs,
            mock_auth_session,
        ]

        with patch("api.db.session.client") as mock_client:
            with patch("api.db.session.settings") as mock_settings:
                mock_client.__getitem__.return_value = mock_database
                mock_settings.DB_NAME = "test_db"
                mock_settings.CONTROLLER_SESSION_TIMEOUT_CONFIG_FILE = None

                await init_db()

                # Verify auth session indexes are created in correct order
                expected_calls = [
                    ([("pres_exch_id", ASCENDING)], {"unique": True}),
                    ([("pyop_auth_code", ASCENDING)], {"unique": True}),
                    (
                        [("socket_id", ASCENDING)],
                        {
                            "unique": True,
                            "partialFilterExpression": {"socket_id": {"$gt": ""}},
                        },
                    ),
                ]

                actual_calls = mock_auth_session.create_index.call_args_list
                assert len(actual_calls) == 3

                for i, (expected_args, expected_kwargs) in enumerate(expected_calls):
                    actual_args, actual_kwargs = actual_calls[i]
                    assert actual_args == (expected_args,)
                    assert actual_kwargs == expected_kwargs


class TestGetDb:
    """Test get_db function."""

    @pytest.mark.asyncio
    async def test_get_db_returns_database(self):
        """Test that get_db returns the correct database."""
        with patch("api.db.session.client") as mock_client:
            with patch("api.db.session.settings") as mock_settings:
                mock_settings.DB_NAME = "test_db"
                mock_database = MagicMock()
                mock_client.__getitem__.return_value = mock_database

                result = await get_db()

                assert result == mock_database
                mock_client.__getitem__.assert_called_once_with("test_db")


class TestGetAsyncSession:
    """Test get_async_session function."""

    @pytest.mark.asyncio
    async def test_get_async_session_yields_none(self):
        """Test that get_async_session yields None."""
        async_gen = get_async_session()
        result = await async_gen.__anext__()
        assert result is None

        # Verify it raises StopAsyncIteration on next call
        with pytest.raises(StopAsyncIteration):
            await async_gen.__anext__()


class TestAuthSessionStateValidation:
    """Test AuthSessionState validation in TTL functions."""

    def test_all_auth_session_states_are_strings(self):
        """Test that all AuthSessionState values are strings."""
        auth_session_states = [str(i) for i in list(AuthSessionState)]

        for state in auth_session_states:
            assert isinstance(state, str)
            assert len(state) > 0

        # Test that we have all expected states
        expected_states = {
            "not_started",
            "pending",
            "expired",
            "verified",
            "failed",
            "abandoned",
        }
        actual_states = set(auth_session_states)
        assert actual_states == expected_states

    def test_valid_expiration_times_validation(self, mock_collection):
        """Test that valid expiration times are properly validated."""
        valid_states = ["verified", "failed", "expired"]
        config_file = "/tmp/valid_config.json"

        with patch("builtins.open", mock_open(read_data=json.dumps(valid_states))):
            with patch("api.db.session.apply_expiration_times") as mock_apply:
                create_ttl_indexes(mock_collection, config_file)

                mock_apply.assert_called_once_with(mock_collection, valid_states)
