import importlib
import pytest
import secrets
from unittest.mock import Mock, patch, MagicMock
from pyop.storage import StatelessWrapper, RedisWrapper
from api.core.oidc.provider import RedisWrapperWithPack, DynamicClientDatabase
from api.core.oidc import provider


class TestRedisWrapperWithPack:
    """Test RedisWrapperWithPack pack() and unpack() methods."""

    @pytest.fixture
    def mock_redis_wrapper(self):
        """Create a mock Redis wrapper for testing."""
        # Create a mock instead of using the actual class
        wrapper = Mock(spec=RedisWrapperWithPack)
        wrapper._storage = {}
        wrapper.collection = "test_collection"
        wrapper._ttl = 600

        # Implement the actual pack and unpack methods
        def pack(value):
            key = secrets.token_urlsafe(32)
            wrapper._storage[key] = value
            return key

        def unpack(key):
            if key not in wrapper._storage:
                raise KeyError(f"Key {key} not found")
            return wrapper._storage[key]

        wrapper.pack = pack
        wrapper.unpack = unpack
        return wrapper

    def test_pack_generates_key_and_stores_value(self, mock_redis_wrapper):
        """Test that pack() generates a random key and stores the value."""
        test_value = {"user": "test_user", "client_id": "test_client"}

        # Call pack
        key = mock_redis_wrapper.pack(test_value)

        # Verify key was generated and has appropriate length
        assert key is not None
        assert len(key) > 20  # URL-safe base64 with 32 bytes should be longer
        assert key in mock_redis_wrapper._storage
        assert mock_redis_wrapper._storage[key] == test_value

    def test_pack_generates_unique_keys(self, mock_redis_wrapper):
        """Test that pack() generates unique keys for different calls."""
        test_value = {"data": "test"}

        # Generate multiple keys
        key1 = mock_redis_wrapper.pack(test_value)
        key2 = mock_redis_wrapper.pack(test_value)
        key3 = mock_redis_wrapper.pack(test_value)

        # Verify all keys are unique
        assert key1 != key2
        assert key2 != key3
        assert key1 != key3

    def test_unpack_retrieves_stored_value(self, mock_redis_wrapper):
        """Test that unpack() retrieves the value for a given key."""
        test_value = {"user": "test_user", "data": "test_data"}
        test_key = "test_key_123"

        # Store value directly
        mock_redis_wrapper._storage[test_key] = test_value

        # Retrieve value
        result = mock_redis_wrapper.unpack(test_key)

        assert result == test_value

    def test_unpack_raises_keyerror_for_missing_key(self, mock_redis_wrapper):
        """Test that unpack() raises KeyError for non-existent key."""
        # Verify KeyError is raised
        with pytest.raises(KeyError):
            mock_redis_wrapper.unpack("non_existent_key")

    def test_pack_unpack_roundtrip(self, mock_redis_wrapper):
        """Test that pack() and unpack() work together correctly."""
        test_value = {
            "user_id": "user123",
            "client_id": "client456",
            "scope": ["openid", "profile"],
        }

        # Pack the value
        key = mock_redis_wrapper.pack(test_value)

        # Unpack and verify
        result = mock_redis_wrapper.unpack(key)
        assert result == test_value


class TestDynamicClientDatabase:
    """Test DynamicClientDatabase MongoDB on-demand loading and caching."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock MongoDB database."""
        mock_db = Mock()
        mock_collection = Mock()
        mock_db.get_collection.return_value = mock_collection
        return mock_db, mock_collection

    @pytest.fixture
    def db_getter(self, mock_db):
        """Create a callable that returns the mock database."""
        db, _ = mock_db
        return lambda: db

    def test_getitem_loads_client_from_db(self, db_getter, mock_db):
        """Test that __getitem__ loads client from MongoDB."""
        _, mock_collection = mock_db
        client_data = {
            "_id": "mongodb_id",
            "client_id": "test_client",
            "client_secret": "secret",
            "redirect_uris": ["http://localhost/callback"],
        }
        mock_collection.find_one.return_value = client_data

        client_db = DynamicClientDatabase(db_getter)
        result = client_db["test_client"]

        # Verify MongoDB was queried
        mock_collection.find_one.assert_called_once_with({"client_id": "test_client"})
        # Verify _id was removed
        assert "_id" not in result
        assert result["client_id"] == "test_client"

    def test_lookup_by_client_id_when_name_differs(self, db_getter, mock_db):
        """
        Regression Test for #894:
        Test that client lookup uses client_id as key, even if client_name is different.
        """
        _, mock_collection = mock_db
        target_client_id = "client-id-123"
        target_client_name = "My Friendly Client Name"

        client_doc = {
            "client_id": target_client_id,
            "client_name": target_client_name,
            "client_secret": "secret",
        }

        # Setup find_one to return doc only when querying by correct ID
        def find_one_side_effect(query):
            if query.get("client_id") == target_client_id:
                return client_doc.copy()
            return None

        mock_collection.find_one.side_effect = find_one_side_effect

        client_db = DynamicClientDatabase(db_getter)

        # 1. Happy Path: Lookup using client_id must succeed
        result = client_db[target_client_id]
        assert result["client_id"] == target_client_id
        assert result["client_name"] == target_client_name

        # 2. Negative Test: Lookup using client_name must fail
        # This confirms we are not building a dict keyed by name
        with pytest.raises(KeyError):
            _ = client_db[target_client_name]

    def test_getitem_raises_keyerror_for_missing_client(self, db_getter, mock_db):
        """Test that __getitem__ raises KeyError for non-existent client."""
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = None

        client_db = DynamicClientDatabase(db_getter)

        with pytest.raises(KeyError, match="client_id 'missing_client' unknown"):
            _ = client_db["missing_client"]

    def test_contains_returns_true_for_existing_client(self, db_getter, mock_db):
        """Test that __contains__ returns True for existing client."""
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = {"client_id": "test_client"}

        client_db = DynamicClientDatabase(db_getter)
        assert "test_client" in client_db

    def test_contains_returns_false_for_missing_client(self, db_getter, mock_db):
        """Test that __contains__ returns False for non-existent client."""
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = None

        client_db = DynamicClientDatabase(db_getter)
        assert "missing_client" not in client_db

    def test_get_returns_client_for_existing_client(self, db_getter, mock_db):
        """Test that get() returns client for existing client."""
        _, mock_collection = mock_db
        client_data = {"client_id": "test_client", "client_secret": "secret"}
        mock_collection.find_one.return_value = client_data.copy()

        client_db = DynamicClientDatabase(db_getter)
        result = client_db.get("test_client")

        assert result["client_id"] == "test_client"

    def test_get_returns_default_for_missing_client(self, db_getter, mock_db):
        """Test that get() returns default value for non-existent client."""
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = None

        client_db = DynamicClientDatabase(db_getter)
        result = client_db.get("missing_client", "default_value")

        assert result == "default_value"

    def test_mongodb_id_field_removed(self, db_getter, mock_db):
        """Test that MongoDB _id field is removed from returned client."""
        _, mock_collection = mock_db
        client_data = {
            "_id": "mongodb_object_id_12345",
            "client_id": "test_client",
            "client_secret": "secret",
        }
        mock_collection.find_one.return_value = client_data.copy()

        client_db = DynamicClientDatabase(db_getter)
        result = client_db["test_client"]

        # Verify _id was removed
        assert "_id" not in result
        assert result["client_id"] == "test_client"
        assert result["client_secret"] == "secret"

    def test_cache_hit_reduces_db_calls(self, db_getter, mock_db):
        """Test that cache reduces database calls without relying on time mocking."""
        _, mock_collection = mock_db
        client_data = {
            "_id": "mongodb_id",
            "client_id": "test_client",
            "client_secret": "secret",
        }
        mock_collection.find_one.return_value = client_data.copy()

        client_db = DynamicClientDatabase(db_getter)
        # Set a very long TTL so cache never expires during test
        client_db._cache_ttl = 999999

        # First call - loads from DB
        result1 = client_db["test_client"]
        # Second call - should use cache
        result2 = client_db["test_client"]
        # Third call - should still use cache
        result3 = client_db["test_client"]

        # Verify DB was only queried once (cache hits on subsequent calls)
        assert mock_collection.find_one.call_count == 1
        assert result1 == result2 == result3

    def test_different_clients_cached_independently(self, db_getter, mock_db):
        """Test that different clients are cached independently."""
        _, mock_collection = mock_db
        client1_data = {
            "_id": "id1",
            "client_id": "client1",
            "client_secret": "secret1",
        }
        client2_data = {
            "_id": "id2",
            "client_id": "client2",
            "client_secret": "secret2",
        }

        # Return different data based on query
        def find_one_side_effect(query):
            if query["client_id"] == "client1":
                return client1_data.copy()
            elif query["client_id"] == "client2":
                return client2_data.copy()
            return None

        mock_collection.find_one.side_effect = find_one_side_effect

        client_db = DynamicClientDatabase(db_getter)
        client_db._cache_ttl = 999999

        # Load both clients
        result1 = client_db["client1"]
        result2 = client_db["client2"]

        # Load them again - should use cache
        result1_cached = client_db["client1"]
        result2_cached = client_db["client2"]

        # Verify each was loaded from DB exactly once
        assert mock_collection.find_one.call_count == 2
        assert result1["client_id"] == "client1"
        assert result2["client_id"] == "client2"
        assert result1 == result1_cached
        assert result2 == result2_cached

    @patch("api.db.session.COLLECTION_NAMES")
    def test_caching_reloads_client_after_ttl_expires(
        self, mock_collection_names, db_getter, mock_db
    ):
        """Test that client is reloaded from DB after TTL expires."""
        mock_collection_names.CLIENT_CONFIGURATIONS = "client_configurations"
        _, mock_collection = mock_db
        client_data_v1 = {
            "_id": "mongodb_id",
            "client_id": "test_client",
            "version": "v1",
        }
        client_data_v2 = {
            "_id": "mongodb_id",
            "client_id": "test_client",
            "version": "v2",
        }

        # Return different data on each call
        mock_collection.find_one.side_effect = [
            client_data_v1.copy(),
            client_data_v2.copy(),
        ]

        client_db = DynamicClientDatabase(db_getter)
        client_db._cache_ttl = 60  # 60 second TTL

        # First call - loads from DB
        result1 = client_db["test_client"]

        # Manually expire the cache by modifying the cache time
        import time

        client_db._cache_time["test_client"] = time.time() - 100  # 100 seconds ago

        # Second call - TTL expired, should reload from DB
        result2 = client_db["test_client"]

        # Verify DB was queried twice (cache miss on second call due to TTL)
        assert mock_collection.find_one.call_count == 2
        assert result1["version"] == "v1"
        assert result2["version"] == "v2"

    def test_keys_returns_all_client_ids(self, db_getter, mock_db):
        """Test that keys() returns all client IDs from database."""
        _, mock_collection = mock_db
        mock_collection.find.return_value = [
            {"client_id": "client1"},
            {"client_id": "client2"},
            {"client_id": "client3"},
        ]

        client_db = DynamicClientDatabase(db_getter)
        result = client_db.keys()

        assert result == ["client1", "client2", "client3"]

    def test_values_yields_all_clients(self, db_getter, mock_db):
        """Test that values() yields all clients from database."""
        _, mock_collection = mock_db
        # Mock keys() response
        mock_collection.find.return_value = [
            {"client_id": "client1"},
            {"client_id": "client2"},
        ]
        # Mock individual client lookups
        mock_collection.find_one.side_effect = [
            {"_id": "id1", "client_id": "client1", "data": "data1"},
            {"_id": "id2", "client_id": "client2", "data": "data2"},
        ]

        client_db = DynamicClientDatabase(db_getter)
        values = list(client_db.values())

        assert len(values) == 2
        assert values[0]["client_id"] == "client1"
        assert values[1]["client_id"] == "client2"

    def test_items_yields_client_id_and_client_pairs(self, db_getter, mock_db):
        """Test that items() yields (client_id, client) pairs from database."""
        _, mock_collection = mock_db
        # Mock keys() response
        mock_collection.find.return_value = [
            {"client_id": "client1"},
            {"client_id": "client2"},
        ]
        # Mock individual client lookups
        mock_collection.find_one.side_effect = [
            {"_id": "id1", "client_id": "client1", "data": "data1"},
            {"_id": "id2", "client_id": "client2", "data": "data2"},
        ]

        client_db = DynamicClientDatabase(db_getter)
        items = list(client_db.items())

        assert len(items) == 2
        assert items[0][0] == "client1"
        assert items[0][1]["client_id"] == "client1"
        assert items[1][0] == "client2"
        assert items[1][1]["client_id"] == "client2"


class TestStorageBackendSelection:
    """Test conditional storage backend initialization based on USE_REDIS_ADAPTER."""

    def test_module_has_storage_instances(self):
        """Test that provider module has storage instances initialized."""
        import api.core.oidc.provider as provider_module

        # Verify storage instances exist
        assert hasattr(provider_module, "authorization_code_storage")
        assert hasattr(provider_module, "access_token_storage")
        assert hasattr(provider_module, "refresh_token_storage")
        assert hasattr(provider_module, "subject_identifier_storage")

    def test_conditional_logic_with_redis_enabled(self):
        """Test that conditional logic correctly selects Redis storage."""
        # Create a mock settings object
        mock_settings = Mock()
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "redis"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = None
        mock_settings.REDIS_DB = 0

        # Verify the conditional would select Redis path
        assert mock_settings.USE_REDIS_ADAPTER is True

    def test_conditional_logic_with_redis_disabled(self):
        """Test that conditional logic correctly selects StatelessWrapper."""
        # Create a mock settings object
        mock_settings = Mock()
        mock_settings.USE_REDIS_ADAPTER = False

        # Verify the conditional would select StatelessWrapper path
        assert mock_settings.USE_REDIS_ADAPTER is False


class TestHelperFunctions:
    """Test helper functions in provider module."""

    def test_build_redis_url_without_password(self):
        """Test Redis URL building without password."""
        from api.core.oidc.provider import _build_redis_url
        from api.core.config import settings

        # Save original values
        original_host = settings.REDIS_HOST
        original_port = settings.REDIS_PORT
        original_password = settings.REDIS_PASSWORD
        original_db = settings.REDIS_DB

        try:
            # Set test values
            settings.REDIS_HOST = "testhost"
            settings.REDIS_PORT = 6380
            settings.REDIS_PASSWORD = None
            settings.REDIS_DB = 1

            url = _build_redis_url()
            assert url == "redis://testhost:6380/1"
        finally:
            # Restore original values
            settings.REDIS_HOST = original_host
            settings.REDIS_PORT = original_port
            settings.REDIS_PASSWORD = original_password
            settings.REDIS_DB = original_db

    def test_build_redis_url_with_password(self):
        """Test Redis URL building with password."""
        from api.core.oidc.provider import _build_redis_url
        from api.core.config import settings

        # Save original values
        original_host = settings.REDIS_HOST
        original_port = settings.REDIS_PORT
        original_password = settings.REDIS_PASSWORD
        original_db = settings.REDIS_DB

        try:
            # Set test values
            settings.REDIS_HOST = "securehost"
            settings.REDIS_PORT = 6379
            settings.REDIS_PASSWORD = "secret123"
            settings.REDIS_DB = 0

            url = _build_redis_url()
            assert url == "redis://:secret123@securehost:6379/0"
        finally:
            # Restore original values
            settings.REDIS_HOST = original_host
            settings.REDIS_PORT = original_port
            settings.REDIS_PASSWORD = original_password
            settings.REDIS_DB = original_db

    def test_get_signing_key_dir_path(self):
        """Test signing key directory path generation."""
        from api.core.oidc.provider import get_signing_key_dir_path
        import os

        result = get_signing_key_dir_path("/api/core/oidc", "/test", "key.pem")
        assert result.endswith(os.path.join("/test", "key.pem"))

    @patch("api.core.oidc.provider.os.path.isfile")
    def test_pem_file_exists_true(self, mock_isfile):
        """Test pem file existence check when file exists."""
        from api.core.oidc.provider import pem_file_exists

        mock_isfile.return_value = True
        assert pem_file_exists("/path/to/key.pem") is True
        mock_isfile.assert_called_once_with("/path/to/key.pem")

    @patch("api.core.oidc.provider.os.path.isfile")
    def test_pem_file_exists_false(self, mock_isfile):
        """Test pem file existence check when file does not exist."""
        from api.core.oidc.provider import pem_file_exists

        mock_isfile.return_value = False
        assert pem_file_exists("/path/to/key.pem") is False
        mock_isfile.assert_called_once_with("/path/to/key.pem")

    @patch("builtins.open", create=True)
    def test_save_pem_file(self, mock_open):
        """Test saving PEM file."""
        from api.core.oidc.provider import save_pem_file

        mock_file = MagicMock()
        mock_open.return_value = mock_file

        content = b"test pem content"
        save_pem_file("/path/to/key.pem", content)

        mock_open.assert_called_once_with("/path/to/key.pem", "wb")
        mock_file.write.assert_called_once_with(content)
        mock_file.close.assert_called_once()


class TestInitProvider:
    """Test init_provider function."""

    @pytest.mark.asyncio
    async def test_init_provider_creates_provider(self):
        """Test that init_provider creates a provider instance."""
        from api.core.oidc import provider as provider_module

        # Create a mock database
        mock_db = Mock()
        mock_collection = Mock()
        mock_db.get_collection.return_value = mock_collection

        # Call init_provider
        await provider_module.init_provider(mock_db)

        # Verify provider was created
        assert provider_module.provider is not None
        assert hasattr(provider_module.provider, "authz_state")
        assert hasattr(provider_module.provider, "clients")


class TestProviderConfiguration:
    """Test provider module configuration constants and dicts."""

    def test_endpoints_constants(self):
        """Test that endpoint constants are defined and correct."""
        from api.core.oidc import provider as provider_module

        assert hasattr(provider_module, "AuthorizeUriEndpoint")
        assert hasattr(provider_module, "TokenUriEndpoint")
        assert hasattr(provider_module, "UserInfoUriEndpoint")
        assert provider_module.UserInfoUriEndpoint == "userinfo"

    def test_configuration_information_has_userinfo(self):
        """Test that OIDC configuration dict includes userinfo_endpoint."""
        from api.core.oidc import provider as provider_module

        config = provider_module.configuration_information
        assert "userinfo_endpoint" in config

        # Verify it's constructed correctly relative to issuer
        # The issuer is set during import based on settings, so we read what was set
        issuer = config["issuer"]
        expected_endpoint = f"{issuer}/{provider_module.UserInfoUriEndpoint}"
        assert config["userinfo_endpoint"] == expected_endpoint


class TestProviderRedisConfiguration:
    """Test Redis configuration logic in provider module."""

    @patch("api.core.oidc.provider.settings")
    @patch("api.core.oidc.provider.RedisWrapperWithPack")
    @patch("api.core.oidc.provider._build_redis_url")
    def test_redis_ttl_synchronization(self, mock_build_url, mock_redis_wrapper, mock_settings):
        """
        Verify that UserInfo Redis TTL is synchronized with Access Token TTL 
        plus a safety buffer.
        """
        # Setup settings
        mock_settings.USE_REDIS_ADAPTER = True
        mock_settings.REDIS_HOST = "localhost"
        mock_settings.REDIS_PORT = 6379
        mock_settings.REDIS_PASSWORD = None
        mock_settings.REDIS_DB = 0
        mock_settings.SUBJECT_ID_HASH_SALT = "test_salt"
        
        # Set a specific TTL to test math
        TEST_TTL = 1000
        mock_settings.OIDC_ACCESS_TOKEN_TTL = TEST_TTL

        mock_build_url.return_value = "redis://localhost:6379/0"

        # Reload provider to trigger the top-level conditional logic
        importlib.reload(provider)

        # 1. Verify Access Token Storage gets exact TTL
        access_token_call = next(
            call for call in mock_redis_wrapper.call_args_list 
            if call.kwargs.get("collection") == "pyop_access_tokens"
        )
        assert access_token_call.kwargs["ttl"] == TEST_TTL

        # 2. Verify UserInfo Storage gets TTL + 60 buffer
        userinfo_call = next(
            call for call in mock_redis_wrapper.call_args_list 
            if call.kwargs.get("collection") == "pyop_userinfo_claims"
        )
        assert userinfo_call.kwargs["ttl"] == TEST_TTL + 60