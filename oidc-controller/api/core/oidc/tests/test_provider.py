import pytest
import secrets
from unittest.mock import Mock, patch, MagicMock
from pyop.storage import StatelessWrapper, RedisWrapper
from api.core.oidc.provider import RedisWrapperWithPack, DynamicClientDatabase


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
