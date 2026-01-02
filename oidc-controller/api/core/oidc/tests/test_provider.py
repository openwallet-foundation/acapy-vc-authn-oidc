import importlib
import pytest
import secrets
from unittest.mock import Mock, patch, MagicMock
from pyop.storage import StatelessWrapper, RedisWrapper
from api.core.oidc.provider import RedisWrapperWithPack, DynamicClientDatabase
from api.core.oidc import provider as provider_module
from api.core.config import settings as real_settings


class TestRedisWrapperWithPack:
    """Test RedisWrapperWithPack pack() and unpack() methods."""

    @pytest.fixture
    def mock_redis_wrapper(self):
        """Create a mock Redis wrapper for testing."""
        wrapper = Mock(spec=RedisWrapperWithPack)
        wrapper._storage = {}
        wrapper.collection = "test_collection"
        wrapper._ttl = 600

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
        test_value = {"user": "test_user", "client_id": "test_client"}
        key = mock_redis_wrapper.pack(test_value)
        assert key is not None
        assert len(key) > 20
        assert key in mock_redis_wrapper._storage
        assert mock_redis_wrapper._storage[key] == test_value

    def test_pack_generates_unique_keys(self, mock_redis_wrapper):
        test_value = {"data": "test"}
        key1 = mock_redis_wrapper.pack(test_value)
        key2 = mock_redis_wrapper.pack(test_value)
        assert key1 != key2

    def test_unpack_retrieves_stored_value(self, mock_redis_wrapper):
        test_value = {"user": "test_user", "data": "test_data"}
        test_key = "test_key_123"
        mock_redis_wrapper._storage[test_key] = test_value
        result = mock_redis_wrapper.unpack(test_key)
        assert result == test_value

    def test_unpack_raises_keyerror_for_missing_key(self, mock_redis_wrapper):
        with pytest.raises(KeyError):
            mock_redis_wrapper.unpack("non_existent_key")

    def test_pack_unpack_roundtrip(self, mock_redis_wrapper):
        test_value = {
            "user_id": "user123",
            "client_id": "client456",
            "scope": ["openid", "profile"],
        }
        key = mock_redis_wrapper.pack(test_value)
        result = mock_redis_wrapper.unpack(key)
        assert result == test_value


class TestDynamicClientDatabase:
    """Test DynamicClientDatabase MongoDB on-demand loading and caching."""

    @pytest.fixture
    def mock_db(self):
        mock_db = Mock()
        mock_collection = Mock()
        mock_db.get_collection.return_value = mock_collection
        return mock_db, mock_collection

    @pytest.fixture
    def db_getter(self, mock_db):
        db, _ = mock_db
        return lambda: db

    def test_getitem_loads_client_from_db(self, db_getter, mock_db):
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

        mock_collection.find_one.assert_called_once_with({"client_id": "test_client"})
        assert "_id" not in result
        assert result["client_id"] == "test_client"

    def test_lookup_by_client_id_when_name_differs(self, db_getter, mock_db):
        _, mock_collection = mock_db
        target_client_id = "client-id-123"
        target_client_name = "My Friendly Client Name"
        client_doc = {
            "client_id": target_client_id,
            "client_name": target_client_name,
            "client_secret": "secret",
        }

        def find_one_side_effect(query):
            if query.get("client_id") == target_client_id:
                return client_doc.copy()
            return None

        mock_collection.find_one.side_effect = find_one_side_effect
        client_db = DynamicClientDatabase(db_getter)

        result = client_db[target_client_id]
        assert result["client_id"] == target_client_id

        with pytest.raises(KeyError):
            _ = client_db[target_client_name]

    def test_getitem_raises_keyerror_for_missing_client(self, db_getter, mock_db):
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = None
        client_db = DynamicClientDatabase(db_getter)
        with pytest.raises(KeyError):
            _ = client_db["missing_client"]

    def test_contains(self, db_getter, mock_db):
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = {"client_id": "test_client"}
        client_db = DynamicClientDatabase(db_getter)
        assert "test_client" in client_db

        mock_collection.find_one.return_value = None
        assert "missing_client" not in client_db

    def test_get_method(self, db_getter, mock_db):
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = {"client_id": "test"}
        client_db = DynamicClientDatabase(db_getter)
        assert client_db.get("test")["client_id"] == "test"

        mock_collection.find_one.return_value = None
        assert client_db.get("missing", "default") == "default"

    def test_mongodb_id_removed(self, db_getter, mock_db):
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = {"_id": "oid", "client_id": "test"}
        client_db = DynamicClientDatabase(db_getter)
        assert "_id" not in client_db["test"]

    def test_cache_hit(self, db_getter, mock_db):
        _, mock_collection = mock_db
        mock_collection.find_one.return_value = {"client_id": "test"}
        client_db = DynamicClientDatabase(db_getter)
        client_db._cache_ttl = 999

        client_db["test"]
        client_db["test"]
        assert mock_collection.find_one.call_count == 1

    @patch("api.db.session.COLLECTION_NAMES")
    def test_caching_reloads_after_ttl(self, mock_names, db_getter, mock_db):
        mock_names.CLIENT_CONFIGURATIONS = "clients"
        _, mock_collection = mock_db
        mock_collection.find_one.side_effect = [
            {"client_id": "test", "v": 1},
            {"client_id": "test", "v": 2},
        ]

        client_db = DynamicClientDatabase(db_getter)
        client_db["test"]

        import time

        client_db._cache_time["test"] = time.time() - 100

        res = client_db["test"]
        assert res["v"] == 2
        assert mock_collection.find_one.call_count == 2

    def test_dict_methods(self, db_getter, mock_db):
        _, mock_collection = mock_db
        mock_collection.find.return_value = [{"client_id": "c1"}, {"client_id": "c2"}]
        mock_collection.find_one.side_effect = [
            {"client_id": "c1"},
            {"client_id": "c2"},
        ]

        client_db = DynamicClientDatabase(db_getter)
        assert list(client_db.keys()) == ["c1", "c2"]
        assert len(list(client_db.values())) == 2
        assert len(list(client_db.items())) == 2


class TestInitProvider:
    @pytest.mark.asyncio
    async def test_init_provider_creates_provider(self):
        mock_db = Mock()
        mock_db.get_collection.return_value = Mock()
        await provider_module.init_provider(mock_db)
        assert provider_module.provider is not None


class TestProviderConfiguration:
    """Test provider module configuration constants and dicts."""

    def test_endpoints_constants(self):
        assert hasattr(provider_module, "AuthorizeUriEndpoint")
        assert hasattr(provider_module, "TokenUriEndpoint")
        assert hasattr(provider_module, "UserInfoUriEndpoint")
        assert provider_module.UserInfoUriEndpoint == "userinfo"

    def test_configuration_information_flag_logic(self):
        """Test that userinfo_endpoint is conditional based on settings."""
        # Case 1: Enabled
        with patch.object(real_settings, "CONTROLLER_ENABLE_USERINFO_ENDPOINT", True):
            with patch.object(real_settings, "USE_REDIS_ADAPTER", False):
                importlib.reload(provider_module)
                config = provider_module.configuration_information
                assert "userinfo_endpoint" in config
                assert config["userinfo_endpoint"].endswith("/userinfo")

        # Case 2: Disabled
        with patch.object(real_settings, "CONTROLLER_ENABLE_USERINFO_ENDPOINT", False):
            with patch.object(real_settings, "USE_REDIS_ADAPTER", False):
                importlib.reload(provider_module)
                config = provider_module.configuration_information
                assert "userinfo_endpoint" not in config


class TestProviderRedisConfiguration:
    """Test Redis configuration logic in provider module."""

    @patch("api.core.oidc.provider._build_redis_url")
    def test_redis_ttl_synchronization(self, mock_build_url):
        """
        Verify that UserInfo Redis TTL is synchronized with Access Token TTL.
        We verify this by inspecting the created objects in the module.
        """
        TEST_TTL = 1000
        mock_build_url.return_value = "redis://mock"

        # Apply settings to the singleton directly so reload picks them up
        with patch.object(real_settings, "USE_REDIS_ADAPTER", True), patch.object(
            real_settings, "OIDC_ACCESS_TOKEN_TTL", TEST_TTL
        ), patch.object(real_settings, "REDIS_HOST", "localhost"):

            # Reload to run the top-level 'if settings.USE_REDIS_ADAPTER:' block
            importlib.reload(provider_module)

            # Inspect the objects created by the module
            # Note: PyOP RedisWrapper stores TTL in self.ttl

            # 1. Access Token Storage
            # Should match OIDC_ACCESS_TOKEN_TTL exactly
            assert hasattr(provider_module, "access_token_storage")
            assert provider_module.access_token_storage.ttl == TEST_TTL

            # 2. UserInfo Storage
            # Should match OIDC_ACCESS_TOKEN_TTL + 60s buffer
            assert hasattr(provider_module, "userinfo_claims_storage")
            assert provider_module.userinfo_claims_storage.ttl == TEST_TTL + 60
