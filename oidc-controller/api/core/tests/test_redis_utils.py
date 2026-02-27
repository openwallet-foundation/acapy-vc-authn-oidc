"""Tests for api/core/redis_utils.py"""

from unittest.mock import MagicMock, patch

import pytest

from api.core.redis_utils import (
    BaseRedisWrapperWithPack,
    _get_sentinel_master,
)


class TestGetSentinelMaster:
    """Tests for _get_sentinel_master: REDIS_PASSWORD is used for both sentinel
    authentication and master authentication."""

    def _make_sentinel_mock(self):
        master = MagicMock()
        sentinel_instance = MagicMock()
        sentinel_instance.master_for.return_value = master
        return sentinel_instance, master

    @patch("api.core.redis_utils.Sentinel")
    def test_password_passed_to_sentinel_kwargs(self, mock_sentinel_cls):
        """REDIS_PASSWORD is forwarded to sentinel_kwargs for sentinel auth."""
        sentinel_instance, _ = self._make_sentinel_mock()
        mock_sentinel_cls.return_value = sentinel_instance

        with patch("api.core.redis_utils.settings") as mock_settings:
            mock_settings.REDIS_HOST = "sentinel1:26379,sentinel2:26379"
            mock_settings.REDIS_PASSWORD = "shared-pw"
            mock_settings.REDIS_SENTINEL_MASTER_NAME = "mymaster"

            _get_sentinel_master()

        _, kwargs = mock_sentinel_cls.call_args
        assert kwargs["sentinel_kwargs"]["password"] == "shared-pw"

    @patch("api.core.redis_utils.Sentinel")
    def test_password_passed_to_master_for(self, mock_sentinel_cls):
        """REDIS_PASSWORD is forwarded to master_for for master auth."""
        sentinel_instance, _ = self._make_sentinel_mock()
        mock_sentinel_cls.return_value = sentinel_instance

        with patch("api.core.redis_utils.settings") as mock_settings:
            mock_settings.REDIS_HOST = "sentinel1:26379"
            mock_settings.REDIS_PASSWORD = "shared-pw"
            mock_settings.REDIS_SENTINEL_MASTER_NAME = "mymaster"

            _get_sentinel_master()

        sentinel_instance.master_for.assert_called_once_with(
            "mymaster", password="shared-pw"
        )

    @patch("api.core.redis_utils.Sentinel")
    def test_no_password_when_unset(self, mock_sentinel_cls):
        """When REDIS_PASSWORD is unset, sentinel_kwargs has no password key."""
        sentinel_instance, _ = self._make_sentinel_mock()
        mock_sentinel_cls.return_value = sentinel_instance

        with patch("api.core.redis_utils.settings") as mock_settings:
            mock_settings.REDIS_HOST = "sentinel1:26379"
            mock_settings.REDIS_PASSWORD = None
            mock_settings.REDIS_SENTINEL_MASTER_NAME = "mymaster"

            _get_sentinel_master()

        _, kwargs = mock_sentinel_cls.call_args
        assert "password" not in kwargs["sentinel_kwargs"]

    @patch("api.core.redis_utils.Sentinel")
    def test_multiple_sentinel_hosts(self, mock_sentinel_cls):
        """All sentinel hosts are parsed and passed to Sentinel."""
        sentinel_instance, _ = self._make_sentinel_mock()
        mock_sentinel_cls.return_value = sentinel_instance

        with patch("api.core.redis_utils.settings") as mock_settings:
            mock_settings.REDIS_HOST = "s1:26379,s2:26379,s3:26379"
            mock_settings.REDIS_PASSWORD = "pw"
            mock_settings.REDIS_SENTINEL_MASTER_NAME = "mymaster"

            _get_sentinel_master()

        hosts, _ = mock_sentinel_cls.call_args
        assert hosts[0] == [("s1", 26379), ("s2", 26379), ("s3", 26379)]


class TestParseHostPortPairsEmptyEntry:
    def test_empty_entries_are_skipped(self):
        """Double-comma produces an empty entry that is silently skipped."""
        from api.core.redis_utils import parse_host_port_pairs

        result = parse_host_port_pairs("node1:6379,,node2:6379")
        assert result == [("node1", 6379), ("node2", 6379)]

    def test_trailing_comma_is_skipped(self):
        """Trailing comma produces an empty entry that is silently skipped."""
        from api.core.redis_utils import parse_host_port_pairs

        result = parse_host_port_pairs("node1:6379,")
        assert result == [("node1", 6379)]


class TestGetClusterClient:
    @patch("api.core.redis_utils.RedisCluster")
    @patch("api.core.redis_utils.ClusterNode")
    @patch("api.core.redis_utils.settings")
    def test_get_cluster_client_builds_correct_nodes(
        self, mock_settings, mock_cluster_node, mock_redis_cluster
    ):
        from api.core.redis_utils import _get_cluster_client

        mock_settings.REDIS_HOST = "node1:6379,node2:6380"
        mock_settings.REDIS_PASSWORD = "secret"

        mock_node1, mock_node2 = MagicMock(), MagicMock()
        mock_cluster_node.side_effect = [mock_node1, mock_node2]

        mock_client = MagicMock()
        mock_redis_cluster.return_value = mock_client

        result = _get_cluster_client()

        assert result is mock_client
        mock_redis_cluster.assert_called_once_with(
            startup_nodes=[mock_node1, mock_node2],
            password="secret",
        )


class TestGetSingleRedisClient:
    @patch("api.core.redis_utils.redis")
    @patch("api.core.redis_utils.settings")
    def test_get_single_redis_client(self, mock_settings, mock_redis):
        from api.core.redis_utils import _get_single_redis_client

        mock_settings.REDIS_MODE = "single"
        mock_settings.REDIS_HOST = "redis:6379"
        mock_settings.REDIS_PASSWORD = None
        mock_settings.REDIS_DB = 0

        mock_client = MagicMock()
        mock_redis.from_url.return_value = mock_client

        result = _get_single_redis_client()

        assert result is mock_client
        mock_redis.from_url.assert_called_once_with("redis://redis:6379/0")


def _make_wrapper(mock_client=None):
    """Return a concrete BaseRedisWrapperWithPack wired to the given mock client."""
    if mock_client is None:
        mock_client = MagicMock()

    class _Wrapper(BaseRedisWrapperWithPack):
        backend_name = "test"

        def _connect(self):
            return mock_client

    return _Wrapper("testcol", 300), mock_client


class TestBaseRedisWrapperWithPackConnect:
    def test_base_connect_raises_not_implemented(self):
        wrapper = BaseRedisWrapperWithPack("col", 60)
        with pytest.raises(NotImplementedError):
            wrapper._connect()

    def test_db_property_connects_lazily(self):
        wrapper, mock_client = _make_wrapper()
        assert wrapper._db is None
        db = wrapper.db
        assert db is mock_client
        assert wrapper._db is mock_client

    def test_db_property_caches_client(self):
        wrapper, mock_client = _make_wrapper()
        first = wrapper.db
        second = wrapper.db
        assert first is second is mock_client

    def test_db_property_caches_connection_error(self):
        class _FailingWrapper(BaseRedisWrapperWithPack):
            backend_name = "test"

            def _connect(self):
                raise ConnectionError("Redis down")

        wrapper = _FailingWrapper("col", 60)

        with pytest.raises(ConnectionError):
            _ = wrapper.db

        assert wrapper._connect_error is not None

        # Second access re-raises without calling _connect again
        with pytest.raises(ConnectionError):
            _ = wrapper.db

    @patch("api.core.redis_utils.time")
    def test_db_property_retries_after_delay_expires(self, mock_time):
        call_count = 0
        mock_client = MagicMock()

        class _FailOnceThenSucceed(BaseRedisWrapperWithPack):
            backend_name = "test"

            def _connect(self):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise ConnectionError("First attempt fails")
                return mock_client

        wrapper = _FailOnceThenSucceed("col", 60)

        mock_time.monotonic.return_value = 0.0
        with pytest.raises(ConnectionError):
            _ = wrapper.db

        # Within retry window — re-raises, no new _connect call
        mock_time.monotonic.return_value = 10.0
        with pytest.raises(ConnectionError):
            _ = wrapper.db
        assert call_count == 1

        # After retry window — clears error, retries _connect
        mock_time.monotonic.return_value = 35.0
        db = wrapper.db
        assert db is mock_client
        assert call_count == 2


class TestBaseRedisWrapperWithPackOperations:
    def test_key_builds_prefixed_key(self):
        wrapper, _ = _make_wrapper()
        assert wrapper._key("mykey") == "testcol:mykey"

    def test_setitem_stores_json_with_ttl(self):
        wrapper, mock_client = _make_wrapper()
        wrapper["mykey"] = {"data": "value"}
        mock_client.set.assert_called_once_with(
            "testcol:mykey", '{"data": "value"}', ex=300
        )

    def test_getitem_returns_parsed_value(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.get.return_value = b'{"data": "value"}'
        assert wrapper["mykey"] == {"data": "value"}
        mock_client.get.assert_called_once_with("testcol:mykey")

    def test_getitem_missing_key_raises_key_error(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.get.return_value = None
        with pytest.raises(KeyError, match="missing"):
            _ = wrapper["missing"]

    def test_delitem_calls_redis_delete(self):
        wrapper, mock_client = _make_wrapper()
        del wrapper["mykey"]
        mock_client.delete.assert_called_once_with("testcol:mykey")

    def test_contains_returns_true_for_existing_key(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.exists.return_value = 1
        assert "mykey" in wrapper
        mock_client.exists.assert_called_once_with("testcol:mykey")

    def test_contains_returns_false_for_missing_key(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.exists.return_value = 0
        assert "missing" not in wrapper

    def test_keys_strips_collection_prefix(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.scan_iter.return_value = iter([b"testcol:key1", b"testcol:key2"])
        assert list(wrapper.keys()) == ["key1", "key2"]
        mock_client.scan_iter.assert_called_once_with(match="testcol:*")

    def test_values_yields_all_values(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.scan_iter.return_value = iter([b"testcol:k1", b"testcol:k2"])
        mock_client.get.side_effect = [b'"val1"', b'"val2"']
        assert list(wrapper.values()) == ["val1", "val2"]

    def test_values_skips_expired_keys(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.scan_iter.return_value = iter([b"testcol:k1", b"testcol:k2"])
        mock_client.get.side_effect = [b'"val1"', None]  # k2 expired
        assert list(wrapper.values()) == ["val1"]

    def test_items_yields_key_value_pairs(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.scan_iter.return_value = iter([b"testcol:k1"])
        mock_client.get.return_value = b'"val1"'
        assert list(wrapper.items()) == [("k1", "val1")]

    def test_items_skips_expired_keys(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.scan_iter.return_value = iter([b"testcol:k1", b"testcol:k2"])
        mock_client.get.side_effect = [b'"val1"', None]  # k2 expired
        assert list(wrapper.items()) == [("k1", "val1")]


class TestBaseRedisWrapperWithPackPackUnpack:
    def test_pack_stores_value_and_returns_key(self):
        wrapper, mock_client = _make_wrapper()
        key = wrapper.pack({"token": "abc123"})
        assert isinstance(key, str) and len(key) > 0
        mock_client.set.assert_called_once()
        stored_key = mock_client.set.call_args[0][0]
        assert stored_key.startswith("testcol:")

    def test_unpack_retrieves_value(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.get.return_value = b'{"token": "abc123"}'
        assert wrapper.unpack("somekey") == {"token": "abc123"}

    def test_unpack_raises_key_error_for_missing(self):
        wrapper, mock_client = _make_wrapper()
        mock_client.get.return_value = None
        with pytest.raises(KeyError):
            wrapper.unpack("missing")


class TestRedisSubclasses:
    @patch("api.core.redis_utils._get_sentinel_master")
    def test_sentinel_wrapper_connect(self, mock_fn):
        from api.core.redis_utils import SentinelRedisWrapperWithPack

        mock_master = MagicMock()
        mock_fn.return_value = mock_master

        wrapper = SentinelRedisWrapperWithPack("col", 60)
        assert wrapper._connect() is mock_master
        mock_fn.assert_called_once()

    @patch("api.core.redis_utils._get_cluster_client")
    def test_cluster_wrapper_connect(self, mock_fn):
        from api.core.redis_utils import ClusterRedisWrapperWithPack

        mock_client = MagicMock()
        mock_fn.return_value = mock_client

        wrapper = ClusterRedisWrapperWithPack("col", 60)
        assert wrapper._connect() is mock_client
        mock_fn.assert_called_once()

    @patch("api.core.redis_utils._get_single_redis_client")
    def test_single_wrapper_connect(self, mock_fn):
        from api.core.redis_utils import SingleRedisWrapperWithPack

        mock_client = MagicMock()
        mock_fn.return_value = mock_client

        wrapper = SingleRedisWrapperWithPack("col", 60)
        assert wrapper._connect() is mock_client
        mock_fn.assert_called_once()


class TestExtractStorageClass:
    def test_sentinel_mode(self):
        from api.core.redis_utils import (
            extract_storage_class,
            SentinelRedisWrapperWithPack,
        )

        assert extract_storage_class("sentinel") is SentinelRedisWrapperWithPack

    def test_cluster_mode(self):
        from api.core.redis_utils import (
            extract_storage_class,
            ClusterRedisWrapperWithPack,
        )

        assert extract_storage_class("cluster") is ClusterRedisWrapperWithPack

    def test_default_falls_back_to_single(self):
        from api.core.redis_utils import (
            extract_storage_class,
            SingleRedisWrapperWithPack,
        )

        assert extract_storage_class("single") is SingleRedisWrapperWithPack
        assert extract_storage_class("none") is SingleRedisWrapperWithPack
