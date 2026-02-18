"""Shared Redis utilities for connection management across modules.

Used by:
- api/routers/socketio.py (Socket.IO Redis adapter)
- api/core/oidc/provider.py (PyOP token storage)
- api/main.py (startup health checks)
"""

import json
import secrets
import time

import redis
import structlog
from redis.cluster import RedisCluster, ClusterNode
from redis.sentinel import Sentinel

from api.core.config import settings

logger = structlog.getLogger(__name__)


def parse_host_port_pairs(hosts_string: str) -> list[tuple[str, int]]:
    """Parse 'host1:port1,host2:port2' into list of (host, port) tuples.

    Filters out empty entries (e.g., from "host1:6379,,host2:6379").

    Args:
        hosts_string: Comma-separated host:port pairs

    Returns:
        List of (host, port) tuples
    """
    nodes = []
    for node in hosts_string.split(","):
        node = node.strip()
        if not node:
            continue
        host, port = node.rsplit(":", 1)
        nodes.append((host, int(port)))
    return nodes


def build_redis_url() -> str | None:
    """Build Redis connection URL from settings based on REDIS_MODE.

    REDIS_HOST is always in host:port format (validated at startup).

    Returns:
        str | None: Redis URL for single/sentinel modes, None for cluster mode
                    (cluster uses parse_host_port_pairs directly)

    URL Formats:
        - single: redis://[:password@]host:port/db
        - sentinel: redis+sentinel://[:password@]host1:port1,host2:port2/db/master_name
        - cluster: Returns None (uses parse_host_port_pairs instead)

    Note: python-socketio's parse_redis_sentinel_url expects /db/service_name order,
    not /service_name/db. See socketio/redis_manager.py:parse_redis_sentinel_url.
    """
    mode = settings.REDIS_MODE.lower()

    if mode == "single":
        # REDIS_HOST is already host:port after validation
        host_port = settings.REDIS_HOST
        if settings.REDIS_PASSWORD:
            return f"redis://:{settings.REDIS_PASSWORD}@{host_port}/{settings.REDIS_DB}"
        return f"redis://{host_port}/{settings.REDIS_DB}"

    elif mode == "sentinel":
        nodes = settings.REDIS_HOST
        master = settings.REDIS_SENTINEL_MASTER_NAME
        # python-socketio expects /db/service_name (not /service_name/db)
        if settings.REDIS_PASSWORD:
            return f"redis+sentinel://:{settings.REDIS_PASSWORD}@{nodes}/{settings.REDIS_DB}/{master}"
        return f"redis+sentinel://{nodes}/{settings.REDIS_DB}/{master}"

    # Cluster and other modes don't use URL format
    return None


# --- Redis client helpers ---


def _get_sentinel_master():
    """Get a Redis master connection via Sentinel."""
    sentinel_hosts = parse_host_port_pairs(settings.REDIS_HOST)

    sentinel_kwargs = {}
    if settings.REDIS_PASSWORD:
        sentinel_kwargs["password"] = settings.REDIS_PASSWORD

    sentinel = Sentinel(sentinel_hosts, sentinel_kwargs=sentinel_kwargs)
    return sentinel.master_for(
        settings.REDIS_SENTINEL_MASTER_NAME, password=settings.REDIS_PASSWORD
    )


def _get_cluster_client():
    """Get a Redis Cluster client."""
    hosts = parse_host_port_pairs(settings.REDIS_HOST)
    startup_nodes = [ClusterNode(host, port) for host, port in hosts]

    return RedisCluster(
        startup_nodes=startup_nodes,
        password=settings.REDIS_PASSWORD,
    )


def _get_single_redis_client():
    """Get a single Redis client connection."""
    redis_url = build_redis_url()
    return redis.from_url(redis_url)


# --- Redis storage wrappers for PyOP ---


class BaseRedisWrapperWithPack:
    """
    Base class for Redis storage wrappers with pack/unpack support.

    Provides a dict-like interface for storing JSON-serializable values in Redis
    with automatic TTL. Subclasses implement `_connect()` to return the
    appropriate Redis client (Sentinel master, Cluster, etc.).

    Works with PyOP's storage interface for authorization codes, tokens, etc.
    """

    # Override in subclass for logging (e.g., "sentinel", "cluster")
    backend_name: str = "redis"

    # How long (seconds) to wait before retrying after a failed connection.
    # Prevents hammering an unavailable Redis on every request.
    _connect_retry_delay: int = 30

    def __init__(self, collection: str, ttl: int):
        """Initialize Redis storage.

        Args:
            collection: Key prefix/namespace for this storage
            ttl: Time to live in seconds for stored values
        """
        self._collection = collection
        self.ttl = ttl
        self._db = None
        self._connect_error: Exception | None = None
        self._connect_error_time: float = 0.0

    def _connect(self):
        """Create and return a Redis client. Override in subclass."""
        raise NotImplementedError("Subclasses must implement _connect()")

    @property
    def db(self):
        """Return Redis client, initializing lazily on first use.

        Connection errors are cached for _connect_retry_delay seconds to avoid
        hammering an unavailable Redis on every request. After the delay the
        next access will attempt to reconnect.
        """
        if self._db is None:
            # Re-raise a cached connection error until the retry window expires
            if self._connect_error is not None:
                if time.monotonic() - self._connect_error_time < self._connect_retry_delay:
                    raise self._connect_error
                # Retry delay elapsed — clear the error and try again
                self._connect_error = None

            try:
                self._db = self._connect()
            except Exception as e:
                self._connect_error = e
                self._connect_error_time = time.monotonic()
                logger.error(
                    f"Redis {self.backend_name} connection failed",
                    error=str(e),
                    collection=self._collection,
                    retry_in_seconds=self._connect_retry_delay,
                )
                raise
        return self._db

    def _key(self, key: str) -> str:
        """Build full Redis key with collection prefix."""
        return f"{self._collection}:{key}"

    def __setitem__(self, key, value):
        """Store a value in Redis with TTL."""
        full_key = self._key(key)
        self.db.set(full_key, json.dumps(value), ex=self.ttl)

    def __getitem__(self, key):
        """Retrieve a value from Redis."""
        full_key = self._key(key)
        value = self.db.get(full_key)
        if value is None:
            raise KeyError(key)
        return json.loads(value)

    def __delitem__(self, key):
        """Delete a value from Redis."""
        full_key = self._key(key)
        self.db.delete(full_key)

    def __contains__(self, key):
        """Check if a key exists in Redis."""
        full_key = self._key(key)
        return self.db.exists(full_key) > 0

    def keys(self):
        """Return all keys in this collection."""
        pattern = f"{self._collection}:*"
        prefix_len = len(self._collection) + 1  # +1 for the colon
        for full_key in self.db.scan_iter(match=pattern):
            # Decode bytes to string if needed
            if isinstance(full_key, bytes):
                full_key = full_key.decode("utf-8")
            # Strip the collection prefix to get the original key
            yield full_key[prefix_len:]

    def values(self):
        """Return all values in this collection."""
        for key in self.keys():
            try:
                yield self[key]
            except KeyError:
                # Key may have expired between scan and get
                continue

    def items(self):
        """Return all (key, value) pairs in this collection."""
        for key in self.keys():
            try:
                yield key, self[key]
            except KeyError:
                # Key may have expired between scan and get
                continue

    def pack(self, value):
        """
        Generate a random key, store the value in Redis, and return the key.

        This enables multi-pod deployments - the value is stored in Redis
        where all pods can access it.
        """
        key = secrets.token_urlsafe(32)
        self[key] = value
        logger.debug(
            f"Stored value in Redis ({self.backend_name})",
            operation="pack",
            collection=self._collection,
            key_prefix=key[:8],
            ttl=self.ttl,
        )
        return key

    def unpack(self, key):
        """
        Retrieve and return the value for the given key from Redis.

        Raises KeyError if the key doesn't exist in Redis.
        """
        try:
            value = self[key]
            logger.debug(
                f"Retrieved value from Redis ({self.backend_name})",
                operation="unpack",
                collection=self._collection,
                key_prefix=key[:8],
            )
            return value
        except KeyError:
            logger.warning(
                f"Key not found in Redis ({self.backend_name})",
                operation="unpack",
                collection=self._collection,
                key_prefix=key[:8],
            )
            raise


class SentinelRedisWrapperWithPack(BaseRedisWrapperWithPack):
    """Redis storage wrapper using Sentinel for high availability."""

    backend_name = "sentinel"

    def _connect(self):
        return _get_sentinel_master()


class ClusterRedisWrapperWithPack(BaseRedisWrapperWithPack):
    """Redis storage wrapper using Redis Cluster for horizontal scaling."""

    backend_name = "cluster"

    def _connect(self):
        return _get_cluster_client()


class SingleRedisWrapperWithPack(BaseRedisWrapperWithPack):
    """Redis storage wrapper using a single Redis instance."""

    backend_name = "single"

    def _connect(self):
        return _get_single_redis_client()


def extract_storage_class(redis_mode: str) -> type[BaseRedisWrapperWithPack]:
    match redis_mode:
        case "sentinel":
            return SentinelRedisWrapperWithPack
        case "cluster":
            return ClusterRedisWrapperWithPack
        case _:
            return SingleRedisWrapperWithPack
