import asyncio
import pickle
import redis.asyncio as async_redis
import redis
from redis.cluster import RedisCluster, ClusterNode
import socketio  # For using websockets
from socketio.async_pubsub_manager import AsyncPubSubManager
import logging
import structlog
from fastapi import Depends
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..db.session import get_db, client
from ..core.config import settings
from ..core.redis_utils import parse_host_port_pairs, build_redis_url

logger = structlog.getLogger(__name__)

# Valid Redis modes
VALID_REDIS_MODES = ("none", "single", "sentinel", "cluster")


class RedisErrorType:
    """Error type classification for Redis failures"""

    CONNECTION = "connection"
    CONFIGURATION = "configuration"
    OPERATION = "operation"


def _classify_redis_error(operation: str, error: Exception) -> str:
    """Classify Redis error type based on operation and error details"""
    error_str = str(error).lower()

    # Connection-related errors (potentially recoverable)
    if any(
        keyword in error_str
        for keyword in [
            "connection refused",
            "connection failed",
            "connection timeout",
            "network is unreachable",
            "no route to host",
            "connection reset",
        ]
    ):
        return RedisErrorType.CONNECTION

    # Configuration-related errors (wrong settings)
    if any(
        keyword in error_str
        for keyword in [
            "authentication failed",
            "wrong number of arguments",
            "unknown command",
            "invalid password",
            "no password is set",
        ]
    ):
        return RedisErrorType.CONFIGURATION

    # Operation-specific errors (runtime issues)
    if operation in ["Socket.IO emit", "background thread"]:
        return RedisErrorType.OPERATION

    # Default to connection error for startup operations
    return RedisErrorType.CONNECTION


def _handle_redis_failure(operation: str, error: Exception) -> str:
    """
    Handle Redis failures with classification and graceful degradation.

    Args:
        operation: Description of the operation that failed
        error: The exception that occurred

    Returns:
        Error type classification string
    """
    error_type = _classify_redis_error(operation, error)

    logger.error(f"Redis {operation} failed: {error}")
    logger.error(f"Error classified as: {error_type}")
    logger.warning(f"Redis {operation} failed, falling back to degraded mode")

    return error_type


def _should_use_redis_adapter():
    """Single check to determine if Redis adapter should be used.

    Checks REDIS_MODE to determine if Redis should be used.
    For backwards compatibility, also supports legacy USE_REDIS_ADAPTER env var
    (handled in _get_redis_mode in config.py).
    """
    mode = settings.REDIS_MODE.lower()

    if mode == "none":
        logger.info("Redis adapter disabled (REDIS_MODE=none) - using default manager")
        return False

    if mode not in VALID_REDIS_MODES:
        logger.error(
            f"Invalid REDIS_MODE: '{mode}'. Must be one of: {', '.join(VALID_REDIS_MODES)}"
        )
        return False

    if not settings.REDIS_HOST:
        logger.warning("REDIS_HOST not configured - falling back to default manager")
        return False

    # All required settings present
    return True


def _build_redis_url():
    """Build Redis connection URL from settings. Delegates to shared module."""
    return build_redis_url()


def _parse_host_port_pairs(hosts_string: str) -> list[tuple[str, int]]:
    """Parse host:port pairs. Delegates to shared module."""
    return parse_host_port_pairs(hosts_string)


class AsyncRedisClusterManager(AsyncPubSubManager):
    """Custom manager for Redis Cluster mode.

    Extends AsyncPubSubManager to use RedisCluster client for publishing
    and a single node connection for pub/sub (since cluster pub/sub messages
    are broadcast to all nodes).

    Based on python-socketio's AsyncRedisManager implementation pattern.
    """

    name = "asyncrediscluster"

    def __init__(
        self,
        startup_nodes: list[tuple[str, int]],
        password: str | None = None,
        channel: str = "socketio",
        write_only: bool = False,
        redis_options: dict | None = None,
    ):
        """Initialize Redis Cluster manager.

        Args:
            startup_nodes: List of (host, port) tuples for cluster nodes
            password: Redis password (optional)
            channel: Pub/Sub channel name (default: 'socketio')
            write_only: If True, only publish messages without subscribing
            redis_options: Additional options passed to RedisCluster client
        """
        # Store raw tuples - ClusterNode objects created when needed
        self._startup_nodes_raw = startup_nodes
        self._password = password
        self._redis_options = redis_options or {}
        self.redis = None  # Cluster client for publish
        self.pubsub_client = None  # Single node client for subscribe
        self.pubsub = None
        super().__init__(channel=channel, write_only=write_only)

    async def _publish(self, data):
        """Publish message to Redis Cluster."""
        retry = True
        while True:
            try:
                if self.redis is None:
                    from redis.asyncio.cluster import RedisCluster as AsyncRedisCluster

                    # Create cluster nodes for async client
                    startup_nodes = [
                        {"host": host, "port": port}
                        for host, port in self._startup_nodes_raw
                    ]
                    self.redis = AsyncRedisCluster(
                        startup_nodes=startup_nodes,
                        password=self._password,
                        **self._redis_options,
                    )
                return await self.redis.publish(self.channel, pickle.dumps(data))
            except Exception:
                if retry:
                    logger.warning("Redis Cluster publish failed, reconnecting...")
                    self.redis = None
                    retry = False
                else:
                    raise

    async def _listen(self):
        """Listen for messages from Redis Cluster pub/sub.

        Redis Cluster broadcasts pub/sub messages to all nodes, so we only need
        to subscribe to one node to receive all messages.
        """
        retry_sleep = 1
        while True:
            try:
                if self.pubsub_client is None:
                    # Connect to the first node for pub/sub
                    # (messages are broadcast to all nodes in cluster)
                    host, port = self._startup_nodes_raw[0]
                    self.pubsub_client = async_redis.Redis(
                        host=host,
                        port=port,
                        password=self._password,
                    )
                    self.pubsub = self.pubsub_client.pubsub()
                    await self.pubsub.subscribe(self.channel)
                    retry_sleep = 1
                    logger.info(
                        f"Redis Cluster pub/sub connected to {host}:{port}"
                    )
                async for message in self.pubsub.listen():
                    if message["type"] == "message":
                        yield message["data"]
            except Exception as e:
                logger.warning(f"Redis Cluster pub/sub error: {e}, retrying...")
                if self.pubsub:
                    try:
                        await self.pubsub.close()
                    except Exception:
                        pass
                if self.pubsub_client:
                    try:
                        await self.pubsub_client.close()
                    except Exception:
                        pass
                self.pubsub_client = None
                self.pubsub = None
                await asyncio.sleep(retry_sleep)
                retry_sleep = min(retry_sleep * 2, 60)


def can_we_reach_cluster(startup_nodes: list[tuple[str, int]]) -> bool:
    """Test Redis Cluster connectivity.

    Args:
        startup_nodes: List of (host, port) tuples

    Returns:
        bool: True if cluster is reachable, False otherwise
    """
    try:
        nodes = [ClusterNode(host, port) for host, port in startup_nodes]
        client = RedisCluster(startup_nodes=nodes, password=settings.REDIS_PASSWORD)
        client.ping()
        client.close()
        return True
    except Exception as e:
        _handle_redis_failure("cluster connectivity test", e)
        return False


def can_we_reach_sentinel(sentinel_hosts: list[tuple[str, int]], master_name: str) -> bool:
    """Test Redis Sentinel connectivity.

    Connects to the sentinel nodes and verifies we can discover and reach the master.

    Args:
        sentinel_hosts: List of (host, port) tuples for sentinel nodes
        master_name: Name of the master to discover (e.g., 'mymaster')

    Returns:
        bool: True if sentinel and master are reachable, False otherwise
    """
    try:
        from redis.sentinel import Sentinel

        # Create Sentinel connection
        sentinel_kwargs = {}
        if settings.REDIS_PASSWORD:
            sentinel_kwargs["password"] = settings.REDIS_PASSWORD

        sentinel = Sentinel(sentinel_hosts, sentinel_kwargs=sentinel_kwargs)

        # Get master from sentinel and ping it
        master = sentinel.master_for(master_name, password=settings.REDIS_PASSWORD)
        master.ping()
        master.close()

        logger.info(
            f"Successfully connected to Redis via Sentinel (master: {master_name})"
        )
        return True
    except Exception as e:
        _handle_redis_failure("sentinel connectivity test", e)
        return False


def can_we_reach_redis(redis_url):
    """
    Test if we can reach Redis right now before creating manager.

    Returns:
        bool: True if Redis is available, False if should fall back to local manager
    """
    try:
        # Use synchronous Redis client to avoid event loop conflicts
        redis_client = redis.from_url(redis_url)
        redis_client.ping()
        redis_client.close()
        return True

    except Exception as e:
        # Log the error and return False to indicate fallback should be used
        _handle_redis_failure("connectivity test before manager creation", e)
        return False


def _patch_redis_manager_for_graceful_failure(manager):
    """Patch Redis manager to handle background thread failures gracefully"""
    if manager is None:
        return

    # Store original methods
    original_thread = manager._thread
    original_redis_listen_with_retries = getattr(
        manager, "_redis_listen_with_retries", None
    )

    async def graceful_redis_failure_thread():
        """Enhanced _thread with comprehensive error handling and restart logic"""
        retry_count = 0
        max_retries = settings.REDIS_THREAD_MAX_RETRIES
        base_delay = settings.REDIS_RETRY_BASE_DELAY
        max_delay = settings.REDIS_RETRY_MAX_DELAY

        while retry_count < max_retries:
            try:
                await original_thread()
                # If we get here, the thread completed normally (shouldn't happen)
                logger.warning("Redis background thread completed unexpectedly")
                break
            except Exception as e:
                retry_count += 1
                error_type = _handle_redis_failure("background thread", e)

                if retry_count >= max_retries:
                    logger.error(
                        f"Redis background thread failed permanently after {max_retries} attempts (error type: {error_type})"
                    )
                    logger.warning("Redis manager switching to write-only mode")
                    break

                # Calculate exponential backoff delay
                delay = min(base_delay * (2 ** (retry_count - 1)), max_delay)
                logger.warning(
                    f"Redis background thread failed (attempt {retry_count}/{max_retries}, error type: {error_type}), retrying in {delay}s"
                )

                await asyncio.sleep(delay)

    async def enhanced_redis_listen_with_retries():
        """Enhanced _redis_listen_with_retries with broader exception handling"""
        if original_redis_listen_with_retries is None:
            return

        retry_sleep = settings.REDIS_RETRY_BASE_DELAY
        connect = False
        max_consecutive_failures = settings.REDIS_PUBSUB_MAX_FAILURES
        consecutive_failures = 0

        while consecutive_failures < max_consecutive_failures:
            try:
                if connect:
                    manager._redis_connect()
                    await manager.pubsub.subscribe(manager.channel)
                    retry_sleep = 1
                    consecutive_failures = 0  # Reset on successful connection

                async for message in manager.pubsub.listen():
                    yield message

            except Exception as e:  # Catch all exceptions for robust error handling
                consecutive_failures += 1
                error_type = _handle_redis_failure("Redis pubsub listen", e)

                if consecutive_failures >= max_consecutive_failures:
                    logger.error(
                        f"Redis pubsub failed {consecutive_failures} consecutive times, giving up"
                    )
                    break

                logger.warning(
                    f"Redis pubsub error (type: {error_type}, failure {consecutive_failures}/{max_consecutive_failures}), retrying in {retry_sleep}s"
                )
                connect = True
                await asyncio.sleep(retry_sleep)
                retry_sleep = min(retry_sleep * 2, settings.REDIS_RETRY_MAX_DELAY)

    # Replace the background thread method
    manager._thread = graceful_redis_failure_thread

    # Also patch the _redis_listen_with_retries method if it exists
    if original_redis_listen_with_retries:
        manager._redis_listen_with_retries = enhanced_redis_listen_with_retries


def create_socket_manager():
    """Create Socket.IO manager with Redis adapter based on REDIS_MODE.

    Supports three Redis deployment modes:
    - single: Standard single Redis instance
    - sentinel: Redis Sentinel for high availability
    - cluster: Redis Cluster for horizontal scaling

    Returns:
        socketio.AsyncRedisManager | AsyncRedisClusterManager | None:
            Redis manager if configured and reachable, None otherwise
    """
    if not _should_use_redis_adapter():
        logger.info("Redis adapter disabled - using default Socket.IO manager")
        return None

    mode = settings.REDIS_MODE.lower()

    try:
        if mode == "single":
            # Single mode uses standard URL-based AsyncRedisManager
            redis_url = _build_redis_url()

            # Test Redis connectivity BEFORE creating manager
            redis_available = can_we_reach_redis(redis_url)
            if not redis_available:
                logger.warning(
                    f"Redis connectivity test failed (mode={mode}) - falling back to default Socket.IO manager"
                )
                return None

            manager = socketio.AsyncRedisManager(redis_url)
            _patch_redis_manager_for_graceful_failure(manager)

            logger.info(
                f"Redis adapter configured: {settings.REDIS_HOST}:{settings.REDIS_PORT}"
            )
            return manager

        elif mode == "sentinel":
            # Sentinel mode: test connectivity via Sentinel client first
            sentinel_hosts = _parse_host_port_pairs(settings.REDIS_HOST)

            sentinel_available = can_we_reach_sentinel(
                sentinel_hosts, settings.REDIS_SENTINEL_MASTER_NAME
            )
            if not sentinel_available:
                logger.warning(
                    "Redis Sentinel connectivity test failed - falling back to default Socket.IO manager"
                )
                return None

            # Build sentinel URL for python-socketio's AsyncRedisManager
            redis_url = _build_redis_url()
            manager = socketio.AsyncRedisManager(redis_url)
            _patch_redis_manager_for_graceful_failure(manager)

            logger.info(
                f"Redis Sentinel adapter configured: {settings.REDIS_HOST} (master: {settings.REDIS_SENTINEL_MASTER_NAME})"
            )
            return manager

        elif mode == "cluster":
            # Cluster mode uses custom AsyncRedisClusterManager
            startup_nodes = _parse_host_port_pairs(settings.REDIS_HOST)

            # Test cluster connectivity BEFORE creating manager
            cluster_available = can_we_reach_cluster(startup_nodes)
            if not cluster_available:
                logger.warning(
                    "Redis Cluster connectivity test failed - falling back to default Socket.IO manager"
                )
                return None

            manager = AsyncRedisClusterManager(
                startup_nodes=startup_nodes,
                password=settings.REDIS_PASSWORD,
            )
            # Note: Cluster manager has its own retry logic built-in

            logger.info(f"Redis Cluster adapter configured: {settings.REDIS_HOST}")
            return manager

        else:
            logger.error(
                f"Invalid REDIS_MODE: '{mode}'. Must be one of: {', '.join(VALID_REDIS_MODES)}"
            )
            return None

    except Exception as e:
        # Handle any unexpected errors gracefully
        error_type = _handle_redis_failure("adapter initialization", e)
        logger.warning(
            f"Unexpected error during Redis adapter initialization (type: {error_type}): {e}"
        )
        logger.info("Falling back to default Socket.IO manager")
        return None


async def safe_emit(event, data=None, **kwargs):
    """
    Safely emit to Socket.IO with graceful Redis failure handling.

    When USE_REDIS_ADAPTER=true, Redis failures are logged but don't crash the application.
    When USE_REDIS_ADAPTER=false, Redis is not used and this function simply calls sio.emit.
    """
    try:
        await sio.emit(event, data, **kwargs)
    except Exception as e:
        if settings.USE_REDIS_ADAPTER:
            # Log the error but continue gracefully - don't crash the application
            error_type = _handle_redis_failure("Socket.IO emit", e)
            logger.warning(f"Socket.IO emit failed (type: {error_type}): {e}")
            logger.info(
                "Continuing without real-time Socket.IO communication for this event"
            )
        else:
            logger.warning(f"Socket.IO emit failed, continuing gracefully: {e}")
            # Continue without Redis when adapter is disabled


# Create Socket.IO server with Redis adapter
sio = socketio.AsyncServer(
    async_mode="asgi", cors_allowed_origins="*", client_manager=create_socket_manager()
)

sio_app = socketio.ASGIApp(socketio_server=sio, socketio_path="/ws/socket.io")


def get_db_for_socketio():
    """
    Get a database connection for use in Socket.IO event handlers.

    FastAPI's dependency injection system (e.g., the get_db() dependency) is not available
    inside Socket.IO event handlers because these handlers are not managed by FastAPI's
    request/response lifecycle. As a result, dependencies like get_db() cannot be injected
    in the usual way.

    Use this function to obtain a database connection when handling Socket.IO events.
    In all other FastAPI routes or dependencies, prefer using the standard get_db() dependency.
    """
    return client[settings.DB_NAME]


@sio.event
async def connect(sid, socket):
    logger.info(f">>> connect : sid={sid}")


@sio.event
async def initialize(sid, data):
    # Store websocket session ID in the AuthSession
    db = get_db_for_socketio()
    pid = data.get("pid")
    if pid:
        try:
            # Update only the socket_id field for efficiency
            await AuthSessionCRUD(db).update_socket_id(pid, sid)
            logger.debug(f"Stored socket_id {sid} for pid {pid}")
        except Exception as e:
            logger.error(f"Failed to store socket_id for pid {pid}: {e}")


@sio.event
async def disconnect(sid):
    logger.info(f">>> disconnect : sid={sid}")
    # Clear socket_id from AuthSession
    db = get_db_for_socketio()
    try:
        auth_session = await AuthSessionCRUD(db).get_by_socket_id(sid)
        if auth_session:
            # Clear only the socket_id field for efficiency
            await AuthSessionCRUD(db).update_socket_id(str(auth_session.id), None)
            logger.debug(f"Cleared socket_id {sid} for pid {auth_session.id}")
    except Exception as e:
        logger.error(f"Failed to clear socket_id {sid}: {e}")


async def get_socket_id_for_pid(pid: str, db: Database) -> str | None:
    """Get current socket ID for presentation ID"""
    try:
        auth_session = await AuthSessionCRUD(db).get(pid)
        return auth_session.socket_id
    except Exception as e:
        logger.error(f"Failed to get socket_id for pid {pid}: {e}")
        return None
