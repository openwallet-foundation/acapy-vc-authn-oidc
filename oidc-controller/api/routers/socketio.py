import asyncio
import redis.asyncio as async_redis
import redis
import socketio  # For using websockets
import logging
import structlog
from fastapi import Depends
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..db.session import get_db, client
from ..core.config import settings

logger = structlog.getLogger(__name__)


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
    """Single check to determine if Redis adapter should be used"""
    if not settings.USE_REDIS_ADAPTER:
        logger.info("Redis adapter disabled - using default manager")
        return False

    if not settings.REDIS_HOST:
        logger.warning("REDIS_HOST not configured - falling back to default manager")
        return False

    # All required settings present
    return True


def _build_redis_url():
    """Build Redis connection URL from settings"""
    if settings.REDIS_PASSWORD:
        return f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
    else:
        return (
            f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
        )


def _validate_redis_before_manager_creation(redis_url):
    """
    Synchronously validate Redis connection before creating AsyncRedisManager.

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
        _handle_redis_failure("validation before manager creation", e)
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
    """Create Socket.IO manager with Redis adapter if configured"""
    if not _should_use_redis_adapter():
        logger.info("Redis adapter disabled - using default Socket.IO manager")
        return None

    try:
        # Build Redis URL
        redis_url = _build_redis_url()

        # Part 1: Validate Redis connectivity BEFORE creating manager
        # This prevents background threads from starting with bad Redis config
        redis_available = _validate_redis_before_manager_creation(redis_url)

        if not redis_available:
            logger.warning(
                "Redis validation failed - falling back to default Socket.IO manager"
            )
            return None

        # Create manager only if Redis validation passed
        manager = socketio.AsyncRedisManager(redis_url)

        # Part 2: Patch manager for graceful error handling
        # This ensures background thread failures are handled gracefully
        _patch_redis_manager_for_graceful_failure(manager)

        logger.info(
            f"Redis adapter configured: {settings.REDIS_HOST}:{settings.REDIS_PORT}"
        )
        return manager

    except Exception as e:
        # Handle any unexpected errors gracefully
        error_type = _handle_redis_failure("adapter initialization", e)
        logger.warning(
            f"Unexpected error during Redis adapter initialization (type: {error_type}): {e}"
        )
        logger.info("Falling back to default Socket.IO manager")
        return None


async def validate_redis_connection():
    """
    Validate Redis connection when Redis adapter is enabled.

    Returns:
        bool: True if Redis is available or not required, False if Redis should be available but failed
    """
    if not settings.USE_REDIS_ADAPTER:
        logger.debug("Redis adapter disabled - skipping validation")
        return True

    try:
        # Build Redis URL
        redis_url = _build_redis_url()

        # Test Redis connection
        redis_client = async_redis.from_url(redis_url)
        await redis_client.ping()
        await redis_client.close()
        logger.info("Redis connection validated successfully")
        return True

    except Exception as e:
        # Log the error but don't crash the application during startup
        error_type = _handle_redis_failure("connection validation", e)
        logger.warning(
            f"Redis connection validation failed (type: {error_type}) - application will continue with degraded Socket.IO functionality"
        )
        return False


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
