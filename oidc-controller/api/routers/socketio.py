import sys
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


class RedisCriticalError(Exception):
    """Critical Redis error that should terminate the application immediately"""

    pass


def _handle_redis_error(operation: str, error: Exception) -> None:
    """Common error handling for Redis failures"""
    logger.error(f"Redis {operation} failed: {error}")
    logger.error("USE_REDIS_ADAPTER=true but Redis failed. Crashing application.")
    raise RedisCriticalError(f"Redis {operation} failed: {error}") from error


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
    """Synchronously validate Redis connection before creating AsyncRedisManager"""
    try:
        # Use synchronous Redis client to avoid event loop conflicts
        redis_client = redis.from_url(redis_url)
        redis_client.ping()
        redis_client.close()

    except Exception as e:
        try:
            _handle_redis_error("validation before manager creation", e)
        except:
            # If exception handling fails during import, force immediate exit
            sys.exit(1)


def _patch_redis_manager_for_crash_on_failure(manager):
    """Patch Redis manager to crash app if background thread fails"""
    if manager is None:
        return

    # Store original _thread method
    original_thread = manager._thread

    async def crash_on_redis_failure_thread():
        try:
            await original_thread()
        except Exception as e:
            logger.error(f"Redis background thread failed: {e}")
            logger.error(
                "USE_REDIS_ADAPTER=true but Redis background thread failed. Crashing application."
            )
            sys.exit(1)  # Immediate process termination

    # Replace the background thread method
    manager._thread = crash_on_redis_failure_thread


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
        _validate_redis_before_manager_creation(redis_url)

        # Create manager only if Redis validation passed
        manager = socketio.AsyncRedisManager(redis_url)

        # Part 2: Patch manager for runtime protection
        # This ensures background thread failures crash the app
        _patch_redis_manager_for_crash_on_failure(manager)

        logger.info(
            f"Redis adapter configured: {settings.REDIS_HOST}:{settings.REDIS_PORT}"
        )
        return manager

    except RedisCriticalError:
        # Re-raise our custom exceptions as-is
        raise
    except Exception as e:
        # Convert any other exceptions to RedisCriticalError
        _handle_redis_error("adapter initialization", e)


async def validate_redis_connection():
    """Validate Redis connection when Redis adapter is enabled"""
    if not settings.USE_REDIS_ADAPTER:
        return

    try:
        # Build Redis URL
        redis_url = _build_redis_url()

        # Test Redis connection
        redis_client = async_redis.from_url(redis_url)
        await redis_client.ping()
        await redis_client.close()
        logger.info("Redis connection validated successfully")

    except Exception as e:
        _handle_redis_error("connection validation", e)


async def safe_emit(event, data=None, **kwargs):
    """
    Safely emit to Socket.IO with Redis failure handling.

    When USE_REDIS_ADAPTER=true, Redis is always required and any failure will crash the application.
    When USE_REDIS_ADAPTER=false, Redis is not used and this function simply calls sio.emit.
    """
    try:
        await sio.emit(event, data, **kwargs)
    except Exception as e:
        if settings.USE_REDIS_ADAPTER:
            _handle_redis_error("Socket.IO emit", e)
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
