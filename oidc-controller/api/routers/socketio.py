import socketio  # For using websockets
import logging
import structlog
from fastapi import Depends
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..db.session import get_db, client
from ..core.config import settings

logger = structlog.getLogger(__name__)


def create_socket_manager():
    """Create Socket.IO manager with Redis adapter if configured"""
    if not settings.USE_REDIS_ADAPTER:
        logger.info("Redis adapter disabled - using default manager")
        return None

    if not settings.REDIS_HOST:
        logger.warning("REDIS_HOST not configured - falling back to default manager")
        return None

    try:
        # Build Redis URL
        redis_url = f"redis://:{settings.REDIS_PASSWORD}@{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"
        if not settings.REDIS_PASSWORD:
            redis_url = f"redis://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}"

        manager = socketio.AsyncRedisManager(redis_url)
        logger.info(
            f"Redis adapter configured: {settings.REDIS_HOST}:{settings.REDIS_PORT}"
        )
        return manager
    except Exception as e:
        logger.error(f"Failed to initialize Redis adapter: {e}")
        logger.warning(
            "Falling back to default manager - cross-pod communication disabled"
        )
        return None


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
