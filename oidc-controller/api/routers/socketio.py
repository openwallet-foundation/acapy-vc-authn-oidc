import socketio  # For using websockets
import logging
from fastapi import Depends
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..authSessions.models import AuthSessionPatch
from ..db.session import get_db

logger = logging.getLogger(__name__)

sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")

sio_app = socketio.ASGIApp(socketio_server=sio, socketio_path="/ws/socket.io")


@sio.event
async def connect(sid, socket):
    logger.info(f">>> connect : sid={sid}")


@sio.event
async def initialize(sid, data):
    # Store websocket session ID in the AuthSession
    db = await get_db()
    pid = data.get("pid")
    if pid:
        try:
            auth_session = await AuthSessionCRUD(db).get(pid)
            patch_data = auth_session.model_dump()
            patch_data["socket_id"] = sid
            patch = AuthSessionPatch(**patch_data)
            await AuthSessionCRUD(db).patch(pid, patch)
            logger.debug(f"Stored socket_id {sid} for pid {pid}")
        except Exception as e:
            logger.error(f"Failed to store socket_id for pid {pid}: {e}")


@sio.event
async def disconnect(sid):
    logger.info(f">>> disconnect : sid={sid}")
    # Clear socket_id from AuthSession
    db = await get_db()
    try:
        auth_session = await AuthSessionCRUD(db).get_by_socket_id(sid)
        if auth_session:
            patch_data = auth_session.model_dump()
            patch_data["socket_id"] = None
            patch = AuthSessionPatch(**patch_data)
            await AuthSessionCRUD(db).patch(str(auth_session.id), patch)
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
