import json
from pydantic.plugin import Any
import structlog
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..authSessions.models import AuthSession, AuthSessionPatch, AuthSessionState
from ..db.session import get_db
from ..core.acapy.client import AcapyClient
from ..verificationConfigs.crud import VerificationConfigCRUD

from ..core.config import settings
from ..routers.socketio import sio, connections_reload

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

router = APIRouter()


async def _parse_webhook_body(request: Request) -> dict[Any, Any]:
    return json.loads((await request.body()).decode("ascii"))


@router.post("/topic/{topic}/")
async def post_topic(request: Request, topic: str, db: Database = Depends(get_db)):
    """Called by aca-py agent."""
    logger.info(f">>> post_topic : topic={topic}")
    logger.info(f">>> web hook post_body : {await _parse_webhook_body(request)}")

    match topic:
        case "connections":
            if settings.USE_CONNECTION_BASED_VERIFICATION:
                webhook_body = await _parse_webhook_body(request)
                logger.info(f">>>> connection_id: {webhook_body.get('connection_id')}")
                logger.info(f">>>> connection state: {webhook_body.get('state')}")

                # Log request state for debugging but don't act on it yet
                if webhook_body.get("state") == "request":
                    logger.info(
                        f"Connection {webhook_body.get('connection_id')} is in request state, waiting for active/completed"
                    )

                if webhook_body.get("state") in ["active", "completed"]:
                    # NEW: Connection established, now send presentation request
                    connection_id = webhook_body.get("connection_id")
                    invitation_msg_id = webhook_body.get("invitation_msg_id")

                    logger.info(f"Full webhook body: {webhook_body}")
                    logger.info(f"Available keys: {list(webhook_body.keys())}")

                    # Try multiple possible fields for invitation message ID
                    search_id = (
                        invitation_msg_id
                        or webhook_body.get("invi_msg_id")
                        or webhook_body.get("invitation_id")
                    )

                    # Find the auth session by invitation message ID (stored as connection_id initially)
                    logger.info(f"Looking for auth session with search_id: {search_id}")
                    auth_session = await AuthSessionCRUD(db).get_by_connection_id(
                        search_id
                    )

                    # If not found by invitation message ID, try by connection_id directly
                    if not auth_session and connection_id:
                        logger.info(
                            f"Trying to find auth session by connection_id: {connection_id}"
                        )
                        auth_session = await AuthSessionCRUD(db).get_by_connection_id(
                            connection_id
                        )

                    # If still not found, try searching by pres_exch_id pattern
                    if not auth_session and search_id:
                        logger.info(
                            f"Trying to find auth session by pres_exch_id pattern: pending-{search_id}"
                        )
                        try:
                            auth_session = await AuthSessionCRUD(
                                db
                            ).get_by_pres_exch_id(f"pending-{search_id}")
                        except:
                            pass  # This lookup might fail if the pattern doesn't match

                    if auth_session:
                        logger.info(f"Found auth session: {auth_session.id}")
                        logger.info(
                            f"Auth session has proof_request: {auth_session.proof_request is not None}"
                        )

                        if auth_session.proof_request:
                            logger.info(
                                f"Sending presentation request to connection {connection_id}"
                            )

                            # Send presentation request to the established connection
                            client = AcapyClient()
                            try:
                                pres_response = client.send_presentation_request_by_connection(
                                    connection_id=connection_id,
                                    presentation_request_configuration=auth_session.proof_request,
                                )

                                # Update auth session with presentation exchange details and real connection ID
                                auth_session.pres_exch_id = pres_response.pres_ex_id
                                auth_session.presentation_exchange = (
                                    pres_response.model_dump()
                                )
                                auth_session.connection_id = (
                                    connection_id  # Update with real connection ID
                                )
                                await AuthSessionCRUD(db).patch(
                                    str(auth_session.id),
                                    AuthSessionPatch(**auth_session.model_dump()),
                                )

                                logger.info(
                                    f"Presentation request sent successfully: {pres_response.pres_ex_id}"
                                )
                            except Exception as e:
                                logger.error(
                                    f"Failed to send presentation request: {e}"
                                )
                                # Could set auth session to failed state here
                        else:
                            logger.warning(
                                f"Auth session found but no proof_request: {auth_session.id}"
                            )
                    else:
                        logger.warning(
                            f"No auth session found for invitation_msg_id: {invitation_msg_id}"
                        )

        case "present_proof_v2_0":
            webhook_body = await _parse_webhook_body(request)
            logger.info(f">>>> pres_exch_id: {webhook_body['pres_ex_id']}")
            # logger.info(f">>>> web hook: {webhook_body}")
            auth_session: AuthSession = await AuthSessionCRUD(db).get_by_pres_exch_id(
                webhook_body["pres_ex_id"]
            )

            # Get the saved websocket session
            pid = str(auth_session.id)
            connections = connections_reload()
            sid = connections.get(pid)
            logger.debug(f"sid: {sid} found for pid: {pid}")

            if webhook_body["state"] == "presentation-received":
                logger.info("presentation-received")

            if webhook_body["state"] == "done":
                logger.info("VERIFIED")
                if webhook_body["verified"] == "true":
                    auth_session.proof_status = AuthSessionState.VERIFIED
                    auth_session.presentation_exchange = webhook_body["by_format"]
                    if sid:
                        await sio.emit("status", {"status": "verified"}, to=sid)
                else:
                    auth_session.proof_status = AuthSessionState.FAILED
                    if sid:
                        await sio.emit("status", {"status": "failed"}, to=sid)

                await AuthSessionCRUD(db).patch(
                    str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
                )

                # Cleanup connection after verification is complete (for connection-based flow)
                if settings.USE_CONNECTION_BASED_VERIFICATION and auth_session.connection_id:
                    try:
                        client = AcapyClient()
                        success = client.delete_connection(auth_session.connection_id)
                        if success:
                            logger.info(f"Cleaned up connection {auth_session.connection_id} after verification")
                        else:
                            logger.warning(f"Failed to cleanup connection {auth_session.connection_id}")
                    except Exception as e:
                        logger.error(f"Error cleaning up connection {auth_session.connection_id}: {e}")

            # abandoned state
            if webhook_body["state"] == "abandoned":
                logger.info("ABANDONED")
                logger.info(webhook_body["error_msg"])
                auth_session.proof_status = AuthSessionState.ABANDONED
                if sid:
                    await sio.emit("status", {"status": "abandoned"}, to=sid)

                await AuthSessionCRUD(db).patch(
                    str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
                )

                # Cleanup connection after verification is abandoned (for connection-based flow)
                if settings.USE_CONNECTION_BASED_VERIFICATION and auth_session.connection_id:
                    try:
                        client = AcapyClient()
                        success = client.delete_connection(auth_session.connection_id)
                        if success:
                            logger.info(f"Cleaned up connection {auth_session.connection_id} after abandonment")
                        else:
                            logger.warning(f"Failed to cleanup connection {auth_session.connection_id}")
                    except Exception as e:
                        logger.error(f"Error cleaning up connection {auth_session.connection_id}: {e}")

            # Calcuate the expiration time of the proof
            now_time = datetime.now()
            expired_time = now_time + timedelta(
                seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME
            )

            # Update the expiration time of the proof
            auth_session.expired_timestamp = expired_time
            await AuthSessionCRUD(db).patch(
                str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
            )

            # Check if expired. But only if the proof has not been started.
            if (
                expired_time < now_time
                and auth_session.proof_status == AuthSessionState.NOT_STARTED
            ):
                logger.info("EXPIRED")
                auth_session.proof_status = AuthSessionState.EXPIRED
                if sid:
                    await sio.emit("status", {"status": "expired"}, to=sid)

                await AuthSessionCRUD(db).patch(
                    str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
                )

                # Cleanup connection after verification expires (for connection-based flow)
                if settings.USE_CONNECTION_BASED_VERIFICATION and auth_session.connection_id:
                    try:
                        client = AcapyClient()
                        success = client.delete_connection(auth_session.connection_id)
                        if success:
                            logger.info(f"Cleaned up connection {auth_session.connection_id} after expiration")
                        else:
                            logger.warning(f"Failed to cleanup connection {auth_session.connection_id}")
                    except Exception as e:
                        logger.error(f"Error cleaning up connection {auth_session.connection_id}: {e}")

            pass
        case _:
            logger.debug("skipping webhook")

    return {}
