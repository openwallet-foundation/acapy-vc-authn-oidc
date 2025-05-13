import json
from pydantic.plugin import Any
import structlog
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Request
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..authSessions.models import AuthSession, AuthSessionPatch, AuthSessionState
from ..db.session import get_db

from ..core.config import settings
from ..core.acapy.client import AcapyClient
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
        case "present_proof_v2_0":
            webhook_body = await _parse_webhook_body(request)
            logger.info(f">>>> pres_exch_id: {webhook_body['pres_ex_id']}")
            logger.info(f">>>> web hook: {webhook_body}")
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
                    client = AcapyClient()
                    logger.debug(
                        f"rev_reg_id: {webhook_body['by_format']['pres']['indy']['identifiers'][0]['rev_reg_id']}"
                    )
                    rev = client.is_revoked(
                        webhook_body["by_format"]["pres"]["indy"]["identifiers"][0][
                            "rev_reg_id"
                        ]
                    )
                    logger.warning(f"Credential was revoked {rev}")

                    auth_session.proof_status = (
                        AuthSessionState.REVOKED if rev else AuthSessionState.FAILED
                    )
                    if sid:
                        await sio.emit(
                            "status", {"status": auth_session.proof_status}, to=sid
                        )

                await AuthSessionCRUD(db).patch(
                    str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
                )

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

            pass
        case _:
            logger.debug("skipping webhook")

    return {}
