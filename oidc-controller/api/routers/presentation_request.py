import structlog

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Template
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..authSessions.models import AuthSession, AuthSessionState

from ..core.config import settings
from ..routers.socketio import get_socket_id_for_pid, safe_emit
from ..routers.oidc import gen_deep_link
from ..db.session import get_db

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

router = APIRouter()


async def toggle_pending(db, auth_session: AuthSession):
    # We need to set this to pending now
    auth_session.proof_status = AuthSessionState.PENDING
    await AuthSessionCRUD(db).patch(auth_session.id, auth_session)
    sid = await get_socket_id_for_pid(str(auth_session.id), db)
    if sid:
        await safe_emit("status", {"status": "pending"}, to=sid)


@router.get("/url/pres_exch/{pres_exch_id}")
async def send_connectionless_proof_req(
    pres_exch_id: str, req: Request, db: Database = Depends(get_db)
):
    """
    If the user scanes the QR code with a mobile camera,
    they will be redirected to a help page.
    """
    # First prepare the response depending on the redirect url
    if ".html" in settings.CONTROLLER_CAMERA_REDIRECT_URL:
        response = RedirectResponse(settings.CONTROLLER_CAMERA_REDIRECT_URL)
    else:
        template_file = open(
            f"{settings.CONTROLLER_TEMPLATE_DIR}/{settings.CONTROLLER_CAMERA_REDIRECT_URL}.html",
            "r",
        ).read()

        auth_session: AuthSession = await AuthSessionCRUD(db).get_by_pres_exch_id(
            pres_exch_id
        )
        wallet_deep_link = gen_deep_link(auth_session)
        template = Template(template_file)

        # If the qrcode was scanned by mobile phone camera toggle the pending flag
        await toggle_pending(db, auth_session)
        response = HTMLResponse(template.render({"wallet_deep_link": wallet_deep_link}))

    if "text/html" in req.headers.get("accept"):
        logger.info("Redirecting to instructions page")
        return response

    auth_session: AuthSession = await AuthSessionCRUD(db).get_by_pres_exch_id(
        pres_exch_id
    )

    # Get the websocket session
    sid = await get_socket_id_for_pid(str(auth_session.id), db)

    # If the qrcode has been scanned, toggle the pending flag
    if auth_session.proof_status is AuthSessionState.NOT_STARTED:
        await toggle_pending(db, auth_session)

    msg = auth_session.presentation_request_msg

    logger.debug(msg)
    return JSONResponse(msg)
