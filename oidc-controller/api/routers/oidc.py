import base64
import io
import json
import uuid
from datetime import datetime, UTC
from typing import cast
from urllib.parse import urlencode

import qrcode
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi import status as http_status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Template
from oic.oic.message import AuthorizationRequest
from pymongo.database import Database
from pyop.exceptions import InvalidAuthenticationRequest

from ..authSessions.crud import AuthSessionCreate, AuthSessionCRUD
from ..authSessions.models import AuthSessionPatch, AuthSessionState, AuthSession
from ..core.acapy.client import AcapyClient
from ..core.acapy import (
    PresentationRequestMessage,
    PresentProofv20Attachment,
    ServiceDecorator,
)
from ..core.config import settings
from ..core.logger_util import log_debug
from ..core.oidc import provider
from ..core.oidc.issue_token_service import Token
from ..db.session import get_db

# Access to the websocket
from ..routers.socketio import connections_reload, sio

from ..verificationConfigs.crud import VerificationConfigCRUD
from ..verificationConfigs.helpers import VariableSubstitutionError
from ..verificationConfigs.models import MetaData


ChallengePollUri = "/poll"
AuthorizeCallbackUri = "/callback"
VerifiedCredentialAuthorizeUri = f"/{provider.AuthorizeUriEndpoint}"
VerifiedCredentialTokenUri = f"/{provider.TokenUriEndpoint}"

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

router = APIRouter()


@log_debug
# TODO: To be replaced by a websocket and a python scheduler
# TODO: This is a hack to get the websocket to expire the proof, if necessary
@router.get(f"{ChallengePollUri}/{{pid}}")
async def poll_pres_exch_complete(pid: str, db: Database = Depends(get_db)):
    """Called by authorize webpage to see if request
    is verified and token issuance can proceed."""
    auth_session = await AuthSessionCRUD(db).get(pid)

    pid = str(auth_session.id)
    connections = connections_reload()
    sid = connections.get(pid)

    """
     Check if proof is expired. But only if the proof has not been started.
     NOTE: This should eventually be moved to a background task.
    """
    # Handle comparison between timezone-aware and naive datetimes
    now = datetime.now()
    expired_time = auth_session.expired_timestamp

    # If expired_time is timezone-aware, convert now to UTC for comparison
    if expired_time.tzinfo is not None:
        now = datetime.now(UTC)

    if expired_time < now and auth_session.proof_status == AuthSessionState.NOT_STARTED:
        logger.info("PROOF EXPIRED")
        auth_session.proof_status = AuthSessionState.EXPIRED
        await AuthSessionCRUD(db).patch(
            str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
        )
        # Send message through the websocket.
        if sid:
            await sio.emit("status", {"status": "expired"}, to=sid)

        # Cleanup connection after verification expires (for connection-based flow)
        if (
            settings.USE_CONNECTION_BASED_VERIFICATION
            and auth_session.connection_id
            and not auth_session.multi_use  # Only delete single-use connections
        ):
            try:
                client = AcapyClient()
                success = client.delete_connection(auth_session.connection_id)
                if success:
                    logger.info(
                        f"Cleaned up single-use connection {auth_session.connection_id} after expiration"
                    )
                else:
                    logger.warning(
                        f"Failed to cleanup single-use connection {auth_session.connection_id}"
                    )
            except Exception as e:
                logger.error(
                    f"Error cleaning up single-use connection {auth_session.connection_id}: {e}"
                )
        elif (
            settings.USE_CONNECTION_BASED_VERIFICATION
            and auth_session.connection_id
            and auth_session.multi_use
        ):
            logger.info(
                f"Preserving multi-use connection {auth_session.connection_id} after expiration"
            )

    return {"proof_status": auth_session.proof_status}


def gen_deep_link(auth_session: AuthSession) -> str:
    controller_host = settings.CONTROLLER_URL
    url_to_message = (
        controller_host + "/url/pres_exch/" + str(auth_session.pres_exch_id)
    )
    WALLET_DEEP_LINK_PREFIX = settings.WALLET_DEEP_LINK_PREFIX
    wallet_deep_link = f"""{WALLET_DEEP_LINK_PREFIX}?_url={base64.urlsafe_b64encode(
        url_to_message.encode("utf-8")).decode("utf-8")}"""
    return wallet_deep_link


@log_debug
@router.get(VerifiedCredentialAuthorizeUri, response_class=HTMLResponse)
async def get_authorize(request: Request, db: Database = Depends(get_db)):
    """Called by oidc platform."""
    logger.debug(">>> get_authorize")

    # Verify OIDC forward payload
    model = AuthorizationRequest().from_dict(request.query_params._dict)
    model.verify()

    try:
        auth_req = provider.provider.parse_authentication_request(
            urlencode(request.query_params._dict), request.headers
        )
    except InvalidAuthenticationRequest as e:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid auth request: {e}",
        )

    # Create proof for this request
    new_user_id = str(uuid.uuid4())
    authn_response = provider.provider.authorize(model, new_user_id)

    # retrieve presentation_request config.
    client = AcapyClient()
    ver_config_id = model.get("pres_req_conf_id")
    ver_config = await VerificationConfigCRUD(db).get(ver_config_id)

    # Generate proof request configuration
    try:
        proof_request = ver_config.generate_proof_request()
    except VariableSubstitutionError as e:
        return JSONResponse(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            content={
                "detail": f"Variable substitution error: \
'{e.variable_name}' not found in substitution map."
            },
        )

    use_public_did = not settings.USE_OOB_LOCAL_DID_SERVICE

    if settings.USE_CONNECTION_BASED_VERIFICATION:
        # Connection-based verification flow
        oob_invite_response = client.create_connection_invitation(
            multi_use=False,
            presentation_exchange=None,  # No attachment - establish connection first
            use_public_did=use_public_did,
            auto_accept=True,  # Auto-accept connections to avoid manual acceptance
        )
        msg_contents = oob_invite_response.invitation

        # We'll create the presentation request after connection is established
        pres_exch_dict = None
        # Use invitation message ID as temporary unique identifier
        if not oob_invite_response.invi_msg_id:
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to create OOB invitation message; missing invitation message ID",
            )
        pres_ex_id = f"{oob_invite_response.invi_msg_id}"
    else:
        # EXISTING: Out-of-band verification flow
        response = client.create_presentation_request(proof_request)
        pres_exch_dict = response.model_dump()
        pres_ex_id = response.pres_ex_id

        oob_invite_response = client.oob_create_invitation(
            pres_exch_dict, use_public_did
        )
        msg_contents = oob_invite_response.invitation

    # Create and save OIDC AuthSession
    new_auth_session = AuthSessionCreate(
        response_url=authn_response.request(auth_req["redirect_uri"]),
        pyop_auth_code=authn_response["code"],
        request_parameters=model.to_dict(),
        ver_config_id=ver_config_id,
        pres_exch_id=pres_ex_id,
        presentation_exchange=pres_exch_dict,
        presentation_request_msg=msg_contents.model_dump(by_alias=True),
        connection_id=(
            oob_invite_response.invi_msg_id
            if settings.USE_CONNECTION_BASED_VERIFICATION
            else None
        ),
        proof_request=(
            proof_request if settings.USE_CONNECTION_BASED_VERIFICATION else None
        ),
        multi_use=False,  # Currently all connections are single-use
    )
    auth_session = await AuthSessionCRUD(db).create(new_auth_session)

    # QR CONTENTS
    controller_host = settings.CONTROLLER_URL
    url_to_message = (
        controller_host + "/url/pres_exch/" + str(auth_session.pres_exch_id)
    )
    # CREATE the image
    buff = io.BytesIO()
    qrcode.make(url_to_message).save(buff, format="PNG")
    image_contents = base64.b64encode(buff.getvalue()).decode("utf-8")
    callback_url = f"""{controller_host}{AuthorizeCallbackUri}?pid={auth_session.id}"""

    # BC Wallet deep link
    wallet_deep_link = gen_deep_link(auth_session)

    metadata = (
        ver_config.metadata["en"]
        if ver_config.metadata and "en" in ver_config.metadata
        else MetaData(title="Scan with a Digital Wallet", claims=[])
    )
    # This is the payload to send to the template
    data = {
        "image_contents": image_contents,
        "url_to_message": url_to_message,
        "callback_url": callback_url,
        "pres_exch_id": auth_session.pres_exch_id,
        "pid": auth_session.id,
        "controller_host": controller_host,
        "challenge_poll_uri": ChallengePollUri,
        "wallet_deep_link": wallet_deep_link,
        "title": metadata.title,
        "claims": metadata.claims,
    }

    # Prepare the template
    template_file = open(
        settings.CONTROLLER_TEMPLATE_DIR + "/verified_credentials.html", "r"
    ).read()
    template = Template(template_file)

    # Render and return the template
    return template.render(data)


@log_debug
@router.get("/callback", response_class=RedirectResponse)
async def get_authorize_callback(pid: str, db: Database = Depends(get_db)):
    """Called by Authorize page when verification is complete"""
    auth_session = await AuthSessionCRUD(db).get(pid)

    url = auth_session.response_url
    return RedirectResponse(url)


@log_debug
@router.post(VerifiedCredentialTokenUri, response_class=JSONResponse)
async def post_token(request: Request, db: Database = Depends(get_db)):
    """Called by oidc platform to retrieve token contents"""
    async with request.form() as form:
        logger.warn(f"post_token: form was {form}")
        form_dict = cast(dict[str, str], form._dict)
        auth_session = await AuthSessionCRUD(db).get_by_pyop_auth_code(
            form_dict["code"]
        )
        ver_config = await VerificationConfigCRUD(db).get(auth_session.ver_config_id)
        claims = Token.get_claims(auth_session, ver_config)

        # Replace auto-generated sub with one coming from proof, if available
        # The stateless storage uses a cypher, so a new item can be added and
        # the reference in the form needs to be updated with the new key value
        if claims.get("sub"):
            authz_info = provider.provider.authz_state.authorization_codes[
                form_dict["code"]
            ]
            authz_info["sub"] = claims.pop("sub")
            new_code = provider.provider.authz_state.authorization_codes.pack(
                authz_info
            )
            form_dict["code"] = new_code

        # convert form data to what library expects, Flask.app.request.get_data()
        data = urlencode(form_dict)
        token_response = provider.provider.handle_token_request(
            data, request.headers, claims
        )
        logger.debug(f"Token response: {token_response.to_dict()}")
        return token_response.to_dict()
