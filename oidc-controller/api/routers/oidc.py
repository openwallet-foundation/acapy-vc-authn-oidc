import base64
import io
import time
import uuid
from datetime import UTC, datetime
from typing import cast
from urllib.parse import urlencode

import jwt
import qrcode
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi import status as http_status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import Template
from oic.oic.message import AuthorizationRequest
from pymongo.database import Database
from pyop.exceptions import (
    BearerTokenError,
    InvalidAccessToken,
    InvalidAuthenticationRequest,
)

from ..authSessions.crud import AuthSessionCreate, AuthSessionCRUD
from ..authSessions.models import AuthSession, AuthSessionPatch, AuthSessionState
from ..core.acapy.client import AcapyClient
from ..core.config import settings
from ..core.logger_util import log_debug
from ..core.oidc import provider
from ..core.oidc.issue_token_service import Token
from ..core.siam_audit import (
    audit_auth_session_initiated,
    audit_proof_request_created,
    audit_token_issued,
)
from ..db.session import get_db

# Access to the websocket
from ..routers.socketio import get_socket_id_for_pid, safe_emit
from ..verificationConfigs.crud import VerificationConfigCRUD
from ..verificationConfigs.helpers import VariableSubstitutionError
from ..verificationConfigs.models import MetaData

ChallengePollUri = "/poll"
AuthorizeCallbackUri = "/callback"
VerifiedCredentialAuthorizeUri = f"/{provider.AuthorizeUriEndpoint}"
VerifiedCredentialTokenUri = f"/{provider.TokenUriEndpoint}"
VerifiedCredentialUserInfoUri = f"/{provider.UserInfoUriEndpoint}"

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
    sid = await get_socket_id_for_pid(pid, db)

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
        logger.warning("PROOF EXPIRED")
        auth_session.proof_status = AuthSessionState.EXPIRED
        await AuthSessionCRUD(db).patch(
            str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
        )
        # Send message through the websocket.
        if sid:
            await safe_emit("status", {"status": "expired"}, to=sid)

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
        pyop_user_id=new_user_id,  # Store original user_id for regeneration
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

    # SIAM Audit: Log auth session initiation (no PII, safe metadata only)
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    audit_auth_session_initiated(
        session_id=str(auth_session.id),
        client_id=model.get("client_id", "unknown"),
        ver_config=ver_config,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # SIAM Audit: Log proof request creation
    audit_proof_request_created(
        session_id=str(auth_session.id),
        ver_config=ver_config,
        proof_name=ver_config.proof_request.name,
    )

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


def store_subject_identifier(user_id: str, subject_type: str, identifier: str) -> bool:
    """
    Store subject identifier with Redis-aware persistence.

    This function properly handles storage to Redis by explicitly reading,
    modifying, and writing back the subject identifier mapping. This is
    necessary because RedisWrapper doesn't auto-persist dict modifications.

    Args:
        user_id: The PyOP internal user ID
        subject_type: Type of subject identifier (e.g., "public", "pairwise")
        identifier: The actual subject identifier value

    Returns:
        bool: True if this created a new user mapping, False if updating existing

    Note:
        This function preserves existing subject identifier types when adding
        new ones (e.g., adding "public" won't overwrite existing "pairwise").
    """
    # Get existing subject identifiers for this user (or empty dict)
    if user_id in provider.provider.authz_state.subject_identifiers:
        subject_ids = provider.provider.authz_state.subject_identifiers[user_id]
        is_new_user = False
    else:
        subject_ids = {}
        is_new_user = True

    # Update the dict with the new subject identifier
    subject_ids[subject_type] = identifier

    # Store the updated dict back to Redis (critical for Redis storage)
    # Note: With StatelessWrapper, this is a no-op as tokens are self-contained
    provider.provider.authz_state.subject_identifiers[user_id] = subject_ids

    logger.debug(
        "Stored subject identifier",
        operation="store_subject_identifier",
        user_id=user_id,
        subject_type=subject_type,
        identifier_prefix=identifier[:8] if len(identifier) >= 8 else identifier,
        is_new_user=is_new_user,
        preserved_types=list(subject_ids.keys()),
    )

    return is_new_user


async def generate_auth_code(claims, auth_session, form_dict, db):
    """Regenerate authorization code using the original PyOP user_id.

    This is necessary when the authorization code is not found in Redis storage,
    which can happen in multi-pod deployments when a different pod handled the
    initial authorization request.
    """
    old_code_prefix = (
        form_dict["code"][:8] if len(form_dict["code"]) >= 8 else form_dict["code"]
    )
    logger.debug(
        "Authorization code invalid in PyOP storage, regenerating",
        operation="regenerate_auth_code",
        auth_session_id=str(auth_session.id),
        old_code_prefix=old_code_prefix,
        reason="code_not_found_in_redis",
    )
    try:
        auth_req_model = AuthorizationRequest().from_dict(
            auth_session.request_parameters
        )

        # Handle legacy sessions without pyop_user_id (from before migration)
        user_id = auth_session.pyop_user_id
        is_legacy_session = user_id is None
        if is_legacy_session:
            user_id = str(uuid.uuid4())
            logger.warning(
                "Legacy AuthSession missing pyop_user_id, generated new UUID",
                operation="regenerate_auth_code",
                auth_session_id=str(auth_session.id),
                generated_user_id=user_id,
                legacy_session=True,
            )

        # Use the user_id to ensure subject identifier consistency in PyOP's storage
        new_auth_response = provider.provider.authorize(auth_req_model, user_id)
        new_code = new_auth_response["code"]
        new_code_prefix = new_code[:8] if len(new_code) >= 8 else new_code

        # Update database with new authorization code for consistency
        await AuthSessionCRUD(db).update_pyop_auth_code(str(auth_session.id), new_code)
        form_dict["code"] = new_code
        logger.info(
            "Successfully regenerated authorization code",
            operation="regenerate_auth_code",
            auth_session_id=str(auth_session.id),
            user_id=user_id,
            old_code_prefix=old_code_prefix,
            new_code_prefix=new_code_prefix,
            legacy_session=is_legacy_session,
        )
    except Exception as regenerate_error:
        logger.error(
            "Failed to regenerate authorization code",
            operation="regenerate_auth_code",
            auth_session_id=str(auth_session.id),
            error=str(regenerate_error),
            error_type=type(regenerate_error).__name__,
        )
        # Continue without subject replacement - this maintains functionality
        # while logging the issue for monitoring
        pass


@log_debug
@router.post(VerifiedCredentialTokenUri, response_class=JSONResponse)
async def post_token(request: Request, db: Database = Depends(get_db)):
    """Called by oidc platform to retrieve token contents"""
    token_start_time = time.time()
    async with request.form() as form:
        logger.info(f"post_token: form was {form}")
        form_dict = cast(dict[str, str], form._dict)
        auth_session = await AuthSessionCRUD(db).get_by_pyop_auth_code(
            form_dict["code"]
        )

        ver_config = await VerificationConfigCRUD(db).get(auth_session.ver_config_id)
        claims = Token.get_claims(auth_session, ver_config)

        # Get the user_id early - needed for both subject identifier and
        # claims storage
        user_id = auth_session.pyop_user_id
        if user_id is None:
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Missing pyop_user_id in AuthSession; "
                    "cannot process token request"
                ),
            )

        # CRITICAL: For StatelessWrapper (in-memory storage), claims MUST be
        # stored INSIDE the authorization code in authz_info["user_info"] before
        # packing, otherwise PyOP will retrieve empty claims when generating the
        # ID token. This must happen regardless of whether claims contain a "sub"
        # field. For RedisWrapper, this field is not used (claims are in Redis).
        authz_info = provider.provider.authz_state.authorization_codes[
            form_dict["code"]
        ]
        authz_info["user_info"] = claims

        # Replace auto-generated sub with one coming from proof, if available
        # The Redis storage uses a shared data store, so a new item can be
        # added and the reference in the form needs to be updated with the
        # new key value
        if claims.get("sub"):
            # Update the subject with the one from the presentation
            presentation_sub = claims.pop("sub")

            logger.info(
                "About to update authorization info with presentation subject",
                operation="update_authz_sub",
                auth_session_id=str(auth_session.id),
                original_authz_sub=authz_info.get("sub"),
                presentation_sub=presentation_sub,
            )

            authz_info["sub"] = presentation_sub

            # CRITICAL: Update AuthSession.pyop_user_id to match the
            # presentation subject. This ensures consistency throughout
            # the system - PyOP will use this subject as the user_id for
            # all subsequent operations including userinfo lookups.
            await AuthSessionCRUD(db).update_pyop_user_id(
                str(auth_session.id), presentation_sub
            )
            # Update our local reference to the new user_id
            user_id = presentation_sub

            # Create subject identifier mapping: subject -> user_id
            # This is needed because PyOP will look up the user_id for this
            # subject. Store the public subject identifier with Redis-aware
            # persistence
            store_subject_identifier(user_id, "public", presentation_sub)

            # Need to update user_info again after removing "sub" from claims
            authz_info["user_info"] = claims

            logger.info(
                "Replaced authorization code with presentation subject",
                operation="update_auth_code_subject",
                auth_session_id=str(auth_session.id),
                original_user_id=auth_session.pyop_user_id,
                new_user_id=presentation_sub,
                updated_auth_session=True,
                updated_user_info_in_code=True,
            )

        # Pack the authorization code with updated authz_info
        new_code = provider.provider.authz_state.authorization_codes.pack(authz_info)
        form_dict["code"] = new_code

        # NOTE: Do NOT add sub back to claims dict. PyOP will get the
        # sub from authz_info["sub"] when generating the ID token.
        # If we include sub in claims as well, PyOP will receive it
        # twice and raise: "TypeError: IdToken() got multiple values
        # for keyword argument 'sub'"

        logger.info(
            "Updated authorization code with claims for StatelessWrapper",
            operation="update_auth_code_claims",
            auth_session_id=str(auth_session.id),
            user_id=user_id,
            claims_keys=list(claims.keys()),
        )

        # Store claims in VCUserinfo so PyOP can retrieve them when
        # generating the ID token. This is critical - without this,
        # get_claims_for will return empty dict.
        # Now user_id is guaranteed to match what PyOP will use for lookup
        try:
            provider.provider.userinfo.set_claims_for_user(user_id, claims)
            logger.info(
                "Stored claims in VCUserinfo for ID token generation",
                operation="store_claims",
                auth_session_id=str(auth_session.id),
                user_id=user_id,
                claims_keys=list(claims.keys()),
            )
        except Exception as e:
            logger.error(
                "Failed to store claims in VCUserinfo",
                operation="store_claims",
                auth_session_id=str(auth_session.id),
                user_id=user_id,
                error=str(e),
                error_type=type(e).__name__,
            )
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to store claims: {str(e)}",
            )

        # convert form data to what library expects,
        # Flask.app.request.get_data()
        data = urlencode(form_dict)

        logger.info(
            "About to call PyOP handle_token_request",
            operation="handle_token_request",
            auth_session_id=str(auth_session.id),
            user_id=user_id,
            code_prefix=(
                form_dict["code"][:16] + "..."
                if len(form_dict["code"]) > 16
                else form_dict["code"]
            ),
        )

        token_response = provider.provider.handle_token_request(
            data, request.headers, claims
        )
        logger.debug(f"Token response: {token_response.to_dict()}")

        # Log the actual sub in the ID token for debugging
        if "id_token" in token_response.to_dict():

            # Decode without verification to inspect the token
            decoded = jwt.decode(
                token_response.to_dict()["id_token"],
                options={"verify_signature": False},
            )
            logger.debug(
                "ID token generated",
                operation="id_token_generated",
                auth_session_id=str(auth_session.id),
                sub_in_token=decoded.get("sub"),
                all_claims=list(decoded.keys()),
            )

        # SIAM Audit: Log successful token issuance (count only, no claim values)
        token_duration_ms = int((time.time() - token_start_time) * 1000)
        audit_token_issued(
            session_id=str(auth_session.id),
            client_id=auth_session.request_parameters.get("client_id", "unknown"),
            ver_config_id=auth_session.ver_config_id,
            claims_count=len(claims),
            duration_ms=token_duration_ms,
        )

        return token_response.to_dict()


@log_debug
@router.get(VerifiedCredentialUserInfoUri, response_class=JSONResponse)
@router.post(VerifiedCredentialUserInfoUri, response_class=JSONResponse)
async def get_userinfo(request: Request):
    """
    Called by RPs (like Firebase) to retrieve user claims using the Access Token.
    Only available if CONTROLLER_ENABLE_USERINFO_ENDPOINT is True.
    """
    if not settings.CONTROLLER_ENABLE_USERINFO_ENDPOINT:
        raise HTTPException(
            status_code=http_status.HTTP_404_NOT_FOUND,
            detail="UserInfo endpoint is disabled",
        )
    try:
        # We need to read the body for POST requests, though standard GETs won't have one.
        # pyop expects the body as a string if it exists.
        body = (await request.body()).decode("utf-8")

        # Parse and process the request using pyop
        # This validates the Bearer token and looks up claims in VCUserinfo
        userinfo_response = provider.provider.handle_userinfo_request(
            body, request.headers
        )

        return userinfo_response.to_dict()

    except (BearerTokenError, InvalidAccessToken) as e:
        logger.warning(f"UserInfo request failed: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except Exception as e:
        logger.error(f"UserInfo unexpected error: {e}")
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve user info",
        )
