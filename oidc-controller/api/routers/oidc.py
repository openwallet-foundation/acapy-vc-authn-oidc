import base64
import io
import time
import uuid
from datetime import UTC, datetime
from typing import Any, cast
from urllib.parse import urlencode, urlparse

import jwt
import qrcode
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi import status as http_status
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jinja2 import BaseLoader, Environment
from oic.oic.message import AuthorizationRequest
from pymongo.database import Database
from pyop.exceptions import (
    BearerTokenError,
    InvalidAccessToken,
    InvalidAuthenticationRequest,
    OAuthError,
)

from ..authSessions.crud import AuthSessionCreate, AuthSessionCRUD
from ..authSessions.models import AuthSession, AuthSessionPatch, AuthSessionState
from ..clientConfigurations.crud import ClientConfigurationCRUD
from ..core.acapy.client import AcapyClient
from ..core.config import settings
from ..core.logger_util import log_debug
from ..core.oidc import provider
from ..core.oidc.issue_token_service import Token
from ..core.siem_audit import (
    audit_auth_session_initiated,
    audit_proof_request_created,
    audit_token_issued,
)
from ..db.session import get_db
from ..routers.sse import notify
from ..verificationConfigs.crud import VerificationConfigCRUD
from ..verificationConfigs.helpers import VariableSubstitutionError
from ..verificationConfigs.models import MetaData

ChallengePollUri = "/poll"
AuthorizeCallbackUri = "/callback"
VerifiedCredentialAuthorizeUri = f"/{provider.AuthorizeUriEndpoint}"
VerifiedCredentialTokenUri = f"/{provider.TokenUriEndpoint}"
VerifiedCredentialUserInfoUri = f"/{provider.UserInfoUriEndpoint}"

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

# Module-level Jinja2 environment — thread-safe, avoids per-request allocation.
_jinja_env = Environment(loader=BaseLoader(), autoescape=True)

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
        await notify(pid, "expired")

    return {"proof_status": auth_session.proof_status}


def gen_deep_link(auth_session: AuthSession) -> str:
    controller_host = settings.CONTROLLER_URL
    url_to_message = (
        controller_host + "/url/pres_exch/" + str(auth_session.pres_exch_id)
    )
    WALLET_DEEP_LINK_PREFIX = settings.WALLET_DEEP_LINK_PREFIX
    wallet_deep_link = f"""{WALLET_DEEP_LINK_PREFIX}?_url={
        base64.urlsafe_b64encode(url_to_message.encode("utf-8")).decode("utf-8")
    }"""
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

    # PyOP checks a code_verifier only when a challenge was sent, so without
    # this an RP could opt out of PKCE by omitting it.
    if settings.CONTROLLER_REQUIRE_PKCE and not (
        model.get("code_challenge") and model.get("code_challenge_method") == "S256"
    ):
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Invalid auth request: PKCE with code_challenge_method=S256 "
            "is required",
        )

    # Create proof for this request
    new_user_id = str(uuid.uuid4())
    authn_response = provider.provider.authorize(model, new_user_id)

    # retrieve presentation_request config.
    client = AcapyClient(request.app.state.http_client)
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
        oob_invite_response = await client.create_connection_invitation(
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
        response = await client.create_presentation_request(proof_request)
        pres_exch_dict = response.model_dump()
        pres_ex_id = response.pres_ex_id

        oob_invite_response = await client.oob_create_invitation(
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
        presentation_request_msg=msg_contents.model_dump(
            by_alias=True, exclude_none=True
        ),
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

    # SIEM Audit: Log auth session initiation (no PII, safe metadata only)
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    audit_auth_session_initiated(
        session_id=str(auth_session.id),
        client_id=model.get("client_id", "unknown"),
        ver_config=ver_config,
        client_ip=client_ip,
        user_agent=user_agent,
    )

    # SIEM Audit: Log proof request creation
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
        "pid": str(auth_session.id),
        "controller_host": controller_host,
        "challenge_poll_uri": ChallengePollUri,
        "wallet_deep_link": wallet_deep_link,
        "title": metadata.title,
        "claims": metadata.claims,
    }

    # Prepare the template (autoescape=True prevents XSS via template injection)
    with open(
        settings.CONTROLLER_TEMPLATE_DIR + "/verified_credentials.html", "r"
    ) as f:
        template_file = f.read()
    template = _jinja_env.from_string(template_file)

    # Render and return the template
    return template.render(data)


@log_debug
@router.get("/callback", response_class=RedirectResponse)
async def get_authorize_callback(pid: str, db: Database = Depends(get_db)):
    """Called by Authorize page when verification is complete"""
    auth_session = await AuthSessionCRUD(db).get(pid)

    # pid is not a secret, so only hand out the auth code once the proof is done
    if auth_session.proof_status != AuthSessionState.VERIFIED:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Presentation has not been verified",
        )

    url = auth_session.response_url

    # CWE-601: Validate redirect URL against the registered redirect_uris for
    # the client. Prevents an open redirect if response_url is ever tampered
    # with (e.g. via a DB-level attack). PyOP already validates redirect_uri at
    # auth-request time; this is a defense-in-depth check at redirect time.
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Invalid redirect URL",
        )
    client_id = auth_session.request_parameters.get("client_id")
    if not client_id:
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Missing client_id in auth session",
        )
    client_config = await ClientConfigurationCRUD(db).get(client_id)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if not any(
        base_url.rstrip("/") == registered.rstrip("/")
        for registered in client_config.redirect_uris
    ):
        raise HTTPException(
            status_code=http_status.HTTP_400_BAD_REQUEST,
            detail="Invalid redirect URL",
        )

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


def _invalid_grant() -> HTTPException:
    return HTTPException(
        status_code=http_status.HTTP_400_BAD_REQUEST,
        detail={
            "error": "invalid_grant",
            "error_description": "Authorization code is invalid, unverified "
            "or already used",
        },
    )


def _split_subject(claims: dict[str, Any]) -> tuple[str | None, dict[str, Any]]:
    """Separate the presentation's `sub` from the other claims.

    PyOP reads `sub` from authz_info; leaving it in the claims as well makes
    IdToken() receive it twice and raise a TypeError.
    """
    rest = {k: v for k, v in claims.items() if k != "sub"}
    return claims.get("sub") or None, rest


def _with_claims(
    authz_info: dict[str, Any], claims: dict[str, Any], sub: str | None
) -> dict[str, Any]:
    """Copy of a code's authz_info carrying the claims and, if given, a new sub.

    StatelessWrapper reads the claims from inside the code, so they must be
    packed into it whether or not there is a sub, otherwise the ID token gets
    empty claims. Redis storage ignores this field.
    """
    return {**authz_info, "user_info": claims, **({"sub": sub} if sub else {})}


def _store_claims(user_id: str, claims: dict[str, Any], session_id: str) -> None:
    """Make claims available to PyOP's userinfo lookup when it builds tokens.

    Without this, get_claims_for returns an empty dict and the ID token has
    no VC claims. user_id must be the id PyOP will look up.
    """
    try:
        provider.provider.userinfo.set_claims_for_user(user_id, claims)
    except Exception as e:
        logger.error(
            "Failed to store claims in VCUserinfo",
            operation="store_claims",
            auth_session_id=session_id,
            user_id=user_id,
            error=str(e),
            error_type=type(e).__name__,
        )
        raise HTTPException(
            status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to store claims: {str(e)}",
        )


def _log_id_token(token_response: dict[str, Any], session_id: str) -> None:
    """Debug-log the ID token's sub and claim names (signature not verified)."""
    if "id_token" not in token_response:
        return
    decoded = jwt.decode(
        token_response["id_token"], options={"verify_signature": False}
    )
    logger.debug(
        "ID token generated",
        operation="id_token_generated",
        auth_session_id=session_id,
        sub_in_token=decoded.get("sub"),
        all_claims=list(decoded.keys()),
    )


@log_debug
@router.post(VerifiedCredentialTokenUri, response_class=JSONResponse)
async def post_token(request: Request, db: Database = Depends(get_db)):
    """Called by oidc platform to retrieve token contents"""
    token_start_time = time.time()
    async with request.form() as form:
        form_dict = cast(dict[str, str], form._dict)
        code = form_dict["code"]
        crud = AuthSessionCRUD(db)
        auth_session = await crud.get_by_pyop_auth_code(code)
        session_id = str(auth_session.id)

        # Checked before claiming so a broken session does not burn the code
        if auth_session.pyop_user_id is None:
            raise HTTPException(
                status_code=http_status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=(
                    "Missing pyop_user_id in AuthSession; cannot process token request"
                ),
            )

        # RFC 6749 4.1.2: a code is single-use. The code is repacked below before
        # PyOP sees it, so PyOP's own "used" flag cannot enforce this.
        if not await crud.claim_auth_code(code):
            raise _invalid_grant()

        ver_config = await VerificationConfigCRUD(db).get(auth_session.ver_config_id)
        sub, claims = _split_subject(Token.get_claims(auth_session, ver_config))
        user_id = sub or auth_session.pyop_user_id

        if sub:
            # Replace the auto-generated sub with the presentation's subject.
            # PyOP uses it as the user_id for all later lookups (incl. userinfo)
            # and resolves it via the subject identifier mapping, which is
            # persisted in Redis when available.
            await crud.update_pyop_user_id(session_id, sub)
            store_subject_identifier(user_id, "public", sub)

        _store_claims(user_id, claims, session_id)

        # Packing creates a new code (a new Redis key, or a new encrypted blob
        # when stateless), so the form must reference the new one.
        codes = provider.provider.authz_state.authorization_codes
        form_dict["code"] = codes.pack(_with_claims(codes[code], claims, sub))

        logger.info(
            "Issuing token",
            operation="handle_token_request",
            auth_session_id=session_id,
            user_id=user_id,
            subject_replaced=sub is not None,
            claims_keys=list(claims.keys()),
        )
        # PyOP expects the raw body, as Flask's request.get_data() would give
        try:
            token_response = provider.provider.handle_token_request(
                urlencode(form_dict), request.headers, claims
            ).to_dict()
        except OAuthError as e:
            # e.g. a wrong PKCE code_verifier, redirect_uri or client secret
            raise HTTPException(
                status_code=http_status.HTTP_401_UNAUTHORIZED
                if e.oauth_error == "invalid_client"
                else http_status.HTTP_400_BAD_REQUEST,
                detail={"error": e.oauth_error, "error_description": str(e)},
            )
        _log_id_token(token_response, session_id)

        # SIEM Audit: Log successful token issuance (count only, no claim values)
        audit_token_issued(
            session_id=session_id,
            client_id=auth_session.request_parameters.get("client_id", "unknown"),
            ver_config_id=auth_session.ver_config_id,
            claims_count=len(claims),
            duration_ms=int((time.time() - token_start_time) * 1000),
        )

        return token_response


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
