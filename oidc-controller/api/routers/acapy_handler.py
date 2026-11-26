import time
from datetime import UTC, datetime
from typing import Final

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from pymongo.database import Database

from ..adapters.acapy.client import AcapyClient, AcapyError
from ..adapters.siem_audit import (
    audit_proof_verification_failed,
    audit_proof_verified,
    audit_session_abandoned,
    audit_session_expired,
    audit_webhook_received,
)
from ..authSessions.crud import AuthSessionCRUD
from ..authSessions.models import AuthSession
from ..config import settings
from ..core.acapy.models import CreatePresentationResponse
from ..core.acapy.presentation import Presentations
from ..core.acapy.webhooks import ConnectionWebhook, PresentProofWebhook
from ..core.auth_session import (
    Abandoned,
    Expired,
    Failed,
    RequestSent,
    Verified,
)
from ..core.models import FrozenModel
from ..db.session import get_db
from ..routers.sse import notify

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

router = APIRouter()


def _audit_presentations(by_format: object) -> Presentations:
    """Credential identifiers for the audit log. Schema names and issuer DIDs
    are public metadata, not PII. Never raises, so a bad record can't fail a
    login that ACA-Py already verified."""
    pres = by_format.get("pres") if isinstance(by_format, dict) else None
    try:
        return Presentations.model_validate(pres or {})
    except ValidationError as e:
        # The error count only: the errors themselves can echo credential values.
        logger.warning(
            "Could not read credential identifiers for the audit log",
            error_count=e.error_count(),
        )
        return Presentations()


async def _cleanup__connection(
    client: AcapyClient, auth_session: AuthSession, context: str
) -> None:
    """Delete the session's connection if it was single-use. A failure is
    only logged; the background cleanup retries it."""
    if (
        settings.USE_CONNECTION_BASED_VERIFICATION
        and auth_session.connection_id
        and not auth_session.multi_use  # Only delete single-use connections
    ):
        connection_id_to_delete = auth_session.connection_id
    else:
        return

    match await client.delete_connection(connection_id_to_delete):
        case None:
            logger.info(
                f"Successfully cleaned up single-use connection {connection_id_to_delete} after {context}"
            )
        case AcapyError(reason=reason):
            logger.warning(
                f"Failed to cleanup single-use connection {connection_id_to_delete} after {context}",
                reason=reason,
            )


async def _send_problem_report(
    client: AcapyClient, pres_ex_id: str, description: str
) -> None:
    """Tell the wallet the exchange failed. A failure is only logged: the
    session's outcome is already saved."""
    if (error := await client.send_problem_report(pres_ex_id, description)) is not None:
        logger.warning(
            "Could not send problem report", pres_ex_id=pres_ex_id, reason=error.reason
        )


async def _parse_webhook[M: FrozenModel](request: Request, model: type[M]) -> M:
    try:
        return model.model_validate_json(await request.body())
    except ValidationError as e:
        # Leave the input out of the error: it can hold presentation data.
        raise HTTPException(
            status_code=422,
            detail=e.errors(include_input=False, include_url=False),
        ) from e


async def _find_connection_session(
    db: Database, search_id: str | None, connection_id: str
) -> AuthSession | None:
    """Find the session a newly established connection belongs to.

    The session stores the invitation message ID as its connection_id until
    the real connection ID is known, so try that first, then the real
    connection ID, then the search ID as a presentation exchange ID.
    """
    crud = AuthSessionCRUD(db)
    logger.info(f"Looking for auth session with search_id: {search_id}")
    if search_id and (session := await crud.get_by_connection_id(search_id)):
        return session

    logger.info(f"Trying to find auth session by connection_id: {connection_id}")
    if session := await crud.get_by_connection_id(connection_id):
        return session

    if not search_id:
        return None
    logger.info(f"Trying to find auth session by pres_exch_id pattern: {search_id}")
    return await crud.find_by_pres_exch_id(search_id)


@router.post("/topic/{topic}/")
async def post_topic(request: Request, topic: str, db: Database = Depends(get_db)):
    """Called by aca-py agent."""
    webhook_start_time = time.time()
    logger.info(f">>> post_topic : topic={topic}")
    # Note: Full webhook body is logged at DEBUG level only to protect privacy
    logger.debug(f">>> web hook received for topic: {topic}")

    client = AcapyClient(request.app.state.http_client)

    match topic:
        case "connections":
            if settings.USE_CONNECTION_BASED_VERIFICATION:
                connection = await _parse_webhook(request, ConnectionWebhook)
                logger.info(f">>>> connection_id: {connection.connection_id}")
                logger.info(f">>>> connection state: {connection.state}")

                # Log request state for debugging but don't act on it yet
                if connection.state == "request":
                    logger.info(
                        f"Connection {connection.connection_id} is in request state, waiting for active/completed"
                    )

                if (
                    connection.state in ["active", "completed"]
                    and connection.connection_id is not None
                ):
                    # Connection established, now send presentation request
                    connection_id = connection.connection_id

                    logger.debug(f"Full webhook body: {connection}")

                    # Try multiple possible fields for invitation message ID
                    search_id = connection.invitation_search_id()

                    session: Final = await _find_connection_session(
                        db, search_id, connection_id
                    )

                    if session:
                        logger.info(f"Found auth session: {session.id}")
                        logger.info(
                            f"Auth session has proof_request: {session.proof_request is not None}"
                        )

                        if session.proof_request:
                            logger.info(
                                f"Sending presentation request to connection {connection_id}"
                            )

                            sent: Final = await client.send_presentation_request_by_connection(
                                connection_id=connection_id,
                                presentation_request_configuration=session.proof_request,
                            )
                            match sent:
                                case CreatePresentationResponse():
                                    # Record the exchange and the real connection ID
                                    await AuthSessionCRUD(db).advance(
                                        session,
                                        RequestSent(
                                            sent.pres_ex_id,
                                            sent.model_dump(),
                                            connection_id,
                                        ),
                                    )
                                    logger.info(
                                        f"Presentation request sent successfully: {sent.pres_ex_id}"
                                    )
                                case AcapyError(reason=reason):
                                    logger.error(
                                        f"Failed to send presentation request: {reason}"
                                    )
                                    failed = await AuthSessionCRUD(db).advance(
                                        session, Failed()
                                    )
                                    if isinstance(failed, AuthSession):
                                        if failed.pres_exch_id:
                                            # The reason stays in our logs; it can
                                            # hold ACA-Py's response body.
                                            await _send_problem_report(
                                                client,
                                                failed.pres_exch_id,
                                                "Failed to send presentation request",
                                            )
                                        await notify(str(failed.id), "failed")
                        else:
                            logger.debug(
                                f"Auth session found but no proof_request: {session.id}"
                            )
                    else:
                        logger.debug(
                            f"No auth session found for invitation_msg_id: {connection.invitation_msg_id}"
                        )

        case "present_proof_v2_0":
            webhook_body = await _parse_webhook(request, PresentProofWebhook)

            pres_ex_id = webhook_body.pres_ex_id
            state = webhook_body.state
            role = webhook_body.role

            # Emitted by ACA-Py for every record removal (auto-remove, cleanup)
            if state == "deleted":
                logger.debug(
                    "Ignoring deleted presentation record", pres_ex_id=pres_ex_id
                )
                return {"status": "ignored"}

            # SIEM Audit: Log webhook receipt (safe metadata only)
            audit_webhook_received(
                topic="present_proof_v2_0",
                state=state,
                role=role,
            )

            logger.info(f">>>> pres_exch_id: {pres_ex_id}, state: {state}")

            # Check for prover-role (issue #898)

            if role == "prover":
                # Handle prover-role separately - VC-AuthN is responding to a proof request
                connection_id = webhook_body.connection_id

                logger.info(
                    f"Prover-role webhook received: {state}",
                    pres_ex_id=pres_ex_id,
                    connection_id=connection_id,
                    role=role,
                    state=state,
                    timestamp=datetime.now(UTC).isoformat(),
                )

                # Return early - do NOT trigger verifier-role logic or cleanup
                return {"status": "prover-role event logged"}

            auth_session: Final = await AuthSessionCRUD(db).find_by_pres_exch_id(
                pres_ex_id
            )
            if auth_session is None:
                # Acknowledge so ACA-Py does not retry for a session that no longer exists
                logger.info(
                    "No auth session for presentation exchange, ignoring webhook",
                    pres_ex_id=pres_ex_id,
                    state=state,
                )
                return {"status": "unknown presentation exchange"}

            if state == "presentation-received":
                logger.info("presentation-received")

            if state == "done":
                duration_ms = int((time.time() - webhook_start_time) * 1000)

                if webhook_body.is_verified:
                    logger.info("VERIFIED")

                    by_format = webhook_body.by_format
                    if not by_format:
                        logger.error(
                            "Missing by_format in webhook body — cannot extract proof claims. "
                            "Ensure ACA-Py is configured with --debug-webhooks.",
                            pres_ex_id=pres_ex_id,
                        )
                        failed = await AuthSessionCRUD(db).advance(
                            auth_session, Failed()
                        )
                        if isinstance(failed, AuthSession):
                            await notify(str(failed.id), "failed")
                        await _cleanup__connection(
                            client,
                            auth_session,
                            "missing by_format in webhook body",
                        )
                        return {"status": "missing by_format"}

                    verified = await AuthSessionCRUD(db).advance(
                        auth_session, Verified(by_format)
                    )
                    if isinstance(verified, AuthSession):
                        # SIEM Audit: Log successful verification (metadata only, no PII)
                        presentations = _audit_presentations(by_format)
                        audit_proof_verified(
                            session_id=str(verified.id),
                            ver_config_id=verified.ver_config_id,
                            credential_schemas=presentations.schema_names(),
                            issuer_dids=presentations.issuer_dids(),
                            duration_ms=duration_ms,
                            revocation_checked=settings.SET_NON_REVOKED,
                        )

                        await notify(str(verified.id), "verified")
                else:
                    logger.info("VERIFICATION FAILED")
                    failed = await AuthSessionCRUD(db).advance(auth_session, Failed())
                    if isinstance(failed, AuthSession):
                        # SIEM Audit: Log failed verification
                        audit_proof_verification_failed(
                            session_id=str(failed.id),
                            ver_config_id=failed.ver_config_id,
                            failure_category="unknown",  # ACA-Py doesn't provide detailed failure reason
                            duration_ms=duration_ms,
                        )

                        await notify(str(failed.id), "failed")

                        # Send problem report for failed verification in connection-based flow
                        if (
                            settings.USE_CONNECTION_BASED_VERIFICATION
                            and failed.pres_exch_id
                        ):
                            await _send_problem_report(
                                client,
                                failed.pres_exch_id,
                                f"Presentation verification failed: {webhook_body.error_msg or 'Unknown error'}",
                            )

                await _cleanup__connection(
                    client, auth_session, "connection has been verified"
                )
                return {}

            if state == "abandoned":
                logger.info("ABANDONED")
                # Note: error_msg may contain sensitive info, log at debug level only
                logger.debug(
                    f"Abandonment reason: {webhook_body.error_msg or 'No reason provided'}"
                )
                abandoned = await AuthSessionCRUD(db).advance(auth_session, Abandoned())
                if isinstance(abandoned, AuthSession):
                    # SIEM Audit: Log session abandonment
                    duration_ms = int((time.time() - webhook_start_time) * 1000)
                    audit_session_abandoned(
                        session_id=str(abandoned.id),
                        ver_config_id=abandoned.ver_config_id,
                        phase="wallet_response",
                        duration_ms=duration_ms,
                    )

                    await notify(str(abandoned.id), "abandoned")

                    # Send problem report for abandoned presentation in connection-based flow
                    if (
                        settings.USE_CONNECTION_BASED_VERIFICATION
                        and abandoned.pres_exch_id
                    ):
                        await _send_problem_report(
                            client,
                            abandoned.pres_exch_id,
                            f"Presentation abandoned: {webhook_body.error_msg or 'Unknown error'}",
                        )
                await _cleanup__connection(client, auth_session, "abandonment")
                return {}

            # Any other state: the wallet may have gone quiet past the deadline.
            expired = await AuthSessionCRUD(db).advance(
                auth_session, Expired(datetime.now(UTC))
            )
            if isinstance(expired, AuthSession):
                logger.info("EXPIRED")
                # SIEM Audit: Log session expiration
                audit_session_expired(
                    session_id=str(expired.id),
                    ver_config_id=expired.ver_config_id,
                    phase="qr_scan",
                    timeout_seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME,
                )

                await notify(str(expired.id), "expired")

                # Send problem report for expired presentation in connection-based flow
                if settings.USE_CONNECTION_BASED_VERIFICATION and expired.pres_exch_id:
                    await _send_problem_report(
                        client,
                        expired.pres_exch_id,
                        f"Presentation expired: timeout after {settings.CONTROLLER_PRESENTATION_EXPIRE_TIME} seconds",
                    )

                await _cleanup__connection(client, expired, "expiration")
        case _:
            logger.debug("skipping webhook")

    return {}
