import time
from datetime import UTC, datetime

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import ValidationError
from pymongo.database import Database

from ..adapters.acapy.client import AcapyClient
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
from ..core.acapy.presentation import Presentations
from ..core.acapy.webhooks import ConnectionWebhook, PresentProofWebhook
from ..core.auth_session import (
    Abandoned,
    Expired,
    Failed,
    RequestSent,
    Verified,
    has_expired,
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


async def _send_problem_report_safely(
    client: AcapyClient, pres_ex_id: str, description: str
) -> None:
    """Send a problem report with error handling."""
    try:
        await client.send_problem_report(pres_ex_id, description)
        logger.info(f"Problem report sent for pres_ex_id: {pres_ex_id}")
    except Exception as e:
        logger.error(f"Failed to send problem report: {e}")


async def _cleanup__connection(
    client: AcapyClient, auth_session: AuthSession, pres_ex_id: str, context: str
) -> None:
    """Clean up connection with proper error handling."""
    if (
        settings.USE_CONNECTION_BASED_VERIFICATION
        and auth_session.connection_id
        and not auth_session.multi_use  # Only delete single-use connections
    ):
        connection_id_to_delete = auth_session.connection_id
    else:
        return

    try:
        if await client.delete_connection(connection_id_to_delete):
            logger.info(
                f"Successfully cleaned up single-use connection {connection_id_to_delete} after {context}"
            )
        else:
            logger.warning(
                f"Failed to cleanup single-use connection {connection_id_to_delete} after {context}"
            )

    except Exception as cleanup_error:
        logger.warning(
            f"Cleanup failed for presentation record {pres_ex_id} after {context}: {cleanup_error} - will be handled by background cleanup"
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

                    # Find the auth session by invitation message ID (stored as connection_id initially)
                    logger.info(f"Looking for auth session with search_id: {search_id}")
                    auth_session = (
                        await AuthSessionCRUD(db).get_by_connection_id(search_id)
                        if search_id
                        else None
                    )

                    # If not found by invitation message ID, try by connection_id directly
                    if not auth_session:
                        logger.info(
                            f"Trying to find auth session by connection_id: {connection_id}"
                        )
                        auth_session = await AuthSessionCRUD(db).get_by_connection_id(
                            connection_id
                        )

                    # If still not found, try searching by pres_exch_id pattern
                    if not auth_session and search_id:
                        logger.info(
                            f"Trying to find auth session by pres_exch_id pattern: {search_id}"
                        )
                        try:
                            auth_session = await AuthSessionCRUD(
                                db
                            ).get_by_pres_exch_id(search_id)
                        except HTTPException as e:
                            # Not found is expected; anything else is a real failure.
                            if e.status_code != 404:
                                raise

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
                            try:
                                pres_response = await client.send_presentation_request_by_connection(
                                    connection_id=connection_id,
                                    presentation_request_configuration=auth_session.proof_request,
                                )

                                # Update auth session with presentation exchange details and real connection ID
                                sent = await AuthSessionCRUD(db).advance(
                                    auth_session,
                                    RequestSent(
                                        pres_response.pres_ex_id,
                                        pres_response.model_dump(),
                                        connection_id,  # the real connection ID
                                    ),
                                )
                                auth_session = sent or auth_session

                                logger.info(
                                    f"Presentation request sent successfully: {pres_response.pres_ex_id}"
                                )
                            except Exception as e:
                                logger.error(
                                    f"Failed to send presentation request: {e}"
                                )
                                failed = await AuthSessionCRUD(db).advance(
                                    auth_session, Failed()
                                )
                                if failed is not None:
                                    # Send problem report if we have a presentation exchange ID
                                    if failed.pres_exch_id:
                                        await _send_problem_report_safely(
                                            client,
                                            failed.pres_exch_id,
                                            f"Failed to send presentation request: {str(e)}",
                                        )

                                    # Emit failure status to frontend
                                    await notify(str(failed.id), "failed")
                        else:
                            logger.debug(
                                f"Auth session found but no proof_request: {auth_session.id}"
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

            # Existing verifier-role code continues below...
            try:
                auth_session = await AuthSessionCRUD(db).get_by_pres_exch_id(pres_ex_id)
            except HTTPException as e:
                if e.status_code != 404:
                    raise
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
                        if (
                            await AuthSessionCRUD(db).advance(auth_session, Failed())
                            is not None
                        ):
                            await notify(str(auth_session.id), "failed")
                        await _cleanup__connection(
                            client,
                            auth_session,
                            pres_ex_id,
                            "missing by_format in webhook body",
                        )
                        return {"status": "missing by_format"}

                    verified = await AuthSessionCRUD(db).advance(
                        auth_session, Verified(by_format)
                    )
                    if verified is not None:
                        auth_session = verified

                        # SIEM Audit: Log successful verification (metadata only, no PII)
                        presentations = _audit_presentations(by_format)
                        audit_proof_verified(
                            session_id=str(auth_session.id),
                            ver_config_id=auth_session.ver_config_id,
                            credential_schemas=presentations.schema_names(),
                            issuer_dids=presentations.issuer_dids(),
                            duration_ms=duration_ms,
                            revocation_checked=settings.SET_NON_REVOKED,
                        )

                        await notify(str(auth_session.id), "verified")
                else:
                    logger.info("VERIFICATION FAILED")
                    failed = await AuthSessionCRUD(db).advance(auth_session, Failed())
                    if failed is not None:
                        auth_session = failed

                        # SIEM Audit: Log failed verification
                        audit_proof_verification_failed(
                            session_id=str(auth_session.id),
                            ver_config_id=auth_session.ver_config_id,
                            failure_category="unknown",  # ACA-Py doesn't provide detailed failure reason
                            duration_ms=duration_ms,
                        )

                        await notify(str(auth_session.id), "failed")

                        # Send problem report for failed verification in connection-based flow
                        if (
                            settings.USE_CONNECTION_BASED_VERIFICATION
                            and auth_session.pres_exch_id
                        ):
                            await _send_problem_report_safely(
                                client,
                                auth_session.pres_exch_id,
                                f"Presentation verification failed: {webhook_body.error_msg or 'Unknown error'}",
                            )

                await _cleanup__connection(
                    client, auth_session, pres_ex_id, "connection has been verified"
                )

                # Connection cleanup is now handled above in the combined cleanup operation
            if state == "abandoned":
                logger.info("ABANDONED")
                # Note: error_msg may contain sensitive info, log at debug level only
                logger.debug(
                    f"Abandonment reason: {webhook_body.error_msg or 'No reason provided'}"
                )
                abandoned = await AuthSessionCRUD(db).advance(auth_session, Abandoned())
                if abandoned is not None:
                    auth_session = abandoned

                    # SIEM Audit: Log session abandonment
                    duration_ms = int((time.time() - webhook_start_time) * 1000)
                    audit_session_abandoned(
                        session_id=str(auth_session.id),
                        ver_config_id=auth_session.ver_config_id,
                        phase="wallet_response",
                        duration_ms=duration_ms,
                    )

                    await notify(str(auth_session.id), "abandoned")

                    # Send problem report for abandoned presentation in connection-based flow
                    if (
                        settings.USE_CONNECTION_BASED_VERIFICATION
                        and auth_session.pres_exch_id
                    ):
                        await _send_problem_report_safely(
                            client,
                            auth_session.pres_exch_id,
                            f"Presentation abandoned: {webhook_body.error_msg or 'Unknown error'}",
                        )
                await _cleanup__connection(
                    client, auth_session, pres_ex_id, "abandonment"
                )

            # Check if expired. But only if the proof has not been started.
            now = datetime.now(UTC)
            if (
                has_expired(auth_session, now)
                and (
                    expired := await AuthSessionCRUD(db).advance(
                        auth_session, Expired(now)
                    )
                )
                is not None
            ):
                logger.info("EXPIRED")
                auth_session = expired

                # SIEM Audit: Log session expiration
                audit_session_expired(
                    session_id=str(auth_session.id),
                    ver_config_id=auth_session.ver_config_id,
                    phase="qr_scan",
                    timeout_seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME,
                )

                await notify(str(auth_session.id), "expired")

                # Send problem report for expired presentation in connection-based flow
                if (
                    settings.USE_CONNECTION_BASED_VERIFICATION
                    and auth_session.pres_exch_id
                ):
                    await _send_problem_report_safely(
                        client,
                        auth_session.pres_exch_id,
                        f"Presentation expired: timeout after {settings.CONTROLLER_PRESENTATION_EXPIRE_TIME} seconds",
                    )

                await _cleanup__connection(
                    client, auth_session, pres_ex_id, "expiration"
                )

            pass
        case _:
            logger.debug("skipping webhook")

    return {}
