import json
import time
from datetime import UTC, datetime, timedelta

import structlog
from fastapi import APIRouter, Depends, Request
from pydantic.plugin import Any
from pymongo.database import Database

from ..authSessions.crud import AuthSessionCRUD
from ..authSessions.models import AuthSession, AuthSessionPatch, AuthSessionState
from ..core.acapy.client import AcapyClient
from ..core.config import settings
from ..core.siam_audit import (
    audit_proof_verification_failed,
    audit_proof_verified,
    audit_session_abandoned,
    audit_session_expired,
    audit_webhook_received,
)
from ..db.session import get_db
from ..routers.socketio import get_socket_id_for_pid, safe_emit, sio
from ..verificationConfigs.crud import VerificationConfigCRUD

logger: structlog.typing.FilteringBoundLogger = structlog.getLogger(__name__)

router = APIRouter()


def _extract_credential_schemas(presentation_data: dict) -> list[str]:
    """
    Extract schema names from verified presentation data.

    Safe to log - schema names are public metadata, not PII.
    """
    schemas = set()
    try:
        # Try to extract from various proof formats
        by_format = presentation_data.get("by_format", {})
        for format_key in ["indy", "anoncreds"]:
            if format_key in by_format:
                pres = by_format[format_key].get("pres", {})
                identifiers = pres.get("identifiers", [])
                for identifier in identifiers:
                    if schema_id := identifier.get("schema_id"):
                        # Extract schema name from schema_id (format: did:schema_name:version)
                        parts = schema_id.split(":")
                        if len(parts) >= 3:
                            schemas.add(parts[-2])  # schema name is second to last
                        else:
                            schemas.add(schema_id)
    except Exception:
        pass  # Return empty list if extraction fails
    return sorted(list(schemas))


def _extract_issuer_dids(presentation_data: dict) -> list[str]:
    """
    Extract issuer DIDs from verified presentation data.

    Safe to log - DIDs are public identifiers, not PII.
    """
    issuers = set()
    try:
        by_format = presentation_data.get("by_format", {})
        for format_key in ["indy", "anoncreds"]:
            if format_key in by_format:
                pres = by_format[format_key].get("pres", {})
                identifiers = pres.get("identifiers", [])
                for identifier in identifiers:
                    if cred_def_id := identifier.get("cred_def_id"):
                        # Extract issuer DID from cred_def_id (format: did:3:CL:schema:tag)
                        parts = cred_def_id.split(":")
                        if len(parts) >= 1:
                            issuers.add(parts[0])
    except Exception:
        pass  # Return empty list if extraction fails
    return sorted(list(issuers))


async def _send_problem_report_safely(
    client: AcapyClient, pres_ex_id: str, description: str
) -> None:
    """Send a problem report with error handling."""
    try:
        client.send_problem_report(pres_ex_id, description)
        logger.info(f"Problem report sent for pres_ex_id: {pres_ex_id}")
    except Exception as e:
        logger.error(f"Failed to send problem report: {e}")


async def _cleanup_presentation_and_connection(
    auth_session: AuthSession, pres_ex_id: str, context: str
) -> None:
    """Clean up presentation record and connection (if applicable) with proper error handling."""
    # Determine if connection should also be deleted based on verification type and multi-use flag
    connection_id_to_delete = (
        auth_session.connection_id
        if (
            settings.USE_CONNECTION_BASED_VERIFICATION
            and auth_session.connection_id
            and not auth_session.multi_use  # Only delete single-use connections
        )
        else None
    )

    try:
        client = AcapyClient()
        presentation_deleted, connection_deleted, errors = (
            client.delete_presentation_record_and_connection(
                pres_ex_id, connection_id_to_delete
            )
        )

        # Log results for presentation cleanup
        if presentation_deleted:
            logger.info(
                f"Successfully cleaned up presentation record {pres_ex_id} after {context}"
            )
        else:
            logger.warning(
                f"Failed to cleanup presentation record {pres_ex_id} after {context} - will be handled by background cleanup"
            )

        # Log results for connection cleanup (if attempted)
        if connection_deleted:
            logger.info(
                f"Successfully cleaned up single-use connection {connection_id_to_delete} after {context}"
            )
        elif connection_id_to_delete:
            logger.warning(
                f"Failed to cleanup single-use connection {connection_id_to_delete} after {context}"
            )
        elif (
            settings.USE_CONNECTION_BASED_VERIFICATION
            and auth_session.connection_id
            and auth_session.multi_use
        ):
            logger.info(
                f"Preserving multi-use connection {auth_session.connection_id} after {context}"
            )

        # Log any errors from the cleanup operation
        if errors:
            logger.warning(f"{context.capitalize()} cleanup errors: {errors}")

    except Exception as cleanup_error:
        logger.warning(
            f"Cleanup failed for presentation record {pres_ex_id} after {context}: {cleanup_error} - will be handled by background cleanup"
        )


async def _update_auth_session(db: Database, auth_session: AuthSession) -> None:
    """Update auth session in database with error handling."""
    await AuthSessionCRUD(db).patch(
        str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
    )


async def _emit_status_to_socket(
    db: Database, auth_session: AuthSession, status: str
) -> None:
    """Emit status update to socket if session ID exists."""
    pid = str(auth_session.id)
    sid = await get_socket_id_for_pid(pid, db)
    if sid:
        await safe_emit("status", {"status": status}, to=sid)


async def _parse_webhook_body(request: Request) -> dict[Any, Any]:
    return json.loads((await request.body()).decode("ascii"))


@router.post("/topic/{topic}/")
async def post_topic(request: Request, topic: str, db: Database = Depends(get_db)):
    """Called by aca-py agent."""
    webhook_start_time = time.time()
    logger.info(f">>> post_topic : topic={topic}")
    # Note: Full webhook body is logged at DEBUG level only to protect privacy
    logger.debug(f">>> web hook received for topic: {topic}")

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
                    # Connection established, now send presentation request
                    connection_id = webhook_body.get("connection_id")
                    invitation_msg_id = webhook_body.get("invitation_msg_id")

                    logger.debug(f"Full webhook body: {webhook_body}")
                    logger.debug(f"Available keys: {list(webhook_body.keys())}")

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
                            f"Trying to find auth session by pres_exch_id pattern: {search_id}"
                        )
                        try:
                            auth_session = await AuthSessionCRUD(
                                db
                            ).get_by_pres_exch_id(f"{search_id}")
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
                                await _update_auth_session(db, auth_session)

                                logger.info(
                                    f"Presentation request sent successfully: {pres_response.pres_ex_id}"
                                )
                            except Exception as e:
                                logger.error(
                                    f"Failed to send presentation request: {e}"
                                )
                                # Set auth session to failed state
                                auth_session.proof_status = AuthSessionState.FAILED
                                await _update_auth_session(db, auth_session)

                                # Send problem report if we have a presentation exchange ID
                                if auth_session.pres_exch_id:
                                    await _send_problem_report_safely(
                                        client,
                                        auth_session.pres_exch_id,
                                        f"Failed to send presentation request: {str(e)}",
                                    )

                                # Emit failure status to frontend
                                await _emit_status_to_socket(db, auth_session, "failed")
                        else:
                            logger.debug(
                                f"Auth session found but no proof_request: {auth_session.id}"
                            )
                    else:
                        logger.debug(
                            f"No auth session found for invitation_msg_id: {invitation_msg_id}"
                        )

        case "present_proof_v2_0":
            webhook_body = await _parse_webhook_body(request)
            state = webhook_body.get("state")
            role = webhook_body.get("role")

            # SIAM Audit: Log webhook receipt (safe metadata only)
            audit_webhook_received(
                topic="present_proof_v2_0",
                state=state,
                role=role,
            )

            logger.info(
                f">>>> pres_exch_id: {webhook_body['pres_ex_id']}, state: {state}"
            )

            # Check for prover-role (issue #898)

            if role == "prover":
                # Handle prover-role separately - VC-AuthN is responding to a proof request
                pres_ex_id = webhook_body.get("pres_ex_id")
                connection_id = webhook_body.get("connection_id")
                state = webhook_body.get("state")

                deleted = False
                delete_error = None

                # Clean up presentation records in terminal states
                if pres_ex_id and state in ["done", "abandoned", "declined"]:
                    try:
                        deleted = AcapyClient().delete_presentation_record(pres_ex_id)
                        if not deleted:
                            logger.warning(
                                f"Failed to delete prover-role presentation record",
                                pres_ex_id=pres_ex_id,
                                state=state,
                            )
                    except Exception as e:
                        delete_error = str(e)
                        logger.error(
                            f"Error deleting prover-role presentation record",
                            pres_ex_id=pres_ex_id,
                            error=delete_error,
                        )

                logger.info(
                    f"Prover-role webhook received: {state}",
                    pres_ex_id=pres_ex_id,
                    connection_id=connection_id,
                    deleted=deleted,
                    delete_error=delete_error,
                    role=role,
                    state=state,
                    timestamp=datetime.now(UTC).isoformat(),
                )

                # Return early - do NOT trigger verifier-role logic or cleanup
                return {"status": "prover-role event logged"}

            # Existing verifier-role code continues below...
            auth_session: AuthSession = await AuthSessionCRUD(db).get_by_pres_exch_id(
                webhook_body["pres_ex_id"]
            )

            # Get the saved websocket session
            pid = str(auth_session.id)
            sid = await get_socket_id_for_pid(pid, db)
            logger.debug(f"sid: {sid} found for pid: {pid}")

            if webhook_body["state"] == "presentation-received":
                logger.info("presentation-received")

            if webhook_body["state"] == "done":
                duration_ms = int((time.time() - webhook_start_time) * 1000)

                if webhook_body["verified"] == "true":
                    logger.info("VERIFIED")
                    auth_session.proof_status = AuthSessionState.VERIFIED

                    # Get presentation data via API call instead of webhook payload
                    client = AcapyClient()
                    presentation_data = client.get_presentation_request(
                        webhook_body["pres_ex_id"]
                    )

                    if not presentation_data:
                        raise ValueError(
                            f"Failed to retrieve presentation data for {webhook_body['pres_ex_id']} - record may have been deleted or is inaccessible"
                        )

                    auth_session.presentation_exchange = presentation_data.get(
                        "by_format", {}
                    )
                    logger.debug(
                        f"Retrieved presentation data via API for {webhook_body['pres_ex_id']}"
                    )

                    # SIAM Audit: Log successful verification (metadata only, no PII)
                    # Extract schema names from presentation for audit
                    credential_schemas = _extract_credential_schemas(presentation_data)
                    issuer_dids = _extract_issuer_dids(presentation_data)

                    audit_proof_verified(
                        session_id=str(auth_session.id),
                        ver_config_id=auth_session.ver_config_id,
                        credential_schemas=credential_schemas,
                        issuer_dids=issuer_dids,
                        duration_ms=duration_ms,
                        revocation_checked=settings.SET_NON_REVOKED,
                    )

                    # Cleanup presentation record and connection after successful verification
                    await _cleanup_presentation_and_connection(
                        auth_session,
                        webhook_body["pres_ex_id"],
                        "successful verification",
                    )

                    await _emit_status_to_socket(db, auth_session, "verified")
                else:
                    logger.info("VERIFICATION FAILED")
                    auth_session.proof_status = AuthSessionState.FAILED

                    # SIAM Audit: Log failed verification
                    audit_proof_verification_failed(
                        session_id=str(auth_session.id),
                        ver_config_id=auth_session.ver_config_id,
                        failure_category="unknown",  # ACA-Py doesn't provide detailed failure reason
                        duration_ms=duration_ms,
                    )

                    await _emit_status_to_socket(db, auth_session, "failed")

                    # Send problem report for failed verification in connection-based flow
                    if (
                        settings.USE_CONNECTION_BASED_VERIFICATION
                        and auth_session.pres_exch_id
                    ):
                        client = AcapyClient()
                        await _send_problem_report_safely(
                            client,
                            auth_session.pres_exch_id,
                            f"Presentation verification failed: {webhook_body.get('error_msg', 'Unknown error')}",
                        )

                await _update_auth_session(db, auth_session)

                # Connection cleanup is now handled above in the combined cleanup operation

            # abandoned state
            if webhook_body["state"] == "abandoned":
                logger.info("ABANDONED")
                # Note: error_msg may contain sensitive info, log at debug level only
                logger.debug(
                    f"Abandonment reason: {webhook_body.get('error_msg', 'No reason provided')}"
                )
                auth_session.proof_status = AuthSessionState.ABANDONED

                # SIAM Audit: Log session abandonment
                duration_ms = int((time.time() - webhook_start_time) * 1000)
                audit_session_abandoned(
                    session_id=str(auth_session.id),
                    ver_config_id=auth_session.ver_config_id,
                    phase="wallet_response",
                    duration_ms=duration_ms,
                )

                await _emit_status_to_socket(db, auth_session, "abandoned")

                # Send problem report for abandoned presentation in connection-based flow
                if (
                    settings.USE_CONNECTION_BASED_VERIFICATION
                    and auth_session.pres_exch_id
                ):
                    client = AcapyClient()
                    await _send_problem_report_safely(
                        client,
                        auth_session.pres_exch_id,
                        f"Presentation abandoned: {webhook_body.get('error_msg', 'Unknown error')}",
                    )

                await _update_auth_session(db, auth_session)

                # Cleanup presentation record and connection after abandonment
                await _cleanup_presentation_and_connection(
                    auth_session, webhook_body["pres_ex_id"], "abandonment"
                )

            # Calcuate the expiration time of the proof
            now_time = datetime.now(UTC)
            expired_time = now_time + timedelta(
                seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME
            )

            # Update the expiration time of the proof
            auth_session.expired_timestamp = expired_time
            await AuthSessionCRUD(db).patch(
                str(auth_session.id), AuthSessionPatch(**auth_session.model_dump())
            )

            # Check if expired. But only if the proof has not been started.
            # Handle comparison between timezone-aware and naive datetimes
            if auth_session.expired_timestamp.tzinfo is not None:
                # Use timezone-aware comparison if database has timezone-aware timestamp
                expired_time = datetime.now(UTC) + timedelta(
                    seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME
                )
                now_time = datetime.now(UTC)

            if (
                expired_time < now_time
                and auth_session.proof_status == AuthSessionState.NOT_STARTED
            ):
                logger.info("EXPIRED")
                auth_session.proof_status = AuthSessionState.EXPIRED

                # SIAM Audit: Log session expiration
                audit_session_expired(
                    session_id=str(auth_session.id),
                    ver_config_id=auth_session.ver_config_id,
                    phase="qr_scan",
                    timeout_seconds=settings.CONTROLLER_PRESENTATION_EXPIRE_TIME,
                )

                await _emit_status_to_socket(db, auth_session, "expired")

                # Send problem report for expired presentation in connection-based flow
                if (
                    settings.USE_CONNECTION_BASED_VERIFICATION
                    and auth_session.pres_exch_id
                ):
                    client = AcapyClient()
                    await _send_problem_report_safely(
                        client,
                        auth_session.pres_exch_id,
                        f"Presentation expired: timeout after {settings.CONTROLLER_PRESENTATION_EXPIRE_TIME} seconds",
                    )

                await _update_auth_session(db, auth_session)

                # Cleanup presentation record and connection after expiration
                await _cleanup_presentation_and_connection(
                    auth_session, auth_session.pres_exch_id, "expiration"
                )

            pass
        case _:
            logger.debug("skipping webhook")

    return {}
