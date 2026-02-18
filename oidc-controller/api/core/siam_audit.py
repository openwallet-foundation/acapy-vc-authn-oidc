"""
SIAM Audit Logger - Privacy-Preserving Audit Events

This module provides structured logging for SIAM (Security Information and
Analytics Management) platforms while maintaining the privacy-preserving
principles of verifiable credentials.

PRIVACY GUIDELINES:
- NEVER log attribute values (given_names, email, etc.) - they contain PII
- NEVER log subject identifiers (sub claim) - enables user tracking
- NEVER log presentation data/revealed attributes - credential contents
- NEVER log consistent identifier hashes - allows user correlation
- DO log credential metadata (schema names, issuer DIDs)
- DO log session lifecycle events with ephemeral session IDs
- DO log aggregate counts and durations
- DO log anonymized client information (hashed IPs)
"""

import hashlib
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, Optional

import structlog

if TYPE_CHECKING:
    from ..authSessions.models import AuthSession
    from ..verificationConfigs.models import VerificationConfig

logger = structlog.getLogger("siam.audit")


def _strtobool(val: str | bool) -> bool:
    """Convert a string representation of truth to a boolean."""
    if isinstance(val, bool):
        return val
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return True
    elif val in ("n", "no", "f", "false", "off", "0"):
        return False
    else:
        raise ValueError(f"invalid truth value {val}")


# Feature flag: set SIAM_AUDIT_ENABLED=false to disable SIAM audit logging.
# Enabled by default.
SIAM_AUDIT_ENABLED: bool = _strtobool(
    os.environ.get("SIAM_AUDIT_ENABLED", "true")
)

# Salt for IP anonymization - should be rotated periodically
# In production, load from environment or secrets manager
_IP_ANONYMIZATION_SALT = os.environ.get(
    "SIAM_IP_SALT", "vc-authn-oidc-default-salt-rotate-me"
)

# Audit event types
AuditEventType = Literal[
    # Session lifecycle
    "auth_session_initiated",
    "auth_session_completed",
    # Proof request flow
    "proof_request_created",
    "qr_scanned",
    "wallet_connected",
    "proof_submitted",
    "proof_verified",
    "proof_verification_failed",
    # Session termination
    "session_timeout",
    "session_expired",
    "session_abandoned",
    # Token flow
    "token_issued",
    # Security events
    "invalid_client_request",
    "webhook_received",
]

# Outcome categories
OutcomeType = Literal[
    "verified",
    "failed",
    "expired",
    "abandoned",
    "timeout",
]

# Failure categories (safe to log - no PII)
FailureCategoryType = Literal[
    "revoked",
    "expired_credential",
    "invalid_signature",
    "missing_attributes",
    "schema_mismatch",
    "issuer_not_trusted",
    "predicate_not_satisfied",
    "unknown",
]


def _anonymize_ip(ip: Optional[str]) -> Optional[str]:
    """
    One-way hash of IP address for fraud detection without tracking.

    Returns a truncated hash that allows detection of repeated IPs
    without enabling full IP reconstruction.
    """
    if not ip:
        return None
    # Use first 16 chars of SHA256 - sufficient for anomaly detection
    return hashlib.sha256(f"{ip}{_IP_ANONYMIZATION_SALT}".encode()).hexdigest()[:16]


def _extract_user_agent_family(user_agent: Optional[str]) -> Optional[str]:
    """
    Extract generic browser/client family from User-Agent string.

    Returns generic identifiers like 'Chrome', 'Safari', 'Mobile'
    rather than full UA strings which could fingerprint users.
    """
    if not user_agent:
        return None

    ua_lower = user_agent.lower()

    # Check for common browsers (order matters for accuracy)
    if "edg" in ua_lower:
        return "Edge"
    elif "chrome" in ua_lower:
        return "Chrome"
    elif "safari" in ua_lower:
        return "Safari"
    elif "firefox" in ua_lower:
        return "Firefox"
    elif "opera" in ua_lower or "opr" in ua_lower:
        return "Opera"
    elif "mobile" in ua_lower:
        return "Mobile"
    elif "bot" in ua_lower or "crawler" in ua_lower:
        return "Bot"
    else:
        return "Other"


def _extract_schema_names(ver_config: "VerificationConfig") -> list[str]:
    """
    Extract schema names from verification config.

    Schema names are safe metadata - they describe what type of credential
    is being requested, not the actual credential contents.
    """
    schemas = set()
    for attr in ver_config.proof_request.requested_attributes:
        for restriction in attr.restrictions:
            if restriction.schema_name:
                schemas.add(restriction.schema_name)
    return sorted(list(schemas))


def _extract_issuer_dids(ver_config: "VerificationConfig") -> list[str]:
    """
    Extract issuer DIDs from verification config restrictions.

    Issuer DIDs are public identifiers - safe to log for ecosystem analytics.
    """
    issuers = set()
    for attr in ver_config.proof_request.requested_attributes:
        for restriction in attr.restrictions:
            if restriction.issuer_did:
                issuers.add(restriction.issuer_did)
            if restriction.schema_issuer_did:
                issuers.add(restriction.schema_issuer_did)
    return sorted(list(issuers))


def audit_event(
    event: AuditEventType,
    *,
    session_id: Optional[str] = None,
    client_id: Optional[str] = None,
    ver_config_id: Optional[str] = None,
    outcome: Optional[OutcomeType] = None,
    failure_category: Optional[FailureCategoryType] = None,
    duration_ms: Optional[int] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    **extra_safe_fields,
) -> None:
    """
    Log a privacy-preserving audit event for SIAM collection.

    This function ensures consistent event structure and privacy guarantees.

    Args:
        event: The type of audit event (from AuditEventType)
        session_id: Ephemeral session identifier (safe - per-request only)
        client_id: OIDC client/relying party identifier
        ver_config_id: Verification configuration identifier
        outcome: Session outcome category
        failure_category: Category of failure (if applicable)
        duration_ms: Processing duration in milliseconds
        client_ip: Client IP (will be anonymized via hashing)
        user_agent: User-Agent header (will be reduced to family only)
        **extra_safe_fields: Additional fields (caller must ensure privacy)

    WARNING: Never pass PII, attribute values, or subject identifiers
    to this function. All extra_safe_fields must be privacy-safe.
    """
    if not SIAM_AUDIT_ENABLED:
        return

    log_data = {
        "audit_event_type": event,
        "timestamp": datetime.now(UTC).isoformat(),
        "service": "vc-authn-oidc",
        # Session context
        "session_id": session_id,
        "client_id": client_id,
        "ver_config_id": ver_config_id,
        # Outcome
        "outcome": outcome,
        "failure_category": failure_category,
        "duration_ms": duration_ms,
        # Anonymized client info
        "client_ip_hash": _anonymize_ip(client_ip),
        "user_agent_family": _extract_user_agent_family(user_agent),
    }

    # Merge extra fields (caller responsible for privacy)
    log_data.update(extra_safe_fields)

    # Remove None values for cleaner logs
    log_data = {k: v for k, v in log_data.items() if v is not None}

    logger.info(f"audit_{event}", **log_data)


def audit_auth_session_initiated(
    session_id: str,
    client_id: str,
    ver_config: "VerificationConfig",
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Log when an authentication session is initiated."""
    audit_event(
        "auth_session_initiated",
        session_id=session_id,
        client_id=client_id,
        ver_config_id=ver_config.ver_config_id,
        client_ip=client_ip,
        user_agent=user_agent,
        requested_schemas=_extract_schema_names(ver_config),
        requested_attributes_count=len(ver_config.proof_request.requested_attributes),
        requested_predicates_count=len(ver_config.proof_request.requested_predicates),
    )


def audit_proof_request_created(
    session_id: str,
    ver_config: "VerificationConfig",
    proof_name: Optional[str] = None,
) -> None:
    """Log when a proof request is created and ready for scanning."""
    audit_event(
        "proof_request_created",
        session_id=session_id,
        ver_config_id=ver_config.ver_config_id,
        proof_name=proof_name or ver_config.proof_request.name,
        requested_schemas=_extract_schema_names(ver_config),
        expected_issuers=_extract_issuer_dids(ver_config),
    )


def audit_qr_scanned(
    session_id: str,
    scan_method: Literal["qr_code", "deep_link"],
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> None:
    """Log when QR code is scanned or deep link is invoked."""
    audit_event(
        "qr_scanned",
        session_id=session_id,
        scan_method=scan_method,
        client_ip=client_ip,
        user_agent=user_agent,
    )


def audit_proof_verified(
    session_id: str,
    ver_config_id: str,
    credential_schemas: list[str],
    issuer_dids: list[str],
    duration_ms: Optional[int] = None,
    revocation_checked: bool = False,
) -> None:
    """
    Log successful proof verification.

    Only logs credential metadata (schemas, issuers) - never attribute values.
    """
    audit_event(
        "proof_verified",
        session_id=session_id,
        ver_config_id=ver_config_id,
        outcome="verified",
        duration_ms=duration_ms,
        credential_schemas=credential_schemas,
        issuer_dids=issuer_dids,
        credential_count=len(credential_schemas),
        revocation_checked=revocation_checked,
    )


def audit_proof_verification_failed(
    session_id: str,
    ver_config_id: str,
    failure_category: FailureCategoryType = "unknown",
    duration_ms: Optional[int] = None,
) -> None:
    """Log failed proof verification with categorized failure reason."""
    audit_event(
        "proof_verification_failed",
        session_id=session_id,
        ver_config_id=ver_config_id,
        outcome="failed",
        failure_category=failure_category,
        duration_ms=duration_ms,
    )


def audit_session_abandoned(
    session_id: str,
    ver_config_id: str,
    phase: Literal[
        "qr_scan", "wallet_response", "proof_submission"
    ] = "wallet_response",
    duration_ms: Optional[int] = None,
) -> None:
    """Log when user abandons/declines the proof request."""
    audit_event(
        "session_abandoned",
        session_id=session_id,
        ver_config_id=ver_config_id,
        outcome="abandoned",
        phase=phase,
        duration_ms=duration_ms,
    )


def audit_session_expired(
    session_id: str,
    ver_config_id: str,
    phase: Literal["qr_scan", "wallet_response", "proof_submission"] = "qr_scan",
    timeout_seconds: Optional[int] = None,
) -> None:
    """Log when session expires due to timeout."""
    audit_event(
        "session_expired",
        session_id=session_id,
        ver_config_id=ver_config_id,
        outcome="expired",
        phase=phase,
        timeout_seconds=timeout_seconds,
    )


def audit_token_issued(
    session_id: str,
    client_id: str,
    ver_config_id: str,
    claims_count: int,
    duration_ms: Optional[int] = None,
) -> None:
    """
    Log successful token issuance.

    Only logs the count of claims, never the claim names or values.
    """
    audit_event(
        "token_issued",
        session_id=session_id,
        client_id=client_id,
        ver_config_id=ver_config_id,
        claims_count=claims_count,
        duration_ms=duration_ms,
    )


def audit_webhook_received(
    topic: str,
    state: Optional[str] = None,
    role: Optional[str] = None,
) -> None:
    """Log agent webhook receipt for monitoring."""
    audit_event(
        "webhook_received",
        webhook_topic=topic,
        webhook_state=state,
        webhook_role=role,
    )


def audit_invalid_client_request(
    client_id: Optional[str],
    error_type: str,
    client_ip: Optional[str] = None,
) -> None:
    """Log invalid client requests for security monitoring."""
    audit_event(
        "invalid_client_request",
        client_id=client_id,
        error_type=error_type,
        client_ip=client_ip,
    )
