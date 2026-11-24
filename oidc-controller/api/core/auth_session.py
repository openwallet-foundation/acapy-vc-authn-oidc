"""Auth session state transitions.

Routers load a session, describe what happened as an event, and save the
session that apply returns. apply never modifies its argument.

A session moves from NOT_STARTED (or PENDING once the wallet has fetched the
request) to exactly one final state: VERIFIED, FAILED, ABANDONED or EXPIRED.
apply returns Rejected for any event that would leave a final state, so a late
or repeated webhook cannot overwrite the outcome.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, assert_never

from api.authSessions.models import AuthSession, AuthSessionState


@dataclass(frozen=True)
class Scanned:
    """The wallet fetched the proof request."""


@dataclass(frozen=True)
class RequestSent:
    """A proof request was sent over an established connection."""

    pres_exch_id: str
    presentation_exchange: dict[str, Any]
    connection_id: str


@dataclass(frozen=True)
class Verified:
    """ACA-Py verified the presentation."""

    presentation: dict[str, Any]


@dataclass(frozen=True)
class Failed:
    """Verification failed or the proof request could not be sent."""


@dataclass(frozen=True)
class Abandoned:
    """The wallet declined or abandoned the presentation."""


@dataclass(frozen=True)
class Expired:
    """The session's deadline passed before the wallet responded."""

    now: datetime


Event = Scanned | RequestSent | Verified | Failed | Abandoned | Expired


@dataclass(frozen=True)
class Rejected:
    """The event is not legal for a session in this state."""

    reason: str


OPEN_STATES = frozenset({AuthSessionState.NOT_STARTED, AuthSessionState.PENDING})
FINAL_STATES = frozenset(AuthSessionState) - OPEN_STATES


def apply(session: AuthSession, event: Event) -> AuthSession | Rejected:
    status = session.proof_status
    if status in FINAL_STATES:
        return Rejected(f"session is already {status}")
    update: dict[str, Any]
    match event:
        case Scanned() if status is AuthSessionState.NOT_STARTED:
            update = {"proof_status": AuthSessionState.PENDING}
        case Scanned():
            return Rejected("already scanned")
        case RequestSent(pres_exch_id, presentation_exchange, connection_id):
            update = {
                "pres_exch_id": pres_exch_id,
                "presentation_exchange": presentation_exchange,
                "connection_id": connection_id,
            }
        case Verified(presentation):
            update = {
                "proof_status": AuthSessionState.VERIFIED,
                "presentation_exchange": presentation,
            }
        case Failed():
            update = {"proof_status": AuthSessionState.FAILED}
        case Abandoned():
            update = {"proof_status": AuthSessionState.ABANDONED}
        case Expired(now) if has_expired(session, now):
            update = {"proof_status": AuthSessionState.EXPIRED}
        case Expired():
            return Rejected("session has not expired")
        case _:
            assert_never(event)
    return _updated(session, update)


def _updated(session: AuthSession, update: dict[str, Any]) -> AuthSession:
    """Copy SESSION with UPDATE applied, validating the result.

    model_copy(update=...) skips validation and accepts unknown keys, so a
    typo would be silently dropped and a wrong type would reach the database.
    """
    unknown = update.keys() - AuthSession.model_fields.keys()
    if unknown:
        raise ValueError(f"Unknown AuthSession fields: {sorted(unknown)}")
    return AuthSession.model_validate({**dict(session), **update})


def as_utc(timestamp: datetime) -> datetime:
    """MongoDB returns naive datetimes, which are in UTC."""
    return timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=UTC)


def has_expired(session: AuthSession, now: datetime) -> bool:
    """Whether the wallet never responded before the session's deadline."""
    return (
        session.proof_status is AuthSessionState.NOT_STARTED
        and as_utc(session.expired_timestamp) < now
    )
