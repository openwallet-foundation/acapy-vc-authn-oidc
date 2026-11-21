"""Auth session state transitions.

Routers load a session, describe what happened as an event, and save the
session that apply returns. apply never modifies its argument.
"""

from dataclasses import dataclass
from typing import Any

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
    """The session timed out before the wallet responded."""


Event = Scanned | RequestSent | Verified | Failed | Abandoned | Expired


def apply(session: AuthSession, event: Event) -> AuthSession:
    match event:
        case Scanned():
            update = {"proof_status": AuthSessionState.PENDING}
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
        case Expired():
            update = {"proof_status": AuthSessionState.EXPIRED}
    return session.model_copy(update=update)
