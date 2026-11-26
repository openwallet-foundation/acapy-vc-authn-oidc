from unittest.mock import AsyncMock

from api.authSessions.models import AuthSession
from api.core.auth_session import Event, Rejected, apply


def fake_advance() -> AsyncMock:
    """Stand-in for AuthSessionCRUD.advance that applies the event without a database."""

    async def advance(session: AuthSession, event: Event) -> AuthSession | Rejected:
        return apply(session, event)

    return AsyncMock(side_effect=advance)


def saved_sessions(advance: AsyncMock) -> list[AuthSession]:
    """The sessions ADVANCE saved, skipping the calls it rejected."""
    applied = (apply(*call.args) for call in advance.call_args_list)
    return [after for after in applied if isinstance(after, AuthSession)]


def saved_session(advance: AsyncMock) -> AuthSession:
    """The session the last accepted advance call saved."""
    saved = saved_sessions(advance)
    assert saved, "advance saved nothing"
    return saved[-1]
