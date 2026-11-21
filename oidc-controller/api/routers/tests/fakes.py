from unittest.mock import AsyncMock

from api.authSessions.models import AuthSession
from api.core.auth_session import Event, Rejected, apply


def fake_advance() -> AsyncMock:
    """Stand-in for AuthSessionCRUD.advance that applies the event without a database."""

    async def advance(session: AuthSession, event: Event) -> AuthSession | None:
        after = apply(session, event)
        return None if isinstance(after, Rejected) else after

    return AsyncMock(side_effect=advance)


def saved_session(advance: AsyncMock) -> AuthSession:
    """The session the last advance call saved."""
    after = apply(*advance.call_args.args)
    assert isinstance(after, AuthSession)
    return after
