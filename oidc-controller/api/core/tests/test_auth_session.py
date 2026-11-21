import pytest
from api.authSessions.models import AuthSession, AuthSessionState
from api.core.auth_session import (
    Abandoned,
    Event,
    Expired,
    Failed,
    RequestSent,
    Scanned,
    Verified,
    apply,
)


def _session() -> AuthSession:
    return AuthSession(
        ver_config_id="test-config",
        request_parameters={},
        pyop_auth_code="test-code",
        response_url="http://test.com/callback",
    )


@pytest.mark.parametrize(
    ("event", "status"),
    [
        (Scanned(), AuthSessionState.PENDING),
        (Failed(), AuthSessionState.FAILED),
        (Abandoned(), AuthSessionState.ABANDONED),
        (Expired(), AuthSessionState.EXPIRED),
    ],
)
def test_apply_sets_status_without_changing_the_input(
    event: Event, status: AuthSessionState
):
    session = _session()

    result = apply(session, event)

    assert result.proof_status is status
    assert session.proof_status is AuthSessionState.NOT_STARTED
    assert result.id == session.id


def test_verified_stores_the_presentation():
    presentation = {"pres": {"indy": {}}}

    result = apply(_session(), Verified(presentation))

    assert result.proof_status is AuthSessionState.VERIFIED
    assert result.presentation_exchange == presentation


def test_request_sent_records_the_exchange_and_keeps_the_status():
    session = apply(_session(), Scanned())

    result = apply(session, RequestSent("pres-ex-1", {"state": "x"}, "conn-1"))

    assert result.pres_exch_id == "pres-ex-1"
    assert result.presentation_exchange == {"state": "x"}
    assert result.connection_id == "conn-1"
    assert result.proof_status is AuthSessionState.PENDING
