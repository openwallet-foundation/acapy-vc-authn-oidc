from datetime import UTC, datetime, timedelta

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
    has_expired,
)

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _session(**fields: object) -> AuthSession:
    return AuthSession(
        **fields,
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


def test_naive_deadlines_are_read_as_utc():
    # MongoDB returns naive UTC datetimes, whatever the server's local timezone
    deadline = (NOW - timedelta(minutes=1)).replace(tzinfo=None)

    assert has_expired(_session(expired_timestamp=deadline), NOW)


def test_only_sessions_the_wallet_has_not_started_expire():
    past = NOW - timedelta(minutes=1)
    pending = apply(_session(expired_timestamp=past), Scanned())

    assert not has_expired(pending, NOW)


def test_sessions_before_their_deadline_have_not_expired():
    assert not has_expired(_session(expired_timestamp=NOW + timedelta(minutes=1)), NOW)
