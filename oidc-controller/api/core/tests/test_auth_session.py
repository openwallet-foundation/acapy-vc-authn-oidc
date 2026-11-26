from datetime import UTC, datetime, timedelta

import pytest
from api.authSessions.models import AuthSession, AuthSessionState
from api.core.auth_session import (
    Abandoned,
    Event,
    Expired,
    Failed,
    Rejected,
    RequestSent,
    Scanned,
    Verified,
    _updated,
    apply,
)
from hypothesis import given
from hypothesis import strategies as st

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)


def _session(**fields: object) -> AuthSession:
    return AuthSession(
        **fields,
        ver_config_id="test-config",
        request_parameters={},
        pyop_auth_code="test-code",
        response_url="http://test.com/callback",
    )


PAST = NOW - timedelta(minutes=1)
FINAL_STATES = [
    AuthSessionState.VERIFIED,
    AuthSessionState.FAILED,
    AuthSessionState.ABANDONED,
    AuthSessionState.EXPIRED,
]
ALL_EVENTS: list[Event] = [
    Scanned(),
    RequestSent("pres-ex-1", {}, "conn-1"),
    Verified({}),
    Failed(),
    Abandoned(),
    Expired(NOW),
]


def _applied(session: AuthSession, event: Event) -> AuthSession:
    result = apply(session, event)
    assert isinstance(result, AuthSession)
    return result


@pytest.mark.parametrize(
    ("event", "status"),
    [
        (Scanned(), AuthSessionState.PENDING),
        (Failed(), AuthSessionState.FAILED),
        (Abandoned(), AuthSessionState.ABANDONED),
        (Expired(NOW), AuthSessionState.EXPIRED),
    ],
)
def test_apply_sets_status_without_changing_the_input(
    event: Event, status: AuthSessionState
):
    session = _session(expired_timestamp=PAST)

    result = _applied(session, event)

    assert result.proof_status is status
    assert session.proof_status is AuthSessionState.NOT_STARTED
    assert result.id == session.id


def test_verified_stores_the_presentation():
    presentation = {"pres": {"indy": {}}}

    result = _applied(_session(), Verified(presentation))

    assert result.proof_status is AuthSessionState.VERIFIED
    assert result.presentation_exchange == presentation


@pytest.mark.parametrize("event", [Verified({}), Failed(), Abandoned()])
def test_pending_sessions_can_finish(event: Event):
    pending = _applied(_session(), Scanned())

    assert isinstance(apply(pending, event), AuthSession)


def test_request_sent_records_the_exchange_and_keeps_the_status():
    session = _applied(_session(), Scanned())

    result = _applied(session, RequestSent("pres-ex-1", {"state": "x"}, "conn-1"))

    assert result.pres_exch_id == "pres-ex-1"
    assert result.presentation_exchange == {"state": "x"}
    assert result.connection_id == "conn-1"
    assert result.proof_status is AuthSessionState.PENDING


@pytest.mark.parametrize("status", FINAL_STATES)
@pytest.mark.parametrize("event", ALL_EVENTS)
def test_final_states_reject_every_event(status: AuthSessionState, event: Event):
    session = _session(proof_status=status, expired_timestamp=PAST)

    assert apply(session, event) == Rejected(f"session is already {status}")


def test_a_second_scan_is_rejected():
    pending = _applied(_session(), Scanned())

    assert apply(pending, Scanned()) == Rejected("already scanned")


def test_expired_is_rejected_before_the_deadline():
    session = _session(expired_timestamp=NOW + timedelta(minutes=1))

    assert apply(session, Expired(NOW)) == Rejected("session has not expired")


def test_pending_sessions_do_not_expire():
    pending = _applied(_session(expired_timestamp=PAST), Scanned())

    assert apply(pending, Expired(NOW)) == Rejected("session has not expired")


def test_apply_validates_the_new_session():
    # Event fields are only checked by the type checker, so a bad value must
    # fail here rather than reach the database.
    session = _session(pres_exch_id="before")

    with pytest.raises(ValueError):
        apply(session, RequestSent(123, {}, "conn-1"))  # type: ignore[arg-type]


def test_misspelled_fields_are_not_silently_dropped():
    with pytest.raises(ValueError, match="proof_statu"):
        _updated(_session(), {"proof_statu": AuthSessionState.PENDING})


def test_naive_deadlines_are_read_as_utc():
    # MongoDB returns naive UTC datetimes, whatever the server's local timezone
    deadline = (NOW - timedelta(minutes=1)).replace(tzinfo=None)

    result = _applied(_session(expired_timestamp=deadline), Expired(NOW))

    assert result.proof_status is AuthSessionState.EXPIRED


# Property tests: random event sequences instead of hand-picked cases.

_FINISHES = {
    Verified: AuthSessionState.VERIFIED,
    Failed: AuthSessionState.FAILED,
    Abandoned: AuthSessionState.ABANDONED,
    Expired: AuthSessionState.EXPIRED,
}
_RANK = {AuthSessionState.NOT_STARTED: 0, AuthSessionState.PENDING: 1} | dict.fromkeys(
    FINAL_STATES, 2
)
_offsets = st.timedeltas(min_value=timedelta(hours=-1), max_value=timedelta(hours=1))
_events: st.SearchStrategy[Event] = st.one_of(
    st.just(Scanned()),
    st.builds(RequestSent, st.text(max_size=5), st.just({}), st.text(max_size=5)),
    st.just(Verified({})),
    st.just(Failed()),
    st.just(Abandoned()),
    _offsets.map(lambda offset: Expired(NOW + offset)),
)
_sessions = st.builds(
    lambda status, offset: _session(
        proof_status=status, expired_timestamp=NOW + offset
    ),
    st.sampled_from([AuthSessionState.NOT_STARTED, AuthSessionState.PENDING]),
    _offsets,
)


@given(_sessions, st.lists(_events, max_size=12))
def test_event_sequences_finish_at_most_once(session: AuthSession, events: list[Event]):
    finished = 0
    for event in events:
        before = session.model_dump()
        result = apply(session, event)

        assert session.model_dump() == before
        if isinstance(result, Rejected):
            continue
        assert session.proof_status not in FINAL_STATES
        assert _RANK[result.proof_status] >= _RANK[session.proof_status]
        if (finish := _FINISHES.get(type(event))) is not None:
            assert result.proof_status is finish
            finished += 1
        session = result

    assert finished <= 1


@given(st.sampled_from(FINAL_STATES), st.lists(_events, max_size=12))
def test_final_states_are_absorbing(status: AuthSessionState, events: list[Event]):
    session = _session(proof_status=status, expired_timestamp=NOW)

    assert all(isinstance(apply(session, event), Rejected) for event in events)
