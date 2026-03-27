"""Integration tests: OOB (out-of-band) verification flow.

Full pipeline under test:
  GET  /authorize              → creates AuthSession, returns QR-code HTML
  POST /webhooks/topic/present_proof_v2_0/  → updates AuthSession to VERIFIED
  GET  /sse/status/{pid}       → SSE emits current DB state ("verified")
  GET  /callback?pid={pid}     → 307 redirect to RP with auth code
  POST /token                  → exchanges auth code for access+id tokens
  (assert id_token claims include VC attributes)

AcaPy is mocked via respx; MongoDB is replaced with mongomock.
"""

from unittest.mock import patch

import jwt
import pytest

from .conftest import (
    FAKE_PRES_EX_ID,
    TEST_CLIENT_ID,
    TEST_CLIENT_SECRET,
    TEST_REDIRECT_URI,
    TEST_VER_CONFIG_ID,
    acapy_oob_mock,
    authorize_params,
    basic_auth_header,
    called_paths,
    make_abandoned_webhook,
    make_proof_webhook,
    parse_auth_code_from_url,
    parse_pid_from_html,
    parse_pres_exch_id_from_html,
    parse_sse_status,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Authorize endpoint
# ---------------------------------------------------------------------------


class TestAuthorize:
    def test_authorize_returns_html(self, integration_client, oob_mode):
        """GET /authorize creates an auth session and returns HTML with pid."""
        client, _ = integration_client

        with acapy_oob_mock() as mock_router:
            resp = client.get("/authorize", params=authorize_params())

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        pid = parse_pid_from_html(resp.text)
        assert len(pid) == 24  # MongoDB ObjectId hex length

        # Verify AcaPy was actually called (not silently skipped)
        paths = called_paths(mock_router)
        assert "/present-proof-2.0/create-request" in paths
        assert "/out-of-band/create-invitation" in paths

    def test_authorize_embeds_pres_exch_id(self, integration_client, oob_mode):
        """The HTML response exposes pres_exch_id matching the mocked AcaPy value."""
        client, _ = integration_client

        with acapy_oob_mock(pres_ex_id=FAKE_PRES_EX_ID):
            resp = client.get("/authorize", params=authorize_params())

        assert resp.status_code == 200
        pres_exch_id = parse_pres_exch_id_from_html(resp.text)
        assert pres_exch_id == FAKE_PRES_EX_ID

    def test_authorize_creates_auth_session_in_db(self, integration_client, oob_mode):
        """An AuthSession record is written to DB on /authorize."""
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_oob_mock() as mock_router:
            resp = client.get("/authorize", params=authorize_params())

        assert resp.status_code == 200
        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        assert col.count_documents({}) == 1

        # Verify AcaPy was actually called
        paths = called_paths(mock_router)
        assert "/present-proof-2.0/create-request" in paths
        assert "/out-of-band/create-invitation" in paths

    def test_authorize_unknown_ver_config_returns_404(
        self, integration_client, oob_mode
    ):
        """Unknown pres_req_conf_id returns 404 (ver_config not found)."""
        client, _ = integration_client

        with acapy_oob_mock():
            resp = client.get(
                "/authorize",
                params={**authorize_params(), "pres_req_conf_id": "nonexistent"},
            )

        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Webhook injection
# ---------------------------------------------------------------------------


class TestWebhookInjection:
    def test_present_proof_verified_webhook_updates_db(
        self, integration_client, oob_mode
    ):
        """Injecting a verified present_proof_v2_0 webhook sets proof_status=VERIFIED."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        webhook = make_proof_webhook(FAKE_PRES_EX_ID, verified=True)
        with patch("api.routers.acapy_handler.audit_proof_verified") as mock_audit:
            resp = client.post("/webhooks/topic/present_proof_v2_0/", json=webhook)
        assert resp.status_code == 200

        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        session = col.find_one({"pres_exch_id": FAKE_PRES_EX_ID})
        assert session is not None
        assert session["proof_status"] == AuthSessionState.VERIFIED

        mock_audit.assert_called_once()
        assert mock_audit.call_args.kwargs["ver_config_id"] == TEST_VER_CONFIG_ID

    def test_present_proof_failed_webhook_updates_db(
        self, integration_client, oob_mode
    ):
        """Injecting verified=false sets proof_status=FAILED."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        webhook = make_proof_webhook(FAKE_PRES_EX_ID, verified=False)
        with patch(
            "api.routers.acapy_handler.audit_proof_verification_failed"
        ) as mock_audit:
            resp = client.post("/webhooks/topic/present_proof_v2_0/", json=webhook)
        assert resp.status_code == 200

        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        session = col.find_one({"pres_exch_id": FAKE_PRES_EX_ID})
        assert session["proof_status"] == AuthSessionState.FAILED

        mock_audit.assert_called_once()
        assert mock_audit.call_args.kwargs["ver_config_id"] == TEST_VER_CONFIG_ID

    def test_present_proof_abandoned_webhook_updates_db(
        self, integration_client, oob_mode
    ):
        """Injecting an abandoned webhook sets proof_status=ABANDONED."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        webhook = make_abandoned_webhook(FAKE_PRES_EX_ID)
        with patch("api.routers.acapy_handler.audit_session_abandoned") as mock_audit:
            resp = client.post("/webhooks/topic/present_proof_v2_0/", json=webhook)
        assert resp.status_code == 200

        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        session = col.find_one({"pres_exch_id": FAKE_PRES_EX_ID})
        assert session["proof_status"] == AuthSessionState.ABANDONED

        mock_audit.assert_called_once()
        assert mock_audit.call_args.kwargs["ver_config_id"] == TEST_VER_CONFIG_ID


# ---------------------------------------------------------------------------
# SSE endpoint
# ---------------------------------------------------------------------------


class TestSseAfterWebhook:
    """Verify SSE delivers the correct terminal state when the webhook fires
    BEFORE the browser opens the SSE connection — the typical real-world timing
    for a mobile wallet (slow to scan → proof arrives before the page polls).

    In REDIS_MODE=none, notify() silently drops the in-process signal when no
    SSE subscriber is registered yet (pid not in _signals). Recovery relies on
    the initial DB-state read that _sse_event_loop performs on every connect.
    All tests in this class exercise that fallback path explicitly.
    """

    def test_sse_emits_verified_after_verified_webhook(
        self, integration_client, oob_mode
    ):
        """After a verified webhook, SSE emits 'verified' as the first event."""
        client, _ = integration_client

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
        )

        sse_resp = client.get(f"/sse/status/{pid}")
        assert sse_resp.status_code == 200
        assert parse_sse_status(sse_resp.text) == "verified"

    def test_sse_emits_failed_after_failed_webhook(self, integration_client, oob_mode):
        """After a failed webhook, SSE emits 'failed'."""
        client, _ = integration_client

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
        )

        sse_resp = client.get(f"/sse/status/{pid}")
        assert parse_sse_status(sse_resp.text) == "failed"

    def test_sse_emits_abandoned_after_abandoned_webhook(
        self, integration_client, oob_mode
    ):
        """After an abandoned webhook, SSE emits 'abandoned'."""
        client, _ = integration_client

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_abandoned_webhook(FAKE_PRES_EX_ID),
        )

        sse_resp = client.get(f"/sse/status/{pid}")
        assert parse_sse_status(sse_resp.text) == "abandoned"

    def test_sse_delivers_state_when_notify_signal_was_dropped(
        self, integration_client, oob_mode
    ):
        """Regression: SSE delivers verified state even when notify() dropped the signal.

        In REDIS_MODE=none, notify() only writes to _latest[pid] when a subscriber
        is already connected (pid in _signals). If the webhook fires before the
        browser opens /sse/status, the signal is silently dropped. The SSE
        endpoint must still deliver the correct state via the initial DB read on
        connect. This test pins that contract explicitly.
        """
        client, _ = integration_client

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        # Webhook fires. No SSE subscriber is connected yet, so notify() drops
        # the in-process signal — the session state update is only in the DB.
        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
        )

        # SSE connects after the fact. Must recover via initial DB read.
        sse_resp = client.get(f"/sse/status/{pid}")
        assert sse_resp.status_code == 200
        assert parse_sse_status(sse_resp.text) == "verified"


# ---------------------------------------------------------------------------
# Callback endpoint
# ---------------------------------------------------------------------------


class TestCallback:
    def test_callback_redirects_to_redirect_uri(self, integration_client, oob_mode):
        """GET /callback?pid={pid} returns a 3xx redirect to the RP redirect_uri."""
        client, _ = integration_client

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
        )

        cb_resp = client.get("/callback", params={"pid": pid}, follow_redirects=False)
        assert cb_resp.status_code in (302, 307)
        location = cb_resp.headers["location"]
        assert TEST_REDIRECT_URI in location

    def test_callback_redirect_contains_auth_code(self, integration_client, oob_mode):
        """The redirect Location header contains an authorization code."""
        client, _ = integration_client

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
        )

        cb_resp = client.get("/callback", params={"pid": pid}, follow_redirects=False)
        location = cb_resp.headers["location"]
        auth_code = parse_auth_code_from_url(location)
        assert auth_code  # non-empty


# ---------------------------------------------------------------------------
# Token endpoint
# ---------------------------------------------------------------------------


class TestToken:
    def _run_authorize_and_webhook(self, client):
        """Run the authorize + webhook steps; return (pid, auth_code).

        Caller is responsible for applying oob_mode fixture before calling this.
        """
        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
        )

        cb_resp = client.get("/callback", params={"pid": pid}, follow_redirects=False)
        auth_code = parse_auth_code_from_url(cb_resp.headers["location"])
        return pid, auth_code

    def test_token_returns_access_and_id_token(self, integration_client, oob_mode):
        """POST /token with valid auth code returns access_token and id_token."""
        client, _ = integration_client
        _, auth_code = self._run_authorize_and_webhook(client)

        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": TEST_REDIRECT_URI,
            },
            headers={
                "Authorization": basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_SECRET),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert "id_token" in body

    def test_id_token_contains_vc_claims(self, integration_client, oob_mode):
        """id_token payload includes pres_req_conf_id, acr, and vc_presented_attributes."""
        client, _ = integration_client
        _, auth_code = self._run_authorize_and_webhook(client)

        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": TEST_REDIRECT_URI,
            },
            headers={
                "Authorization": basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_SECRET),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        assert resp.status_code == 200
        id_token_raw = resp.json()["id_token"]
        claims = jwt.decode(id_token_raw, options={"verify_signature": False})

        assert claims.get("pres_req_conf_id") == TEST_VER_CONFIG_ID
        assert claims.get("acr") == "vc_authn"
        assert "vc_presented_attributes" in claims

    def test_id_token_sub_derived_from_vc_attribute(self, integration_client, oob_mode):
        """sub claim is '<first_name>@<ver_config_id>' (subject_identifier=first_name)."""
        client, _ = integration_client
        _, auth_code = self._run_authorize_and_webhook(client)

        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": TEST_REDIRECT_URI,
            },
            headers={
                "Authorization": basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_SECRET),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )

        claims = jwt.decode(
            resp.json()["id_token"], options={"verify_signature": False}
        )
        # subject_identifier=first_name, value="Alice"
        assert claims["sub"] == f"Alice@{TEST_VER_CONFIG_ID}"


# ---------------------------------------------------------------------------
# Full end-to-end happy-path (single test covering the entire pipeline)
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_oob_full_pipeline(integration_client, oob_mode):
    """
    Smoke test: authorize → webhook → SSE → callback → token.

    One test that exercises the complete OOB pipeline so a single failure
    points immediately to the broken seam.
    """
    client, _ = integration_client

    # 1. Start OIDC authorization flow
    with acapy_oob_mock(pres_ex_id=FAKE_PRES_EX_ID) as mock_router:
        auth_resp = client.get("/authorize", params=authorize_params())
    assert auth_resp.status_code == 200
    pid = parse_pid_from_html(auth_resp.text)

    # Verify both OOB AcaPy routes were called
    paths = called_paths(mock_router)
    assert "/present-proof-2.0/create-request" in paths
    assert "/out-of-band/create-invitation" in paths

    # 2. Simulate wallet submitting proof (inject webhook)
    wh_resp = client.post(
        "/webhooks/topic/present_proof_v2_0/",
        json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
    )
    assert wh_resp.status_code == 200

    # 3. SSE reports the terminal state immediately (DB already updated)
    sse_resp = client.get(f"/sse/status/{pid}")
    assert sse_resp.status_code == 200
    assert parse_sse_status(sse_resp.text) == "verified"

    # 4. Callback returns redirect with auth code
    cb_resp = client.get("/callback", params={"pid": pid}, follow_redirects=False)
    assert cb_resp.status_code in (302, 307)
    location = cb_resp.headers["location"]
    assert TEST_REDIRECT_URI in location
    auth_code = parse_auth_code_from_url(location)

    # 5. Exchange auth code for tokens
    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": TEST_REDIRECT_URI,
        },
        headers={
            "Authorization": basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_SECRET),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert token_resp.status_code == 200
    body = token_resp.json()
    assert "access_token" in body
    assert "id_token" in body

    # 6. Verify id_token claims
    claims = jwt.decode(body["id_token"], options={"verify_signature": False})
    assert claims["pres_req_conf_id"] == TEST_VER_CONFIG_ID
    assert claims["acr"] == "vc_authn"
    assert "vc_presented_attributes" in claims
    assert claims["sub"] == f"Alice@{TEST_VER_CONFIG_ID}"


# ---------------------------------------------------------------------------
# Webhook idempotency — duplicate deliveries must not corrupt state
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestWebhookIdempotency:
    """ACA-Py can deliver the same webhook twice.

    The terminal DB state must survive duplicate delivery. These tests also
    document the current lack of idempotency guards: audit functions fire once
    per delivery, so duplicate webhooks produce duplicate audit events. If that
    becomes a problem, add a guard in acapy_handler.py and update call_count
    assertions below to == 1.
    """

    def test_duplicate_verified_webhook_does_not_corrupt_state(
        self, integration_client, oob_mode
    ):
        """Delivering the same verified webhook twice leaves session VERIFIED.
        Currently audit_proof_verified is called once per delivery (no guard)."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        parse_pid_from_html(auth_resp.text)

        webhook = make_proof_webhook(FAKE_PRES_EX_ID, verified=True)
        with patch("api.routers.acapy_handler.audit_proof_verified") as mock_audit:
            assert (
                client.post(
                    "/webhooks/topic/present_proof_v2_0/", json=webhook
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/webhooks/topic/present_proof_v2_0/", json=webhook
                ).status_code
                == 200
            )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one(
            {"pres_exch_id": FAKE_PRES_EX_ID}
        )
        assert session["proof_status"] == AuthSessionState.VERIFIED
        # No idempotency guard: audit fires once per delivery
        assert mock_audit.call_count == 2

    def test_duplicate_failed_webhook_stays_failed(self, integration_client, oob_mode):
        """Delivering failed webhook twice keeps session FAILED.
        Currently audit_proof_verification_failed is called once per delivery."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        webhook = make_proof_webhook(FAKE_PRES_EX_ID, verified=False)
        with patch(
            "api.routers.acapy_handler.audit_proof_verification_failed"
        ) as mock_audit:
            assert (
                client.post(
                    "/webhooks/topic/present_proof_v2_0/", json=webhook
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/webhooks/topic/present_proof_v2_0/", json=webhook
                ).status_code
                == 200
            )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one(
            {"pres_exch_id": FAKE_PRES_EX_ID}
        )
        assert session["proof_status"] == AuthSessionState.FAILED
        assert mock_audit.call_count == 2

    def test_duplicate_abandoned_webhook_stays_abandoned(
        self, integration_client, oob_mode
    ):
        """Delivering abandoned webhook twice keeps session ABANDONED.
        Currently audit_session_abandoned is called once per delivery."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        webhook = make_abandoned_webhook(FAKE_PRES_EX_ID)
        with patch("api.routers.acapy_handler.audit_session_abandoned") as mock_audit:
            assert (
                client.post(
                    "/webhooks/topic/present_proof_v2_0/", json=webhook
                ).status_code
                == 200
            )
            assert (
                client.post(
                    "/webhooks/topic/present_proof_v2_0/", json=webhook
                ).status_code
                == 200
            )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one(
            {"pres_exch_id": FAKE_PRES_EX_ID}
        )
        assert session["proof_status"] == AuthSessionState.ABANDONED
        assert mock_audit.call_count == 2


# ---------------------------------------------------------------------------
# QR code / wallet fetch → PENDING state transition
# ---------------------------------------------------------------------------


@pytest.mark.integration
class TestPresentationRequestURL:
    """Tests for GET /url/pres_exch/{pres_exch_id} — the URL encoded in the QR code.

    When a wallet (non-browser) fetches this URL it should:
      1. Transition the session from NOT_STARTED → PENDING
      2. Fire a 'pending' SSE notification
      3. Return the OOB invitation/presentation request as JSON
    """

    def _setup(self, client, oob_mode, monkeypatch):
        """Run /authorize and return (pid, pres_exch_id).

        oob_mode fixture is passed in to document the dependency; it has already
        been applied by pytest before this helper is called.
        """
        # Point camera redirect at a plain URL so the endpoint doesn't try to
        # open a template file before reaching the wallet (non-HTML) branch.
        monkeypatch.setattr(
            "api.core.config.settings.CONTROLLER_CAMERA_REDIRECT_URL",
            "http://example.com/scan-help.html",
        )
        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)
        pres_exch_id = parse_pres_exch_id_from_html(auth_resp.text)
        return pid, pres_exch_id

    def test_wallet_fetch_returns_proof_request_json(
        self, integration_client, oob_mode, monkeypatch
    ):
        """Wallet GET returns 200 JSON containing the OOB invitation message."""
        client, _ = integration_client
        _, pres_exch_id = self._setup(client, oob_mode, monkeypatch)

        resp = client.get(
            f"/url/pres_exch/{pres_exch_id}",
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 200
        body = resp.json()
        # The invitation message has a DIDComm type field
        assert "@type" in body or "type" in body

    def test_wallet_fetch_transitions_session_to_pending(
        self, integration_client, oob_mode, monkeypatch
    ):
        """Wallet fetch moves proof_status from NOT_STARTED to PENDING in DB."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        pid, pres_exch_id = self._setup(client, oob_mode, monkeypatch)

        # Confirm initial state
        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one({})
        assert session["proof_status"] == AuthSessionState.NOT_STARTED

        client.get(
            f"/url/pres_exch/{pres_exch_id}",
            headers={"Accept": "application/json"},
        )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one({})
        assert session["proof_status"] == AuthSessionState.PENDING

    def test_wallet_fetch_fires_pending_sse_notification(
        self, integration_client, oob_mode, monkeypatch
    ):
        """toggle_pending calls notify(pid, 'pending') when session is NOT_STARTED."""
        from unittest.mock import AsyncMock

        client, _ = integration_client
        pid, pres_exch_id = self._setup(client, oob_mode, monkeypatch)

        with patch(
            "api.routers.presentation_request.notify", new_callable=AsyncMock
        ) as mock_notify:
            client.get(
                f"/url/pres_exch/{pres_exch_id}",
                headers={"Accept": "application/json"},
            )

        mock_notify.assert_called_once_with(pid, "pending")

    def test_second_wallet_fetch_does_not_re_notify(
        self, integration_client, oob_mode, monkeypatch
    ):
        """Once PENDING, a second wallet fetch is a no-op (no double notification)."""
        from unittest.mock import AsyncMock

        client, _ = integration_client
        pid, pres_exch_id = self._setup(client, oob_mode, monkeypatch)

        # First fetch: transitions NOT_STARTED → PENDING
        client.get(
            f"/url/pres_exch/{pres_exch_id}",
            headers={"Accept": "application/json"},
        )

        # Second fetch: session is already PENDING, guard in handler should skip
        with patch(
            "api.routers.presentation_request.notify", new_callable=AsyncMock
        ) as mock_notify:
            client.get(
                f"/url/pres_exch/{pres_exch_id}",
                headers={"Accept": "application/json"},
            )

        mock_notify.assert_not_called()
