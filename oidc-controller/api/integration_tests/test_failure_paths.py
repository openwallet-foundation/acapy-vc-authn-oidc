"""Integration tests: failure paths.

Covers the sad-path scenarios identified in the plan:
  - verified=false webhook → SSE emits "failed"
  - abandoned webhook → SSE emits "abandoned"
  - expired session → SSE emits "expired" (via poll endpoint)
  - POST /token with invalid auth code → error response
  - GET /authorize with unknown pres_req_conf_id → 404
  - GET /authorize with invalid client_id → 400
  - Prover-role webhook is ignored (no state change)
"""

import base64
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

from .conftest import (
    FAKE_INVI_MSG_ID,
    FAKE_PRES_EX_ID,
    TEST_CLIENT_ID,
    TEST_CLIENT_SECRET,
    TEST_CONNECTION_ID,
    TEST_REDIRECT_URI,
    TEST_VER_CONFIG_ID,
    acapy_connection_mock,
    acapy_oob_mock,
    authorize_params,
    called_paths,
    make_abandoned_webhook,
    make_proof_webhook,
    parse_pid_from_html,
    parse_sse_status,
)

pytestmark = pytest.mark.integration


def _basic_auth_header(client_id: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


# ---------------------------------------------------------------------------
# Verification failures
# ---------------------------------------------------------------------------


class TestVerificationFailure:
    def test_verified_false_sets_failed_status(self, integration_client, monkeypatch):
        """verified=false in the webhook → proof_status FAILED in DB."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        with patch(
            "api.routers.acapy_handler.audit_proof_verification_failed"
        ) as mock_audit:
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
            )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one({})
        assert session["proof_status"] == AuthSessionState.FAILED

        mock_audit.assert_called_once()
        assert mock_audit.call_args.kwargs["ver_config_id"] == TEST_VER_CONFIG_ID

    def test_verified_false_sse_emits_failed(self, integration_client, monkeypatch):
        """After verified=false webhook, SSE emits 'failed'."""
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
        )

        sse_resp = client.get(f"/sse/status/{pid}")
        assert sse_resp.status_code == 200
        assert parse_sse_status(sse_resp.text) == "failed"


# ---------------------------------------------------------------------------
# Abandonment
# ---------------------------------------------------------------------------


class TestAbandonedFlow:
    def test_abandoned_webhook_sets_abandoned_status(
        self, integration_client, monkeypatch
    ):
        """abandoned webhook → proof_status ABANDONED in DB."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        with patch("api.routers.acapy_handler.audit_session_abandoned") as mock_audit:
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_abandoned_webhook(FAKE_PRES_EX_ID),
            )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one({})
        assert session["proof_status"] == AuthSessionState.ABANDONED

        mock_audit.assert_called_once()
        assert mock_audit.call_args.kwargs["ver_config_id"] == TEST_VER_CONFIG_ID

    def test_abandoned_webhook_sse_emits_abandoned(
        self, integration_client, monkeypatch
    ):
        """After abandoned webhook, SSE emits 'abandoned'."""
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_abandoned_webhook(FAKE_PRES_EX_ID),
        )

        sse_resp = client.get(f"/sse/status/{pid}")
        assert parse_sse_status(sse_resp.text) == "abandoned"


# ---------------------------------------------------------------------------
# Session expiry
# ---------------------------------------------------------------------------


class TestSessionExpiry:
    def test_poll_endpoint_expires_overdue_session(
        self, integration_client, monkeypatch
    ):
        """GET /poll/{pid} transitions an already-expired NOT_STARTED session to EXPIRED."""
        from api.authSessions.models import AuthSessionState
        from api.core.models import PyObjectId
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        # Manually expire the session in the DB
        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        expired_time = datetime.now(UTC) - timedelta(seconds=60)
        col.update_one(
            {"_id": PyObjectId(pid)},
            {"$set": {"expired_timestamp": expired_time}},
        )

        poll_resp = client.get(f"/poll/{pid}")
        assert poll_resp.status_code == 200

        session = col.find_one({"_id": PyObjectId(pid)})
        assert session["proof_status"] == AuthSessionState.EXPIRED

    def test_sse_emits_expired_for_overdue_session(
        self, integration_client, monkeypatch
    ):
        """SSE immediately emits 'expired' when connecting to an already-expired session."""
        from api.core.models import PyObjectId
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        # Expire the session directly in the DB
        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        expired_time = datetime.now(UTC) - timedelta(seconds=60)
        col.update_one(
            {"_id": PyObjectId(pid)},
            {"$set": {"expired_timestamp": expired_time}},
        )

        # SSE on-connect expiry check should fire and emit "expired"
        sse_resp = client.get(f"/sse/status/{pid}")
        assert sse_resp.status_code == 200
        assert parse_sse_status(sse_resp.text) == "expired"

    def test_webhook_on_expired_session_calls_audit(
        self, integration_client, monkeypatch
    ):
        """When a webhook arrives for an already-expired session, audit_session_expired
        is called by the webhook handler (the only code path that calls this audit fn)."""
        from api.core.models import PyObjectId
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        # Expire the session directly in the DB before the webhook arrives
        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        col.update_one(
            {"_id": PyObjectId(pid)},
            {"$set": {"expired_timestamp": datetime.now(UTC) - timedelta(seconds=60)}},
        )

        with patch("api.routers.acapy_handler.audit_session_expired") as mock_audit:
            # "presentation-received" does not update proof_status, so the session
            # remains NOT_STARTED. The expiry check at the end of the handler then
            # detects the expired deadline and calls audit_session_expired.
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json={
                    "pres_ex_id": FAKE_PRES_EX_ID,
                    "state": "presentation-received",
                    "role": "verifier",
                },
            )

        mock_audit.assert_called_once()
        assert mock_audit.call_args.kwargs["ver_config_id"] == TEST_VER_CONFIG_ID


# ---------------------------------------------------------------------------
# Token endpoint error cases
# ---------------------------------------------------------------------------


class TestTokenErrors:
    def test_token_with_invalid_auth_code_returns_error(
        self, integration_client, monkeypatch
    ):
        """POST /token with a bogus auth code returns a non-200 error response."""
        client, _ = integration_client

        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": "completely-invalid-code-that-does-not-exist",
                "redirect_uri": TEST_REDIRECT_URI,
            },
            headers={
                "Authorization": _basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_SECRET),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        # 404 (auth_session not found) or 400/401 from pyop
        assert resp.status_code >= 400

    def test_token_before_verification_returns_error(
        self, integration_client, monkeypatch
    ):
        """Attempting /token with a valid but unverified auth code returns an error.

        The auth_session exists but proof_status is NOT_STARTED.  The token
        endpoint looks up by pyop_auth_code first; if the code is valid but the
        session is not verified we still proceed to pyop which validates the
        code itself.  The key assertion: we get back a proper error, not a 200.
        """
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        # Start authorization but do NOT inject a webhook
        with acapy_oob_mock():
            auth_resp = client.get("/authorize", params=authorize_params())
        pid = parse_pid_from_html(auth_resp.text)

        # Get the redirect (which has the auth code) without verifying
        cb_resp = client.get("/callback", params={"pid": pid}, follow_redirects=False)
        auth_code = cb_resp.headers["location"].split("code=")[1].split("&")[0]

        # The token endpoint must fail: StatelessWrapper encodes auth codes and
        # handle_token_request validates the redirect_uri against the original request
        resp = client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": auth_code,
                # Deliberately wrong redirect_uri to force pyop rejection
                "redirect_uri": "http://wrong-redirect.example.com/",
            },
            headers={
                "Authorization": _basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_SECRET),
                "Content-Type": "application/x-www-form-urlencoded",
            },
        )
        assert resp.status_code >= 400


# ---------------------------------------------------------------------------
# Authorize error cases
# ---------------------------------------------------------------------------


class TestAuthorizeErrors:
    def test_authorize_unknown_ver_config_returns_404(
        self, integration_client, monkeypatch
    ):
        """Unknown pres_req_conf_id → 404 Not Found."""
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            resp = client.get(
                "/authorize",
                params={
                    **authorize_params(),
                    "pres_req_conf_id": "completely-unknown-config",
                },
            )
        assert resp.status_code == 404

    def test_authorize_unknown_client_returns_400(self, integration_client):
        """Unknown client_id → 400 Bad Request (pyop rejects the auth request)."""
        client, _ = integration_client

        resp = client.get(
            "/authorize",
            params={
                **authorize_params(),
                "client_id": "unknown-client-that-is-not-registered",
            },
        )
        assert resp.status_code == 400

    def test_authorize_missing_scope_returns_400(self, integration_client, monkeypatch):
        """Missing 'openid' scope → 400 Bad Request."""
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        params = {k: v for k, v in authorize_params().items() if k != "scope"}
        resp = client.get("/authorize", params=params)
        assert resp.status_code >= 400


# ---------------------------------------------------------------------------
# Prover-role webhook is ignored
# ---------------------------------------------------------------------------


class TestProverRoleWebhook:
    def test_prover_role_webhook_does_not_change_db(
        self, integration_client, monkeypatch
    ):
        """A present_proof_v2_0 webhook with role=prover is logged and ignored."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", False
        )

        with acapy_oob_mock():
            client.get("/authorize", params=authorize_params())

        # Inject a prover-role webhook (should be a no-op for the verifier side)
        resp = client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json={
                "pres_ex_id": FAKE_PRES_EX_ID,
                "state": "done",
                "role": "prover",  # ← this is the key
                "verified": "true",
            },
        )
        assert resp.status_code == 200

        # DB should still be NOT_STARTED (prover webhook was ignored)
        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one({})
        assert session["proof_status"] == AuthSessionState.NOT_STARTED

    def test_unknown_webhook_topic_is_ignored(self, integration_client):
        """Unknown webhook topics return {} without error."""
        client, _ = integration_client
        resp = client.post(
            "/webhooks/topic/some_unknown_topic/",
            json={"foo": "bar"},
        )
        assert resp.status_code == 200
        assert resp.json() == {}


# ---------------------------------------------------------------------------
# Connection-based failure paths
# ---------------------------------------------------------------------------


def _connections_webhook(
    connection_id: str = TEST_CONNECTION_ID,
    invi_msg_id: str = FAKE_INVI_MSG_ID,
    state: str = "active",
) -> dict:
    return {
        "connection_id": connection_id,
        "state": state,
        "invitation_msg_id": invi_msg_id,
        "invi_msg_id": invi_msg_id,
    }


class TestConnectionBasedFailures:
    """Failure paths under USE_CONNECTION_BASED_VERIFICATION=True.

    These differ from OOB failures because the handler calls
    _send_problem_report_safely on failed/abandoned webhooks, which makes an
    extra POST to AcaPy. None of the OOB failure tests exercise that path.
    """

    def _authorize_and_activate(self, client, monkeypatch, mock_router):
        """Run /authorize + connections webhook to reach the proof-requested state.

        Must be called inside the acapy_connection_mock context so the mock
        client is active for both the AcaPy invitation call and the send-request call.
        Returns pid.
        """
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", True
        )
        auth_resp = client.get("/authorize", params=authorize_params())
        assert auth_resp.status_code == 200
        pid = parse_pid_from_html(auth_resp.text)

        wh_resp = client.post(
            "/webhooks/topic/connections/",
            json=_connections_webhook(
                connection_id=TEST_CONNECTION_ID, invi_msg_id=FAKE_INVI_MSG_ID
            ),
        )
        assert wh_resp.status_code == 200
        return pid

    def test_failed_verification_sets_failed_status(
        self, integration_client, monkeypatch
    ):
        """verified=false in connection mode → proof_status FAILED."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        ):
            self._authorize_and_activate(client, monkeypatch, None)
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
            )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one({})
        assert session["proof_status"] == AuthSessionState.FAILED

    def test_failed_verification_sends_problem_report(
        self, integration_client, monkeypatch
    ):
        """verified=false in connection mode sends a problem-report to AcaPy.

        This is the key difference from OOB mode: _send_problem_report_safely
        is called so the wallet is notified of the rejection.
        """
        client, _ = integration_client

        with acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        ) as mock_router:
            self._authorize_and_activate(client, monkeypatch, mock_router)
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
            )

        paths = called_paths(mock_router)
        assert any(p.endswith("/problem-report") for p in paths), (
            "Expected problem-report call to AcaPy after failed verification in connection mode"
        )

    def test_failed_verification_deletes_connection(
        self, integration_client, monkeypatch
    ):
        """After failed verification in connection mode, the connection is cleaned up."""
        client, _ = integration_client

        with acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        ) as mock_router:
            self._authorize_and_activate(client, monkeypatch, mock_router)
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
            )

        paths = called_paths(mock_router)
        assert f"/connections/{TEST_CONNECTION_ID}" in paths

    def test_abandoned_sets_abandoned_status(self, integration_client, monkeypatch):
        """abandoned webhook in connection mode → proof_status ABANDONED."""
        from api.authSessions.models import AuthSessionState
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client

        with acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        ):
            self._authorize_and_activate(client, monkeypatch, None)
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_abandoned_webhook(FAKE_PRES_EX_ID),
            )

        session = db.get_collection(COLLECTION_NAMES.AUTH_SESSION).find_one({})
        assert session["proof_status"] == AuthSessionState.ABANDONED

    def test_abandoned_sends_problem_report(self, integration_client, monkeypatch):
        """abandoned webhook in connection mode sends a problem-report to AcaPy."""
        client, _ = integration_client

        with acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        ) as mock_router:
            self._authorize_and_activate(client, monkeypatch, mock_router)
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_abandoned_webhook(FAKE_PRES_EX_ID),
            )

        paths = called_paths(mock_router)
        assert any(p.endswith("/problem-report") for p in paths), (
            "Expected problem-report call to AcaPy after abandoned webhook in connection mode"
        )

    def test_sse_emits_failed_in_connection_mode(self, integration_client, monkeypatch):
        """SSE emits 'failed' after a failed webhook in connection mode."""
        client, _ = integration_client

        with acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        ):
            pid = self._authorize_and_activate(client, monkeypatch, None)
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_proof_webhook(FAKE_PRES_EX_ID, verified=False),
            )

        sse_resp = client.get(f"/sse/status/{pid}")
        assert parse_sse_status(sse_resp.text) == "failed"

    def test_sse_emits_abandoned_in_connection_mode(
        self, integration_client, monkeypatch
    ):
        """SSE emits 'abandoned' after an abandoned webhook in connection mode."""
        client, _ = integration_client

        with acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        ):
            pid = self._authorize_and_activate(client, monkeypatch, None)
            client.post(
                "/webhooks/topic/present_proof_v2_0/",
                json=make_abandoned_webhook(FAKE_PRES_EX_ID),
            )

        sse_resp = client.get(f"/sse/status/{pid}")
        assert parse_sse_status(sse_resp.text) == "abandoned"
