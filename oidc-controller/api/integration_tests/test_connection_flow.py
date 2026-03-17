"""Integration tests: connection-based verification flow.

Pipeline under test (USE_CONNECTION_BASED_VERIFICATION=True):
  1. GET  /authorize
       → AcaPy: create_connection_invitation (OOB with handshake only)
       → AuthSession created with pres_exch_id=invi_msg_id, connection_id=invi_msg_id

  2. POST /webhooks/topic/connections/  (state=active)
       → AcaPy: send_presentation_request_by_connection
       → AuthSession updated: pres_exch_id=FAKE_PRES_EX_ID, connection_id=real_conn_id

  3. POST /webhooks/topic/present_proof_v2_0/  (state=done, verified=true)
       → AuthSession updated: proof_status=VERIFIED, presentation_exchange set
       → AcaPy: delete_connection (cleanup)

  4. GET  /sse/status/{pid}  → "verified"
  5. GET  /callback?pid={pid} → redirect with auth_code
  6. POST /token → tokens with VC claims
"""

import base64

import jwt
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
    authorize_params,
    called_paths,
    make_proof_webhook,
    parse_auth_code_from_url,
    parse_pid_from_html,
    parse_sse_status,
)

pytestmark = pytest.mark.integration


def _basic_auth_header(client_id: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


def _connections_webhook(
    connection_id: str = TEST_CONNECTION_ID,
    invi_msg_id: str = FAKE_INVI_MSG_ID,
    state: str = "active",
) -> dict:
    """Build a connections webhook body (emitted by AcaPy when a connection is established)."""
    return {
        "connection_id": connection_id,
        "state": state,
        "invitation_msg_id": invi_msg_id,
        "invi_msg_id": invi_msg_id,
    }


# ---------------------------------------------------------------------------
# Authorize (connection-based)
# ---------------------------------------------------------------------------


class TestConnectionAuthorize:
    def test_authorize_returns_html_connection_mode(
        self, integration_client, monkeypatch
    ):
        """GET /authorize in connection mode returns HTML with pid."""
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", True
        )

        with acapy_connection_mock():
            resp = client.get("/authorize", params=authorize_params())

        assert resp.status_code == 200
        assert "text/html" in resp.headers["content-type"]
        pid = parse_pid_from_html(resp.text)
        assert len(pid) == 24

    def test_authorize_creates_auth_session_with_invitation_id(
        self, integration_client, monkeypatch
    ):
        """AuthSession pres_exch_id is set to invi_msg_id in connection-based mode."""
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", True
        )

        with acapy_connection_mock(invi_msg_id=FAKE_INVI_MSG_ID):
            client.get("/authorize", params=authorize_params())

        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        session = col.find_one({})
        assert session is not None
        # Initial pres_exch_id is the invitation message ID
        assert session["pres_exch_id"] == FAKE_INVI_MSG_ID
        assert session["connection_id"] == FAKE_INVI_MSG_ID


# ---------------------------------------------------------------------------
# Connections webhook (step 2)
# ---------------------------------------------------------------------------


class TestConnectionsWebhook:
    def test_connections_webhook_sends_presentation_request(
        self, integration_client, monkeypatch
    ):
        """connections webhook triggers send_presentation_request_by_connection."""
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", True
        )

        mock = acapy_connection_mock(
            invi_msg_id=FAKE_INVI_MSG_ID,
            pres_ex_id=FAKE_PRES_EX_ID,
            connection_id=TEST_CONNECTION_ID,
        )
        with mock as mock_router:
            client.get("/authorize", params=authorize_params())

            wh_resp = client.post(
                "/webhooks/topic/connections/",
                json=_connections_webhook(
                    connection_id=TEST_CONNECTION_ID,
                    invi_msg_id=FAKE_INVI_MSG_ID,
                ),
            )
        assert wh_resp.status_code == 200

        # AuthSession is updated: pres_exch_id now points to the real exchange
        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        session = col.find_one({})
        assert session["pres_exch_id"] == FAKE_PRES_EX_ID
        assert session["connection_id"] == TEST_CONNECTION_ID

        # Verify the presentation request was actually sent to AcaPy
        paths = called_paths(mock_router)
        assert "/present-proof-2.0/send-request" in paths

    def test_connections_webhook_ignored_when_not_active(
        self, integration_client, monkeypatch
    ):
        """connections webhook with state=request is a no-op."""
        from api.db.collections import COLLECTION_NAMES

        client, db = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", True
        )

        with acapy_connection_mock():
            client.get("/authorize", params=authorize_params())
            resp = client.post(
                "/webhooks/topic/connections/",
                json=_connections_webhook(state="request"),
            )
        assert resp.status_code == 200

        # AuthSession pres_exch_id still = FAKE_INVI_MSG_ID (not updated)
        col = db.get_collection(COLLECTION_NAMES.AUTH_SESSION)
        session = col.find_one({})
        assert session["pres_exch_id"] == FAKE_INVI_MSG_ID


# ---------------------------------------------------------------------------
# Full connection-based pipeline
# ---------------------------------------------------------------------------


@pytest.mark.integration
def test_connection_flow_full_pipeline(integration_client, monkeypatch):
    """
    Smoke test: connection authorize → connections webhook → proof webhook
                → SSE verified → callback → token with VC claims.
    """
    client, _ = integration_client
    monkeypatch.setattr(
        "api.core.config.settings.USE_CONNECTION_BASED_VERIFICATION", True
    )

    with acapy_connection_mock(
        invi_msg_id=FAKE_INVI_MSG_ID,
        pres_ex_id=FAKE_PRES_EX_ID,
        connection_id=TEST_CONNECTION_ID,
    ) as mock_router:
        # Step 1: Authorize
        auth_resp = client.get("/authorize", params=authorize_params())
        assert auth_resp.status_code == 200
        pid = parse_pid_from_html(auth_resp.text)

        # Step 2: Connection established webhook
        wh1_resp = client.post(
            "/webhooks/topic/connections/",
            json=_connections_webhook(
                connection_id=TEST_CONNECTION_ID,
                invi_msg_id=FAKE_INVI_MSG_ID,
            ),
        )
        assert wh1_resp.status_code == 200

        # Step 3: Proof verified webhook
        wh2_resp = client.post(
            "/webhooks/topic/present_proof_v2_0/",
            json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
        )
        assert wh2_resp.status_code == 200

    # Verify all 3 AcaPy routes were called
    paths = called_paths(mock_router)
    assert "/out-of-band/create-invitation" in paths  # Step 1: create invitation
    assert "/present-proof-2.0/send-request" in paths  # Step 2: send proof request
    assert f"/connections/{TEST_CONNECTION_ID}" in paths  # Step 3: delete connection

    # Step 4: SSE emits "verified"
    sse_resp = client.get(f"/sse/status/{pid}")
    assert sse_resp.status_code == 200
    assert parse_sse_status(sse_resp.text) == "verified"

    # Step 5: Callback → redirect with auth code
    cb_resp = client.get("/callback", params={"pid": pid}, follow_redirects=False)
    assert cb_resp.status_code in (302, 307)
    auth_code = parse_auth_code_from_url(cb_resp.headers["location"])

    # Step 6: Token exchange
    token_resp = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": TEST_REDIRECT_URI,
        },
        headers={
            "Authorization": _basic_auth_header(TEST_CLIENT_ID, TEST_CLIENT_SECRET),
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    assert token_resp.status_code == 200
    body = token_resp.json()
    assert "access_token" in body
    assert "id_token" in body

    # Step 7: Verify id_token claims
    claims = jwt.decode(body["id_token"], options={"verify_signature": False})
    assert claims["pres_req_conf_id"] == TEST_VER_CONFIG_ID
    assert claims["acr"] == "vc_authn"
    assert "vc_presented_attributes" in claims
    assert claims["sub"] == f"Alice@{TEST_VER_CONFIG_ID}"
