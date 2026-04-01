"""E2E tests: connection-based verification flow.

In connection-based mode (USE_CONNECTION_BASED_VERIFICATION=true):
  1. GET /authorize  → controller creates OOB handshake invitation (no attachment)
  2. Holder receives invitation → DIDComm connection is established
  3. Controller receives connections webhook → sends proof request via connection
  4. Holder auto-responds with proof
  5. Controller processes proof webhook → SSE "verified"
  6. GET /callback → auth code
  7. POST /token   → tokens

This is the default configuration (USE_CONNECTION_BASED_VERIFICATION=true).

Requires:
  - Full stack running with USE_CONNECTION_BASED_VERIFICATION=true
  - Bootstrap done: python scripts/bootstrap-test-holder.py
"""

import asyncio

import jwt
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.connection]


@pytest.mark.asyncio
async def test_connection_happy_path(
    oidc_client, holder_admin, sse_client, ver_config_id
):
    """Full connection-based flow: authorize → connection → proof → verified → token."""
    # 1. Authorize: get handshake-only OOB invitation
    pid, invitation = await oidc_client.authorize(pres_req_conf_id=ver_config_id)
    assert pid, "Expected pid from /authorize"
    assert invitation, "Expected OOB invitation from /url/pres_exch/..."

    # 2. Subscribe to SSE before holder connects (avoid race)
    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="verified", timeout=90)
    )
    await asyncio.sleep(0.5)

    # 3. Holder accepts connection invitation
    #    ACA-Py auto-responds to connection + proof request via ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST
    await holder_admin.receive_invitation(invitation)

    # 4. Wait for SSE verified
    status = await sse_task
    assert status == "verified", f"Expected 'verified', got {status!r}"

    # 5. Get auth code and exchange for tokens
    auth_code = await oidc_client.get_auth_code(pid)
    tokens = await oidc_client.get_token(auth_code)
    assert "id_token" in tokens
    assert "access_token" in tokens


@pytest.mark.asyncio
async def test_connection_id_token_claims(
    oidc_client, holder_admin, sse_client, ver_config_id, holder_credential_values
):
    """Verify VC attributes appear in id_token after connection-based flow."""
    pid, invitation = await oidc_client.authorize(pres_req_conf_id=ver_config_id)

    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="verified", timeout=90)
    )
    await asyncio.sleep(0.5)
    await holder_admin.receive_invitation(invitation)

    status = await sse_task
    assert status == "verified"

    auth_code = await oidc_client.get_auth_code(pid)
    tokens = await oidc_client.get_token(auth_code)

    id_token = jwt.decode(
        tokens["id_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )

    # Subject should be derived from the credential's subject_identifier (first_name)
    assert id_token.get("sub"), "id_token must contain sub"
    assert id_token.get("acr") == "vc_authn", "id_token must have acr=vc_authn"
    assert "pres_req_conf_id" in id_token, "id_token must contain pres_req_conf_id"
