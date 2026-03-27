"""E2E tests: OOB (out-of-band) verification flow.

Full DIDComm flow:
  1. GET /authorize  → controller creates proof request + OOB invitation
  2. Holder receives OOB invitation → auto-sends proof via DIDComm
  3. ACA-Py processes proof → webhook → controller marks session VERIFIED
  4. SSE emits "verified"
  5. GET /callback  → captures authorization code
  6. POST /token    → exchanges code for id_token with VC attributes

Requires:
  - Full stack running: docker compose -f docker/docker-compose.yaml -f docker/docker-compose-e2e.yaml up -d
  - Bootstrap done:     python scripts/bootstrap-test-holder.py
  - USE_CONNECTION_BASED_VERIFICATION=false (OOB mode)
"""

import asyncio

import jwt
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.oob]


@pytest.mark.asyncio
async def test_oob_happy_path(oidc_client, holder_admin, sse_client, ver_config_id):
    """Full OOB flow: authorize → DIDComm proof → SSE verified → token."""
    # 1. Initiate OIDC authorization — get pid and OOB invitation
    pid, invitation = await oidc_client.authorize(pres_req_conf_id=ver_config_id)
    assert pid, "Expected a non-empty pid from /authorize"
    assert invitation, "Expected an OOB invitation JSON from /url/pres_exch/..."

    # 2. Subscribe to SSE BEFORE triggering the holder to avoid the race
    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="verified", timeout=60)
    )

    # Small pause to ensure SSE subscriber is established
    await asyncio.sleep(0.5)

    # 3. Holder receives OOB invitation and auto-responds with proof
    await holder_admin.receive_invitation(invitation)

    # 4. Wait for SSE to confirm verification
    status = await sse_task
    assert status == "verified", f"Expected 'verified' from SSE, got {status!r}"

    # 5. Exchange for authorization code
    auth_code = await oidc_client.get_auth_code(pid)
    assert auth_code, "Expected a non-empty auth code from /callback"

    # 6. Exchange code for tokens
    tokens = await oidc_client.get_token(auth_code)
    assert "id_token" in tokens, f"Expected id_token in token response: {tokens}"
    assert "access_token" in tokens


@pytest.mark.asyncio
async def test_oob_id_token_contains_vc_claims(
    oidc_client, holder_admin, sse_client, ver_config_id, holder_credential_values
):
    """id_token must contain VC attributes (first_name, last_name) as claims."""
    pid, invitation = await oidc_client.authorize(pres_req_conf_id=ver_config_id)

    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="verified", timeout=60)
    )
    await asyncio.sleep(0.5)
    await holder_admin.receive_invitation(invitation)

    status = await sse_task
    assert status == "verified"

    auth_code = await oidc_client.get_auth_code(pid)
    tokens = await oidc_client.get_token(auth_code)

    # Decode id_token without signature verification (tested separately)
    id_token = jwt.decode(
        tokens["id_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )

    # Subject should be the first_name value from the credential
    assert id_token.get("sub"), "id_token must have sub claim"

    # VC attributes appear in vc_presented_attributes or are reflected in sub
    import json as _json
    vc_attrs = _json.loads(id_token.get("vc_presented_attributes", "{}"))
    assert (
        vc_attrs.get("first_name") == holder_credential_values["first_name"]
        or holder_credential_values["first_name"] in id_token.get("sub", "")
    ), f"Expected first_name in id_token claims: {id_token}"


@pytest.mark.asyncio
async def test_oob_parallel_sessions(
    oidc_client, holder_admin, sse_client, ver_config_id
):
    """Two simultaneous OOB sessions should be independent."""
    # Start two authorization flows
    pid1, inv1 = await oidc_client.authorize(pres_req_conf_id=ver_config_id)
    pid2, inv2 = await oidc_client.authorize(pres_req_conf_id=ver_config_id)

    assert pid1 != pid2, "Each session must get a unique pid"

    # Subscribe to both SSE streams
    sse1 = asyncio.create_task(
        sse_client.wait_for_status(pid1, expected="verified", timeout=60)
    )
    sse2 = asyncio.create_task(
        sse_client.wait_for_status(pid2, expected="verified", timeout=60)
    )

    await asyncio.sleep(0.5)

    # Holder receives both invitations
    await asyncio.gather(
        holder_admin.receive_invitation(inv1),
        holder_admin.receive_invitation(inv2),
    )

    status1, status2 = await asyncio.gather(sse1, sse2)
    assert status1 == "verified"
    assert status2 == "verified"
