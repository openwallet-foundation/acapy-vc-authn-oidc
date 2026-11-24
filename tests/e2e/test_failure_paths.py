"""E2E tests: failure and edge-case paths.

Tests scenarios where verification does not complete successfully:
  - Session expiry (proof not presented within the timeout window)
  - Invalid auth code (token endpoint rejects unknown codes)
  - Unknown verification config (authorize returns 4xx)

  - Abandonment (holder cannot satisfy the proof request)

Not covered here: FAILED (verification returns verified=false). The test holder's
credential has no revocation support and auto-responds with valid proofs, so this
path is covered only at the integration-test layer.
"""

import asyncio
import base64
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.oob, pytest.mark.connection]


# ---------------------------------------------------------------------------
# Session expiry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_expired_session_emits_sse_expired(
    oidc_client, sse_client, ver_config_id
):
    """When no proof is presented within CONTROLLER_PRESENTATION_EXPIRE_TIME, SSE
    emits 'expired'.

    This test relies on the controller being configured with a very short expiry
    (e.g. CONTROLLER_PRESENTATION_EXPIRE_TIME=5).  It skips if the SSE stream
    does not emit 'expired' within 30 s — which means the expiry is too long.
    """
    pid, _ = await oidc_client.authorize(pres_req_conf_id=ver_config_id)
    assert pid

    try:
        status = await sse_client.wait_for_status(pid, expected="expired", timeout=30)
    except TimeoutError:
        pytest.skip(
            "Controller expiry window is too long for this test. "
            "Set CONTROLLER_PRESENTATION_EXPIRE_TIME=5 to enable it."
        )

    assert status == "expired", f"Expected 'expired', got {status!r}"


@pytest.mark.asyncio
async def test_callback_after_expiry_is_rejected(
    oidc_client, sse_client, ver_config_id
):
    """After session expiry, any auth code from /callback must not yield tokens.

    The controller validates the redirect URL (scheme, client_id, registered URI)
    in /callback but does not gate on proof status — so /callback redirects even
    for expired sessions.  Security is enforced at the token endpoint: the code
    must not be exchangeable for tokens.
    """
    pid, _ = await oidc_client.authorize(pres_req_conf_id=ver_config_id)

    try:
        await sse_client.wait_for_status(pid, expected="expired", timeout=30)
    except TimeoutError:
        pytest.skip(
            "Expiry window too long — set CONTROLLER_PRESENTATION_EXPIRE_TIME=5"
        )

    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        r = await client.get(f"{oidc_client._url}/callback", params={"pid": pid})

    # /callback validates redirect URL but not proof status — it redirects even
    # for expired sessions.  A 4xx is also acceptable if the session was cleaned up.
    if r.status_code >= 400:
        return  # Already rejected — security property holds

    assert r.status_code in (301, 302, 303, 307, 308), (
        f"Unexpected status from /callback on expired session: {r.status_code}"
    )

    query = urlparse(r.headers.get("location", "")).query
    code = parse_qs(query).get("code", [None])[0]
    if not code:
        return  # No code in redirect — cannot issue a token

    # The code from an expired session must be rejected at the token endpoint.
    creds = base64.b64encode(
        f"{oidc_client._client_id}:{oidc_client._client_secret}".encode()
    ).decode()
    async with httpx.AsyncClient(timeout=10) as token_client:
        tr = await token_client.post(
            f"{oidc_client._url}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oidc_client._redirect_uri,
            },
            headers={"Authorization": f"Basic {creds}"},
        )
    assert tr.status_code >= 400, (
        f"Token endpoint must reject code from expired session, got {tr.status_code}"
    )


# ---------------------------------------------------------------------------
# Token endpoint validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_exchange_with_invalid_code_returns_4xx(oidc_client):
    """POST /token with a made-up auth code must return an error response."""
    async with httpx.AsyncClient(timeout=10) as client:
        creds = base64.b64encode(
            f"{oidc_client._client_id}:{oidc_client._client_secret}".encode()
        ).decode()
        r = await client.post(
            f"{oidc_client._url}/token",
            data={
                "grant_type": "authorization_code",
                "code": "invalid-code-that-does-not-exist",
                "redirect_uri": oidc_client._redirect_uri,
            },
            headers={"Authorization": f"Basic {creds}"},
        )
    assert r.status_code >= 400, f"Expected 4xx for invalid code, got {r.status_code}"


# ---------------------------------------------------------------------------
# Unknown verification config
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_authorize_unknown_ver_config_returns_404(oidc_client):
    """GET /authorize with a non-existent pres_req_conf_id must return 404."""
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        r = await client.get(
            f"{oidc_client._url}/authorize",
            params={
                "response_type": "code",
                "client_id": oidc_client._client_id,
                "redirect_uri": oidc_client._redirect_uri,
                "scope": "openid",
                "pres_req_conf_id": "nonexistent-config-xyz",
                "state": "s",
                "nonce": "n",
            },
        )
    assert r.status_code == 404, (
        f"Expected 404 for unknown ver config, got {r.status_code}"
    )


# ---------------------------------------------------------------------------
# Holder-side decline (ABANDONED)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unsatisfiable_proof_request_emits_sse_abandoned(
    oidc_client, holder_admin, sse_client, e2e_unsatisfiable_ver_config_id
):
    """A holder that cannot satisfy the request reports a problem; the session
    becomes ABANDONED and SSE emits 'abandoned'."""
    pid, invitation = await oidc_client.authorize(
        pres_req_conf_id=e2e_unsatisfiable_ver_config_id
    )

    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="abandoned", timeout=60)
    )
    await asyncio.sleep(0.5)
    await holder_admin.receive_invitation(invitation)

    status = await sse_task
    assert status == "abandoned", f"Expected 'abandoned', got {status!r}"


@pytest.mark.asyncio
async def test_abandoned_session_code_is_not_exchangeable(
    oidc_client, holder_admin, sse_client, e2e_unsatisfiable_ver_config_id
):
    """An abandoned session must never yield tokens."""
    pid, invitation = await oidc_client.authorize(
        pres_req_conf_id=e2e_unsatisfiable_ver_config_id
    )
    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="abandoned", timeout=60)
    )
    await asyncio.sleep(0.5)
    await holder_admin.receive_invitation(invitation)
    assert await sse_task == "abandoned"

    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        r = await client.get(f"{oidc_client._url}/callback", params={"pid": pid})
    if r.status_code >= 400:
        return
    code = parse_qs(urlparse(r.headers.get("location", "")).query).get("code", [None])[
        0
    ]
    if not code:
        return

    creds = base64.b64encode(
        f"{oidc_client._client_id}:{oidc_client._client_secret}".encode()
    ).decode()
    async with httpx.AsyncClient(timeout=10) as token_client:
        tr = await token_client.post(
            f"{oidc_client._url}/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": oidc_client._redirect_uri,
            },
            headers={"Authorization": f"Basic {creds}"},
        )
    assert tr.status_code >= 400, (
        f"Token endpoint must reject code from abandoned session, got {tr.status_code}"
    )
