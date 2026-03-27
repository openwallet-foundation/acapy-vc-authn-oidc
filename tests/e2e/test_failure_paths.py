"""E2E tests: failure and edge-case paths.

Tests scenarios where verification does not complete successfully:
  - Session expiry (proof not presented within the timeout window)
  - Invalid auth code (token endpoint rejects unknown codes)
  - Unknown verification config (authorize returns 4xx)

Note: Testing real abandonment/rejection requires the holder to intentionally
decline the proof request, which is not supported by ACAPY_AUTO_RESPOND_PRESENTATION_REQUEST.
Those paths are covered at the integration-test layer (test_failure_paths.py).
"""

import asyncio

import httpx
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.oob]


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
    """GET /callback after session expiry should not return a usable auth code."""
    pid, _ = await oidc_client.authorize(pres_req_conf_id=ver_config_id)

    try:
        await sse_client.wait_for_status(pid, expected="expired", timeout=30)
    except TimeoutError:
        pytest.skip(
            "Expiry window too long — set CONTROLLER_PRESENTATION_EXPIRE_TIME=5"
        )

    # /callback on an expired session should redirect without a usable code
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        r = await client.get(f"{oidc_client._url}/callback", params={"pid": pid})

    # Either 4xx/5xx or a redirect to RP with an error parameter
    if r.status_code in (200, 307, 302, 301):
        location = r.headers.get("location", "")
        # If there IS a redirect, it should carry an error, not a code
        if "code=" in location and "error" not in location:
            pytest.fail(f"Expired session returned an auth code in {location!r}")
    elif r.status_code >= 400:
        pass  # Expected: controller refuses the callback


# ---------------------------------------------------------------------------
# Token endpoint validation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_exchange_with_invalid_code_returns_4xx(oidc_client):
    """POST /token with a made-up auth code must return an error response."""
    async with httpx.AsyncClient(timeout=10) as client:
        import base64

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
