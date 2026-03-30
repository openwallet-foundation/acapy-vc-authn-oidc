"""E2E tests: multi-pod Redis-backed storage.

Verifies that the authorization code, access token, and subject identifier
survive being created on one controller pod and consumed on another.

With CONTROLLER_REPLICAS>=2 and REDIS_MODE=single the nginx load balancer
round-robins requests across pods.  Running N concurrent sessions ensures
that at least some authorize/token pairs cross pod boundaries, which would
fail immediately if StatelessWrapper were accidentally used in multi-pod mode.

Requires:
  - CONTROLLER_REPLICAS=2 (or more)
  - REDIS_MODE=single
  - Full stack running with docker-compose-e2e.yaml overlay
"""

import asyncio

import jwt
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.oob, pytest.mark.redis]


async def _complete_flow(oidc_client, holder_admin, sse_client, ver_config_id) -> dict:
    """Run one full OOB flow and return the raw token response dict."""
    pid, invitation = await oidc_client.authorize(pres_req_conf_id=ver_config_id)
    sse_task = asyncio.create_task(
        sse_client.wait_for_status(pid, expected="verified", timeout=60)
    )
    await asyncio.sleep(0.5)
    await holder_admin.receive_invitation(invitation)
    await sse_task
    auth_code = await oidc_client.get_auth_code(pid)
    return await oidc_client.get_token(auth_code)


@pytest.mark.asyncio
async def test_concurrent_sessions_succeed_with_redis(
    oidc_client, holder_admin, sse_client, ver_config_id
):
    """Four concurrent sessions must all complete successfully.

    With two replicas and four sessions the load balancer distributes
    requests across pods, so authorization codes created on pod-A must be
    redeemable on pod-B via the shared Redis store.
    """
    N = 4

    async def one_session():
        pid, invitation = await oidc_client.authorize(pres_req_conf_id=ver_config_id)
        sse_task = asyncio.create_task(
            sse_client.wait_for_status(pid, expected="verified", timeout=60)
        )
        await asyncio.sleep(0.5)
        await holder_admin.receive_invitation(invitation)
        await sse_task
        auth_code = await oidc_client.get_auth_code(pid)
        tokens = await oidc_client.get_token(auth_code)
        assert "id_token" in tokens
        return tokens

    results = await asyncio.gather(*[one_session() for _ in range(N)])
    assert len(results) == N, f"Expected {N} successful sessions, got {len(results)}"


@pytest.mark.asyncio
async def test_tokens_from_redis_backed_session_are_valid(
    oidc_client, holder_admin, sse_client, ver_config_id
):
    """id_token issued via Redis-backed storage must pass RS256 signature check."""
    import httpx as _httpx
    from jwt.algorithms import RSAAlgorithm

    tokens = await _complete_flow(oidc_client, holder_admin, sse_client, ver_config_id)

    async with _httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{oidc_client._url}/.well-known/openid-configuration/jwks"
        )
        r.raise_for_status()
        jwks = r.json()

    rsa_key = None
    for k in jwks.get("keys", []):
        if k.get("kty") == "RSA":
            rsa_key = RSAAlgorithm.from_jwk(k)
            break
    assert rsa_key, "JWKS must contain an RSA key"

    decoded = jwt.decode(
        tokens["id_token"],
        key=rsa_key,
        algorithms=["RS256"],
        audience=oidc_client._client_id,
    )
    assert decoded.get("sub"), "id_token from Redis-backed session must have sub"
    assert decoded.get("acr") == "vc_authn"
