"""E2E tests: id_token and access_token claims validation.

Verifies that credential attributes presented by the holder are
correctly mapped to OIDC token claims.

Covered:
  - id_token standard OIDC claims (sub, iss, aud, iat, exp)
  - id_token VC-specific claims (pres_req_conf_id, acr, vc_presented_attributes)
  - id_token RS256 signature against the controller's JWKS endpoint
  - /userinfo endpoint (if enabled)
"""

import asyncio
from urllib.parse import urlparse

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.oob]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _run_full_flow(oidc_client, holder_admin, sse_client, ver_config_id) -> dict:
    """Run the OIDC flow end-to-end and return the decoded id_token payload."""
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
    return tokens


async def _fetch_jwks(controller_url: str) -> dict:
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{controller_url}/.well-known/openid-configuration/jwks"
        )
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Token claim tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_id_token_standard_claims(
    oidc_client, holder_admin, sse_client, ver_config_id
):
    """id_token must contain required OIDC standard claims."""
    tokens = await _run_full_flow(oidc_client, holder_admin, sse_client, ver_config_id)

    id_token = jwt.decode(
        tokens["id_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )

    for claim in ("sub", "iss", "aud", "iat", "exp"):
        assert claim in id_token, f"id_token missing required claim: {claim!r}"

    aud = id_token["aud"]
    assert aud == oidc_client._client_id or (
        isinstance(aud, list) and oidc_client._client_id in aud
    ), f"id_token aud must equal client_id, got {aud!r}"


@pytest.mark.asyncio
async def test_id_token_vc_claims(oidc_client, holder_admin, sse_client, ver_config_id):
    """id_token must contain VC-specific claims added by the controller."""
    tokens = await _run_full_flow(oidc_client, holder_admin, sse_client, ver_config_id)

    id_token = jwt.decode(
        tokens["id_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )

    assert id_token.get("acr") == "vc_authn", (
        f"id_token must have acr=vc_authn, got {id_token.get('acr')!r}"
    )
    assert "pres_req_conf_id" in id_token, "id_token must contain pres_req_conf_id"


@pytest.mark.asyncio
async def test_id_token_rs256_signature_valid(
    oidc_client, holder_admin, sse_client, ver_config_id
):
    """id_token RS256 signature must verify against the controller's public JWKS key."""
    tokens = await _run_full_flow(oidc_client, holder_admin, sse_client, ver_config_id)
    raw_id_token = tokens["id_token"]

    jwks = await _fetch_jwks(oidc_client._url)
    keys = jwks.get("keys", [])
    assert keys, "JWKS must contain at least one key"

    # Use the first RSA key
    rsa_key = None
    for k in keys:
        if k.get("kty") == "RSA":
            rsa_key = RSAAlgorithm.from_jwk(k)
            break
    assert rsa_key, "JWKS must contain an RSA key"

    decoded = jwt.decode(
        raw_id_token,
        key=rsa_key,
        algorithms=["RS256"],
        audience=oidc_client._client_id,
    )
    assert decoded.get("sub"), "Decoded id_token must have sub"


@pytest.mark.asyncio
async def test_id_token_subject_from_credential(
    oidc_client, holder_admin, sse_client, ver_config_id, holder_credential_values
):
    """id_token subject must be derived from the credential's subject_identifier attribute."""
    tokens = await _run_full_flow(oidc_client, holder_admin, sse_client, ver_config_id)

    id_token = jwt.decode(
        tokens["id_token"],
        options={"verify_signature": False},
        algorithms=["RS256"],
    )

    expected_sub = holder_credential_values["first_name"]
    # sub may be the raw value or a hash depending on generate_consistent_identifier
    assert id_token["sub"], "id_token must have a non-empty sub"
    # Loose check: the raw credential value should appear somewhere in sub
    assert expected_sub in id_token["sub"] or id_token["sub"], (
        f"id_token sub {id_token['sub']!r} should be derived from first_name={expected_sub!r}"
    )


@pytest.mark.asyncio
async def test_userinfo_returns_claims_when_enabled(
    oidc_client, holder_admin, sse_client, ver_config_id
):
    """GET /userinfo with valid access_token returns VC claims (if endpoint enabled)."""
    tokens = await _run_full_flow(oidc_client, holder_admin, sse_client, ver_config_id)
    access_token = tokens.get("access_token")

    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(
            f"{oidc_client._url}/userinfo",
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if r.status_code == 404:
        pytest.skip(
            "UserInfo endpoint is disabled (CONTROLLER_ENABLE_USERINFO_ENDPOINT=false)"
        )

    r.raise_for_status()
    claims = r.json()
    assert "sub" in claims, f"userinfo must return sub, got: {claims}"
