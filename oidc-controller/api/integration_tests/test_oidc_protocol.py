"""Integration tests: OIDC protocol surface.

Covers the gaps not exercised by the flow-focused tests:
  - Discovery document (/.well-known/openid-configuration)
  - JWKS endpoint (/.well-known/openid-configuration/jwks)
  - id_token signature verification against the JWKS public key
  - /userinfo endpoint (disabled by default, enabled by setting)
"""

import json

import jwt
import pytest
from jwt.algorithms import RSAAlgorithm

from .conftest import (
    FAKE_PRES_EX_ID,
    TEST_CLIENT_ID,
    TEST_CLIENT_SECRET,
    TEST_REDIRECT_URI,
    TEST_VER_CONFIG_ID,
    acapy_oob_mock,
    authorize_params,
    basic_auth_header,
    make_proof_webhook,
    parse_auth_code_from_url,
    parse_pid_from_html,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Shared helper
# ---------------------------------------------------------------------------


def _full_token_flow(client) -> dict:
    """Run the full OOB authorize → webhook → callback → token pipeline.

    Returns the parsed token response dict (access_token, id_token, …).
    Callers must apply the ``oob_mode`` fixture to ensure OOB mode is set.
    """
    with acapy_oob_mock(pres_ex_id=FAKE_PRES_EX_ID):
        auth_resp = client.get("/authorize", params=authorize_params())
    pid = parse_pid_from_html(auth_resp.text)

    client.post(
        "/webhooks/topic/present_proof_v2_0/",
        json=make_proof_webhook(FAKE_PRES_EX_ID, verified=True),
    )

    cb_resp = client.get("/callback", params={"pid": pid}, follow_redirects=False)
    auth_code = parse_auth_code_from_url(cb_resp.headers["location"])

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
    return token_resp.json()


# ---------------------------------------------------------------------------
# Discovery document + JWKS
# ---------------------------------------------------------------------------


class TestOIDCDiscovery:
    def test_discovery_document_has_required_fields(self, integration_client):
        """/.well-known/openid-configuration returns a valid OIDC discovery document."""
        client, _ = integration_client
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200
        doc = resp.json()
        for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
            assert field in doc, f"Missing required OIDC discovery field: {field}"
        assert doc["authorization_endpoint"].endswith("/authorize")
        assert doc["token_endpoint"].endswith("/token")

    def test_jwks_endpoint_returns_rsa_public_key(self, integration_client):
        """/.well-known/openid-configuration/jwks returns an RSA public key."""
        client, _ = integration_client
        resp = client.get("/.well-known/openid-configuration/jwks")
        assert resp.status_code == 200
        keys = resp.json()["keys"]
        assert len(keys) >= 1
        key = keys[0]
        assert key["kty"] == "RSA"
        assert "n" in key and "e" in key  # RSA modulus and public exponent
        assert key.get("use") == "sig"  # intended for signing


# ---------------------------------------------------------------------------
# id_token signature
# ---------------------------------------------------------------------------


class TestIdTokenSignature:
    def test_id_token_is_validly_signed(self, integration_client, oob_mode):
        """id_token RS256 signature verifies against the key from the JWKS endpoint.

        This catches: wrong signing key loaded, key rotation bugs, algorithm
        mismatch, or provider.py failing to persist the key correctly.
        """
        client, _ = integration_client
        tokens = _full_token_flow(client)
        id_token = tokens["id_token"]

        # Fetch the public key from the JWKS endpoint (exercises that endpoint too)
        jwks_resp = client.get("/.well-known/openid-configuration/jwks")
        assert jwks_resp.status_code == 200
        jwk_data = jwks_resp.json()["keys"][0]

        # RSAAlgorithm.from_jwk accepts a JWK dict or JSON string
        pub_key = RSAAlgorithm.from_jwk(json.dumps(jwk_data))

        # Verify signature AND audience. The OIDC spec requires aud == client_id.
        # Skipping exp only because the test signing key has a short-lived token.
        claims = jwt.decode(
            id_token,
            pub_key,
            algorithms=["RS256"],
            audience=TEST_CLIENT_ID,
            options={"verify_exp": False},
        )

        # aud must contain the registered client_id (OIDC Core §2 requirement)
        aud = claims["aud"]
        assert (aud == TEST_CLIENT_ID) or (TEST_CLIENT_ID in aud)

        # Sanity-check the VC claims survived signature round-trip
        assert claims.get("pres_req_conf_id") == TEST_VER_CONFIG_ID
        assert claims.get("acr") == "vc_authn"
        assert "vc_presented_attributes" in claims


# ---------------------------------------------------------------------------
# /userinfo endpoint
# ---------------------------------------------------------------------------


class TestUserInfo:
    def test_userinfo_disabled_by_default(self, integration_client):
        """GET /userinfo returns 404 when CONTROLLER_ENABLE_USERINFO_ENDPOINT is False."""
        client, _ = integration_client
        resp = client.get("/userinfo", headers={"Authorization": "Bearer dummy"})
        assert resp.status_code == 404

    def test_userinfo_without_token_returns_401(self, integration_client, monkeypatch):
        """GET /userinfo with no Authorization header returns 401."""
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.CONTROLLER_ENABLE_USERINFO_ENDPOINT", True
        )
        resp = client.get("/userinfo")
        assert resp.status_code == 401

    def test_userinfo_returns_vc_claims(
        self, integration_client, monkeypatch, oob_mode
    ):
        """GET /userinfo with a valid Bearer access_token returns VC attributes."""
        client, _ = integration_client
        monkeypatch.setattr(
            "api.core.config.settings.CONTROLLER_ENABLE_USERINFO_ENDPOINT", True
        )

        tokens = _full_token_flow(client)
        access_token = tokens["access_token"]

        resp = client.get(
            "/userinfo", headers={"Authorization": f"Bearer {access_token}"}
        )
        assert resp.status_code == 200
        claims = resp.json()
        assert "pres_req_conf_id" in claims
        assert "vc_presented_attributes" in claims
