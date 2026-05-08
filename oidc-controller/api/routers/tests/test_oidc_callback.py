"""Tests for get_authorize_callback redirect validation (CWE-601)."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bson import ObjectId
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api.authSessions.models import AuthSession, AuthSessionState
from api.clientConfigurations.models import ClientConfiguration
from api.routers.oidc import router


def _make_auth_session(response_url: str, client_id: str = "test-client") -> MagicMock:
    session = MagicMock(spec=AuthSession)
    session.id = ObjectId()
    session.response_url = response_url
    session.request_parameters = {"client_id": client_id}
    session.proof_status = AuthSessionState.VERIFIED
    return session


def _make_client_config(redirect_uris: list[str]) -> MagicMock:
    config = MagicMock(spec=ClientConfiguration)
    config.redirect_uris = redirect_uris
    return config


class TestAuthorizeCallbackRedirectValidation:
    @pytest.fixture
    def client(self):
        app = FastAPI()
        app.include_router(router)
        return TestClient(app, follow_redirects=False)

    # ------------------------------------------------------------------
    # (1) Non-http(s) schemes must be rejected
    # ------------------------------------------------------------------

    @pytest.mark.parametrize("bad_url", [
        "javascript:alert(1)",
        "data:text/html,<h1>hi</h1>",
        "ftp://evil.example.com/callback",
        "file:///etc/passwd",
    ])
    @patch("api.routers.oidc.AuthSessionCRUD")
    def test_non_https_scheme_rejected(self, mock_crud_cls, bad_url, client):
        """Redirect URLs with non-http(s) schemes must return 400."""
        mock_crud = AsyncMock()
        mock_crud.get.return_value = _make_auth_session(bad_url)
        mock_crud_cls.return_value = mock_crud

        response = client.get("/callback", params={"pid": str(ObjectId())})

        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid redirect URL"

    # ------------------------------------------------------------------
    # (2) A URL not in the registered redirect_uris must be rejected
    # ------------------------------------------------------------------

    @patch("api.routers.oidc.ClientConfigurationCRUD")
    @patch("api.routers.oidc.AuthSessionCRUD")
    def test_unregistered_redirect_uri_rejected(
        self, mock_auth_crud_cls, mock_client_crud_cls, client
    ):
        """A response_url whose base does not match any registered redirect_uri is rejected."""
        registered = "https://legitimate.example.com/callback"
        tampered = "https://evil.example.com/callback?code=abc"

        mock_auth_crud = AsyncMock()
        mock_auth_crud.get.return_value = _make_auth_session(tampered)
        mock_auth_crud_cls.return_value = mock_auth_crud

        mock_client_crud = AsyncMock()
        mock_client_crud.get.return_value = _make_client_config([registered])
        mock_client_crud_cls.return_value = mock_client_crud

        response = client.get("/callback", params={"pid": str(ObjectId())})

        assert response.status_code == 400
        assert response.json()["detail"] == "Invalid redirect URL"

    # ------------------------------------------------------------------
    # (3) A registered redirect URI (with query params appended) is allowed
    # ------------------------------------------------------------------

    @patch("api.routers.oidc.ClientConfigurationCRUD")
    @patch("api.routers.oidc.AuthSessionCRUD")
    def test_registered_redirect_uri_allowed(
        self, mock_auth_crud_cls, mock_client_crud_cls, client
    ):
        """A response_url matching a registered redirect_uri is followed (302)."""
        base = "https://legitimate.example.com/callback"
        # PyOP appends OIDC query params (code=, state=) to the registered base
        full_url = f"{base}?code=abc123&state=xyz"

        mock_auth_crud = AsyncMock()
        mock_auth_crud.get.return_value = _make_auth_session(full_url)
        mock_auth_crud_cls.return_value = mock_auth_crud

        mock_client_crud = AsyncMock()
        mock_client_crud.get.return_value = _make_client_config([base])
        mock_client_crud_cls.return_value = mock_client_crud

        response = client.get("/callback", params={"pid": str(ObjectId())})

        assert response.status_code in (302, 307)
        assert response.headers["location"] == full_url

    # ------------------------------------------------------------------
    # Edge cases
    # ------------------------------------------------------------------

    @patch("api.routers.oidc.ClientConfigurationCRUD")
    @patch("api.routers.oidc.AuthSessionCRUD")
    def test_trailing_slash_normalised(
        self, mock_auth_crud_cls, mock_client_crud_cls, client
    ):
        """Trailing slash differences between registered and actual URL are tolerated."""
        registered = "https://example.com/callback/"
        actual = "https://example.com/callback?code=abc"

        mock_auth_crud = AsyncMock()
        mock_auth_crud.get.return_value = _make_auth_session(actual)
        mock_auth_crud_cls.return_value = mock_auth_crud

        mock_client_crud = AsyncMock()
        mock_client_crud.get.return_value = _make_client_config([registered])
        mock_client_crud_cls.return_value = mock_client_crud

        response = client.get("/callback", params={"pid": str(ObjectId())})

        assert response.status_code in (302, 307)

    @patch("api.routers.oidc.AuthSessionCRUD")
    def test_no_client_id_skips_allowlist_check(self, mock_crud_cls, client):
        """When no client_id is stored in request_parameters the allowlist check is skipped."""
        session = _make_auth_session("https://example.com/callback")
        session.request_parameters = {}  # no client_id key
        mock_crud = AsyncMock()
        mock_crud.get.return_value = session
        mock_crud_cls.return_value = mock_crud

        response = client.get("/callback", params={"pid": str(ObjectId())})

        # Scheme is valid; no allowlist to check → redirect proceeds
        assert response.status_code in (302, 307)
