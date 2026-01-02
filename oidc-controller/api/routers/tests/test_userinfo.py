import pytest
from unittest.mock import MagicMock, patch
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pyop.exceptions import InvalidAccessToken, BearerTokenError

from api.routers.oidc import router


class TestUserInfoEndpoint:
    @pytest.fixture
    def client(self):
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    @patch("api.routers.oidc.provider.provider")
    def test_userinfo_success(self, mock_provider, client):
        """Test successful userinfo retrieval."""
        # Mock successful response from pyop
        mock_response = MagicMock()
        mock_response.to_dict.return_value = {
            "sub": "test_user",
            "email": "test@example.com",
        }
        mock_provider.handle_userinfo_request.return_value = mock_response

        # Make request with bearer token
        response = client.get(
            "/userinfo", headers={"Authorization": "Bearer valid_token"}
        )

        assert response.status_code == 200
        assert response.json() == {"sub": "test_user", "email": "test@example.com"}

    @patch("api.routers.oidc.provider.provider")
    def test_userinfo_invalid_token(self, mock_provider, client):
        """Test userinfo with invalid token returns 401."""
        # Mock exception from pyop
        mock_provider.handle_userinfo_request.side_effect = InvalidAccessToken(
            "Invalid token"
        )

        response = client.get(
            "/userinfo", headers={"Authorization": "Bearer invalid_token"}
        )

        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers

    @patch("api.routers.oidc.provider.provider")
    def test_userinfo_missing_token(self, mock_provider, client):
        """Test userinfo without token returns 401."""
        mock_provider.handle_userinfo_request.side_effect = BearerTokenError(
            "Missing token"
        )

        response = client.get("/userinfo")

        assert response.status_code == 401

    @patch("api.routers.oidc.provider.provider")
    def test_userinfo_unexpected_error(self, mock_provider, client):
        """Test userinfo handles unexpected exceptions with 500."""
        # Mock generic exception
        mock_provider.handle_userinfo_request.side_effect = RuntimeError(
            "Unexpected db failure"
        )

        response = client.get(
            "/userinfo", headers={"Authorization": "Bearer valid_token"}
        )

        assert response.status_code == 500
        assert response.json()["detail"] == "Failed to retrieve user info"

    @patch("api.routers.oidc.provider.provider")
    def test_userinfo_post_success(self, mock_provider, client):
        """Test successful userinfo retrieval via POST."""
        mock_response = MagicMock()
        mock_response.to_dict.return_value = {
            "sub": "test_user",
            "email": "test@example.com"
        }
        mock_provider.handle_userinfo_request.return_value = mock_response

        response = client.post(
            "/userinfo",
            headers={"Authorization": "Bearer valid_token"},
            content="access_token=valid_token" # Body content
        )

        assert response.status_code == 200
        assert response.json() == {
            "sub": "test_user",
            "email": "test@example.com"
        }
        
        # Verify provider was called with the body
        mock_provider.handle_userinfo_request.assert_called()
        args, _ = mock_provider.handle_userinfo_request.call_args
        assert args[0] == "access_token=valid_token"

    @patch("api.routers.oidc.provider.provider")
    def test_userinfo_post_empty_body(self, mock_provider, client):
        """Test POST with empty body handles gracefully."""
        mock_response = MagicMock()
        mock_response.to_dict.return_value = {"sub": "user"}
        mock_provider.handle_userinfo_request.return_value = mock_response

        response = client.post(
            "/userinfo",
            headers={"Authorization": "Bearer valid_token"},
            content=""
        )

        assert response.status_code == 200