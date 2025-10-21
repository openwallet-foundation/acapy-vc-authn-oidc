"""Tests for well-known OpenID configuration endpoints."""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch, Mock

from api.routers.well_known_oid_config import router


class TestWellKnownEndpoints:
    """Test well-known OpenID configuration endpoints."""

    @pytest.fixture
    def app(self):
        """Create a test FastAPI app."""
        app = FastAPI()
        app.include_router(router)
        return app

    @pytest.fixture
    def client(self, app):
        """Create a test client."""
        return TestClient(app)

    @patch("api.routers.well_known_oid_config.provider")
    def test_get_well_known_oid_config(self, mock_provider, client):
        """Test GET /.well-known/openid-configuration returns config."""
        # Setup mock configuration
        mock_config = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/authorize",
            "token_endpoint": "https://example.com/token",
            "jwks_uri": "https://example.com/.well-known/openid-configuration/jwks",
            "response_types_supported": ["code", "id_token", "token"],
            "subject_types_supported": ["public"],
        }
        mock_provider.configuration_information = mock_config

        # Make request
        response = client.get("/.well-known/openid-configuration")

        # Verify response
        assert response.status_code == 200
        assert response.json() == mock_config

    @patch("api.routers.well_known_oid_config.provider")
    def test_get_well_known_jwks(self, mock_provider, client):
        """Test GET /.well-known/openid-configuration/jwks returns signing keys."""
        # Setup mock signing key
        mock_signing_key = Mock()
        mock_key_dict = {
            "kty": "RSA",
            "use": "sig",
            "kid": "test-key-id",
            "n": "test-modulus",
            "e": "AQAB",
        }
        mock_signing_key.to_dict.return_value = mock_key_dict
        mock_provider.signing_key = mock_signing_key

        # Make request
        response = client.get("/.well-known/openid-configuration/jwks")

        # Verify response
        assert response.status_code == 200
        response_data = response.json()
        assert "keys" in response_data
        assert len(response_data["keys"]) == 1
        assert response_data["keys"][0] == mock_key_dict

        # Verify to_dict was called
        mock_signing_key.to_dict.assert_called_once()
