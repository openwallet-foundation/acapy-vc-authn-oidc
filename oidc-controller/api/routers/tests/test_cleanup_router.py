"""Tests for HTTP cleanup router endpoints."""

import json
from unittest.mock import patch
import pytest
from fastapi import HTTPException, FastAPI
from fastapi.testclient import TestClient

from api.routers.cleanup import cleanup_endpoint, cleanup_health_check, router


class RouterTestConstants:
    """Constants for router tests."""

    DEFAULT_API_KEY = "test-api-key-123"

    # Default cleanup statistics
    DEFAULT_TOTAL_PRESENTATIONS = 100
    DEFAULT_CLEANED_PRESENTATIONS = 30
    DEFAULT_TOTAL_CONNECTIONS = 50
    DEFAULT_CLEANED_CONNECTIONS = 8


class BaseCleanupRouterTest:
    """Base class for cleanup router tests with shared fixtures and utilities."""

    @pytest.fixture
    def valid_api_key(self):
        """Valid API key for authentication."""
        return RouterTestConstants.DEFAULT_API_KEY

    @pytest.fixture
    def auth_headers(self, valid_api_key):
        """Valid authentication headers."""
        return {"X-API-Key": valid_api_key}

    def create_cleanup_stats(
        self,
        total_presentations=None,
        cleaned_presentations=None,
        total_connections=None,
        cleaned_connections=None,
        failed_cleanups=0,
        errors=None,
        hit_presentation_limit=False,
        hit_connection_limit=False,
    ):
        """Create cleanup statistics with optional overrides."""
        return {
            "total_presentation_records": total_presentations
            or RouterTestConstants.DEFAULT_TOTAL_PRESENTATIONS,
            "cleaned_presentation_records": cleaned_presentations
            or RouterTestConstants.DEFAULT_CLEANED_PRESENTATIONS,
            "total_connections": total_connections
            or RouterTestConstants.DEFAULT_TOTAL_CONNECTIONS,
            "cleaned_connections": cleaned_connections
            or RouterTestConstants.DEFAULT_CLEANED_CONNECTIONS,
            "failed_cleanups": failed_cleanups,
            "errors": errors or [],
            "hit_presentation_limit": hit_presentation_limit,
            "hit_connection_limit": hit_connection_limit,
        }

    def assert_cleanup_response(
        self,
        response,
        expected_status_code=200,
        expected_status="completed",
        expected_has_errors=None,
        expected_stats=None,
    ):
        """Assert cleanup response structure and values."""
        assert response.status_code == expected_status_code

        if expected_status_code == 200:
            response_data = json.loads(response.body)
            assert response_data["status"] == expected_status
            assert "timestamp" in response_data

            if expected_has_errors is not None:
                assert response_data["has_errors"] is expected_has_errors

            if expected_stats:
                stats = response_data["statistics"]
                for key, value in expected_stats.items():
                    assert stats[key] == value

    @pytest.fixture
    def mock_cleanup_stats_no_errors(self):
        """Mock cleanup statistics without errors."""
        return self.create_cleanup_stats()

    @pytest.fixture
    def mock_cleanup_stats_with_errors(self):
        """Mock cleanup statistics with errors."""
        return self.create_cleanup_stats(
            total_presentations=150,
            cleaned_presentations=45,
            total_connections=75,
            cleaned_connections=12,
            failed_cleanups=2,
            errors=["Error 1", "Error 2"],
        )

    @pytest.fixture
    def mock_cleanup_stats_with_limits(self):
        """Mock cleanup statistics that hit resource limits."""
        return self.create_cleanup_stats(
            total_presentations=2000,
            cleaned_presentations=1000,
            total_connections=3000,
            cleaned_connections=2000,
            hit_presentation_limit=True,
            hit_connection_limit=True,
        )


class TestCleanupRouter(BaseCleanupRouterTest):
    """Test HTTP cleanup router endpoints."""

    @pytest.mark.asyncio
    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_basic_success(
        self, mock_get_api_key, mock_perform_cleanup, mock_cleanup_stats_no_errors
    ):
        """Test basic cleanup endpoint success case."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.return_value = mock_cleanup_stats_no_errors

        # Call endpoint with explicit default values
        response = await cleanup_endpoint(
            dry_run=False, max_records=None, max_connections=None
        )

        # Verify perform_cleanup called with defaults
        mock_perform_cleanup.assert_called_once_with(
            dry_run=False,
            max_presentation_records=None,
            max_connections=None,
        )

        # Verify response
        assert response.status_code == 200
        response_data = json.loads(response.body)

        assert response_data["status"] == "completed"
        assert "timestamp" in response_data
        assert response_data["has_errors"] is False

        stats = response_data["statistics"]
        assert stats["total_presentation_records"] == 100
        assert stats["cleaned_presentation_records"] == 30
        assert stats["total_connections"] == 50
        assert stats["cleaned_connections"] == 8
        assert stats["failed_cleanups"] == 0
        assert stats["error_count"] == 0
        assert stats["hit_presentation_limit"] is False
        assert stats["hit_connection_limit"] is False

    @pytest.mark.asyncio
    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_with_parameters(
        self, mock_get_api_key, mock_perform_cleanup, mock_cleanup_stats_no_errors
    ):
        """Test cleanup endpoint with custom parameters."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.return_value = mock_cleanup_stats_no_errors

        # Call endpoint with parameters
        response = await cleanup_endpoint(
            dry_run=True, max_records=500, max_connections=1000
        )

        # Verify perform_cleanup called with custom parameters
        mock_perform_cleanup.assert_called_once_with(
            dry_run=True,
            max_presentation_records=500,
            max_connections=1000,
        )

        # Verify response
        assert response.status_code == 200
        response_data = json.loads(response.body)
        assert response_data["status"] == "completed"

    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_with_errors(
        self, mock_get_api_key, mock_perform_cleanup, mock_cleanup_stats_with_errors
    ):
        """Test cleanup endpoint when cleanup operation has errors."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.return_value = mock_cleanup_stats_with_errors

        # Call endpoint
        response = await cleanup_endpoint()

        # Verify response includes error information
        assert response.status_code == 200
        response_data = json.loads(response.body)

        assert response_data["status"] == "completed"
        assert response_data["has_errors"] is True

        stats = response_data["statistics"]
        assert stats["failed_cleanups"] == 2
        assert stats["error_count"] == 2

    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_with_resource_limits(
        self, mock_get_api_key, mock_perform_cleanup, mock_cleanup_stats_with_limits
    ):
        """Test cleanup endpoint when resource limits are hit."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.return_value = mock_cleanup_stats_with_limits

        # Call endpoint
        response = await cleanup_endpoint()

        # Verify response shows limits were hit
        assert response.status_code == 200
        response_data = json.loads(response.body)

        stats = response_data["statistics"]
        assert stats["hit_presentation_limit"] is True
        assert stats["hit_connection_limit"] is True

    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_service_failure(
        self, mock_get_api_key, mock_perform_cleanup
    ):
        """Test cleanup endpoint when cleanup service fails."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.side_effect = Exception("Database connection failed")

        # Call endpoint and expect HTTPException
        with pytest.raises(HTTPException) as exc_info:
            await cleanup_endpoint()

        assert exc_info.value.status_code == 500
        assert "Internal server error during cleanup operation" in str(
            exc_info.value.detail
        )

    @pytest.mark.asyncio
    async def test_cleanup_health_check(self):
        """Test cleanup health check endpoint."""
        response = await cleanup_health_check()

        assert response.status_code == 200
        response_data = json.loads(response.body)

        assert response_data["status"] == "healthy"
        assert response_data["service"] == "cleanup"
        assert "timestamp" in response_data

    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_dry_run_mode(
        self, mock_get_api_key, mock_perform_cleanup, mock_cleanup_stats_no_errors
    ):
        """Test cleanup endpoint in dry-run mode."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.return_value = mock_cleanup_stats_no_errors

        # Call endpoint in dry-run mode
        response = await cleanup_endpoint(
            dry_run=True, max_records=None, max_connections=None
        )

        # Verify dry-run parameter passed to service
        mock_perform_cleanup.assert_called_once_with(
            dry_run=True,
            max_presentation_records=None,
            max_connections=None,
        )

        assert response.status_code == 200

    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_custom_limits(
        self, mock_get_api_key, mock_perform_cleanup, mock_cleanup_stats_no_errors
    ):
        """Test cleanup endpoint with custom resource limits."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.return_value = mock_cleanup_stats_no_errors

        # Call endpoint with custom limits
        response = await cleanup_endpoint(
            dry_run=False, max_records=250, max_connections=500
        )

        # Verify custom limits passed to service
        mock_perform_cleanup.assert_called_once_with(
            dry_run=False,
            max_presentation_records=250,
            max_connections=500,
        )

        assert response.status_code == 200

    @patch("api.routers.cleanup.perform_cleanup")
    @patch("api.core.auth.get_api_key")
    @pytest.mark.asyncio
    async def test_cleanup_endpoint_all_parameters(
        self, mock_get_api_key, mock_perform_cleanup, mock_cleanup_stats_no_errors
    ):
        """Test cleanup endpoint with all parameters provided."""
        # Setup mocks
        mock_get_api_key.return_value = "valid-key"
        mock_perform_cleanup.return_value = mock_cleanup_stats_no_errors

        # Call endpoint with all parameters
        response = await cleanup_endpoint(
            dry_run=True, max_records=100, max_connections=200
        )

        # Verify all parameters passed correctly
        mock_perform_cleanup.assert_called_once_with(
            dry_run=True,
            max_presentation_records=100,
            max_connections=200,
        )

        assert response.status_code == 200


class TestCleanupRouterIntegration:
    """Integration tests for cleanup router with FastAPI test client."""

    @pytest.fixture
    def client(self):
        """FastAPI test client with minimal app setup."""
        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    @patch("api.core.auth.API_KEY", "test-api-key")
    @patch("api.routers.cleanup.perform_cleanup")
    def test_cleanup_endpoint_http_success(self, mock_perform_cleanup, client):
        """Test cleanup endpoint via HTTP with valid authentication."""
        # Setup mock
        mock_stats = {
            "total_presentation_records": 50,
            "cleaned_presentation_records": 15,
            "total_connections": 25,
            "cleaned_connections": 5,
            "failed_cleanups": 0,
            "errors": [],
            "hit_presentation_limit": False,
            "hit_connection_limit": False,
        }
        mock_perform_cleanup.return_value = mock_stats

        # Make HTTP request with authentication
        response = client.delete("/cleanup", headers={"X-API-Key": "test-api-key"})

        # Verify response
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "completed"
        assert data["has_errors"] is False
        assert data["statistics"]["total_presentation_records"] == 50

    @patch("api.core.auth.API_KEY", "test-api-key")
    def test_cleanup_endpoint_http_authentication_failure(self, client):
        """Test cleanup endpoint HTTP authentication failure."""
        # Make request with invalid API key
        response = client.delete("/cleanup", headers={"X-API-Key": "invalid-key"})

        # Verify authentication failure
        assert response.status_code == 403

    @patch("api.core.auth.API_KEY", "test-api-key")
    def test_cleanup_endpoint_http_missing_auth(self, client):
        """Test cleanup endpoint without authentication header."""
        # Make request without API key
        response = client.delete("/cleanup")

        # Verify authentication failure
        assert response.status_code == 403

    @patch("api.core.auth.API_KEY", "test-api-key")
    @patch("api.routers.cleanup.perform_cleanup")
    def test_cleanup_endpoint_http_with_query_params(
        self, mock_perform_cleanup, client
    ):
        """Test cleanup endpoint via HTTP with query parameters."""
        # Setup mock
        mock_stats = {
            "total_presentation_records": 30,
            "cleaned_presentation_records": 10,
            "total_connections": 15,
            "cleaned_connections": 3,
            "failed_cleanups": 0,
            "errors": [],
            "hit_presentation_limit": False,
            "hit_connection_limit": False,
        }
        mock_perform_cleanup.return_value = mock_stats

        # Make HTTP request with query parameters
        response = client.delete(
            "/cleanup?dry_run=true&max_records=100&max_connections=200",
            headers={"X-API-Key": "test-api-key"},
        )

        # Verify service called with correct parameters
        mock_perform_cleanup.assert_called_once_with(
            dry_run=True,
            max_presentation_records=100,
            max_connections=200,
        )

        assert response.status_code == 200

    def test_cleanup_health_endpoint_http(self, client):
        """Test cleanup health endpoint via HTTP (no authentication required)."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "cleanup"

    @patch("api.core.auth.API_KEY", "test-api-key")
    @patch("api.routers.cleanup.perform_cleanup")
    def test_cleanup_endpoint_http_server_error(self, mock_perform_cleanup, client):
        """Test cleanup endpoint HTTP when service raises exception."""
        # Setup mock to raise exception
        mock_perform_cleanup.side_effect = Exception("Service unavailable")

        # Make HTTP request
        response = client.delete("/cleanup", headers={"X-API-Key": "test-api-key"})

        # Verify server error response
        assert response.status_code == 500
        data = response.json()
        assert "Internal server error during cleanup operation" in data["detail"]
