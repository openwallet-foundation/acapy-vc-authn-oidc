import mock
import pytest
from requests.exceptions import RequestException
from api.core.acapy.config import (
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from api.core.config import settings


# ==========================================
# Single Tenant Tests
# ==========================================


@pytest.mark.asyncio
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "name")
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY", "key")
async def test_single_tenant_has_expected_headers_configured():
    acapy = SingleTenantAcapy()
    headers = acapy.get_headers()
    assert headers == {"name": "key"}


@pytest.mark.asyncio
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "name")
@mock.patch.object(settings, "ST_ACAPY_ADMIN_API_KEY", None)
async def test_single_tenant_empty_headers_not_configured():
    acapy = SingleTenantAcapy()
    headers = acapy.get_headers()
    assert headers == {}


# ==========================================
# Multi-Tenant Tests (Unified Config)
# ==========================================


@pytest.mark.asyncio
async def test_multi_tenant_get_headers_returns_bearer_token_auth():
    """Test that get_headers calls get_wallet_token and formats Bearer string."""
    acapy = MultiTenantAcapy()
    # Mock the internal method to isolate header logic
    acapy.get_wallet_token = mock.MagicMock(return_value="token")

    headers = acapy.get_headers()
    assert headers == {"Authorization": "Bearer token"}


@pytest.mark.asyncio
async def test_multi_tenant_uses_unified_variables(requests_mock):
    """Test MultiTenantAcapy uses the unified ACAPY_TENANT_WALLET_* vars."""
    wallet_id = "unified-wallet-id"
    wallet_key = "unified-wallet-key"

    # Patch class attributes directly because they are bound at module import time
    with mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id), mock.patch.object(
        MultiTenantAcapy, "wallet_key", wallet_key
    ):

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            headers={},
            json={"token": "token"},
            status_code=200,
        )

        acapy = MultiTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        token = acapy.get_wallet_token()
        assert token == "token"

        # Verify it sent the wallet_key in the body
        assert requests_mock.last_request.json() == {"wallet_key": wallet_key}


@pytest.mark.asyncio
async def test_multi_tenant_missing_id_raises_error():
    """Test error validation if ACAPY_TENANT_WALLET_ID is missing in multi-tenant mode."""
    with mock.patch.object(MultiTenantAcapy, "wallet_id", None):
        acapy = MultiTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        with pytest.raises(ValueError) as exc:
            acapy.get_wallet_token()
        assert "ACAPY_TENANT_WALLET_ID is required" in str(exc.value)


@pytest.mark.asyncio
async def test_multi_tenant_includes_admin_api_key_headers(requests_mock):
    """Test that ST_ACAPY_ADMIN_API_KEY headers are included in the request if set."""
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"
    admin_key = "admin_key"
    admin_header = "x-api-key"

    with mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id), mock.patch.object(
        MultiTenantAcapy, "wallet_key", wallet_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY", admin_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY_NAME", admin_header
    ):

        acapy = MultiTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "token"},
            status_code=200,
        )

        token = acapy.get_wallet_token()
        assert token == "token"

        # Verify request headers included the admin key
        last_request = requests_mock.last_request
        assert last_request.headers[admin_header] == admin_key


@pytest.mark.asyncio
async def test_multi_tenant_throws_exception_for_401(requests_mock):
    """Test error handling for 401 Unauthorized in multi-tenant mode."""
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"

    with mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id), mock.patch.object(
        MultiTenantAcapy, "wallet_key", wallet_key
    ):

        acapy = MultiTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"error": "unauthorized"},
            status_code=401,
        )

        with pytest.raises(Exception) as excinfo:
            acapy.get_wallet_token()

        assert "401" in str(excinfo.value)


# ==========================================
# Traction Tenant Mode Tests (Unified Config)
# ==========================================


@pytest.mark.asyncio
async def test_traction_mode_uses_unified_variables_as_tenant_creds(requests_mock):
    """
    Test that in Traction mode:
    ACAPY_TENANT_WALLET_ID -> Tenant ID
    ACAPY_TENANT_WALLET_KEY -> Tenant API Key
    """
    tenant_id = "unified-tenant-id"
    api_key = "unified-api-key"

    # TractionTenantAcapy reads from settings at class level
    with mock.patch.object(
        TractionTenantAcapy, "tenant_id", tenant_id
    ), mock.patch.object(TractionTenantAcapy, "api_key", api_key):

        # Verify calls /multitenancy/tenant/{id}/token (Traction API)
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token",
            json={"token": "traction-token"},
            status_code=200,
        )

        acapy = TractionTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        token = acapy.get_wallet_token()
        assert token == "traction-token"

        # Verify payload uses "api_key" (Traction style) instead of "wallet_key"
        last_request = requests_mock.last_request
        assert last_request.json() == {"api_key": api_key}


@pytest.mark.asyncio
async def test_traction_mode_missing_credentials_raises_error():
    """Test that missing credentials in Traction mode raises ValueError."""

    with mock.patch.object(TractionTenantAcapy, "tenant_id", None), mock.patch.object(
        TractionTenantAcapy, "api_key", None
    ):

        acapy = TractionTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        with pytest.raises(ValueError) as exc:
            acapy.get_wallet_token()

        # Verify specific error message for unified config
        assert "Traction mode requires ACAPY_TENANT_WALLET_ID" in str(exc.value)


@pytest.mark.asyncio
async def test_traction_mode_api_failure_raises_exception(requests_mock):
    """Test error handling when Traction API returns non-200."""
    tenant_id = "test-tenant"
    api_key = "test-key"

    with mock.patch.object(
        TractionTenantAcapy, "tenant_id", tenant_id
    ), mock.patch.object(TractionTenantAcapy, "api_key", api_key):

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token",
            status_code=403,
            text="Forbidden",
        )

        acapy = TractionTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        with pytest.raises(Exception) as exc:
            acapy.get_wallet_token()

        assert "403" in str(exc.value)


@pytest.mark.asyncio
async def test_traction_mode_connection_error_raises_exception(requests_mock):
    """Test handling of network exceptions in Traction mode."""
    tenant_id = "test-tenant"
    api_key = "test-key"

    with mock.patch.object(
        TractionTenantAcapy, "tenant_id", tenant_id
    ), mock.patch.object(TractionTenantAcapy, "api_key", api_key):

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token",
            exc=RequestException("Connection refused"),
        )

        acapy = TractionTenantAcapy()
        acapy.get_wallet_token.cache_clear()

        with pytest.raises(RequestException):
            acapy.get_wallet_token()
