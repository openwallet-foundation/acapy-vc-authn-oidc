import mock
import pytest
import json
from api.core.acapy.config import (
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from api.core.config import settings


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
    # Test behavior when API key is missing
    acapy = SingleTenantAcapy()
    headers = acapy.get_headers()
    assert headers == {}


@pytest.mark.asyncio
async def test_multi_tenant_get_headers_returns_bearer_token_auth(requests_mock):
    acapy = MultiTenantAcapy()
    acapy.get_wallet_token = mock.MagicMock(return_value="token")
    headers = acapy.get_headers()
    assert headers == {"Authorization": "Bearer token"}


@pytest.mark.asyncio
async def test_multi_tenant_get_wallet_token_returns_token_at_token_key(requests_mock):
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"

    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(settings, "MT_ACAPY_WALLET_KEY", wallet_key):

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            headers={},
            json={"token": "token"},
            status_code=200,
        )

        acapy = MultiTenantAcapy()
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        token = acapy.get_wallet_token()
        assert token == "token"


@pytest.mark.asyncio
async def test_multi_tenant_get_wallet_token_includes_auth_headers_and_body(
    requests_mock,
):
    # Verify headers and body payload
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"
    admin_key = "admin_key"
    admin_header = "x-api-key"

    # Mock settings for the duration of this test
    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_KEY", wallet_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY", admin_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY_NAME", admin_header
    ):

        acapy = MultiTenantAcapy()
        # Ensure we use the values we expect (class init reads settings once)
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        # Ensure we bypass cache from any previous tests
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "token"},
            status_code=200,
        )

        token = acapy.get_wallet_token()
        assert token == "token"

        # Verify request details
        last_request = requests_mock.last_request
        assert last_request.headers[admin_header] == admin_key
        assert last_request.json() == {"wallet_key": wallet_key}


@pytest.mark.asyncio
async def test_multi_tenant_get_wallet_token_no_auth_headers_when_not_configured(
    requests_mock,
):
    # Test insecure mode behavior
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"

    # Mock settings with None for admin key
    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_KEY", wallet_key
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY", None
    ), mock.patch.object(
        settings, "ST_ACAPY_ADMIN_API_KEY_NAME", "x-api-key"
    ):

        acapy = MultiTenantAcapy()
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "token"},
            status_code=200,
        )

        token = acapy.get_wallet_token()
        assert token == "token"

        # Verify request details
        last_request = requests_mock.last_request
        # Headers might contain Content-Type, but should not contain the api key
        assert "x-api-key" not in last_request.headers
        assert last_request.json() == {"wallet_key": wallet_key}


@pytest.mark.asyncio
async def test_multi_tenant_throws_exception_for_401_unauthorized(requests_mock):
    wallet_id = "wallet_id"
    wallet_key = "wallet_key"

    with mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(settings, "MT_ACAPY_WALLET_KEY", wallet_key):

        acapy = MultiTenantAcapy()
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"error": "unauthorized"},
            status_code=401,
        )

        # Check for generic Exception, as the code now raises Exception(f"{code}::{detail}")
        with pytest.raises(Exception) as excinfo:
            acapy.get_wallet_token()

        assert "401" in str(excinfo.value)
        assert "unauthorized" in str(excinfo.value)


@pytest.mark.asyncio
async def test_traction_tenant_api_key_flow_success(requests_mock):
    """Test Traction mode getting token using Tenant ID and API Key."""
    tenant_id = "test-tenant-id"
    api_key = "test-api-key"

    with mock.patch.object(
        settings, "TRACTION_TENANT_ID", tenant_id
    ), mock.patch.object(settings, "TRACTION_TENANT_API_KEY", api_key):

        # Mock the Traction token endpoint
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token",
            json={"token": "traction-token"},
            status_code=200,
        )

        acapy = TractionTenantAcapy()
        acapy.tenant_id = tenant_id
        acapy.tenant_api_key = api_key
        acapy.get_wallet_token.cache_clear()

        token = acapy.get_wallet_token()
        assert token == "traction-token"

        # Verify request details
        last_request = requests_mock.last_request
        assert last_request.json() == {"api_key": api_key}


@pytest.mark.asyncio
async def test_traction_tenant_fallback_to_wallet_key_success(requests_mock):
    """Test Traction mode falling back to Wallet Key when Tenant API auth missing/fails."""
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"

    # Set TRACTION_ vars to None to trigger fallback immediately
    with mock.patch.object(settings, "TRACTION_TENANT_ID", None), mock.patch.object(
        settings, "TRACTION_TENANT_API_KEY", None
    ), mock.patch.object(settings, "MT_ACAPY_WALLET_ID", wallet_id), mock.patch.object(
        settings, "MT_ACAPY_WALLET_KEY", wallet_key
    ):

        # Mock the Wallet token endpoint (no admin header used in traction mode)
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "fallback-token"},
            status_code=200,
        )

        acapy = TractionTenantAcapy()
        acapy.tenant_id = None
        acapy.tenant_api_key = None
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        token = acapy.get_wallet_token()
        assert token == "fallback-token"


@pytest.mark.asyncio
async def test_traction_tenant_api_auth_fails_then_fallback_succeeds(requests_mock):
    """Test Traction mode tries Tenant API, fails, then succeeds with Wallet Key."""
    tenant_id = "test-tenant-id"
    api_key = "test-api-key"
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"

    with mock.patch.object(
        settings, "TRACTION_TENANT_ID", tenant_id
    ), mock.patch.object(
        settings, "TRACTION_TENANT_API_KEY", api_key
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_KEY", wallet_key
    ):

        # Traction API call fails (e.g. 401/403 or server error)
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token",
            status_code=401,
        )

        # Fallback to Wallet Key succeeds
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "fallback-token"},
            status_code=200,
        )

        acapy = TractionTenantAcapy()
        acapy.tenant_id = tenant_id
        acapy.tenant_api_key = api_key
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        token = acapy.get_wallet_token()
        assert token == "fallback-token"


@pytest.mark.asyncio
async def test_traction_tenant_all_auth_methods_fail(requests_mock):
    """Test exception raised when all authentication methods fail in Traction mode."""
    tenant_id = "test-tenant-id"
    api_key = "test-api-key"
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"

    with mock.patch.object(
        settings, "TRACTION_TENANT_ID", tenant_id
    ), mock.patch.object(
        settings, "TRACTION_TENANT_API_KEY", api_key
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_ID", wallet_id
    ), mock.patch.object(
        settings, "MT_ACAPY_WALLET_KEY", wallet_key
    ):

        # Traction API fails
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token",
            status_code=500,
        )

        # Wallet Key fallback fails
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            status_code=404,
            content=b"Wallet not found",
        )

        acapy = TractionTenantAcapy()
        acapy.tenant_id = tenant_id
        acapy.tenant_api_key = api_key
        acapy.wallet_id = wallet_id
        acapy.wallet_key = wallet_key
        acapy.get_wallet_token.cache_clear()

        with pytest.raises(Exception) as excinfo:
            acapy.get_wallet_token()

        # Verify the exception came from the final fallback failure
        assert "404" in str(excinfo.value)
        assert "Wallet not found" in str(excinfo.value)
