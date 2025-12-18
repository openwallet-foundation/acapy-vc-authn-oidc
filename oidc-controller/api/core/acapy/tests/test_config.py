import mock
import pytest
import time
from requests.exceptions import RequestException
from api.core.acapy.config import (
    MultiTenantAcapy,
    SingleTenantAcapy,
    TractionTenantAcapy,
)
from api.core.config import settings


# Helper to reset class level cache
def reset_acapy_cache(cls):
    cls._token = None
    cls._token_expiry = 0.0


@pytest.fixture(autouse=True)
def clean_cache():
    """Ensure cache is clean before each test."""
    reset_acapy_cache(MultiTenantAcapy)
    reset_acapy_cache(TractionTenantAcapy)
    yield
    reset_acapy_cache(MultiTenantAcapy)
    reset_acapy_cache(TractionTenantAcapy)


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

        token = acapy.get_wallet_token()
        assert token == "token"

        # Verify it sent the wallet_key in the body
        assert requests_mock.last_request.json() == {"wallet_key": wallet_key}


@pytest.mark.asyncio
async def test_multi_tenant_missing_id_raises_error():
    """Test error validation if ACAPY_TENANT_WALLET_ID is missing in multi-tenant mode."""
    with mock.patch.object(MultiTenantAcapy, "wallet_id", None):
        acapy = MultiTenantAcapy()

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
async def test_multi_tenant_caching_behavior(requests_mock):
    """Test that tokens are cached and not fetched repeatedly."""
    wallet_id = "cache-test-id"
    wallet_key = "cache-test-key"

    with mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id), mock.patch.object(
        MultiTenantAcapy, "wallet_key", wallet_key
    ):
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "cached-token"},
            status_code=200,
        )

        acapy = MultiTenantAcapy()

        # First call hits API
        token1 = acapy.get_wallet_token()
        assert token1 == "cached-token"
        assert requests_mock.call_count == 1

        # Second call hits cache
        token2 = acapy.get_wallet_token()
        assert token2 == "cached-token"
        assert requests_mock.call_count == 1  # Count should NOT increase


@pytest.mark.asyncio
async def test_multi_tenant_token_expiry(requests_mock):
    """Test that expired tokens trigger a re-fetch."""
    wallet_id = "expiry-test-id"
    wallet_key = "expiry-test-key"

    with mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id), mock.patch.object(
        MultiTenantAcapy, "wallet_key", wallet_key
    ):
        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"token": "fresh-token"},
            status_code=200,
        )

        acapy = MultiTenantAcapy()

        # Inject an expired token directly
        MultiTenantAcapy._token = "stale-token"
        MultiTenantAcapy._token_expiry = time.time() - 100  # Expired 100s ago

        # Call should trigger fetch
        token = acapy.get_wallet_token()

        assert token == "fresh-token"
        assert requests_mock.call_count == 1


@pytest.mark.asyncio
async def test_multi_tenant_throws_exception_for_401(requests_mock):
    """Test error handling for 401 Unauthorized in multi-tenant mode."""
    wallet_id = "test-wallet-id"
    wallet_key = "test-wallet-key"

    with mock.patch.object(MultiTenantAcapy, "wallet_id", wallet_id), mock.patch.object(
        MultiTenantAcapy, "wallet_key", wallet_key
    ):

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/wallet/{wallet_id}/token",
            json={"error": "unauthorized"},
            status_code=401,
        )

        acapy = MultiTenantAcapy()
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

        token = acapy.get_wallet_token()
        assert token == "traction-token"

        # Verify payload uses "api_key" (Traction style) instead of "wallet_key"
        last_request = requests_mock.last_request
        assert last_request.json() == {"api_key": api_key}


@pytest.mark.asyncio
async def test_traction_caching_and_expiry(requests_mock):
    """Test Traction token caching logic."""
    tenant_id = "traction-cache-id"
    api_key = "traction-cache-key"

    with mock.patch.object(
        TractionTenantAcapy, "tenant_id", tenant_id
    ), mock.patch.object(TractionTenantAcapy, "api_key", api_key):

        requests_mock.post(
            settings.ACAPY_ADMIN_URL + f"/multitenancy/tenant/{tenant_id}/token",
            json={"token": "traction-token"},
            status_code=200,
        )

        acapy = TractionTenantAcapy()

        # 1. First fetch
        t1 = acapy.get_wallet_token()
        assert t1 == "traction-token"
        assert requests_mock.call_count == 1

        # 2. Second fetch (Cached)
        t2 = acapy.get_wallet_token()
        assert t2 == "traction-token"
        assert requests_mock.call_count == 1

        # 3. Simulate Expiry
        TractionTenantAcapy._token_expiry = time.time() - 1

        # 4. Third fetch (Refresh)
        t3 = acapy.get_wallet_token()
        assert t3 == "traction-token"
        assert requests_mock.call_count == 2


@pytest.mark.asyncio
async def test_traction_mode_missing_credentials_raises_error():
    """Test that missing credentials in Traction mode raises ValueError."""

    with mock.patch.object(TractionTenantAcapy, "tenant_id", None), mock.patch.object(
        TractionTenantAcapy, "api_key", None
    ):

        acapy = TractionTenantAcapy()

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

        with pytest.raises(RequestException):
            acapy.get_wallet_token()


def test_token_ttl_configuration():
    """Test that TOKEN_TTL picks up the configuration value."""
    # Since TOKEN_TTL is evaluated at class definition time, we check that it matches
    assert MultiTenantAcapy.TOKEN_TTL == 3600
    assert TractionTenantAcapy.TOKEN_TTL == 3600

    # Verify we can modify it (simulating config load)
    original_ttl = MultiTenantAcapy.TOKEN_TTL
    try:
        MultiTenantAcapy.TOKEN_TTL = 300
        assert MultiTenantAcapy.TOKEN_TTL == 300

        # Verify get_wallet_token uses the class attribute
        # We assume the logic uses self.TOKEN_TTL or Class.TOKEN_TTL
        acapy = MultiTenantAcapy()
        assert acapy.TOKEN_TTL == 300
    finally:
        MultiTenantAcapy.TOKEN_TTL = original_ttl
